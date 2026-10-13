# One audit path for mediated actions

VAK had two audit implementations. Slice 1a gave the kernel the `AuditLog` port: an
RFC 9162 Merkle tree with decision and outcome leaves, receipts, and memory and JSONL
adapters. `audit::AuditLogger` was older: a linear hash chain with memory, file and
SQLite backends, per-entry Ed25519 signatures and rotation. The kernel used only the
first (finding K6). The second had its own defects:

- Its entry hash concatenated fields without length prefixes, so `("ab", "c")` and
  `("a", "bc")` hashed the same, and it left `metadata` out (K7).
- `log` returned the entry even when the backend failed to store it, and the next entry
  then linked to one that didn't exist.
- Rotation evicted the oldest entries, after which `verify_chain`, which starts from
  the genesis hash, failed. Entries it failed to archive were evicted anyway.

The plan for this slice was that `AuditLogger` "becomes an `AuditLog` adapter (SQLite),
or is removed".

## Decisions

**The `AuditLog` port is the only audit path for mediated actions.** Everything
`Kernel::execute` decides or does is recorded through it, and through nothing else.
`AuditLogger` did not become an adapter for it. Its data model is different (a linear
chain of strings, ids from 1, rotation by deletion, synchronous `&mut self` calls), so
adapting it would have meant writing a new type anyway. What the kernel lacked from it
was durable, queryable storage, and that is now `SqliteAuditLog`.

**`SqliteAuditLog` is the third adapter.** `audit.format: sqlite` selects it for the
log at `audit.log_path`; `jsonl` (the default) keeps `FileAuditLog`.

- One table, `vak_audit_log(leaf_index, entry_hash, entry)`. `entry` is the same JSON
  the JSONL file holds, so operators can query it with `json_extract`.
- Each append is one autocommit `INSERT`, in WAL mode with `synchronous = FULL`, so
  `append` returns `Ok` only once the row is durable. A crash mid-append rolls the row
  back. The JSONL file instead refuses to open after a torn last line.
- Opening checks `PRAGMA application_id` and `user_version`, so it refuses a database VAK
  didn't create and a schema version it can't read. It then reads every row in leaf
  order, checks that leaf indices are dense from zero, checks `entry_hash` against the
  entry, verifies the chain, and rebuilds the tree. Anything that fails verification
  is refused, never repaired.
- After a failed write the log refuses appends until it is reopened, as `FileAuditLog`
  does. A second writer on the same database is detected (its insert collides on the
  leaf index), not coordinated.
- A log in the other format is refused, never started afresh. The format is set
  explicitly, not inferred from the file extension.

**Appends run to completion.** `FileAuditLog` (slice 1a) wrote on the caller's future.
If a caller dropped `Kernel::execute` mid-write, the line could still reach the disk
without its leaf joining the tree. The next entry then linked to the wrong
predecessor, and the file refused to open. Both durable adapters now run each append on
its own task, and the port's contract says so. A test drops an append after one poll;
it fails without this change.

**The kernel's log is not rotated.** Deleting old entries would invalidate inclusion
proofs already handed out. `audit.max_log_size_bytes` and `audit.retention_count` are
documented as not applying to it. Bounded storage is Phase 3's tiles.

**`AuditLogger` stays, fixed, as a standalone event log** for applications that record
their own events outside the kernel:

- The entry hash is now version 2. It covers a domain tag and every field except `hash`
  and `signature`, each length-prefixed, `metadata` included (K7).
- Logs written before this change keep verifying. A version 1 entry is accepted only
  in a prefix of the log, before the first version 2 entry, and
  `AuditReport::legacy_entries` counts such entries. A forger can't use the old hash on
  entries written since: making an entry pass as version 1 changes its hash, which
  breaks its successor's link.
- `metadata` is hashed as JSON, so it must survive a write and a read exactly.
  `serde_json` now has `float_roundtrip`. A test of 2,000 arbitrary doubles fails
  without it.
- `log` and `log_with_metadata` return `Result`. A failed write is an error, and the
  chain is left as it was.
- Rotation records where the chain now starts, so the log still verifies after
  eviction. It no longer evicts entries it couldn't archive.

**The Python bindings still use `AuditLogger`**, because `vak.Kernel` doesn't use the
kernel at all. It has its own policy engine and audit log, and its `execute_tool` reports
success without running anything (new finding I4). Moving it onto `Kernel` is its own
change. Removing `AuditLogger` can follow that.

## Considered options

**Making `AuditLogger` an `AuditLog` adapter.** Rejected for the reasons above: it
would keep the name and replace everything else.

**Removing `AuditLogger` now.** The Python bindings, an example and the benches depend
on it, and once fixed it is a sound standalone tool. Its removal is a separate decision,
after I4.

**A hash-version field on each entry.** That would change the stored format of every
backend: the SQLite backend's columns, S3, streaming, multi-region. Trying the current
hash first, and the old one only in a prefix of the log, needs no format change.

**Inferring the log format from the file extension.** A misnamed file would then be read
as the wrong format. An explicit `audit.format`, plus refusing a log in the other
format, makes that a configuration error.

## Consequences

- **Breaking:**
  - `AuditLogger::log` and `log_with_metadata` return `Result<&AuditEntry, AuditError>`.
  - `AuditReport` has a `legacy_entries` field.
  - `AuditConfig` has a `format` field.
  - `AuditLogError` has a `Format` variant, and `Corrupt` now reads "at entry *n*".
- Entries in old `AuditLogger` logs keep verifying, but their `metadata` is still not
  covered by their hash.
- The durable adapters still keep every entry in memory, because the tree needs every
  leaf hash and `entries()` returns them all.
- A log on its own can't detect that its tail was cut off. Anyone holding an earlier
  receipt detects it, because a consistency proof from that receipt's tree head to the
  current one fails.
- Phase 1 is complete.

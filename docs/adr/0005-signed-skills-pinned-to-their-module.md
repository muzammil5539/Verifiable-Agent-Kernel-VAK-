# Skills are signed with Ed25519 and pinned to the module they were verified with

A WASM skill is untrusted code that the kernel runs on an agent's behalf. Until now,
nothing tied a skill to whoever published it (finding K4 in `docs/architecture-v2.md`):

- The registry's "signature" was an unkeyed SHA-256 over the name, version,
  description and permissions. Anyone could recompute it for any manifest.
- If the module file was missing, the hash covered the module's *path* instead, so a
  manifest "verified" with no code at all.
- `SignatureConfig::trusted_keys` existed but was never read.
- The module was verified at load, then read again from disk at every call, so a file
  replaced after load ran unverified.

`docs/architecture-v2.md` planned to reuse `sandbox::verified_publisher`. That module
turned out to store key and signature strings without ever verifying one, so the
signing is written directly on `ed25519-dalek`, in `sandbox::signing`.

## Decisions

**Ed25519 signatures against an explicit trust root.** A manifest carries `signed_by`
(a hex public key) and `signature` (hex). The kernel trusts the keys in
`security.trusted_skill_keys`; the registry loads a skill only if `signed_by` is one of
them and the signature verifies. A trusted key that doesn't parse fails `Kernel::build`
rather than being skipped. With no trusted keys, no skill loads.

**Sign the module's digest and everything that shapes behaviour.** The signed statement
is `vak.skill-signature.v1\n` followed by canonical JSON (sorted keys, no whitespace) of
`author`, `description`, `input_schema`, `module_sha256`, `name`, `output_schema`,
`permissions` and `version`. Signing the name means a skill signed as `calculator`
can't be loaded as `transfer_funds`; signing the permissions means they can't be
widened. `wasm_path` is the one field left out: where a module lives is a deployment
detail, and the digest binds the code. The context prefix keeps a skill signature from
being valid for any other message signed with the same key. The canonical encoding is
written out by hand so it doesn't change if a dependency turns on `serde_json`'s
`preserve_order`.

**Unsigned skills are refused unless explicitly allowed.** `security.allow_unsigned_skills`
(default `false`) admits unsigned skills for development. A skill that *carries* a
signature is always verified, even then: a signature that doesn't verify is evidence of
tampering, not of a development build.

**The module that was verified is the module that runs.** Loading reads the module once,
verifies the signature over those bytes, and records their SHA-256 in the registry. The
kernel calls `SandboxRuntime::prepare_file_pinned` with that digest. If the module is
cached it runs without reading the disk at all; on a cache miss the file is read and
refused unless its digest matches. That closes the window between verification and
execution. Unsigned skills are pinned the same way.

**The outcome leaf names the module that ran.** `AuditOutcome::module_sha256` records
the pinned digest for every WASM skill call, so an audit proof shows not just that a
skill named `X` ran, but which signed bytes.

## Considered options

**Trying every trusted key instead of carrying `signed_by`.** That would avoid a field,
but the audit trail and error messages should name the publisher, and verification
should not cost one signature check per trusted key.

**Embedding the signature in the module (`wasmsign2` custom sections).** That travels
with the binary, but needs a parser for the custom section and a separate story for the
manifest. A detached signature in the manifest covers both, and Sigstore bundles
(the planned next step) are detached too.

**Keeping the old `compute_signature` for compatibility.** Accepting the old format in
any mode would keep a signature anyone can forge. Old manifests fail to verify, and the
fix is to re-sign them.

## Consequences

- **Breaking:** existing "signatures" no longer verify. Re-sign skills with
  `cargo run --example sign_skill -- sign <manifest> <key>`, and put the publisher's
  public key in `security.trusted_skill_keys`.
- A skill whose module file is missing can't be loaded.
- Replacing a module on disk takes effect only after the skill is reloaded and its
  signature re-verified. Until then the kernel runs the cached verified module, or
  refuses with `ModuleChanged` on a cache miss.
- Keys are raw Ed25519 keys with no expiry or revocation. Rotating a publisher means
  editing `trusted_skill_keys`. Sigstore's keyless identities and transparency-log
  entries are the planned replacement.
- `tests/signed_skills.rs` meets the Phase 1 exit criterion: it signs a skill, loads it
  from config alone, runs it through `Kernel::execute`, restarts the kernel on the same
  audit file, and verifies both leaves against the new signed tree head.

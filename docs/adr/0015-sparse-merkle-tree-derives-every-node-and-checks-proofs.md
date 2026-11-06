# The sparse Merkle tree derives every node, and checks what a proof claims

Finding V4 (`docs/architecture-v2.md` §2.2): `SparseMerkleTree::get_sibling_hash`
returned the empty-subtree hash for every sibling. So the root was computed along the
last key's path as though the tree held nothing else. It committed only to the last key
written. An earlier key's value could change, and the root stayed the same. Any proof
for an earlier key failed against the final root.

Fixing that exposed more problems in `src/memory/sparse_merkle.rs`:

- **Forged exclusion proofs.** `SparseProof::verify` walked the path in the directions
  the proof itself gave. A proof of absence for one key could be relabelled with
  another key, present in the tree, and still verify.
- **The inclusion flag was unchecked.** `is_inclusion` wasn't bound to anything: an
  exclusion proof could say it proved inclusion.
- **Leaf hashes collided.** A leaf hashed `"leaf:" ‖ key ‖ ":" ‖ value`, so `("a:b",
  "c")` and `("a", "b:c")` had the same hash.
- **Shared positions.** A tree shallower than 256 levels has fewer leaf positions than
  keys. Two keys at one position silently shared a leaf.
- **Removal hashed the wrong empty value.** It rebuilt the path from the root's
  empty-subtree hash, not the leaf's.
- **Imports trusted what they were given.** `from_export` took the exported root on
  trust and dropped every value, so an imported tree claimed a root it couldn't prove
  anything against.

The tree is not on `Kernel::execute`'s path; nothing in the kernel uses it. Its tests
are unit tests against a reference implementation of the definition.

## Decisions

**The standard construction** (§4.6: Dahlberg, Pulls and Peeters, 2016).

- **Positions.** A key's leaf position is the first `depth` bits of SHA-256 of the key.
- **Empty subtrees.** Each height has a precomputed empty-subtree hash, and only
  non-empty nodes are stored.
- **Internal nodes.** Each is derived from its two real children.
- **The root.** It is the same whatever order the entries were inserted in, and equals
  a from-scratch recursion over the definition. The tests check both.

**Hashes are domain-separated and length-prefixed.**

- **Leaves.** `SHA-256(0x00 ‖ len(key) ‖ key ‖ len(value) ‖ value)`, with 8-byte
  big-endian lengths.
- **Internal nodes.** `SHA-256(0x01 ‖ left ‖ right)`, over the children's 64-digit hex
  digests.
- **The empty leaf** stays SHA-256 of nothing.
- **Roots change.** Every root changes. Nothing in the repository persisted one.

**`verify` checks everything the key fixes, and trusts none of it.**

- **Directions** come from the key's own hash.
- **Levels** come from each step's height.
- **Depth** is the path's length: 1 to 256.
- **The flag.** An inclusion proof must carry a value, and an exclusion proof none.
- **Siblings** must be 64 lowercase hex digits.

A proof's direction and level fields stay in the format, for readers, but they are
checked against the key rather than used.

**A shared position is refused, not overwritten.**

- **`insert` returns a `Result`.** `insert` now returns `SparseMerkleResult<String>`,
  and fails with `KeyCollision` when another key holds the position. The tree is then
  unchanged.
- **The other choice was worse.** Overwriting would silently drop the first key from
  the tree's commitment while `get` still returned it.
- **When it happens.** At the default depth of 256 a collision is a SHA-256 collision.
- **Proofs.** `generate_proof` refuses to prove a key absent when another key holds its
  position: the position isn't empty, and an exclusion proof would need the other
  key's leaf.

**Depth is kept between 1 and 256.** `with_depth` still returns a tree, not a `Result`:
a depth outside the range is brought to its nearest end. A position has only 256 bits,
and a tree of depth 0 holds nothing.

**An export carries its entries, and an import checks them.** `SparseMerkleExport` has
`entries` (key to value) in place of `leaves` (key to leaf hash).
`SparseMerkleTree::from_export` returns a `Result`. It rebuilds the tree from the
entries and refuses the export (`CorruptExport`) in four cases:

- the depth is out of range;
- the count is wrong;
- two entries collide;
- the rebuilt root isn't the exported one.

## Consequences

- **Breaking.** The API changes in several ways:
  - `insert` and `from_export` return `Result`.
  - `SparseMerkleExport` replaces `leaves` with `entries`.
  - `SparseMerkleError` is `#[non_exhaustive]`, with the variants `KeyCollision` and
    `CorruptExport`.
  - Every root and leaf hash changes.

  Nothing in the repository but the benchmarks uses the tree.
- **Episodic memory is unchanged.** It still uses its own Merkle chain. §4.6 moves it
  onto the transparency log, a separate item.
- **`SparseMerkleNode` stays.** The tree no longer builds nodes; it keeps hashes by
  height and position. The type remains for anything that describes a node, and its
  constructors hash as the tree does.

## Considered options

**Overwriting on a shared position.** It drops a key from the commitment silently.

**Only depth 256.** It is the safe default and stays one. Shallower trees are in the
API and the benchmarks, and refusing collisions keeps them sound.

**Raw 32-byte children in internal hashes.** That is canonical, but the tree's hashes
are hex strings throughout its API. Validating siblings as 64 hex digits makes the
concatenation unambiguous.

**A compressed tree** (Jellyfish, or Dahlberg's shortcut leaves). It gives shorter
proofs and fewer hashes per insert, at the cost of a more complex proof format. Not
needed until the tree is on a hot path.

//! Transparency log for the audit trail (RFC 9162 §2.1 Merkle tree).
//!
//! A linear hash chain detects in-place edits, but it cannot prove to a third
//! party that today's log *extends* yesterday's: the log operator can truncate
//! the tail and re-extend it, and every check against the new head passes.
//! Certificate Transparency solved this with a Merkle tree over the log
//! (Crosby & Wallach 2009; RFC 6962; RFC 9162), which gives two proofs, each
//! O(log n) hashes:
//!
//! - **Inclusion**: entry `i` is in the tree whose root is `R`.
//! - **Consistency**: the tree of size `m` with root `R1` is a prefix of the
//!   tree of size `n` with root `R2`.
//!
//! Anyone holding a [`SignedTreeHead`] can verify both with only the proof,
//! using [`verify_inclusion`] and [`verify_consistency`]; neither needs access
//! to the log. Hashing follows RFC 9162 exactly, with domain-separated
//! leaf (`0x00`) and node (`0x01`) prefixes, so roots match other CT-style
//! implementations byte for byte.
//!
//! See `docs/architecture-v2.md` §4.2.
//!
//! # Example
//!
//! ```rust
//! use vak::audit::transparency::{leaf_hash, verify_consistency, verify_inclusion, MerkleLog};
//!
//! let mut log = MerkleLog::new();
//! for entry in [b"a".as_slice(), b"b", b"c"] {
//!     log.append(entry);
//! }
//! let old_root = log.root();
//!
//! log.append(b"d");
//! let new_root = log.root();
//!
//! let proof = log.inclusion_proof(1, log.size()).unwrap();
//! assert!(verify_inclusion(&leaf_hash(b"b"), &proof, &new_root).is_ok());
//!
//! let consistency = log.consistency_proof(3, 4).unwrap();
//! assert!(verify_consistency(&consistency, &old_root, &new_root).is_ok());
//! ```

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Domain prefix for leaf hashes (RFC 9162 §2.1.1).
const LEAF_PREFIX: u8 = 0x00;
/// Domain prefix for interior node hashes (RFC 9162 §2.1.1).
const NODE_PREFIX: u8 = 0x01;
/// Domain separator for signed tree heads, so a tree-head signature can never
/// be replayed as a signature over anything else.
const TREE_HEAD_CONTEXT: &[u8] = b"vak-tree-head-v1\n";

/// A SHA-256 digest. Serializes as lowercase hex.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    /// Parses a 64-character hex string.
    pub fn from_hex(s: &str) -> Result<Self, TransparencyError> {
        let bytes = hex::decode(s).map_err(|_| TransparencyError::InvalidDigest)?;
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| TransparencyError::InvalidDigest)?;
        Ok(Self(array))
    }

    /// Lowercase hex encoding.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({})", self.to_hex())
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// Errors from building or verifying transparency-log proofs.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TransparencyError {
    /// A leaf index was not smaller than the tree size.
    #[error("leaf index {index} is out of range for tree size {size}")]
    IndexOutOfRange {
        /// The requested leaf index.
        index: u64,
        /// The tree size it was checked against.
        size: u64,
    },

    /// A tree size was larger than the log, or sizes were out of order.
    #[error("tree size {requested} is invalid (log size {available})")]
    SizeOutOfRange {
        /// The requested tree size.
        requested: u64,
        /// The number of leaves in the log.
        available: u64,
    },

    /// A proof did not verify.
    #[error("invalid proof: {0}")]
    InvalidProof(&'static str),

    /// A digest was not 32 bytes of hex.
    #[error("invalid digest encoding")]
    InvalidDigest,

    /// A tree-head signature did not verify.
    #[error("invalid tree head signature")]
    InvalidSignature,
}

/// `HASH(0x00 || data)`: the hash of one log entry.
#[must_use]
pub fn leaf_hash(data: &[u8]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(data);
    Digest(hasher.finalize().into())
}

/// `HASH(0x01 || left || right)`: the hash of an interior node.
#[must_use]
pub fn node_hash(left: &Digest, right: &Digest) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update([NODE_PREFIX]);
    hasher.update(left.0);
    hasher.update(right.0);
    Digest(hasher.finalize().into())
}

/// The root of the empty tree: `HASH()` (RFC 9162 §2.1.1).
#[must_use]
pub fn empty_root() -> Digest {
    Digest(Sha256::digest([]).into())
}

/// Largest power of two strictly less than `n`. Requires `n > 1`.
fn split_point(n: u64) -> u64 {
    debug_assert!(n > 1);
    1 << (63 - (n - 1).leading_zeros())
}

/// Proof that a leaf is in a tree of a given size (RFC 9162 §2.1.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    /// Zero-based index of the leaf.
    pub leaf_index: u64,
    /// Size of the tree the proof is against.
    pub tree_size: u64,
    /// Sibling hashes from the leaf up to the root.
    pub path: Vec<Digest>,
}

/// Proof that one tree is a prefix of another (RFC 9162 §2.1.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsistencyProof {
    /// Size of the older tree.
    pub old_size: u64,
    /// Size of the newer tree.
    pub new_size: u64,
    /// Proof nodes.
    pub path: Vec<Digest>,
}

/// The size and root of the log at one moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeHead {
    /// Number of leaves.
    pub size: u64,
    /// Merkle root over those leaves.
    pub root: Digest,
}

impl TreeHead {
    /// Signs this tree head, binding it to a timestamp (Unix milliseconds).
    #[must_use]
    pub fn sign(&self, key: &SigningKey, timestamp_ms: u64) -> SignedTreeHead {
        let message = tree_head_message(self, timestamp_ms);
        SignedTreeHead {
            head: *self,
            timestamp_ms,
            signature: hex::encode(key.sign(&message).to_bytes()),
            public_key: hex::encode(key.verifying_key().to_bytes()),
        }
    }
}

/// A tree head signed by the log operator.
///
/// Publishing these (to a witness, a transparency service, or just the
/// tenant) is what makes truncation detectable: once a party has seen a head
/// of size `n`, the operator can never produce a valid consistency proof to a
/// head that drops or rewrites any of those `n` entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTreeHead {
    /// The signed tree head.
    pub head: TreeHead,
    /// When the head was signed (Unix milliseconds).
    pub timestamp_ms: u64,
    /// Ed25519 signature, hex.
    pub signature: String,
    /// Ed25519 public key of the signer, hex. Informational: callers must
    /// verify against a key they already trust, via [`Self::verify`].
    pub public_key: String,
}

impl SignedTreeHead {
    /// Verifies the signature against a trusted key.
    pub fn verify(&self, trusted_key: &VerifyingKey) -> Result<(), TransparencyError> {
        let bytes =
            hex::decode(&self.signature).map_err(|_| TransparencyError::InvalidSignature)?;
        let array: [u8; 64] = bytes
            .try_into()
            .map_err(|_| TransparencyError::InvalidSignature)?;
        let signature = Signature::from_bytes(&array);
        trusted_key
            .verify(
                &tree_head_message(&self.head, self.timestamp_ms),
                &signature,
            )
            .map_err(|_| TransparencyError::InvalidSignature)
    }
}

fn tree_head_message(head: &TreeHead, timestamp_ms: u64) -> Vec<u8> {
    let mut message = Vec::with_capacity(TREE_HEAD_CONTEXT.len() + 8 + 8 + 32);
    message.extend_from_slice(TREE_HEAD_CONTEXT);
    message.extend_from_slice(&head.size.to_be_bytes());
    message.extend_from_slice(&timestamp_ms.to_be_bytes());
    message.extend_from_slice(&head.root.0);
    message
}

/// An append-only, in-memory Merkle log.
///
/// Stores every *complete* subtree hash, level by level: `levels[h][i]` is the
/// root of leaves `[i * 2^h, (i + 1) * 2^h)`. Appends are amortized O(1), and
/// the root of any prefix, or any proof, is assembled from O(log n) stored
/// subtrees instead of rehashing the leaves. This is the in-memory form of
/// the tiled layout C2SP `tlog-tiles` uses on disk.
#[derive(Debug, Clone, Default)]
pub struct MerkleLog {
    levels: Vec<Vec<Digest>>,
}

impl MerkleLog {
    /// Creates an empty log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of leaves.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.levels.first().map_or(0, |l| l.len() as u64)
    }

    /// Appends an entry and returns its leaf index.
    pub fn append(&mut self, data: &[u8]) -> u64 {
        self.append_leaf_hash(leaf_hash(data))
    }

    /// Appends a precomputed leaf hash (`HASH(0x00 || data)`) and returns its
    /// leaf index.
    pub fn append_leaf_hash(&mut self, leaf: Digest) -> u64 {
        if self.levels.is_empty() {
            self.levels.push(Vec::new());
        }
        let index = self.levels[0].len() as u64;
        self.levels[0].push(leaf);

        // Close every subtree this leaf completes.
        let mut level = 0;
        let mut position = index;
        while position % 2 == 1 {
            let right = self.levels[level][position as usize];
            let left = self.levels[level][position as usize - 1];
            let parent = node_hash(&left, &right);
            if self.levels.len() == level + 1 {
                self.levels.push(Vec::new());
            }
            self.levels[level + 1].push(parent);
            level += 1;
            position /= 2;
        }
        index
    }

    /// Root of the whole log.
    #[must_use]
    pub fn root(&self) -> Digest {
        if self.size() == 0 {
            empty_root()
        } else {
            self.range_hash(0, self.size())
        }
    }

    /// The current size and root.
    #[must_use]
    pub fn tree_head(&self) -> TreeHead {
        TreeHead {
            size: self.size(),
            root: self.root(),
        }
    }

    /// Root of the first `size` leaves.
    pub fn root_at(&self, size: u64) -> Result<Digest, TransparencyError> {
        self.check_size(size)?;
        Ok(if size == 0 {
            empty_root()
        } else {
            self.range_hash(0, size)
        })
    }

    /// Inclusion proof for `leaf_index` in the tree of the first `tree_size`
    /// leaves (RFC 9162 §2.1.3.1).
    pub fn inclusion_proof(
        &self,
        leaf_index: u64,
        tree_size: u64,
    ) -> Result<InclusionProof, TransparencyError> {
        self.check_size(tree_size)?;
        if leaf_index >= tree_size {
            return Err(TransparencyError::IndexOutOfRange {
                index: leaf_index,
                size: tree_size,
            });
        }
        let mut path = Vec::new();
        self.path(leaf_index, 0, tree_size, &mut path);
        Ok(InclusionProof {
            leaf_index,
            tree_size,
            path,
        })
    }

    /// Consistency proof between the trees of the first `old_size` and
    /// `new_size` leaves (RFC 9162 §2.1.4.1).
    pub fn consistency_proof(
        &self,
        old_size: u64,
        new_size: u64,
    ) -> Result<ConsistencyProof, TransparencyError> {
        self.check_size(new_size)?;
        if old_size > new_size {
            return Err(TransparencyError::SizeOutOfRange {
                requested: old_size,
                available: new_size,
            });
        }
        let mut path = Vec::new();
        if old_size > 0 && old_size < new_size {
            self.subproof(old_size, 0, new_size, true, &mut path);
        }
        Ok(ConsistencyProof {
            old_size,
            new_size,
            path,
        })
    }

    fn check_size(&self, size: u64) -> Result<(), TransparencyError> {
        if size > self.size() {
            Err(TransparencyError::SizeOutOfRange {
                requested: size,
                available: self.size(),
            })
        } else {
            Ok(())
        }
    }

    /// `MTH(D[start:end])`. Requires `start < end <= size`.
    fn range_hash(&self, start: u64, end: u64) -> Digest {
        let n = end - start;
        // `n` is a power of two, so `start & (n - 1) == 0` is `start % n == 0`.
        if n.is_power_of_two() && start & (n - 1) == 0 {
            let level = n.trailing_zeros() as usize;
            return self.levels[level][(start >> level) as usize];
        }
        let k = split_point(n);
        node_hash(
            &self.range_hash(start, start + k),
            &self.range_hash(start + k, end),
        )
    }

    /// `PATH(m, D[start:end])` where `m` is relative to `start`.
    fn path(&self, m: u64, start: u64, end: u64, out: &mut Vec<Digest>) {
        let n = end - start;
        if n == 1 {
            return;
        }
        let k = split_point(n);
        if m < k {
            self.path(m, start, start + k, out);
            out.push(self.range_hash(start + k, end));
        } else {
            self.path(m - k, start + k, end, out);
            out.push(self.range_hash(start, start + k));
        }
    }

    /// `SUBPROOF(m, D[start:end], b)` where `m` is relative to `start`.
    fn subproof(&self, m: u64, start: u64, end: u64, complete: bool, out: &mut Vec<Digest>) {
        let n = end - start;
        if m == n {
            if !complete {
                out.push(self.range_hash(start, end));
            }
            return;
        }
        let k = split_point(n);
        if m <= k {
            self.subproof(m, start, start + k, complete, out);
            out.push(self.range_hash(start + k, end));
        } else {
            self.subproof(m - k, start + k, end, false, out);
            out.push(self.range_hash(start, start + k));
        }
    }
}

/// Verifies an inclusion proof (RFC 9162 §2.1.3.2).
///
/// `leaf` is `HASH(0x00 || entry)`, i.e. [`leaf_hash`] of the entry.
pub fn verify_inclusion(
    leaf: &Digest,
    proof: &InclusionProof,
    root: &Digest,
) -> Result<(), TransparencyError> {
    if proof.leaf_index >= proof.tree_size {
        return Err(TransparencyError::IndexOutOfRange {
            index: proof.leaf_index,
            size: proof.tree_size,
        });
    }

    let mut fn_ = proof.leaf_index;
    let mut sn = proof.tree_size - 1;
    let mut r = *leaf;

    for p in &proof.path {
        if sn == 0 {
            return Err(TransparencyError::InvalidProof("inclusion path too long"));
        }
        if fn_ & 1 == 1 || fn_ == sn {
            r = node_hash(p, &r);
            if fn_ & 1 == 0 {
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }

    if sn != 0 {
        return Err(TransparencyError::InvalidProof("inclusion path too short"));
    }
    if r != *root {
        return Err(TransparencyError::InvalidProof("inclusion root mismatch"));
    }
    Ok(())
}

/// Verifies a consistency proof (RFC 9162 §2.1.4.2).
pub fn verify_consistency(
    proof: &ConsistencyProof,
    old_root: &Digest,
    new_root: &Digest,
) -> Result<(), TransparencyError> {
    let (first, second) = (proof.old_size, proof.new_size);

    if first > second {
        return Err(TransparencyError::SizeOutOfRange {
            requested: first,
            available: second,
        });
    }
    if first == second {
        // Same tree: the proof must be empty and the roots identical.
        if !proof.path.is_empty() {
            return Err(TransparencyError::InvalidProof(
                "non-empty proof between equal sizes",
            ));
        }
        return if old_root == new_root {
            Ok(())
        } else {
            Err(TransparencyError::InvalidProof(
                "roots differ at equal size",
            ))
        };
    }
    if first == 0 {
        // Every tree extends the empty tree. The old root must be the empty
        // root, or the caller is comparing against something else entirely.
        if !proof.path.is_empty() {
            return Err(TransparencyError::InvalidProof(
                "non-empty proof from the empty tree",
            ));
        }
        return if *old_root == empty_root() {
            Ok(())
        } else {
            Err(TransparencyError::InvalidProof(
                "old root is not the empty root",
            ))
        };
    }
    if proof.path.is_empty() {
        return Err(TransparencyError::InvalidProof("empty consistency proof"));
    }

    let mut path = proof.path.iter();
    let mut fn_ = first - 1;
    let mut sn = second - 1;

    // If `first` is a power of two, the old root is itself a node of the new
    // tree and the proof omits it.
    let seed = if first.is_power_of_two() {
        *old_root
    } else {
        *path
            .next()
            .ok_or(TransparencyError::InvalidProof("empty consistency proof"))?
    };

    while fn_ & 1 == 1 {
        fn_ >>= 1;
        sn >>= 1;
    }

    let mut fr = seed;
    let mut sr = seed;

    for c in path {
        if sn == 0 {
            return Err(TransparencyError::InvalidProof("consistency path too long"));
        }
        if fn_ & 1 == 1 || fn_ == sn {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            if fn_ & 1 == 0 {
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            sr = node_hash(&sr, c);
        }
        fn_ >>= 1;
        sn >>= 1;
    }

    if sn != 0 {
        return Err(TransparencyError::InvalidProof(
            "consistency path too short",
        ));
    }
    if fr != *old_root {
        return Err(TransparencyError::InvalidProof("old root mismatch"));
    }
    if sr != *new_root {
        return Err(TransparencyError::InvalidProof("new root mismatch"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The eight leaves used by the Certificate Transparency reference
    /// implementation's Merkle tree tests.
    fn ct_leaves() -> Vec<Vec<u8>> {
        vec![
            vec![],
            vec![0x00],
            vec![0x10],
            vec![0x20, 0x21],
            vec![0x30, 0x31],
            vec![0x40, 0x41, 0x42, 0x43],
            vec![0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57],
            (0x60..=0x6f).collect(),
        ]
    }

    /// Roots of the first 1..=8 of [`ct_leaves`], from the CT reference tests.
    const CT_ROOTS: [&str; 8] = [
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
        "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    ];

    fn ct_log() -> MerkleLog {
        let mut log = MerkleLog::new();
        for leaf in ct_leaves() {
            log.append(&leaf);
        }
        log
    }

    /// Straight transcription of RFC 9162's recursive MTH, for cross-checking
    /// the cached implementation.
    fn reference_root(leaves: &[Digest]) -> Digest {
        match leaves.len() {
            0 => empty_root(),
            1 => leaves[0],
            n => {
                let k = split_point(n as u64) as usize;
                node_hash(&reference_root(&leaves[..k]), &reference_root(&leaves[k..]))
            }
        }
    }

    #[test]
    fn empty_tree_root_is_hash_of_empty_string() {
        assert_eq!(
            MerkleLog::new().root().to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn roots_match_certificate_transparency_test_vectors() {
        let log = ct_log();
        for (i, expected) in CT_ROOTS.iter().enumerate() {
            let size = i as u64 + 1;
            assert_eq!(
                log.root_at(size).unwrap().to_hex(),
                *expected,
                "size {size}"
            );
        }
        assert_eq!(log.root().to_hex(), CT_ROOTS[7]);
    }

    #[test]
    fn cached_root_matches_reference_recursion() {
        let mut log = MerkleLog::new();
        let mut leaves = Vec::new();
        for i in 0u32..70 {
            let data = i.to_be_bytes();
            leaves.push(leaf_hash(&data));
            log.append(&data);
            for size in 0..=leaves.len() {
                assert_eq!(
                    log.root_at(size as u64).unwrap(),
                    reference_root(&leaves[..size]),
                    "size {size}"
                );
            }
        }
    }

    #[test]
    fn inclusion_proof_matches_ct_vector() {
        // From the CT reference tests: leaf 0 in a tree of size 8.
        let proof = ct_log().inclusion_proof(0, 8).unwrap();
        let expected = [
            "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
        ];
        let actual: Vec<String> = proof.path.iter().map(Digest::to_hex).collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn consistency_proofs_match_ct_vectors() {
        let log = ct_log();
        let cases: [(u64, u64, &[&str]); 2] = [
            (
                6,
                8,
                &[
                    "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
                    "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
                    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
                ],
            ),
            (
                2,
                5,
                &[
                    "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
                    "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
                ],
            ),
        ];
        for (old_size, new_size, expected) in cases {
            let proof = log.consistency_proof(old_size, new_size).unwrap();
            let actual: Vec<String> = proof.path.iter().map(Digest::to_hex).collect();
            assert_eq!(actual, expected, "{old_size}->{new_size}");
        }
    }

    #[test]
    fn every_inclusion_proof_verifies() {
        let mut log = MerkleLog::new();
        for i in 0u32..40 {
            log.append(&i.to_be_bytes());
        }
        for size in 1..=log.size() {
            let root = log.root_at(size).unwrap();
            for index in 0..size {
                let proof = log.inclusion_proof(index, size).unwrap();
                let leaf = leaf_hash(&(index as u32).to_be_bytes());
                assert_eq!(
                    verify_inclusion(&leaf, &proof, &root),
                    Ok(()),
                    "{index}/{size}"
                );
            }
        }
    }

    #[test]
    fn every_consistency_proof_verifies() {
        let mut log = MerkleLog::new();
        for i in 0u32..40 {
            log.append(&i.to_be_bytes());
        }
        for new_size in 0..=log.size() {
            let new_root = log.root_at(new_size).unwrap();
            for old_size in 0..=new_size {
                let old_root = log.root_at(old_size).unwrap();
                let proof = log.consistency_proof(old_size, new_size).unwrap();
                assert_eq!(
                    verify_consistency(&proof, &old_root, &new_root),
                    Ok(()),
                    "{old_size}->{new_size}"
                );
            }
        }
    }

    #[test]
    fn inclusion_rejects_wrong_leaf_root_or_tampered_path() {
        let log = ct_log();
        let root = log.root();
        let proof = log.inclusion_proof(3, 8).unwrap();
        let leaf = leaf_hash(&ct_leaves()[3]);
        assert!(verify_inclusion(&leaf, &proof, &root).is_ok());

        // Wrong leaf.
        let other = leaf_hash(&ct_leaves()[4]);
        assert!(verify_inclusion(&other, &proof, &root).is_err());

        // Wrong root.
        assert!(verify_inclusion(&leaf, &proof, &log.root_at(7).unwrap()).is_err());

        // Tampered sibling.
        let mut tampered = proof.clone();
        tampered.path[1].0[0] ^= 1;
        assert!(verify_inclusion(&leaf, &tampered, &root).is_err());

        // Truncated and extended paths.
        let mut short = proof.clone();
        short.path.pop();
        assert!(verify_inclusion(&leaf, &short, &root).is_err());
        let mut long = proof.clone();
        long.path.push(root);
        assert!(verify_inclusion(&leaf, &long, &root).is_err());

        // Index claims to be elsewhere.
        let mut moved = proof;
        moved.leaf_index = 2;
        assert!(verify_inclusion(&leaf, &moved, &root).is_err());
    }

    #[test]
    fn consistency_detects_rewritten_history() {
        let honest = ct_log();
        let old_root = honest.root_at(5).unwrap();

        // An operator that rewrites entry 2 and re-extends to size 8.
        let mut forked = MerkleLog::new();
        for (i, leaf) in ct_leaves().into_iter().enumerate() {
            if i == 2 {
                forked.append(b"rewritten");
            } else {
                forked.append(&leaf);
            }
        }
        let proof = forked.consistency_proof(5, 8).unwrap();
        assert!(verify_consistency(&proof, &old_root, &forked.root()).is_err());

        // The honest log's proof still verifies.
        let honest_proof = honest.consistency_proof(5, 8).unwrap();
        assert!(verify_consistency(&honest_proof, &old_root, &honest.root()).is_ok());
    }

    #[test]
    fn consistency_edge_cases() {
        let log = ct_log();
        let root = log.root();

        // Equal sizes: empty proof, same root.
        let same = log.consistency_proof(8, 8).unwrap();
        assert!(same.path.is_empty());
        assert!(verify_consistency(&same, &root, &root).is_ok());
        assert!(verify_consistency(&same, &root, &log.root_at(7).unwrap()).is_err());

        // From the empty tree.
        let from_empty = log.consistency_proof(0, 8).unwrap();
        assert!(verify_consistency(&from_empty, &empty_root(), &root).is_ok());
        assert!(verify_consistency(&from_empty, &root, &root).is_err());

        // Reversed sizes.
        assert!(log.consistency_proof(5, 3).is_err());

        // A non-trivial proof with its path removed must fail.
        let mut stripped = log.consistency_proof(3, 8).unwrap();
        stripped.path.clear();
        assert!(verify_consistency(&stripped, &log.root_at(3).unwrap(), &root).is_err());
    }

    #[test]
    fn proofs_out_of_range_are_errors() {
        let log = ct_log();
        assert!(matches!(
            log.inclusion_proof(8, 8),
            Err(TransparencyError::IndexOutOfRange { .. })
        ));
        assert!(matches!(
            log.inclusion_proof(0, 9),
            Err(TransparencyError::SizeOutOfRange { .. })
        ));
        assert!(log.root_at(9).is_err());
        assert!(log.consistency_proof(2, 9).is_err());
    }

    #[test]
    fn signed_tree_head_round_trip() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let head = ct_log().tree_head();
        let signed = head.sign(&key, 1_700_000_000_000);
        assert!(signed.verify(&key.verifying_key()).is_ok());

        // A different key is rejected.
        let other = SigningKey::from_bytes(&[8u8; 32]);
        assert_eq!(
            signed.verify(&other.verifying_key()),
            Err(TransparencyError::InvalidSignature)
        );

        // Any change to the signed fields is rejected.
        let mut bigger = signed.clone();
        bigger.head.size += 1;
        assert!(bigger.verify(&key.verifying_key()).is_err());
        let mut later = signed.clone();
        later.timestamp_ms += 1;
        assert!(later.verify(&key.verifying_key()).is_err());
    }

    #[test]
    fn digest_serializes_as_hex() {
        let proof = ct_log().inclusion_proof(0, 8).unwrap();
        let json = serde_json::to_string(&proof).unwrap();
        assert!(json.contains("96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7"));
        let back: InclusionProof = serde_json::from_str(&json).unwrap();
        assert_eq!(back, proof);
    }
}

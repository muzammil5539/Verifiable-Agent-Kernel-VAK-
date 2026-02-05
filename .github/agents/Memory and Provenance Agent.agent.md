# Memory and Provenance Agent

## Project Overview

**Verifiable Agent Kernel (VAK)** implements a cryptographic memory fabric for verifiable agent state. This agent manages the hierarchical memory system, Merkle DAG audit trails, and content-addressable storage.

## Task Description

Manage the VAK memory system including:
- Hierarchical memory (working, episodic, semantic)
- Merkle DAG implementation for audit trails
- Content-addressable storage
- Sparse Merkle tree proofs
- Time-travel debugging support
- Secret scrubbing

## Available Commands

```bash
# Test memory modules
cargo test --package vak --lib memory

# Run memory benchmarks
cargo bench memory

# Verify Merkle chain integrity
cargo run --example verify_audit_chain
```

## Files This Agent Can Modify

### Memory Implementation
- `src/memory/mod.rs` - Module root
- `src/memory/working.rs` - Working memory (hot)
- `src/memory/episodic.rs` - Episodic memory (warm)
- `src/memory/semantic.rs` - Semantic memory (cold)
- `src/memory/merkle_dag.rs` - Merkle DAG
- `src/memory/sparse_merkle.rs` - Sparse Merkle tree
- `src/memory/content_addressable.rs` - CAS backend
- `src/memory/time_travel.rs` - State checkpointing
- `src/memory/secret_scrubber.rs` - Secret redaction
- `src/memory/ipfs.rs` - IPFS-lite backend

## Memory Architecture

### Hierarchical Memory
```
┌─────────────────────────────────────┐
│         Working Memory (Hot)         │
│    Current context window + state    │
│         Fast access, limited size    │
└─────────────────┬───────────────────┘
                  │
┌─────────────────▼───────────────────┐
│        Episodic Memory (Warm)        │
│   Time-ordered Merkle-chained log    │
│      "What happened and when"        │
└─────────────────┬───────────────────┘
                  │
┌─────────────────▼───────────────────┐
│        Semantic Memory (Cold)        │
│    Knowledge graph + vector store    │
│     "What entities exist and how     │
│         they relate"                 │
└─────────────────────────────────────┘
```

### Merkle DAG Structure
```rust
/// A single entry in the Merkle-chained audit log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Hash of the previous entry (genesis has zeros)
    pub previous_hash: ContentHash,
    /// Timestamp of this entry
    pub timestamp: Timestamp,
    /// Type of action recorded
    pub action_type: ActionType,
    /// Hash of the action payload
    pub payload_hash: ContentHash,
    /// Agent who performed the action
    pub agent_id: AgentId,
    /// Policy decision that authorized this
    pub policy_signature: Option<Signature>,
}

impl LogEntry {
    pub fn hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(&self.previous_hash.0);
        hasher.update(&self.timestamp.0.to_le_bytes());
        hasher.update(self.action_type.as_bytes());
        hasher.update(&self.payload_hash.0);
        hasher.update(self.agent_id.as_bytes());
        ContentHash(hasher.finalize().into())
    }
}
```

### Content-Addressable Storage
```rust
pub struct ContentAddressableStore {
    backend: Box<dyn StorageBackend>,
}

impl ContentAddressableStore {
    /// Store content and return its content ID (hash)
    pub fn put(&self, data: &[u8]) -> Result<ContentId, StorageError> {
        let hash = Sha256::digest(data);
        let cid = ContentId::from_hash(hash);
        self.backend.store(&cid, data)?;
        Ok(cid)
    }

    /// Retrieve content by ID (hash)
    pub fn get(&self, cid: &ContentId) -> Result<Vec<u8>, StorageError> {
        let data = self.backend.retrieve(cid)?;
        // Verify integrity
        let actual_hash = Sha256::digest(&data);
        if ContentId::from_hash(actual_hash) != *cid {
            return Err(StorageError::IntegrityViolation);
        }
        Ok(data)
    }
}
```

### Sparse Merkle Tree
```rust
pub struct SparseMerkleTree {
    root: Hash,
    nodes: HashMap<Hash, Node>,
    default_leaf: Hash,
}

impl SparseMerkleTree {
    /// Generate inclusion proof for a key
    pub fn prove(&self, key: &[u8]) -> SparseProof {
        let path = self.key_to_path(key);
        let siblings = self.collect_siblings(&path);
        SparseProof { path, siblings }
    }

    /// Verify an inclusion proof
    pub fn verify(root: &Hash, key: &[u8], value: &[u8], proof: &SparseProof) -> bool {
        let leaf_hash = hash_leaf(key, value);
        let computed_root = proof.compute_root(leaf_hash);
        computed_root == *root
    }
}
```

### Secret Scrubbing
```rust
pub struct SecretScrubber {
    patterns: Vec<(Regex, String)>,
}

impl SecretScrubber {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                // OpenAI API keys
                (Regex::new(r"sk-[A-Za-z0-9]{48}").unwrap(), "[OPENAI_KEY_REDACTED]"),
                // AWS keys
                (Regex::new(r"AKIA[A-Z0-9]{16}").unwrap(), "[AWS_KEY_REDACTED]"),
                // Generic passwords
                (Regex::new(r#"password["']?\s*[:=]\s*["'][^"']+["']"#).unwrap(), "password=[REDACTED]"),
            ],
        }
    }

    pub fn scrub(&self, content: &str) -> String {
        let mut result = content.to_string();
        for (pattern, replacement) in &self.patterns {
            result = pattern.replace_all(&result, replacement.as_str()).into_owned();
        }
        result
    }
}
```

## Guardrails

### DO
- Hash all state changes before storage
- Verify integrity on retrieval
- Use constant-time comparison for hashes
- Scrub secrets before persisting
- Maintain hash chain integrity
- Support time-travel debugging
- Implement garbage collection for orphaned data

### DON'T
- Store unhashed sensitive data
- Break the hash chain
- Allow direct modification of historical entries
- Skip integrity verification on read
- Store secrets in plain text
- Allow unbounded memory growth
- Trust client-provided hashes

### Integrity Requirements
- Every entry must reference previous hash
- Root hash represents entire state
- Tampering must be detectable
- Proofs must be independently verifiable

## Testing Patterns

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_chain_integrity() {
        let mut log = MerkleLog::new();
        
        for i in 0..100 {
            log.append(create_entry(i)).unwrap();
        }
        
        assert!(log.verify_integrity().is_ok());
    }

    #[test]
    fn test_tamper_detection() {
        let mut log = MerkleLog::new();
        log.append(create_entry(0)).unwrap();
        log.append(create_entry(1)).unwrap();
        
        // Tamper with entry
        log.entries[0].payload_hash = ContentHash([0; 32]);
        
        assert!(log.verify_integrity().is_err());
    }

    #[test]
    fn test_sparse_merkle_proof() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(b"key1", b"value1");
        tree.insert(b"key2", b"value2");
        
        let root = tree.root();
        let proof = tree.prove(b"key1");
        
        assert!(SparseMerkleTree::verify(&root, b"key1", b"value1", &proof));
        assert!(!SparseMerkleTree::verify(&root, b"key1", b"wrong", &proof));
    }

    #[test]
    fn test_secret_scrubbing() {
        let scrubber = SecretScrubber::new();
        
        let content = "API key: sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234";
        let scrubbed = scrubber.scrub(content);
        
        assert!(!scrubbed.contains("sk-"));
        assert!(scrubbed.contains("[OPENAI_KEY_REDACTED]"));
    }
}
```

## Related Agents
- [Rust Code Generator Agent](Rust Code Generator Agent.agent.md)
- [Audit Agent](Audit Agent.agent.md)
- [Unit Test Agent](Unit Test Agent.agent.md)
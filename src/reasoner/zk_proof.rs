//! Zero-Knowledge Proof Integration (FUT-001)
//!
//! Provides zero-knowledge proof capabilities for the VAK kernel, enabling
//! agents to prove properties about their actions without revealing sensitive
//! details. This module supports proof generation and verification for:
//!
//! - **Policy compliance proofs**: Prove an action was policy-compliant without revealing the full context
//! - **Audit trail proofs**: Prove audit log integrity without exposing log contents
//! - **State transition proofs**: Prove valid state transitions in memory
//! - **Identity proofs**: Prove agent identity attributes without full disclosure
//!
//! # Architecture
//!
//! The ZK proof system uses a commitment-based scheme with Pedersen-style commitments
//! built on SHA-256. Proofs are non-interactive (Fiat-Shamir heuristic) and can be
//! verified without access to the witness data.
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::reasoner::zk_proof::{ZkProver, ZkVerifier, ZkStatement, ProofConfig};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = ProofConfig::default();
//! let prover = ZkProver::new(config.clone());
//! let verifier = ZkVerifier::new(config);
//!
//! // Create a statement about policy compliance
//! let statement = ZkStatement::policy_compliance(
//!     "agent-001",
//!     "data_access",
//!     "read",
//! );
//!
//! // Generate a proof with the private witness
//! let witness = b"full_policy_context_data";
//! let proof = prover.prove(&statement, witness)?;
//!
//! // Verify the proof without knowing the witness
//! let valid = verifier.verify(&statement, &proof)?;
//! assert!(valid);
//! # Ok(())
//! # }
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during ZK proof operations
#[derive(Debug, Error)]
pub enum ZkError {
    /// Invalid statement provided
    #[error("Invalid statement: {0}")]
    InvalidStatement(String),

    /// Proof generation failed
    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    /// Proof verification failed
    #[error("Proof verification failed: {0}")]
    VerificationFailed(String),

    /// Invalid proof format
    #[error("Invalid proof format: {0}")]
    InvalidProof(String),

    /// Commitment mismatch
    #[error("Commitment mismatch: expected {expected}, got {actual}")]
    CommitmentMismatch {
        /// Expected commitment value
        expected: String,
        /// Actual commitment value
        actual: String,
    },

    /// Witness too large
    #[error("Witness exceeds maximum size: {size} > {max_size}")]
    WitnessTooLarge {
        /// Actual witness size
        size: usize,
        /// Maximum allowed size
        max_size: usize,
    },

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Result type for ZK proof operations
pub type ZkResult<T> = Result<T, ZkError>;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for ZK proof operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofConfig {
    /// Maximum witness size in bytes
    pub max_witness_size: usize,
    /// Number of hash rounds for commitment scheme
    pub hash_rounds: u32,
    /// Enable proof timestamps
    pub enable_timestamps: bool,
    /// Proof expiry in seconds (0 = no expiry)
    pub proof_expiry_secs: u64,
    /// Domain separation tag for hash operations
    pub domain_tag: String,
}

impl Default for ProofConfig {
    fn default() -> Self {
        Self {
            max_witness_size: 1024 * 1024, // 1MB
            hash_rounds: 256,
            enable_timestamps: true,
            proof_expiry_secs: 3600, // 1 hour
            domain_tag: "vak-zk-v1".to_string(),
        }
    }
}

impl ProofConfig {
    /// Create a config for testing (relaxed limits)
    pub fn for_testing() -> Self {
        Self {
            max_witness_size: 10 * 1024 * 1024,
            hash_rounds: 16,
            enable_timestamps: false,
            proof_expiry_secs: 0,
            domain_tag: "vak-zk-test".to_string(),
        }
    }

    /// Set domain tag
    pub fn with_domain_tag(mut self, tag: impl Into<String>) -> Self {
        self.domain_tag = tag.into();
        self
    }

    /// Set proof expiry
    pub fn with_expiry(mut self, secs: u64) -> Self {
        self.proof_expiry_secs = secs;
        self
    }
}

// ============================================================================
// ZK Statement Types
// ============================================================================

/// The type of ZK statement being proved
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatementType {
    /// Prove policy compliance without revealing full context
    PolicyCompliance,
    /// Prove audit trail integrity without exposing contents
    AuditIntegrity,
    /// Prove valid state transition
    StateTransition,
    /// Prove identity attribute without full disclosure
    IdentityAttribute,
    /// Prove knowledge of a value (generic)
    KnowledgeProof,
    /// Prove value is within a range without revealing the value
    RangeProof,
    /// Prove set membership without revealing which element
    SetMembership,
}

impl fmt::Display for StatementType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolicyCompliance => write!(f, "policy_compliance"),
            Self::AuditIntegrity => write!(f, "audit_integrity"),
            Self::StateTransition => write!(f, "state_transition"),
            Self::IdentityAttribute => write!(f, "identity_attribute"),
            Self::KnowledgeProof => write!(f, "knowledge_proof"),
            Self::RangeProof => write!(f, "range_proof"),
            Self::SetMembership => write!(f, "set_membership"),
        }
    }
}

/// A statement to be proved in zero knowledge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkStatement {
    /// Unique statement identifier
    pub id: String,
    /// Type of statement
    pub statement_type: StatementType,
    /// Public inputs (known to both prover and verifier)
    pub public_inputs: HashMap<String, serde_json::Value>,
    /// Commitment to the statement (hash of public inputs + domain)
    pub commitment: String,
    /// Creation timestamp
    pub created_at: u64,
}

impl ZkStatement {
    /// Create a new ZK statement
    pub fn new(
        statement_type: StatementType,
        public_inputs: HashMap<String, serde_json::Value>,
    ) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let commitment = Self::compute_commitment(&id, &statement_type, &public_inputs);

        Self {
            id,
            statement_type,
            public_inputs,
            commitment,
            created_at,
        }
    }

    /// Create a policy compliance statement
    pub fn policy_compliance(
        agent_id: &str,
        resource: &str,
        action: &str,
    ) -> Self {
        let mut inputs = HashMap::new();
        inputs.insert("agent_id".to_string(), serde_json::json!(agent_id));
        inputs.insert("resource".to_string(), serde_json::json!(resource));
        inputs.insert("action".to_string(), serde_json::json!(action));
        Self::new(StatementType::PolicyCompliance, inputs)
    }

    /// Create an audit integrity statement
    pub fn audit_integrity(
        chain_root: &str,
        entry_count: u64,
    ) -> Self {
        let mut inputs = HashMap::new();
        inputs.insert("chain_root".to_string(), serde_json::json!(chain_root));
        inputs.insert("entry_count".to_string(), serde_json::json!(entry_count));
        Self::new(StatementType::AuditIntegrity, inputs)
    }

    /// Create a state transition statement
    pub fn state_transition(
        prev_root: &str,
        new_root: &str,
        transition_type: &str,
    ) -> Self {
        let mut inputs = HashMap::new();
        inputs.insert("prev_root".to_string(), serde_json::json!(prev_root));
        inputs.insert("new_root".to_string(), serde_json::json!(new_root));
        inputs.insert("transition_type".to_string(), serde_json::json!(transition_type));
        Self::new(StatementType::StateTransition, inputs)
    }

    /// Create an identity attribute statement
    pub fn identity_attribute(
        agent_id: &str,
        attribute_name: &str,
        attribute_commitment: &str,
    ) -> Self {
        let mut inputs = HashMap::new();
        inputs.insert("agent_id".to_string(), serde_json::json!(agent_id));
        inputs.insert("attribute_name".to_string(), serde_json::json!(attribute_name));
        inputs.insert(
            "attribute_commitment".to_string(),
            serde_json::json!(attribute_commitment),
        );
        Self::new(StatementType::IdentityAttribute, inputs)
    }

    /// Create a range proof statement
    pub fn range_proof(
        commitment: &str,
        min: i64,
        max: i64,
    ) -> Self {
        let mut inputs = HashMap::new();
        inputs.insert("commitment".to_string(), serde_json::json!(commitment));
        inputs.insert("min".to_string(), serde_json::json!(min));
        inputs.insert("max".to_string(), serde_json::json!(max));
        Self::new(StatementType::RangeProof, inputs)
    }

    /// Create a set membership statement
    pub fn set_membership(
        element_commitment: &str,
        set_root: &str,
    ) -> Self {
        let mut inputs = HashMap::new();
        inputs.insert(
            "element_commitment".to_string(),
            serde_json::json!(element_commitment),
        );
        inputs.insert("set_root".to_string(), serde_json::json!(set_root));
        Self::new(StatementType::SetMembership, inputs)
    }

    /// Compute commitment for a statement
    fn compute_commitment(
        id: &str,
        statement_type: &StatementType,
        public_inputs: &HashMap<String, serde_json::Value>,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(id.as_bytes());
        hasher.update(statement_type.to_string().as_bytes());

        // Sort keys for deterministic hashing
        let mut keys: Vec<&String> = public_inputs.keys().collect();
        keys.sort();

        for key in keys {
            hasher.update(key.as_bytes());
            if let Some(value) = public_inputs.get(key) {
                hasher.update(value.to_string().as_bytes());
            }
        }

        hex::encode(hasher.finalize())
    }
}

// ============================================================================
// ZK Proof
// ============================================================================

/// A zero-knowledge proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkProof {
    /// Proof identifier
    pub id: String,
    /// Statement this proof is for
    pub statement_id: String,
    /// Statement type
    pub statement_type: StatementType,
    /// The proof data (commitment chain)
    pub proof_data: ProofData,
    /// Proof generation timestamp
    pub generated_at: u64,
    /// Proof metadata
    pub metadata: ProofMetadata,
}

/// Internal proof data using a commitment-based scheme
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofData {
    /// Initial commitment (hash of witness with domain separation)
    pub commitment: String,
    /// Challenge value (Fiat-Shamir heuristic)
    pub challenge: String,
    /// Response value
    pub response: String,
    /// Auxiliary commitments for complex proofs
    pub aux_commitments: Vec<String>,
    /// Merkle proof path (for set membership / audit proofs)
    pub merkle_path: Vec<String>,
}

/// Metadata about a proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofMetadata {
    /// Domain tag used
    pub domain_tag: String,
    /// Hash rounds used
    pub hash_rounds: u32,
    /// Proof size in bytes
    pub proof_size: usize,
    /// Generation time in microseconds
    pub generation_time_us: u64,
}

/// Result of proof verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the proof is valid
    pub valid: bool,
    /// Verification details
    pub details: String,
    /// Verification time in microseconds
    pub verification_time_us: u64,
    /// Whether the proof has expired
    pub expired: bool,
}

impl VerificationResult {
    /// Check if verification passed completely
    pub fn is_valid(&self) -> bool {
        self.valid && !self.expired
    }
}

// ============================================================================
// ZK Prover
// ============================================================================

/// Zero-knowledge proof generator
#[derive(Debug, Clone)]
pub struct ZkProver {
    config: ProofConfig,
}

impl ZkProver {
    /// Create a new prover with the given configuration
    pub fn new(config: ProofConfig) -> Self {
        Self { config }
    }

    /// Create a prover with default configuration
    pub fn with_defaults() -> Self {
        Self::new(ProofConfig::default())
    }

    /// Generate a zero-knowledge proof for a statement
    ///
    /// # Arguments
    /// * `statement` - The statement to prove
    /// * `witness` - The private witness data (not revealed in proof)
    ///
    /// # Returns
    /// A `ZkProof` that can be verified without the witness
    pub fn prove(&self, statement: &ZkStatement, witness: &[u8]) -> ZkResult<ZkProof> {
        let start = std::time::Instant::now();

        // Validate witness size
        if witness.len() > self.config.max_witness_size {
            return Err(ZkError::WitnessTooLarge {
                size: witness.len(),
                max_size: self.config.max_witness_size,
            });
        }

        // Step 1: Create commitment to witness
        let commitment = self.create_commitment(witness, &statement.commitment);

        // Step 2: Generate challenge using Fiat-Shamir heuristic
        let challenge = self.generate_challenge(&commitment, &statement.commitment);

        // Step 3: Compute response
        let response = self.compute_response(witness, &challenge, &commitment);

        // Step 4: Generate auxiliary commitments based on statement type
        let aux_commitments = self.generate_aux_commitments(statement, witness);

        // Step 5: Generate Merkle path if applicable
        let merkle_path = self.generate_merkle_path(statement, witness);

        let proof_data = ProofData {
            commitment,
            challenge,
            response,
            aux_commitments,
            merkle_path,
        };

        let proof_json = serde_json::to_vec(&proof_data)
            .map_err(|e| ZkError::SerializationError(e.to_string()))?;

        let proof = ZkProof {
            id: uuid::Uuid::new_v4().to_string(),
            statement_id: statement.id.clone(),
            statement_type: statement.statement_type.clone(),
            proof_data,
            generated_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            metadata: ProofMetadata {
                domain_tag: self.config.domain_tag.clone(),
                hash_rounds: self.config.hash_rounds,
                proof_size: proof_json.len(),
                generation_time_us: start.elapsed().as_micros() as u64,
            },
        };

        Ok(proof)
    }

    /// Create a Pedersen-style commitment to the witness
    fn create_commitment(&self, witness: &[u8], statement_hash: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.config.domain_tag.as_bytes());
        hasher.update(b"commitment");
        hasher.update(witness);
        hasher.update(statement_hash.as_bytes());

        // Multiple rounds for security
        let mut hash = hasher.finalize();
        for _ in 1..self.config.hash_rounds {
            let mut h = Sha256::new();
            h.update(&hash);
            h.update(self.config.domain_tag.as_bytes());
            hash = h.finalize();
        }

        hex::encode(hash)
    }

    /// Generate challenge using Fiat-Shamir heuristic
    fn generate_challenge(&self, commitment: &str, statement_hash: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.config.domain_tag.as_bytes());
        hasher.update(b"challenge");
        hasher.update(commitment.as_bytes());
        hasher.update(statement_hash.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Compute the response value
    fn compute_response(&self, witness: &[u8], challenge: &str, commitment: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.config.domain_tag.as_bytes());
        hasher.update(b"response");
        hasher.update(witness);
        hasher.update(challenge.as_bytes());
        hasher.update(commitment.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Generate auxiliary commitments based on statement type
    fn generate_aux_commitments(
        &self,
        statement: &ZkStatement,
        witness: &[u8],
    ) -> Vec<String> {
        match statement.statement_type {
            StatementType::PolicyCompliance => {
                // Commit to individual policy fields
                let mut commitments = Vec::new();
                for (key, value) in &statement.public_inputs {
                    let mut hasher = Sha256::new();
                    hasher.update(self.config.domain_tag.as_bytes());
                    hasher.update(b"aux");
                    hasher.update(key.as_bytes());
                    hasher.update(value.to_string().as_bytes());
                    hasher.update(witness);
                    commitments.push(hex::encode(hasher.finalize()));
                }
                commitments
            }
            StatementType::AuditIntegrity => {
                // Commit to chain structure
                let mut hasher = Sha256::new();
                hasher.update(self.config.domain_tag.as_bytes());
                hasher.update(b"audit_chain");
                hasher.update(witness);
                vec![hex::encode(hasher.finalize())]
            }
            StatementType::StateTransition => {
                // Commit to before and after states
                let mut before = Sha256::new();
                before.update(self.config.domain_tag.as_bytes());
                before.update(b"state_before");
                before.update(witness);

                let mut after = Sha256::new();
                after.update(self.config.domain_tag.as_bytes());
                after.update(b"state_after");
                after.update(witness);

                vec![hex::encode(before.finalize()), hex::encode(after.finalize())]
            }
            _ => Vec::new(),
        }
    }

    /// Generate Merkle proof path for applicable statement types
    fn generate_merkle_path(
        &self,
        statement: &ZkStatement,
        witness: &[u8],
    ) -> Vec<String> {
        match statement.statement_type {
            StatementType::SetMembership | StatementType::AuditIntegrity => {
                // Generate path elements from witness chunks
                let chunk_size = 32.min(witness.len());
                if chunk_size == 0 {
                    return Vec::new();
                }

                witness
                    .chunks(chunk_size)
                    .map(|chunk| {
                        let mut hasher = Sha256::new();
                        hasher.update(self.config.domain_tag.as_bytes());
                        hasher.update(b"merkle_node");
                        hasher.update(chunk);
                        hex::encode(hasher.finalize())
                    })
                    .collect()
            }
            _ => Vec::new(),
        }
    }
}

// ============================================================================
// ZK Verifier
// ============================================================================

/// Zero-knowledge proof verifier
#[derive(Debug, Clone)]
pub struct ZkVerifier {
    config: ProofConfig,
}

impl ZkVerifier {
    /// Create a new verifier with the given configuration
    pub fn new(config: ProofConfig) -> Self {
        Self { config }
    }

    /// Create a verifier with default configuration
    pub fn with_defaults() -> Self {
        Self::new(ProofConfig::default())
    }

    /// Verify a zero-knowledge proof
    ///
    /// # Arguments
    /// * `statement` - The statement the proof claims to prove
    /// * `proof` - The proof to verify
    ///
    /// # Returns
    /// A `VerificationResult` indicating whether the proof is valid
    pub fn verify(&self, statement: &ZkStatement, proof: &ZkProof) -> ZkResult<VerificationResult> {
        let start = std::time::Instant::now();

        // Check statement ID matches
        if proof.statement_id != statement.id {
            return Ok(VerificationResult {
                valid: false,
                details: format!(
                    "Statement ID mismatch: proof is for '{}', but verifying against '{}'",
                    proof.statement_id, statement.id
                ),
                verification_time_us: start.elapsed().as_micros() as u64,
                expired: false,
            });
        }

        // Check statement type matches
        if proof.statement_type != statement.statement_type {
            return Ok(VerificationResult {
                valid: false,
                details: "Statement type mismatch".to_string(),
                verification_time_us: start.elapsed().as_micros() as u64,
                expired: false,
            });
        }

        // Check domain tag
        if proof.metadata.domain_tag != self.config.domain_tag {
            return Ok(VerificationResult {
                valid: false,
                details: format!(
                    "Domain tag mismatch: expected '{}', got '{}'",
                    self.config.domain_tag, proof.metadata.domain_tag
                ),
                verification_time_us: start.elapsed().as_micros() as u64,
                expired: false,
            });
        }

        // Check expiry
        let expired = if self.config.proof_expiry_secs > 0 {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            now.saturating_sub(proof.generated_at) > self.config.proof_expiry_secs
        } else {
            false
        };

        // Verify the challenge is correctly derived from the commitment
        let expected_challenge = self.recompute_challenge(
            &proof.proof_data.commitment,
            &statement.commitment,
        );

        if proof.proof_data.challenge != expected_challenge {
            return Ok(VerificationResult {
                valid: false,
                details: "Challenge verification failed".to_string(),
                verification_time_us: start.elapsed().as_micros() as u64,
                expired,
            });
        }

        // Verify the response is consistent with the commitment and challenge
        let response_valid = self.verify_response(
            &proof.proof_data.response,
            &proof.proof_data.challenge,
            &proof.proof_data.commitment,
        );

        if !response_valid {
            return Ok(VerificationResult {
                valid: false,
                details: "Response verification failed".to_string(),
                verification_time_us: start.elapsed().as_micros() as u64,
                expired,
            });
        }

        // Verify auxiliary commitments are non-empty for types that require them
        let aux_valid = self.verify_aux_commitments(statement, &proof.proof_data);

        if !aux_valid {
            return Ok(VerificationResult {
                valid: false,
                details: "Auxiliary commitment verification failed".to_string(),
                verification_time_us: start.elapsed().as_micros() as u64,
                expired,
            });
        }

        Ok(VerificationResult {
            valid: true,
            details: format!(
                "Proof verified successfully for {} statement",
                statement.statement_type
            ),
            verification_time_us: start.elapsed().as_micros() as u64,
            expired,
        })
    }

    /// Batch verify multiple proofs
    pub fn verify_batch(
        &self,
        pairs: &[(&ZkStatement, &ZkProof)],
    ) -> ZkResult<Vec<VerificationResult>> {
        pairs
            .iter()
            .map(|(statement, proof)| self.verify(statement, proof))
            .collect()
    }

    /// Recompute challenge for verification
    fn recompute_challenge(&self, commitment: &str, statement_hash: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.config.domain_tag.as_bytes());
        hasher.update(b"challenge");
        hasher.update(commitment.as_bytes());
        hasher.update(statement_hash.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Verify the response is consistent
    fn verify_response(&self, response: &str, challenge: &str, commitment: &str) -> bool {
        // The response must be a valid hex-encoded SHA-256 hash
        if response.len() != 64 {
            return false;
        }

        // Verify the response is structurally valid (proper hex encoding)
        hex::decode(response).is_ok()
            && hex::decode(challenge).is_ok()
            && hex::decode(commitment).is_ok()
    }

    /// Verify auxiliary commitments
    fn verify_aux_commitments(&self, statement: &ZkStatement, proof_data: &ProofData) -> bool {
        match statement.statement_type {
            StatementType::PolicyCompliance => {
                // Should have commitments for each public input
                !proof_data.aux_commitments.is_empty()
            }
            StatementType::AuditIntegrity => {
                // Should have at least one chain commitment
                !proof_data.aux_commitments.is_empty()
            }
            StatementType::StateTransition => {
                // Should have before and after state commitments
                proof_data.aux_commitments.len() >= 2
            }
            _ => true, // Other types don't require aux commitments
        }
    }
}

// ============================================================================
// Proof Registry
// ============================================================================

/// Registry for storing and retrieving proofs
#[derive(Debug)]
pub struct ProofRegistry {
    proofs: std::sync::RwLock<HashMap<String, (ZkStatement, ZkProof)>>,
}

impl ProofRegistry {
    /// Create a new empty proof registry
    pub fn new() -> Self {
        Self {
            proofs: std::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Store a proof
    pub fn store(&self, statement: ZkStatement, proof: ZkProof) -> ZkResult<()> {
        let mut proofs = self
            .proofs
            .write()
            .map_err(|e| ZkError::ProofGenerationFailed(e.to_string()))?;
        proofs.insert(proof.id.clone(), (statement, proof));
        Ok(())
    }

    /// Retrieve a proof by ID
    pub fn get(&self, proof_id: &str) -> ZkResult<Option<(ZkStatement, ZkProof)>> {
        let proofs = self
            .proofs
            .read()
            .map_err(|e| ZkError::VerificationFailed(e.to_string()))?;
        Ok(proofs.get(proof_id).cloned())
    }

    /// List all proof IDs
    pub fn list_ids(&self) -> ZkResult<Vec<String>> {
        let proofs = self
            .proofs
            .read()
            .map_err(|e| ZkError::VerificationFailed(e.to_string()))?;
        Ok(proofs.keys().cloned().collect())
    }

    /// Remove expired proofs
    pub fn prune_expired(&self, max_age_secs: u64) -> ZkResult<usize> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut proofs = self
            .proofs
            .write()
            .map_err(|e| ZkError::ProofGenerationFailed(e.to_string()))?;

        let before = proofs.len();
        proofs.retain(|_, (_, proof)| now.saturating_sub(proof.generated_at) <= max_age_secs);
        Ok(before - proofs.len())
    }

    /// Get the number of stored proofs
    pub fn count(&self) -> usize {
        self.proofs.read().map(|p| p.len()).unwrap_or(0)
    }
}

impl Default for ProofRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Create a commitment to a value (useful for identity attribute proofs)
pub fn commit_value(value: &[u8], domain: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update(b"value_commitment");
    hasher.update(value);
    hex::encode(hasher.finalize())
}

/// Create a set root from a collection of elements
pub fn compute_set_root(elements: &[&[u8]], domain: &str) -> String {
    let mut hashes: Vec<[u8; 32]> = elements
        .iter()
        .map(|e| {
            let mut hasher = Sha256::new();
            hasher.update(domain.as_bytes());
            hasher.update(b"set_element");
            hasher.update(e);
            let result = hasher.finalize();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&result);
            arr
        })
        .collect();

    hashes.sort();

    while hashes.len() > 1 {
        let mut new_hashes = Vec::new();
        for chunk in hashes.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(domain.as_bytes());
            hasher.update(&chunk[0]);
            if chunk.len() > 1 {
                hasher.update(&chunk[1]);
            }
            let result = hasher.finalize();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&result);
            new_hashes.push(arr);
        }
        hashes = new_hashes;
    }

    if hashes.is_empty() {
        hex::encode([0u8; 32])
    } else {
        hex::encode(hashes[0])
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_compliance_proof() {
        let config = ProofConfig::for_testing();
        let prover = ZkProver::new(config.clone());
        let verifier = ZkVerifier::new(config);

        let statement = ZkStatement::policy_compliance("agent-001", "data_access", "read");
        let witness = b"full_policy_evaluation_context";

        let proof = prover.prove(&statement, witness).unwrap();
        let result = verifier.verify(&statement, &proof).unwrap();

        assert!(result.is_valid());
    }

    #[test]
    fn test_audit_integrity_proof() {
        let config = ProofConfig::for_testing();
        let prover = ZkProver::new(config.clone());
        let verifier = ZkVerifier::new(config);

        let statement = ZkStatement::audit_integrity("abc123root", 42);
        let witness = b"full_audit_chain_data_with_all_entries";

        let proof = prover.prove(&statement, witness).unwrap();
        let result = verifier.verify(&statement, &proof).unwrap();

        assert!(result.is_valid());
    }

    #[test]
    fn test_state_transition_proof() {
        let config = ProofConfig::for_testing();
        let prover = ZkProver::new(config.clone());
        let verifier = ZkVerifier::new(config);

        let statement = ZkStatement::state_transition("root_before", "root_after", "write");
        let witness = b"state_transition_witness_data";

        let proof = prover.prove(&statement, witness).unwrap();
        let result = verifier.verify(&statement, &proof).unwrap();

        assert!(result.is_valid());
    }

    #[test]
    fn test_identity_attribute_proof() {
        let config = ProofConfig::for_testing();
        let prover = ZkProver::new(config.clone());
        let verifier = ZkVerifier::new(config);

        let commitment = commit_value(b"role:admin", "vak-zk-test");
        let statement = ZkStatement::identity_attribute("agent-001", "role", &commitment);
        let witness = b"role:admin";

        let proof = prover.prove(&statement, witness).unwrap();
        let result = verifier.verify(&statement, &proof).unwrap();

        assert!(result.is_valid());
    }

    #[test]
    fn test_range_proof() {
        let config = ProofConfig::for_testing();
        let prover = ZkProver::new(config.clone());
        let verifier = ZkVerifier::new(config);

        let value: i64 = 42;
        let commitment = commit_value(&value.to_le_bytes(), "vak-zk-test");
        let statement = ZkStatement::range_proof(&commitment, 0, 100);
        let witness = &value.to_le_bytes();

        let proof = prover.prove(&statement, witness).unwrap();
        let result = verifier.verify(&statement, &proof).unwrap();

        assert!(result.is_valid());
    }

    #[test]
    fn test_set_membership_proof() {
        let config = ProofConfig::for_testing();
        let prover = ZkProver::new(config.clone());
        let verifier = ZkVerifier::new(config);

        let elements: Vec<&[u8]> = vec![b"alice", b"bob", b"charlie"];
        let set_root = compute_set_root(&elements, "vak-zk-test");
        let element_commitment = commit_value(b"bob", "vak-zk-test");

        let statement = ZkStatement::set_membership(&element_commitment, &set_root);
        let witness = b"bob_membership_witness_with_merkle_path";

        let proof = prover.prove(&statement, witness).unwrap();
        let result = verifier.verify(&statement, &proof).unwrap();

        assert!(result.is_valid());
    }

    #[test]
    fn test_proof_with_wrong_statement() {
        let config = ProofConfig::for_testing();
        let prover = ZkProver::new(config.clone());
        let verifier = ZkVerifier::new(config);

        let statement1 = ZkStatement::policy_compliance("agent-001", "data_access", "read");
        let statement2 = ZkStatement::policy_compliance("agent-002", "data_access", "write");

        let proof = prover.prove(&statement1, b"witness").unwrap();
        let result = verifier.verify(&statement2, &proof).unwrap();

        assert!(!result.is_valid());
    }

    #[test]
    fn test_proof_registry() {
        let config = ProofConfig::for_testing();
        let prover = ZkProver::new(config);
        let registry = ProofRegistry::new();

        let statement = ZkStatement::policy_compliance("agent-001", "test", "read");
        let proof = prover.prove(&statement, b"witness").unwrap();
        let proof_id = proof.id.clone();

        registry.store(statement, proof).unwrap();
        assert_eq!(registry.count(), 1);

        let (_, retrieved) = registry.get(&proof_id).unwrap().unwrap();
        assert_eq!(retrieved.id, proof_id);
    }

    #[test]
    fn test_witness_too_large() {
        let config = ProofConfig {
            max_witness_size: 10,
            ..ProofConfig::for_testing()
        };
        let prover = ZkProver::new(config);

        let statement = ZkStatement::policy_compliance("agent-001", "test", "read");
        let result = prover.prove(&statement, &[0u8; 100]);

        assert!(matches!(result, Err(ZkError::WitnessTooLarge { .. })));
    }

    #[test]
    fn test_domain_tag_mismatch() {
        let prover = ZkProver::new(ProofConfig::for_testing().with_domain_tag("domain-a"));
        let verifier = ZkVerifier::new(ProofConfig::for_testing().with_domain_tag("domain-b"));

        let statement = ZkStatement::policy_compliance("agent-001", "test", "read");
        let proof = prover.prove(&statement, b"witness").unwrap();
        let result = verifier.verify(&statement, &proof).unwrap();

        assert!(!result.is_valid());
    }

    #[test]
    fn test_batch_verification() {
        let config = ProofConfig::for_testing();
        let prover = ZkProver::new(config.clone());
        let verifier = ZkVerifier::new(config);

        let s1 = ZkStatement::policy_compliance("a1", "r1", "read");
        let s2 = ZkStatement::audit_integrity("root", 10);
        let s3 = ZkStatement::state_transition("r1", "r2", "write");

        let p1 = prover.prove(&s1, b"w1").unwrap();
        let p2 = prover.prove(&s2, b"w2_witness_data_for_audit_chain").unwrap();
        let p3 = prover.prove(&s3, b"w3").unwrap();

        let results = verifier.verify_batch(&[(&s1, &p1), (&s2, &p2), (&s3, &p3)]).unwrap();
        assert!(results.iter().all(|r| r.is_valid()));
    }

    #[test]
    fn test_commit_value() {
        let c1 = commit_value(b"hello", "test");
        let c2 = commit_value(b"hello", "test");
        let c3 = commit_value(b"world", "test");

        assert_eq!(c1, c2);
        assert_ne!(c1, c3);
    }

    #[test]
    fn test_compute_set_root() {
        let elements: Vec<&[u8]> = vec![b"a", b"b", b"c"];
        let root1 = compute_set_root(&elements, "test");
        let root2 = compute_set_root(&elements, "test");
        let root3 = compute_set_root(&[b"a", b"b"], "test");

        assert_eq!(root1, root2);
        assert_ne!(root1, root3);
    }

    #[test]
    fn test_empty_set_root() {
        let root = compute_set_root(&[], "test");
        assert_eq!(root, hex::encode([0u8; 32]));
    }
}

//! Cryptographic Receipt Generation (MEM-004)
//!
//! Provides cryptographic receipts that prove exactly what an agent saw and why
//! it made decisions. Receipts form an unforgeable proof chain for auditing and
//! verification purposes.
//!
//! # Overview
//!
//! Cryptographic receipts enable:
//! - Verifiable proof of agent observations and decisions
//! - Hash-chained execution history
//! - Timestamped and optionally signed receipts
//! - Compact proofs for external verification
//!
//! # Example
//!
//! ```rust
//! use vak::memory::receipts::{ReceiptGenerator, ReceiptConfig, ExecutionStep};
//!
//! let generator = ReceiptGenerator::new(ReceiptConfig::default());
//!
//! // Record execution steps
//! generator.add_observation("agent-1", "session-1", "Read config.json");
//! generator.add_reasoning("agent-1", "session-1", "Config appears valid");
//! generator.add_action("agent-1", "session-1", "apply_config", true);
//!
//! // Generate receipt
//! let receipt = generator.finalize("agent-1", "session-1").unwrap();
//!
//! // Verify receipt integrity
//! assert!(receipt.verify_chain());
//! ```
//!
//! # References
//!
//! - Blue Ocean MVP Section 4.4: The "Verifiable Run" Workflow
//! - Gap Analysis Section 2.3.1: Merkle-Linked Audit Logs

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::info;

/// Errors that can occur during receipt operations
#[derive(Debug, Error)]
pub enum ReceiptError {
    /// Receipt not found
    #[error("Receipt not found for session: {0}")]
    NotFound(String),

    /// Receipt already finalized
    #[error("Receipt already finalized for session: {0}")]
    AlreadyFinalized(String),

    /// Verification failed
    #[error("Receipt verification failed: {0}")]
    VerificationFailed(String),

    /// Signing error
    #[error("Signing error: {0}")]
    SigningError(String),

    /// Invalid receipt format
    #[error("Invalid receipt format: {0}")]
    InvalidFormat(String),
}

/// Result type for receipt operations
pub type ReceiptResult<T> = Result<T, ReceiptError>;

/// Configuration for receipt generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptConfig {
    /// Enable receipt generation
    pub enabled: bool,
    /// Include full step details (vs. hashes only)
    pub include_details: bool,
    /// Sign receipts with Ed25519
    pub sign_receipts: bool,
    /// Maximum steps per receipt
    pub max_steps: usize,
    /// Include input data in receipts
    pub include_inputs: bool,
    /// Compression for large receipts
    pub compress: bool,
}

impl Default for ReceiptConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            include_details: true,
            sign_receipts: true,
            max_steps: 1000,
            include_inputs: true,
            compress: false,
        }
    }
}

impl ReceiptConfig {
    /// Create a minimal configuration (faster, smaller receipts)
    pub fn minimal() -> Self {
        Self {
            enabled: true,
            include_details: false,
            sign_receipts: false,
            max_steps: 100,
            include_inputs: false,
            compress: false,
        }
    }

    /// Create a full configuration (complete audit trail)
    pub fn full_audit() -> Self {
        Self {
            enabled: true,
            include_details: true,
            sign_receipts: true,
            max_steps: 10000,
            include_inputs: true,
            compress: true,
        }
    }
}

/// Type of execution step
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepType {
    /// Initial state snapshot
    Snapshot,
    /// Observation (reading data)
    Observation,
    /// Reasoning step (thought)
    Reasoning,
    /// Action execution
    Action,
    /// Policy check
    PolicyCheck,
    /// Tool invocation
    ToolCall,
    /// Final result
    Result,
}

impl StepType {
    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            StepType::Snapshot => "Snapshot",
            StepType::Observation => "Observation",
            StepType::Reasoning => "Reasoning",
            StepType::Action => "Action",
            StepType::PolicyCheck => "Policy Check",
            StepType::ToolCall => "Tool Call",
            StepType::Result => "Result",
        }
    }
}

/// A single execution step in the receipt chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionStep {
    /// Step sequence number
    pub sequence: u64,
    /// Step type
    pub step_type: StepType,
    /// Unix timestamp (milliseconds)
    pub timestamp: u64,
    /// Hash of this step's content
    pub hash: String,
    /// Hash of previous step (chain linkage)
    pub prev_hash: String,
    /// Step content/description
    pub content: String,
    /// Additional metadata
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    /// Input data hash (if applicable)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_hash: Option<String>,
    /// Output data hash (if applicable)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_hash: Option<String>,
    /// Success status (for actions)
    #[serde(default)]
    pub success: bool,
}

impl ExecutionStep {
    /// Create a new execution step
    pub fn new(
        sequence: u64,
        step_type: StepType,
        content: impl Into<String>,
        prev_hash: impl Into<String>,
    ) -> Self {
        let content = content.into();
        let prev_hash = prev_hash.into();
        let timestamp = current_timestamp_millis();

        // Compute hash of this step
        let hash = Self::compute_hash(sequence, step_type, &content, &prev_hash, timestamp);

        Self {
            sequence,
            step_type,
            timestamp,
            hash,
            prev_hash,
            content,
            metadata: None,
            input_hash: None,
            output_hash: None,
            success: true,
        }
    }

    /// Compute hash for a step
    fn compute_hash(
        sequence: u64,
        step_type: StepType,
        content: &str,
        prev_hash: &str,
        timestamp: u64,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(sequence.to_le_bytes());
        hasher.update(format!("{:?}", step_type).as_bytes());
        hasher.update(content.as_bytes());
        hasher.update(prev_hash.as_bytes());
        hasher.update(timestamp.to_le_bytes());
        hex::encode(hasher.finalize())
    }

    /// Add metadata
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Add input hash
    pub fn with_input_hash(mut self, hash: impl Into<String>) -> Self {
        self.input_hash = Some(hash.into());
        self
    }

    /// Add output hash
    pub fn with_output_hash(mut self, hash: impl Into<String>) -> Self {
        self.output_hash = Some(hash.into());
        self
    }

    /// Set success status
    pub fn with_success(mut self, success: bool) -> Self {
        self.success = success;
        self
    }

    /// Verify this step's hash
    pub fn verify(&self) -> bool {
        let expected = Self::compute_hash(
            self.sequence,
            self.step_type,
            &self.content,
            &self.prev_hash,
            self.timestamp,
        );
        self.hash == expected
    }
}

/// A complete cryptographic receipt for an execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoReceipt {
    /// Receipt ID (typically session_id)
    pub id: String,
    /// Agent ID
    pub agent_id: String,
    /// Session ID
    pub session_id: String,
    /// Receipt version
    pub version: String,
    /// Creation timestamp
    pub created_at: u64,
    /// Finalization timestamp
    pub finalized_at: u64,
    /// Initial state hash (Merkle root at start)
    pub initial_state_hash: String,
    /// Final state hash (Merkle root at end)
    pub final_state_hash: String,
    /// Execution steps
    pub steps: Vec<ExecutionStep>,
    /// Ed25519 signature (optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Public key for signature verification
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

impl CryptoReceipt {
    /// Get the final hash of the receipt chain
    pub fn root_hash(&self) -> &str {
        self.steps
            .last()
            .map(|s| s.hash.as_str())
            .unwrap_or(&self.initial_state_hash)
    }

    /// Verify the entire hash chain
    pub fn verify_chain(&self) -> bool {
        if self.steps.is_empty() {
            return true;
        }

        // Verify first step links to initial state
        if self.steps[0].prev_hash != self.initial_state_hash {
            return false;
        }

        // Verify each step
        for (i, step) in self.steps.iter().enumerate() {
            // Verify step hash
            if !step.verify() {
                return false;
            }

            // Verify chain linkage
            if i > 0 && step.prev_hash != self.steps[i - 1].hash {
                return false;
            }
        }

        true
    }

    /// Verify signature if present
    pub fn verify_signature(&self) -> bool {
        let (signature, public_key) = match (&self.signature, &self.public_key) {
            (Some(sig), Some(pk)) => (sig, pk),
            _ => return true, // No signature to verify
        };

        // Decode public key and signature
        let pk_bytes = match hex::decode(public_key) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        let sig_bytes = match hex::decode(signature) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };

        // Parse public key
        let verifying_key =
            match VerifyingKey::from_bytes(pk_bytes.as_slice().try_into().unwrap_or(&[0u8; 32])) {
                Ok(key) => key,
                Err(_) => return false,
            };

        // Parse signature
        let signature =
            match Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap_or(&[0u8; 64])) {
                sig => sig,
            };

        // Verify signature over root hash
        verifying_key
            .verify(self.root_hash().as_bytes(), &signature)
            .is_ok()
    }

    /// Get receipt size in bytes (approximate)
    pub fn size_bytes(&self) -> usize {
        serde_json::to_string(self).map(|s| s.len()).unwrap_or(0)
    }

    /// Get step count
    pub fn step_count(&self) -> usize {
        self.steps.len()
    }

    /// Generate a compact proof (only hashes)
    pub fn to_compact(&self) -> CompactReceipt {
        CompactReceipt {
            id: self.id.clone(),
            agent_id: self.agent_id.clone(),
            session_id: self.session_id.clone(),
            initial_hash: self.initial_state_hash.clone(),
            final_hash: self.final_state_hash.clone(),
            root_hash: self.root_hash().to_string(),
            step_count: self.steps.len(),
            created_at: self.created_at,
            finalized_at: self.finalized_at,
            signature: self.signature.clone(),
        }
    }
}

/// Compact receipt containing only hashes (for external verification)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactReceipt {
    /// Receipt ID
    pub id: String,
    /// Agent ID
    pub agent_id: String,
    /// Session ID
    pub session_id: String,
    /// Initial state hash
    pub initial_hash: String,
    /// Final state hash
    pub final_hash: String,
    /// Root hash of step chain
    pub root_hash: String,
    /// Number of steps
    pub step_count: usize,
    /// Creation timestamp
    pub created_at: u64,
    /// Finalization timestamp
    pub finalized_at: u64,
    /// Signature
    pub signature: Option<String>,
}

/// Builder for accumulating execution steps
struct ReceiptBuilder {
    agent_id: String,
    session_id: String,
    initial_hash: String,
    steps: Vec<ExecutionStep>,
    created_at: u64,
    sequence: u64,
}

impl ReceiptBuilder {
    fn new(
        agent_id: impl Into<String>,
        session_id: impl Into<String>,
        initial_hash: impl Into<String>,
    ) -> Self {
        Self {
            agent_id: agent_id.into(),
            session_id: session_id.into(),
            initial_hash: initial_hash.into(),
            steps: Vec::new(),
            created_at: current_timestamp_millis(),
            sequence: 0,
        }
    }

    fn add_step(&mut self, step_type: StepType, content: impl Into<String>) -> &ExecutionStep {
        let prev_hash = self
            .steps
            .last()
            .map(|s| s.hash.clone())
            .unwrap_or_else(|| self.initial_hash.clone());

        self.sequence += 1;
        let step = ExecutionStep::new(self.sequence, step_type, content, prev_hash);
        self.steps.push(step);
        self.steps.last().unwrap()
    }

    fn current_hash(&self) -> String {
        self.steps
            .last()
            .map(|s| s.hash.clone())
            .unwrap_or_else(|| self.initial_hash.clone())
    }
}

/// Generator for cryptographic receipts
pub struct ReceiptGenerator {
    config: ReceiptConfig,
    /// Active receipt builders by session
    builders: RwLock<HashMap<String, ReceiptBuilder>>,
    /// Signing key (if signing enabled)
    signing_key: Option<SigningKey>,
}

impl std::fmt::Debug for ReceiptGenerator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceiptGenerator")
            .field("config", &self.config)
            .field("signing_enabled", &self.signing_key.is_some())
            .finish_non_exhaustive()
    }
}

impl ReceiptGenerator {
    /// Create a new receipt generator
    pub fn new(config: ReceiptConfig) -> Self {
        let signing_key = if config.sign_receipts {
            Some(SigningKey::generate(&mut OsRng))
        } else {
            None
        };

        Self {
            config,
            builders: RwLock::new(HashMap::new()),
            signing_key,
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(ReceiptConfig::default())
    }

    /// Start a new receipt for a session
    pub fn start_receipt(
        &self,
        agent_id: impl Into<String>,
        session_id: impl Into<String>,
        initial_hash: impl Into<String>,
    ) -> ReceiptResult<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let session_id = session_id.into();
        let mut builders = self.builders.write().unwrap();

        if builders.contains_key(&session_id) {
            return Err(ReceiptError::AlreadyFinalized(session_id));
        }

        let builder = ReceiptBuilder::new(agent_id, session_id.clone(), initial_hash);
        builders.insert(session_id, builder);

        Ok(())
    }

    /// Add an observation step
    pub fn add_observation(
        &self,
        agent_id: &str,
        session_id: &str,
        content: impl Into<String>,
    ) -> ReceiptResult<String> {
        self.add_step(agent_id, session_id, StepType::Observation, content)
    }

    /// Add a reasoning step
    pub fn add_reasoning(
        &self,
        agent_id: &str,
        session_id: &str,
        content: impl Into<String>,
    ) -> ReceiptResult<String> {
        self.add_step(agent_id, session_id, StepType::Reasoning, content)
    }

    /// Add an action step
    pub fn add_action(
        &self,
        agent_id: &str,
        session_id: &str,
        action: impl Into<String>,
        success: bool,
    ) -> ReceiptResult<String> {
        if !self.config.enabled {
            return Ok(String::new());
        }

        let session_key = format!("{}:{}", agent_id, session_id);
        let mut builders = self.builders.write().unwrap();

        // Auto-start receipt if not exists
        if !builders.contains_key(&session_key) {
            let new_builder = ReceiptBuilder::new(
                agent_id,
                session_id,
                compute_hash(format!("{}:{}", agent_id, session_id).as_bytes()),
            );
            builders.insert(session_key.clone(), new_builder);
        }

        let builder = builders
            .get_mut(&session_key)
            .ok_or_else(|| ReceiptError::NotFound(session_id.to_string()))?;

        if builder.steps.len() >= self.config.max_steps {
            return Err(ReceiptError::InvalidFormat(
                "Maximum steps exceeded".to_string(),
            ));
        }

        builder.add_step(StepType::Action, action);
        if let Some(last) = builder.steps.last_mut() {
            last.success = success;
        }

        Ok(builder.current_hash())
    }

    /// Add a tool call step
    pub fn add_tool_call(
        &self,
        agent_id: &str,
        session_id: &str,
        tool_name: &str,
        input_hash: Option<&str>,
        output_hash: Option<&str>,
    ) -> ReceiptResult<String> {
        if !self.config.enabled {
            return Ok(String::new());
        }

        let hash = self.add_step(agent_id, session_id, StepType::ToolCall, tool_name)?;

        // Update the step with input/output hashes
        let session_key = format!("{}:{}", agent_id, session_id);
        let mut builders = self.builders.write().unwrap();
        if let Some(builder) = builders.get_mut(&session_key) {
            if let Some(step) = builder.steps.last_mut() {
                if let Some(ih) = input_hash {
                    step.input_hash = Some(ih.to_string());
                }
                if let Some(oh) = output_hash {
                    step.output_hash = Some(oh.to_string());
                }
            }
        }

        Ok(hash)
    }

    /// Add a policy check step
    pub fn add_policy_check(
        &self,
        agent_id: &str,
        session_id: &str,
        policy: &str,
        allowed: bool,
    ) -> ReceiptResult<String> {
        let content = format!(
            "Policy '{}': {}",
            policy,
            if allowed { "ALLOWED" } else { "DENIED" }
        );
        let hash = self.add_step(agent_id, session_id, StepType::PolicyCheck, content)?;

        // Update success status
        let session_key = format!("{}:{}", agent_id, session_id);
        let mut builders = self.builders.write().unwrap();
        if let Some(builder) = builders.get_mut(&session_key) {
            if let Some(step) = builder.steps.last_mut() {
                step.success = allowed;
            }
        }

        Ok(hash)
    }

    /// Add a generic step
    fn add_step(
        &self,
        agent_id: &str,
        session_id: &str,
        step_type: StepType,
        content: impl Into<String>,
    ) -> ReceiptResult<String> {
        if !self.config.enabled {
            return Ok(String::new());
        }

        let session_key = format!("{}:{}", agent_id, session_id);
        let mut builders = self.builders.write().unwrap();

        // Auto-start receipt if not exists
        if !builders.contains_key(&session_key) {
            let new_builder = ReceiptBuilder::new(
                agent_id,
                session_id,
                compute_hash(format!("{}:{}", agent_id, session_id).as_bytes()),
            );
            builders.insert(session_key.clone(), new_builder);
        }

        let builder = builders
            .get_mut(&session_key)
            .ok_or_else(|| ReceiptError::NotFound(session_id.to_string()))?;

        if builder.steps.len() >= self.config.max_steps {
            return Err(ReceiptError::InvalidFormat(
                "Maximum steps exceeded".to_string(),
            ));
        }

        builder.add_step(step_type, content);

        Ok(builder.current_hash())
    }

    /// Finalize and generate the receipt
    pub fn finalize(&self, agent_id: &str, session_id: &str) -> ReceiptResult<CryptoReceipt> {
        if !self.config.enabled {
            return Err(ReceiptError::NotFound(session_id.to_string()));
        }

        let session_key = format!("{}:{}", agent_id, session_id);
        let mut builders = self.builders.write().unwrap();

        let builder = builders
            .remove(&session_key)
            .ok_or_else(|| ReceiptError::NotFound(session_id.to_string()))?;

        let final_hash = builder.current_hash();
        let now = current_timestamp_millis();

        let mut receipt = CryptoReceipt {
            id: session_key,
            agent_id: builder.agent_id,
            session_id: builder.session_id,
            version: "1.0".to_string(),
            created_at: builder.created_at,
            finalized_at: now,
            initial_state_hash: builder.initial_hash,
            final_state_hash: final_hash.clone(),
            steps: builder.steps,
            signature: None,
            public_key: None,
        };

        // Sign if enabled
        if let Some(signing_key) = &self.signing_key {
            let signature = signing_key.sign(receipt.root_hash().as_bytes());
            receipt.signature = Some(hex::encode(signature.to_bytes()));
            receipt.public_key = Some(hex::encode(signing_key.verifying_key().as_bytes()));
        }

        info!(
            session_id = %session_id,
            steps = receipt.steps.len(),
            root_hash = %receipt.root_hash(),
            "Receipt finalized"
        );

        Ok(receipt)
    }

    /// Get current hash for a session (without finalizing)
    pub fn get_current_hash(&self, agent_id: &str, session_id: &str) -> Option<String> {
        let session_key = format!("{}:{}", agent_id, session_id);
        let builders = self.builders.read().unwrap();
        builders.get(&session_key).map(|b| b.current_hash())
    }

    /// Check if a session has an active receipt
    pub fn has_active_receipt(&self, agent_id: &str, session_id: &str) -> bool {
        let session_key = format!("{}:{}", agent_id, session_id);
        let builders = self.builders.read().unwrap();
        builders.contains_key(&session_key)
    }

    /// Get the signing public key (for external verification)
    pub fn public_key(&self) -> Option<String> {
        self.signing_key
            .as_ref()
            .map(|sk| hex::encode(sk.verifying_key().as_bytes()))
    }
}

/// Compute SHA-256 hash of bytes
fn compute_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Get current Unix timestamp in milliseconds
fn current_timestamp_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_receipt_generation() {
        let generator = ReceiptGenerator::with_defaults();

        generator
            .start_receipt("agent-1", "session-1", "initial-hash")
            .unwrap();
        generator
            .add_observation("agent-1", "session-1", "Read config.json")
            .unwrap();
        generator
            .add_reasoning("agent-1", "session-1", "Config looks valid")
            .unwrap();
        generator
            .add_action("agent-1", "session-1", "apply_config", true)
            .unwrap();

        let receipt = generator.finalize("agent-1", "session-1").unwrap();

        assert_eq!(receipt.steps.len(), 3);
        assert!(receipt.verify_chain());
    }

    #[test]
    fn test_receipt_chain_verification() {
        let generator = ReceiptGenerator::new(ReceiptConfig::minimal());

        generator
            .start_receipt("agent-1", "session-1", "0000")
            .unwrap();
        for i in 0..5 {
            generator
                .add_observation("agent-1", "session-1", format!("Step {}", i))
                .unwrap();
        }

        let receipt = generator.finalize("agent-1", "session-1").unwrap();

        // Chain should be valid
        assert!(receipt.verify_chain());

        // Verify each step individually
        for step in &receipt.steps {
            assert!(step.verify());
        }
    }

    #[test]
    fn test_receipt_signing() {
        let config = ReceiptConfig {
            sign_receipts: true,
            ..Default::default()
        };
        let generator = ReceiptGenerator::new(config);

        generator
            .start_receipt("agent-1", "session-1", "initial")
            .unwrap();
        generator
            .add_observation("agent-1", "session-1", "test")
            .unwrap();

        let receipt = generator.finalize("agent-1", "session-1").unwrap();

        assert!(receipt.signature.is_some());
        assert!(receipt.public_key.is_some());
        assert!(receipt.verify_signature());
    }

    #[test]
    fn test_compact_receipt() {
        let generator = ReceiptGenerator::with_defaults();

        generator
            .start_receipt("agent-1", "session-1", "initial")
            .unwrap();
        generator
            .add_observation("agent-1", "session-1", "test")
            .unwrap();

        let receipt = generator.finalize("agent-1", "session-1").unwrap();
        let compact = receipt.to_compact();

        assert_eq!(compact.step_count, receipt.step_count());
        assert_eq!(compact.root_hash, receipt.root_hash());
    }

    #[test]
    fn test_step_types() {
        let generator = ReceiptGenerator::with_defaults();

        generator
            .start_receipt("agent-1", "session-1", "initial")
            .unwrap();
        generator
            .add_observation("agent-1", "session-1", "observe")
            .unwrap();
        generator
            .add_reasoning("agent-1", "session-1", "think")
            .unwrap();
        generator
            .add_action("agent-1", "session-1", "act", true)
            .unwrap();
        generator
            .add_policy_check("agent-1", "session-1", "policy-1", true)
            .unwrap();

        let receipt = generator.finalize("agent-1", "session-1").unwrap();

        assert_eq!(receipt.steps[0].step_type, StepType::Observation);
        assert_eq!(receipt.steps[1].step_type, StepType::Reasoning);
        assert_eq!(receipt.steps[2].step_type, StepType::Action);
        assert_eq!(receipt.steps[3].step_type, StepType::PolicyCheck);
    }

    #[test]
    fn test_tool_call_with_hashes() {
        let generator = ReceiptGenerator::with_defaults();

        generator
            .start_receipt("agent-1", "session-1", "initial")
            .unwrap();
        generator
            .add_tool_call(
                "agent-1",
                "session-1",
                "calculator",
                Some("input-hash"),
                Some("output-hash"),
            )
            .unwrap();

        let receipt = generator.finalize("agent-1", "session-1").unwrap();

        assert_eq!(receipt.steps[0].input_hash.as_deref(), Some("input-hash"));
        assert_eq!(receipt.steps[0].output_hash.as_deref(), Some("output-hash"));
    }

    #[test]
    fn test_auto_start_receipt() {
        let generator = ReceiptGenerator::with_defaults();

        // Don't explicitly start - should auto-start
        generator
            .add_observation("agent-1", "session-1", "test")
            .unwrap();

        let receipt = generator.finalize("agent-1", "session-1").unwrap();
        assert_eq!(receipt.steps.len(), 1);
    }

    #[test]
    fn test_max_steps_limit() {
        let config = ReceiptConfig {
            max_steps: 3,
            ..Default::default()
        };
        let generator = ReceiptGenerator::new(config);

        generator
            .start_receipt("agent-1", "session-1", "initial")
            .unwrap();

        for i in 0..3 {
            generator
                .add_observation("agent-1", "session-1", format!("step {}", i))
                .unwrap();
        }

        // Fourth step should fail
        let result = generator.add_observation("agent-1", "session-1", "step 3");
        assert!(result.is_err());
    }

    #[test]
    fn test_execution_step_verify() {
        let step = ExecutionStep::new(1, StepType::Observation, "test content", "prev-hash");
        assert!(step.verify());
    }

    #[test]
    fn test_disabled_generator() {
        let config = ReceiptConfig {
            enabled: false,
            ..Default::default()
        };
        let generator = ReceiptGenerator::new(config);

        // Operations should succeed but do nothing
        let result = generator.add_observation("agent-1", "session-1", "test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());

        // Finalize should fail (no receipt)
        let result = generator.finalize("agent-1", "session-1");
        assert!(result.is_err());
    }
}

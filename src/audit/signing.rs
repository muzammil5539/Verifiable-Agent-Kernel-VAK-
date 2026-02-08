use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use crate::audit::error::AuditError;

// ============================================================================
// Ed25519 Signing Support (Issue #51 - Non-repudiation)
// ============================================================================

/// Signing key manager for audit entry signatures
///
/// Provides ed25519 signing for audit entries to ensure non-repudiation.
/// Each kernel instance can have its own signing key.
#[derive(Debug)]
pub struct AuditSigner {
    /// Ed25519 signing key
    signing_key: SigningKey,
    /// Public key for verification (hex-encoded for storage)
    pub public_key_hex: String,
}

impl AuditSigner {
    /// Create a new signer with a freshly generated key pair
    pub fn new() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key();
        let public_key_hex = hex::encode(public_key.as_bytes());

        Self {
            signing_key,
            public_key_hex,
        }
    }

    /// Create a signer from a hex-encoded private key
    pub fn from_key_bytes(key_bytes: &[u8; 32]) -> Result<Self, AuditError> {
        let signing_key = SigningKey::from_bytes(key_bytes);
        let public_key = signing_key.verifying_key();
        let public_key_hex = hex::encode(public_key.as_bytes());

        Ok(Self {
            signing_key,
            public_key_hex,
        })
    }

    /// Export the private key bytes for secure storage
    pub fn export_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Sign an audit entry hash
    pub fn sign(&self, entry_hash: &str) -> String {
        let signature = self.signing_key.sign(entry_hash.as_bytes());
        hex::encode(signature.to_bytes())
    }

    /// Verify a signature against an entry hash
    pub fn verify(&self, entry_hash: &str, signature_hex: &str) -> Result<bool, AuditError> {
        let sig_bytes = hex::decode(signature_hex)
            .map_err(|e| AuditError::SerializationError(format!("Invalid signature hex: {}", e)))?;

        let sig_array: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| AuditError::SerializationError("Signature wrong length".to_string()))?;

        let signature = Signature::from_bytes(&sig_array);

        Ok(self
            .signing_key
            .verifying_key()
            .verify(entry_hash.as_bytes(), &signature)
            .is_ok())
    }

    /// Verify a signature using a public key
    pub fn verify_with_public_key(
        public_key_hex: &str,
        entry_hash: &str,
        signature_hex: &str,
    ) -> Result<bool, AuditError> {
        let pk_bytes = hex::decode(public_key_hex).map_err(|e| {
            AuditError::SerializationError(format!("Invalid public key hex: {}", e))
        })?;

        let pk_array: [u8; 32] = pk_bytes
            .try_into()
            .map_err(|_| AuditError::SerializationError("Public key wrong length".to_string()))?;

        let verifying_key = VerifyingKey::from_bytes(&pk_array)
            .map_err(|e| AuditError::SerializationError(format!("Invalid public key: {}", e)))?;

        let sig_bytes = hex::decode(signature_hex)
            .map_err(|e| AuditError::SerializationError(format!("Invalid signature hex: {}", e)))?;

        let sig_array: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| AuditError::SerializationError("Signature wrong length".to_string()))?;

        let signature = Signature::from_bytes(&sig_array);

        Ok(verifying_key
            .verify(entry_hash.as_bytes(), &signature)
            .is_ok())
    }
}

impl Default for AuditSigner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Ed25519 Signing Tests (Issue #51)
    // ========================================================================

    #[test]
    fn test_signer_creation() {
        let signer = AuditSigner::new();
        assert!(!signer.public_key_hex.is_empty());
        assert_eq!(signer.public_key_hex.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_signer_sign_and_verify() {
        let signer = AuditSigner::new();
        let hash = "abc123def456";

        let signature = signer.sign(hash);
        assert!(!signature.is_empty());
        assert_eq!(signature.len(), 128); // 64 bytes = 128 hex chars

        // Verify with the same signer
        assert!(signer.verify(hash, &signature).unwrap());

        // Verify fails with different message
        assert!(!signer.verify("different_hash", &signature).unwrap());
    }

    #[test]
    fn test_signer_key_export_import() {
        let signer1 = AuditSigner::new();
        let key_bytes = signer1.export_key_bytes();

        let signer2 = AuditSigner::from_key_bytes(&key_bytes).unwrap();

        // Both should have same public key
        assert_eq!(signer1.public_key_hex, signer2.public_key_hex);

        // Sign with signer1, verify with signer2
        let hash = "test_hash";
        let signature = signer1.sign(hash);
        assert!(signer2.verify(hash, &signature).unwrap());
    }

    #[test]
    fn test_verify_with_public_key() {
        let signer = AuditSigner::new();
        let hash = "some_audit_hash";
        let signature = signer.sign(hash);

        // Verify using static method with public key
        let result =
            AuditSigner::verify_with_public_key(&signer.public_key_hex, hash, &signature).unwrap();
        assert!(result);
    }
}

//! Skill signatures: Ed25519 over the module's digest and the manifest,
//! verified against a trust root (Phase 1 slice 1c, `docs/adr/0005`).
//!
//! The registry's previous "signature" was an unkeyed SHA-256 over a few
//! manifest fields, which anyone could recompute, so it proved nothing about
//! who published a skill (K4 in `docs/architecture-v2.md`). It also fell
//! back to hashing the module's *path* when the module was missing.
//!
//! # What is signed
//!
//! A publisher signs one statement: [`SIGNATURE_CONTEXT`] followed by the
//! canonical JSON (object keys sorted, no whitespace) of
//!
//! ```text
//! { "author", "description", "input_schema", "module_sha256", "name",
//!   "output_schema", "permissions", "version" }
//! ```
//!
//! That is every manifest field except where the module lives (`wasm_path`,
//! a deployment detail; the module is bound by its digest instead) and the
//! signature fields themselves. So a skill signed as `calculator` can't be
//! loaded as `transfer_funds`, and its permissions can't be widened, without
//! breaking the signature.
//!
//! # What is checked
//!
//! [`SkillSignatureVerifier::verify`] takes the module's digest from the
//! caller, which computed it from the exact bytes it will run. The registry
//! pins that digest at load, and the kernel refuses to run any other bytes
//! under the skill's name (see `SandboxRuntime::prepare_file_pinned`).

use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use tracing::error;

use super::registry::{SignatureConfig, SignatureError, SkillManifest};

/// Domain separation for skill signatures, so a skill signature can never be
/// mistaken for (or replayed as) any other Ed25519-signed message.
pub const SIGNATURE_CONTEXT: &[u8] = b"vak.skill-signature.v1\n";

/// SHA-256 of a module's bytes.
#[must_use]
pub fn module_digest(module: &[u8]) -> [u8; 32] {
    Sha256::digest(module).into()
}

/// The exact bytes a publisher signs for `manifest` with a module whose
/// SHA-256 is `module_sha256`.
///
/// # Errors
///
/// [`SignatureError::InvalidFormat`] if the permissions can't be serialized.
pub fn signed_statement(
    manifest: &SkillManifest,
    module_sha256: &[u8; 32],
) -> Result<Vec<u8>, SignatureError> {
    let permissions =
        serde_json::to_value(&manifest.permissions).map_err(|e| SignatureError::InvalidFormat {
            message: format!("permissions: {e}"),
        })?;
    let statement = serde_json::json!({
        "author": manifest.author,
        "description": manifest.description,
        "input_schema": manifest.input_schema,
        "module_sha256": hex::encode(module_sha256),
        "name": manifest.name,
        "output_schema": manifest.output_schema,
        "permissions": permissions,
        "version": manifest.version,
    });
    let mut out = SIGNATURE_CONTEXT.to_vec();
    let mut json = String::new();
    write_canonical(&statement, &mut json);
    out.extend_from_slice(json.as_bytes());
    Ok(out)
}

/// Canonical JSON: object keys sorted by their UTF-8 bytes, no whitespace,
/// strings escaped as `serde_json` escapes them. Independent of whether
/// `serde_json`'s `preserve_order` feature is enabled anywhere in the build.
fn write_canonical(value: &serde_json::Value, out: &mut String) {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            out.push('{');
            for (i, (key, value)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(key.clone()).to_string());
                out.push(':');
                write_canonical(value, out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
}

/// Signs `manifest` for `module`, setting its `signed_by` and `signature`.
///
/// This is what a skill publisher runs; `examples/sign_skill.rs` wraps it.
///
/// # Errors
///
/// [`SignatureError::InvalidFormat`] if the permissions can't be serialized.
pub fn sign_skill(
    manifest: &mut SkillManifest,
    module: &[u8],
    key: &SigningKey,
) -> Result<(), SignatureError> {
    let statement = signed_statement(manifest, &module_digest(module))?;
    manifest.signed_by = Some(hex::encode(key.verifying_key().to_bytes()));
    manifest.signature = Some(hex::encode(key.sign(&statement).to_bytes()));
    Ok(())
}

/// A skill that passed verification, and the module digest it is pinned to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSkill {
    /// SHA-256 of the module the signature covers.
    pub module_sha256: [u8; 32],
    /// Hex public key of the trusted publisher that signed it, or `None` for
    /// an unsigned skill that the configuration allows.
    pub signed_by: Option<String>,
}

/// Verifies skill signatures against a set of trusted publisher keys.
#[derive(Debug, Clone)]
pub struct SkillSignatureVerifier {
    config: SignatureConfig,
    trusted: Vec<VerifyingKey>,
}

impl SkillSignatureVerifier {
    /// A verifier for `config`. A trusted key that isn't a valid hex Ed25519
    /// public key is logged and left out, so it trusts nothing; use
    /// [`SkillSignatureVerifier::try_new`] to refuse such a configuration.
    #[must_use]
    pub fn new(config: SignatureConfig) -> Self {
        let trusted = config
            .trusted_keys
            .iter()
            .filter_map(|key| match parse_public_key(key) {
                Ok(key) => Some(key),
                Err(e) => {
                    error!(key = %key, error = %e, "Ignoring invalid trusted skill key");
                    None
                }
            })
            .collect();
        Self { config, trusted }
    }

    /// A verifier for `config`, refusing any trusted key that doesn't parse.
    ///
    /// # Errors
    ///
    /// [`SignatureError::InvalidFormat`] naming the first bad key.
    pub fn try_new(config: SignatureConfig) -> Result<Self, SignatureError> {
        let trusted = config
            .trusted_keys
            .iter()
            .map(|key| parse_public_key(key))
            .collect::<Result<_, _>>()?;
        Ok(Self { config, trusted })
    }

    /// Allows unsigned skills. For development only.
    #[must_use]
    pub fn permissive() -> Self {
        Self::new(SignatureConfig::permissive_dev())
    }

    /// Requires a valid signature from a trusted key on every skill. With no
    /// trusted keys, that refuses every skill.
    #[must_use]
    pub fn strict() -> Self {
        Self::new(SignatureConfig::strict())
    }

    /// Whether unsigned skills are accepted.
    #[must_use]
    pub fn allows_unsigned(&self) -> bool {
        !self.config.require_signatures || self.config.allow_unsigned_in_dev
    }

    /// Verifies `manifest` for a module whose SHA-256 is `module_sha256`.
    ///
    /// A skill with a signature is always checked, even when unsigned skills
    /// are allowed: a signature that doesn't verify is worse than none.
    ///
    /// # Errors
    ///
    /// - [`SignatureError::SignatureRequired`]: unsigned, and unsigned skills
    ///   aren't allowed
    /// - [`SignatureError::InvalidFormat`]: `signed_by` or `signature` isn't
    ///   hex of the right length, or only one of them is present
    /// - [`SignatureError::UntrustedKey`]: signed by a key not in the trust
    ///   root
    /// - [`SignatureError::VerificationFailed`]: the signature doesn't cover
    ///   this manifest and module
    pub fn verify(
        &self,
        manifest: &SkillManifest,
        module_sha256: &[u8; 32],
    ) -> Result<VerifiedSkill, SignatureError> {
        let (signed_by, signature) = match (&manifest.signed_by, &manifest.signature) {
            (None, None) => {
                return if self.allows_unsigned() {
                    Ok(VerifiedSkill {
                        module_sha256: *module_sha256,
                        signed_by: None,
                    })
                } else {
                    Err(SignatureError::SignatureRequired {
                        skill_name: manifest.name.clone(),
                    })
                };
            }
            (Some(signed_by), Some(signature)) => (signed_by, signature),
            _ => {
                return Err(SignatureError::InvalidFormat {
                    message: "signed_by and signature must both be present".to_string(),
                })
            }
        };

        let key = parse_public_key(signed_by)?;
        if !self.trusted.contains(&key) {
            return Err(SignatureError::UntrustedKey {
                key_id: signed_by.clone(),
            });
        }
        let signature = parse_signature(signature)?;
        let statement = signed_statement(manifest, module_sha256)?;
        key.verify(&statement, &signature)
            .map_err(|_| SignatureError::VerificationFailed {
                skill_name: manifest.name.clone(),
                reason: "signature does not cover this manifest and module".to_string(),
            })?;

        Ok(VerifiedSkill {
            module_sha256: *module_sha256,
            signed_by: Some(signed_by.clone()),
        })
    }

    /// Reads the module at `manifest.wasm_path` and verifies the manifest for
    /// it. Prefer [`SkillSignatureVerifier::verify`] with a digest of the
    /// bytes you will actually run.
    ///
    /// # Errors
    ///
    /// As [`SkillSignatureVerifier::verify`], plus
    /// [`SignatureError::WasmNotFound`] if the module can't be read.
    pub fn verify_skill(&self, manifest: &SkillManifest) -> Result<VerifiedSkill, SignatureError> {
        let module = read_module(&manifest.wasm_path)?;
        self.verify(manifest, &module_digest(&module))
    }

    /// Whether `public_key` (hex) is in the trust root.
    #[must_use]
    pub fn is_key_trusted(&self, public_key: &str) -> bool {
        parse_public_key(public_key).is_ok_and(|key| self.trusted.contains(&key))
    }

    /// The configuration this verifier was built from.
    #[must_use]
    pub fn config(&self) -> &SignatureConfig {
        &self.config
    }
}

impl Default for SkillSignatureVerifier {
    fn default() -> Self {
        Self::strict()
    }
}

/// Reads a skill module.
///
/// # Errors
///
/// [`SignatureError::WasmNotFound`] if it can't be read.
pub fn read_module(path: &Path) -> Result<Vec<u8>, SignatureError> {
    std::fs::read(path).map_err(|e| SignatureError::WasmNotFound {
        path: path.to_path_buf(),
        message: e.to_string(),
    })
}

fn parse_public_key(hex_key: &str) -> Result<VerifyingKey, SignatureError> {
    let bytes: [u8; 32] = hex::decode(hex_key.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| SignatureError::InvalidFormat {
            message: format!("'{hex_key}' is not a hex Ed25519 public key (64 hex characters)"),
        })?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| SignatureError::InvalidFormat {
        message: format!("'{hex_key}' is not a valid Ed25519 public key: {e}"),
    })
}

fn parse_signature(hex_signature: &str) -> Result<Signature, SignatureError> {
    let bytes: [u8; 64] = hex::decode(hex_signature.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| SignatureError::InvalidFormat {
            message: "signature is not a hex Ed25519 signature (128 hex characters)".to_string(),
        })?;
    Ok(Signature::from_bytes(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::registry::SkillPermissions;
    use std::path::PathBuf;

    const MODULE: &[u8] = b"(module)";

    fn manifest() -> SkillManifest {
        SkillManifest {
            name: "calculator".to_string(),
            version: "1.0.0".to_string(),
            description: "Arithmetic".to_string(),
            author: Some("VAK".to_string()),
            permissions: SkillPermissions::default(),
            input_schema: serde_json::json!({"type": "object", "properties": {"b": {}, "a": {}}}),
            output_schema: serde_json::json!({"type": "object"}),
            wasm_path: PathBuf::from("calculator.wasm"),
            signed_by: None,
            signature: None,
        }
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn trusting(key: &SigningKey) -> SkillSignatureVerifier {
        SkillSignatureVerifier::try_new(
            SignatureConfig::strict().with_trusted_key(hex::encode(key.verifying_key().to_bytes())),
        )
        .unwrap()
    }

    fn signed(key: &SigningKey) -> SkillManifest {
        let mut manifest = manifest();
        sign_skill(&mut manifest, MODULE, key).unwrap();
        manifest
    }

    #[test]
    fn test_signed_skill_verifies_against_trusted_key() {
        let publisher = key(1);
        let verified = trusting(&publisher)
            .verify(&signed(&publisher), &module_digest(MODULE))
            .unwrap();
        assert_eq!(verified.module_sha256, module_digest(MODULE));
        assert_eq!(
            verified.signed_by,
            Some(hex::encode(publisher.verifying_key().to_bytes()))
        );
    }

    #[test]
    fn test_any_change_breaks_the_signature() {
        let publisher = key(1);
        let verifier = trusting(&publisher);
        let digest = module_digest(MODULE);

        // A different module.
        assert!(matches!(
            verifier.verify(&signed(&publisher), &module_digest(b"(module (func))")),
            Err(SignatureError::VerificationFailed { .. })
        ));

        // Each signed manifest field.
        let tamperings: [fn(&mut SkillManifest); 7] = [
            |m| m.name = "transfer_funds".to_string(),
            |m| m.version = "1.0.1".to_string(),
            |m| m.description = "x".to_string(),
            |m| m.author = None,
            |m| m.permissions.network = true,
            |m| m.input_schema = serde_json::json!({}),
            |m| m.output_schema = serde_json::json!({}),
        ];
        for tamper in tamperings {
            let mut manifest = signed(&publisher);
            tamper(&mut manifest);
            assert!(matches!(
                verifier.verify(&manifest, &digest),
                Err(SignatureError::VerificationFailed { .. })
            ));
        }

        // Where the module lives is not signed.
        let mut moved = signed(&publisher);
        moved.wasm_path = PathBuf::from("/opt/skills/calculator.wasm");
        assert!(verifier.verify(&moved, &digest).is_ok());
    }

    #[test]
    fn test_untrusted_and_malformed_signatures_are_refused() {
        let publisher = key(1);
        let stranger = key(2);
        let digest = module_digest(MODULE);
        let verifier = trusting(&publisher);

        assert!(matches!(
            verifier.verify(&signed(&stranger), &digest),
            Err(SignatureError::UntrustedKey { .. })
        ));

        // A trusted key claimed, but the stranger signed.
        let mut forged = signed(&stranger);
        forged.signed_by = Some(hex::encode(publisher.verifying_key().to_bytes()));
        assert!(matches!(
            verifier.verify(&forged, &digest),
            Err(SignatureError::VerificationFailed { .. })
        ));

        // The old unkeyed SHA-256 "signature" format.
        let mut legacy = manifest();
        legacy.signed_by = Some(hex::encode(publisher.verifying_key().to_bytes()));
        legacy.signature = Some(hex::encode([7u8; 32]));
        assert!(matches!(
            verifier.verify(&legacy, &digest),
            Err(SignatureError::InvalidFormat { .. })
        ));

        // Half a signature.
        let mut half = signed(&publisher);
        half.signed_by = None;
        assert!(matches!(
            verifier.verify(&half, &digest),
            Err(SignatureError::InvalidFormat { .. })
        ));
    }

    #[test]
    fn test_unsigned_skills_only_when_allowed() {
        let digest = module_digest(MODULE);
        assert!(matches!(
            SkillSignatureVerifier::strict().verify(&manifest(), &digest),
            Err(SignatureError::SignatureRequired { .. })
        ));
        let verified = SkillSignatureVerifier::permissive()
            .verify(&manifest(), &digest)
            .unwrap();
        assert_eq!(verified.signed_by, None);

        // Allowing unsigned skills doesn't excuse a bad signature.
        let mut bad = signed(&key(1));
        bad.description = "tampered".to_string();
        assert!(SkillSignatureVerifier::permissive()
            .verify(&bad, &digest)
            .is_err());
    }

    #[test]
    fn test_statement_is_canonical() {
        let digest = module_digest(MODULE);
        let statement = String::from_utf8(signed_statement(&manifest(), &digest).unwrap()).unwrap();
        assert!(statement.starts_with("vak.skill-signature.v1\n{\"author\":\"VAK\","));
        // Nested keys are sorted too, whatever order they were written in.
        assert!(statement.contains("\"properties\":{\"a\":{},\"b\":{}}"));
        assert!(!statement.contains(' '));
    }

    #[test]
    fn test_bad_trusted_keys() {
        let config = SignatureConfig::strict().with_trusted_key("not-a-key");
        assert!(matches!(
            SkillSignatureVerifier::try_new(config.clone()),
            Err(SignatureError::InvalidFormat { .. })
        ));
        // `new` leaves it out rather than trusting anything.
        let verifier = SkillSignatureVerifier::new(config);
        assert!(!verifier.is_key_trusted("not-a-key"));
        assert!(verifier
            .verify(&signed(&key(1)), &module_digest(MODULE))
            .is_err());
    }
}

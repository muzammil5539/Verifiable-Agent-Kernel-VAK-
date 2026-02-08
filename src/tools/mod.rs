//! VAK Tools Module
//!
//! Command-line utilities and helper tools for VAK.
//!
//! # Tools
//!
//! - `skill_sign`: CLI for signing and verifying WASM skills

pub mod skill_sign;

pub use skill_sign::{
    cmd_info, cmd_keygen, cmd_sign, cmd_verify, SignedSkillManifest, SigningError, SigningKeypair,
    SkillSignature, SkillSigner, SkillVerifier, VerificationResult,
};

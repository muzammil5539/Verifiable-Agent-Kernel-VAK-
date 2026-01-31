//! VAK Tools Module
//!
//! Command-line utilities and helper tools for VAK.
//!
//! # Tools
//!
//! - `skill_sign`: CLI for signing and verifying WASM skills

pub mod skill_sign;

pub use skill_sign::{
    SigningKeypair, SkillSigner, SkillVerifier, SignedSkillManifest, SkillSignature,
    VerificationResult, SigningError,
    cmd_keygen, cmd_sign, cmd_verify, cmd_info,
};

//! Generate a skill publisher key, or sign a skill manifest.
//!
//! ```text
//! cargo run --example sign_skill -- keygen <secret-key-file>
//! cargo run --example sign_skill -- sign <manifest.yaml> <secret-key-file>
//! ```
//!
//! `keygen` writes a new Ed25519 secret key (hex) to the file, readable only
//! by you, and prints the public key. Put the public key in the kernel's
//! `security.trusted_skill_keys`.
//!
//! `sign` reads the manifest and the module its `wasm_path` names, and
//! prints the `signed_by` and `signature` lines to put in the manifest. The
//! signature covers the module's SHA-256 and every manifest field except
//! `wasm_path`, so re-sign after changing either. See `docs/adr/0005`.

use std::path::Path;
use std::process::ExitCode;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use vak::sandbox::signing::{module_digest, read_module, sign_skill};
use vak::sandbox::SkillManifest;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["keygen", key_file] => keygen(Path::new(key_file)),
        ["sign", manifest, key_file] => sign(Path::new(manifest), Path::new(key_file)),
        _ => Err("usage: sign_skill keygen <secret-key-file>\n       \
                  sign_skill sign <manifest.yaml> <secret-key-file>"
            .to_string()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn keygen(key_file: &Path) -> Result<(), String> {
    if key_file.exists() {
        return Err(format!(
            "{} already exists; not overwriting a key",
            key_file.display()
        ));
    }
    let key = SigningKey::generate(&mut OsRng);
    write_secret(key_file, &hex::encode(key.to_bytes()))
        .map_err(|e| format!("{}: {e}", key_file.display()))?;
    println!("secret key written to {}", key_file.display());
    println!("public key (add to security.trusted_skill_keys):");
    println!("{}", hex::encode(key.verifying_key().to_bytes()));
    Ok(())
}

fn sign(manifest_path: &Path, key_file: &Path) -> Result<(), String> {
    let secret =
        std::fs::read_to_string(key_file).map_err(|e| format!("{}: {e}", key_file.display()))?;
    let bytes: [u8; 32] = hex::decode(secret.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| format!("{} is not a hex Ed25519 secret key", key_file.display()))?;
    let key = SigningKey::from_bytes(&bytes);

    let mut manifest = SkillManifest::from_file(manifest_path).map_err(|e| e.to_string())?;
    let module = read_module(&manifest.wasm_path).map_err(|e| e.to_string())?;
    sign_skill(&mut manifest, &module, &key).map_err(|e| e.to_string())?;

    eprintln!(
        "signed {} v{} (module sha256 {})",
        manifest.name,
        manifest.version,
        hex::encode(module_digest(&module))
    );
    eprintln!("replace any existing signed_by/signature lines in the manifest with:");
    println!("signed_by: \"{}\"", manifest.signed_by.unwrap_or_default());
    println!("signature: \"{}\"", manifest.signature.unwrap_or_default());
    Ok(())
}

#[cfg(unix)]
fn write_secret(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents.as_bytes())
}

#[cfg(not(unix))]
fn write_secret(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(contents.as_bytes())
}

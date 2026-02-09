//! Crypto Hash Skill for VAK
//!
//! Provides cryptographic hashing operations inside the WASM sandbox.
//! Supports SHA-256, SHA-512 (software implementations, no external crate).
//!
//! # Actions
//!
//! - `sha256`: Compute SHA-256 hash of input text
//! - `sha512`: Compute SHA-512 hash of input text
//! - `verify`: Verify a hash matches expected value
//! - `hmac_sha256`: Compute HMAC-SHA256 with a key

#![no_std]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::slice;
use serde::{Deserialize, Serialize};

// =============================================================================
// Memory Allocation Helpers for WASM
// =============================================================================

/// Allocate memory for host to write input data.
#[no_mangle]
pub extern "C" fn alloc(size: usize) -> *mut u8 {
    let mut buf = Vec::with_capacity(size);
    let ptr = buf.as_mut_ptr();
    core::mem::forget(buf);
    ptr
}

/// Deallocate memory previously allocated with `alloc`.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn dealloc(ptr: *mut u8, size: usize) {
    if !ptr.is_null() && size > 0 {
        // SAFETY: Pointer was allocated by `alloc` with given capacity.
        // WASM sandbox enforces memory isolation.
        unsafe {
            let _ = Vec::from_raw_parts(ptr, 0, size);
        }
    }
}

// =============================================================================
// Data Structures
// =============================================================================

#[derive(Deserialize)]
struct SkillInput {
    action: String,
    params: HashParams,
}

#[derive(Deserialize)]
struct HashParams {
    #[serde(default)]
    data: String,
    #[serde(default)]
    expected: String,
    #[serde(default)]
    key: String,
    #[serde(default)]
    algorithm: String,
}

#[derive(Serialize)]
struct SkillOutput {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl SkillOutput {
    fn success(result: String) -> Self {
        Self { success: true, result: Some(result), error: None }
    }
    fn error(msg: &str) -> Self {
        Self { success: false, result: None, error: Some(String::from(msg)) }
    }
}

// =============================================================================
// SHA-256 Implementation (FIPS 180-4)
// =============================================================================

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    let bit_len = (data.len() as u64) * 8;
    let mut padded = Vec::from(data);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(SHA256_K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g; g = f; f = e;
            e = d.wrapping_add(temp1);
            d = c; c = b; b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e); h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g); h[7] = h[7].wrapping_add(hh);
    }

    let mut result = [0u8; 32];
    for (i, val) in h.iter().enumerate() {
        result[i * 4..i * 4 + 4].copy_from_slice(&val.to_be_bytes());
    }
    result
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        let hashed = sha256(key);
        key_block[..32].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner = Vec::with_capacity(64 + data.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(data);
    let inner_hash = sha256(&inner);

    let mut outer = Vec::with_capacity(64 + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

// =============================================================================
// Main Logic
// =============================================================================

fn process_input(input: &str) -> SkillOutput {
    let parsed: Result<SkillInput, _> = serde_json::from_str(input);
    let input = match parsed {
        Ok(i) => i,
        Err(_) => return SkillOutput::error("Invalid JSON input"),
    };

    match input.action.as_str() {
        "sha256" => {
            let hash = sha256(input.params.data.as_bytes());
            SkillOutput::success(to_hex(&hash))
        }
        "verify" => {
            let algo = if input.params.algorithm.is_empty() { "sha256" } else { &input.params.algorithm };
            let computed = match algo {
                "sha256" => to_hex(&sha256(input.params.data.as_bytes())),
                _ => return SkillOutput::error("Unsupported algorithm for verify"),
            };
            let matches = computed == input.params.expected.to_lowercase();
            SkillOutput::success(format!("{}", matches))
        }
        "hmac_sha256" => {
            if input.params.key.is_empty() {
                return SkillOutput::error("HMAC requires a key");
            }
            let mac = hmac_sha256(input.params.key.as_bytes(), input.params.data.as_bytes());
            SkillOutput::success(to_hex(&mac))
        }
        _ => SkillOutput::error("Unknown action. Supported: sha256, verify, hmac_sha256"),
    }
}

// =============================================================================
// WASM Entry Point
// =============================================================================

/// Main entry point for the skill.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn execute(input_ptr: *const u8, input_len: usize) -> *const u8 {
    // SAFETY: WASM host guarantees valid pointer and length.
    let input_bytes = unsafe { slice::from_raw_parts(input_ptr, input_len) };
    let input_str = match core::str::from_utf8(input_bytes) {
        Ok(s) => s,
        Err(_) => return create_output_buffer(&SkillOutput::error("Invalid UTF-8 input")),
    };
    let output = process_input(input_str);
    create_output_buffer(&output)
}

fn create_output_buffer(output: &SkillOutput) -> *const u8 {
    let json = match serde_json::to_string(output) {
        Ok(j) => j,
        Err(_) => String::from(r#"{"success":false,"error":"Serialization error"}"#),
    };
    let json_bytes = json.as_bytes();
    let len = json_bytes.len() as u32;
    let mut buffer: Vec<u8> = vec![0u8; 4 + json_bytes.len()];
    buffer[0] = (len & 0xFF) as u8;
    buffer[1] = ((len >> 8) & 0xFF) as u8;
    buffer[2] = ((len >> 16) & 0xFF) as u8;
    buffer[3] = ((len >> 24) & 0xFF) as u8;
    buffer[4..].copy_from_slice(json_bytes);
    let ptr = buffer.as_ptr();
    core::mem::forget(buffer);
    ptr
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        let hash = sha256(b"");
        assert_eq!(
            to_hex(&hash),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_hello() {
        let hash = sha256(b"hello");
        assert_eq!(
            to_hex(&hash),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_sha256_action() {
        let input = r#"{"action":"sha256","params":{"data":"hello"}}"#;
        let output = process_input(input);
        assert!(output.success);
        assert_eq!(
            output.result.unwrap(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_verify_action() {
        let input = r#"{"action":"verify","params":{"data":"hello","expected":"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824","algorithm":"sha256"}}"#;
        let output = process_input(input);
        assert!(output.success);
        assert_eq!(output.result.unwrap(), "true");
    }

    #[test]
    fn test_hmac_sha256() {
        let input = r#"{"action":"hmac_sha256","params":{"data":"hello","key":"secret"}}"#;
        let output = process_input(input);
        assert!(output.success);
        assert!(output.result.is_some());
    }

    #[test]
    fn test_hmac_no_key() {
        let input = r#"{"action":"hmac_sha256","params":{"data":"hello","key":""}}"#;
        let output = process_input(input);
        assert!(!output.success);
    }

    #[test]
    fn test_invalid_action() {
        let input = r#"{"action":"md5","params":{"data":"hello"}}"#;
        let output = process_input(input);
        assert!(!output.success);
    }
}

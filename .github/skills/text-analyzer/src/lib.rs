//! Text Analyzer Skill for VAK
//!
//! Provides text analysis operations inside the WASM sandbox.
//!
//! # Actions
//!
//! - `word_count`: Count words in text
//! - `char_count`: Count characters (total, alpha, digits, spaces)
//! - `frequency`: Character frequency analysis
//! - `similarity`: Compute Jaccard similarity between two texts
//! - `entropy`: Compute Shannon entropy of text
//! - `summary`: Generate text statistics summary

#![no_std]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::slice;
use serde::{Deserialize, Serialize};

// =============================================================================
// Memory Allocation Helpers
// =============================================================================

/// Allocate memory for host input.
#[no_mangle]
pub extern "C" fn alloc(size: usize) -> *mut u8 {
    let mut buf = Vec::with_capacity(size);
    let ptr = buf.as_mut_ptr();
    core::mem::forget(buf);
    ptr
}

/// Deallocate memory.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn dealloc(ptr: *mut u8, size: usize) {
    if !ptr.is_null() && size > 0 {
        // SAFETY: Pointer was allocated by `alloc` with given capacity.
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
    params: TextParams,
}

#[derive(Deserialize)]
struct TextParams {
    #[serde(default)]
    text: String,
    #[serde(default)]
    second: String,
    #[serde(default)]
    top_n: Option<usize>,
}

#[derive(Serialize)]
struct SkillOutput {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl SkillOutput {
    fn success_val(val: serde_json::Value) -> Self {
        Self { success: true, result: Some(val), error: None }
    }
    fn error(msg: &str) -> Self {
        Self { success: false, result: None, error: Some(String::from(msg)) }
    }
}

// =============================================================================
// Text Analysis Functions
// =============================================================================

fn word_count(text: &str) -> usize {
    text.split_whitespace().count()
}

fn char_stats(text: &str) -> serde_json::Value {
    let total = text.chars().count();
    let alpha = text.chars().filter(|c| c.is_alphabetic()).count();
    let digits = text.chars().filter(|c| c.is_ascii_digit()).count();
    let spaces = text.chars().filter(|c| c.is_whitespace()).count();
    let uppercase = text.chars().filter(|c| c.is_uppercase()).count();
    let lowercase = text.chars().filter(|c| c.is_lowercase()).count();

    serde_json::json!({
        "total": total,
        "alphabetic": alpha,
        "digits": digits,
        "whitespace": spaces,
        "uppercase": uppercase,
        "lowercase": lowercase,
        "other": total - alpha - digits - spaces,
    })
}

fn char_frequency(text: &str, top_n: usize) -> serde_json::Value {
    let mut freq: BTreeMap<char, usize> = BTreeMap::new();
    for c in text.chars() {
        if !c.is_whitespace() {
            *freq.entry(c.to_lowercase().next().unwrap_or(c)).or_insert(0) += 1;
        }
    }

    let mut sorted: Vec<(char, usize)> = freq.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    sorted.truncate(top_n);

    let entries: Vec<serde_json::Value> = sorted
        .iter()
        .map(|(c, count)| serde_json::json!({"char": format!("{}", c), "count": count}))
        .collect();

    serde_json::Value::Array(entries)
}

fn jaccard_similarity(text1: &str, text2: &str) -> f64 {
    let set1: Vec<&str> = text1.split_whitespace().collect();
    let set2: Vec<&str> = text2.split_whitespace().collect();

    if set1.is_empty() && set2.is_empty() {
        return 1.0;
    }

    let mut intersection = 0usize;
    for word in &set1 {
        if set2.contains(word) {
            intersection += 1;
        }
    }

    // Union = |A| + |B| - |A ∩ B|
    let union = set1.len() + set2.len() - intersection;
    if union == 0 {
        return 1.0;
    }
    intersection as f64 / union as f64
}

fn shannon_entropy(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }
    let mut freq: BTreeMap<char, usize> = BTreeMap::new();
    let total = text.chars().count() as f64;
    for c in text.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }

    let mut entropy = 0.0f64;
    for &count in freq.values() {
        let p = count as f64 / total;
        if p > 0.0 {
            // log2 via ln: log2(x) = ln(x) / ln(2)
            let log2_p = ln_approx(p) / core::f64::consts::LN_2;
            entropy -= p * log2_p;
        }
    }
    entropy
}

/// Approximate natural log using a series expansion
fn ln_approx(x: f64) -> f64 {
    if x <= 0.0 {
        return f64::NEG_INFINITY;
    }
    // Use identity: ln(x) = ln(m * 2^e) = ln(m) + e*ln(2)
    // For a simpler approach, use the Taylor series around 1
    // ln(x) for x > 0 using the identity: ln(x) = 2 * atanh((x-1)/(x+1))
    let y = (x - 1.0) / (x + 1.0);
    let y2 = y * y;
    let mut result = y;
    let mut term = y;
    for i in 1..=20 {
        term *= y2;
        result += term / (2 * i + 1) as f64;
    }
    2.0 * result
}

fn text_summary(text: &str) -> serde_json::Value {
    let words = word_count(text);
    let chars = text.chars().count();
    let lines = if text.is_empty() { 0 } else { text.lines().count() };
    let sentences = text.matches('.').count()
        + text.matches('!').count()
        + text.matches('?').count();
    let avg_word_len = if words > 0 {
        text.split_whitespace().map(|w| w.len()).sum::<usize>() as f64 / words as f64
    } else {
        0.0
    };

    // Round to 2 decimal places
    let avg_word_len = (avg_word_len * 100.0) as i64 as f64 / 100.0;
    let entropy = (shannon_entropy(text) * 1000.0) as i64 as f64 / 1000.0;

    serde_json::json!({
        "words": words,
        "characters": chars,
        "lines": lines,
        "sentences": sentences,
        "avg_word_length": avg_word_len,
        "entropy": entropy,
    })
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
        "word_count" => {
            SkillOutput::success_val(serde_json::json!({"count": word_count(&input.params.text)}))
        }
        "char_count" => {
            SkillOutput::success_val(char_stats(&input.params.text))
        }
        "frequency" => {
            let top_n = input.params.top_n.unwrap_or(10);
            SkillOutput::success_val(char_frequency(&input.params.text, top_n))
        }
        "similarity" => {
            if input.params.second.is_empty() {
                return SkillOutput::error("Second text required for similarity");
            }
            let sim = jaccard_similarity(&input.params.text, &input.params.second);
            let rounded = (sim * 10000.0) as i64 as f64 / 10000.0;
            SkillOutput::success_val(serde_json::json!({"similarity": rounded}))
        }
        "entropy" => {
            let e = shannon_entropy(&input.params.text);
            let rounded = (e * 10000.0) as i64 as f64 / 10000.0;
            SkillOutput::success_val(serde_json::json!({"entropy": rounded}))
        }
        "summary" => {
            SkillOutput::success_val(text_summary(&input.params.text))
        }
        _ => SkillOutput::error("Unknown action. Supported: word_count, char_count, frequency, similarity, entropy, summary"),
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
    fn test_word_count() {
        let input = r#"{"action":"word_count","params":{"text":"hello world foo bar"}}"#;
        let output = process_input(input);
        assert!(output.success);
    }

    #[test]
    fn test_char_count() {
        let input = r#"{"action":"char_count","params":{"text":"Hello 123"}}"#;
        let output = process_input(input);
        assert!(output.success);
    }

    #[test]
    fn test_frequency() {
        let input = r#"{"action":"frequency","params":{"text":"aabbcc","top_n":3}}"#;
        let output = process_input(input);
        assert!(output.success);
    }

    #[test]
    fn test_similarity() {
        let input = r#"{"action":"similarity","params":{"text":"the quick brown fox","second":"the quick red fox"}}"#;
        let output = process_input(input);
        assert!(output.success);
    }

    #[test]
    fn test_entropy() {
        let input = r#"{"action":"entropy","params":{"text":"aaaa"}}"#;
        let output = process_input(input);
        assert!(output.success);
    }

    #[test]
    fn test_summary() {
        let input = r#"{"action":"summary","params":{"text":"Hello world. This is a test!"}}"#;
        let output = process_input(input);
        assert!(output.success);
    }

    #[test]
    fn test_empty_text() {
        let input = r#"{"action":"word_count","params":{"text":""}}"#;
        let output = process_input(input);
        assert!(output.success);
    }
}

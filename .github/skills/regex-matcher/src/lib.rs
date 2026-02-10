//! Regex Matcher Skill for VAK
//!
//! Provides pattern matching operations inside the WASM sandbox.
//! Uses a custom lightweight regex engine (no external deps beyond serde).
//!
//! # Actions
//!
//! - `match`: Test if text matches a pattern (glob-style)
//! - `find_all`: Find all occurrences of a substring
//! - `replace`: Replace occurrences of a pattern
//! - `split`: Split text by a delimiter
//! - `extract_patterns`: Extract emails, URLs, numbers from text
//! - `glob`: Match against glob patterns (*, ?)

#![no_std]

extern crate alloc;

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
    params: MatchParams,
}

#[derive(Deserialize)]
struct MatchParams {
    #[serde(default)]
    text: String,
    #[serde(default)]
    pattern: String,
    #[serde(default)]
    replacement: String,
    #[serde(default)]
    delimiter: String,
    #[serde(default)]
    case_insensitive: bool,
    #[serde(default)]
    max_results: Option<usize>,
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
        Self {
            success: true,
            result: Some(val),
            error: None,
        }
    }
    fn error(msg: &str) -> Self {
        Self {
            success: false,
            result: None,
            error: Some(String::from(msg)),
        }
    }
}

// =============================================================================
// Pattern Matching Functions
// =============================================================================

/// Glob-style pattern matching (supports * and ?)
fn glob_match(pattern: &str, text: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = text.chars().collect();
    glob_match_helper(&pat, &txt, 0, 0)
}

fn glob_match_helper(pat: &[char], txt: &[char], pi: usize, ti: usize) -> bool {
    if pi == pat.len() && ti == txt.len() {
        return true;
    }
    if pi == pat.len() {
        return false;
    }
    if pat[pi] == '*' {
        // * matches zero or more characters
        // Try matching zero chars, or skip one text char
        if glob_match_helper(pat, txt, pi + 1, ti) {
            return true;
        }
        if ti < txt.len() && glob_match_helper(pat, txt, pi, ti + 1) {
            return true;
        }
        return false;
    }
    if ti == txt.len() {
        return false;
    }
    if pat[pi] == '?' || pat[pi] == txt[ti] {
        return glob_match_helper(pat, txt, pi + 1, ti + 1);
    }
    false
}

/// Find all occurrences of a substring
fn find_all_occurrences(
    text: &str,
    pattern: &str,
    case_insensitive: bool,
    max_results: usize,
) -> Vec<serde_json::Value> {
    let (search_text, search_pattern);
    let text_ref: &str;
    let pattern_ref: &str;

    if case_insensitive {
        search_text = text
            .chars()
            .map(|c| c.to_lowercase().next().unwrap_or(c))
            .collect::<String>();
        search_pattern = pattern
            .chars()
            .map(|c| c.to_lowercase().next().unwrap_or(c))
            .collect::<String>();
        text_ref = &search_text;
        pattern_ref = &search_pattern;
    } else {
        text_ref = text;
        pattern_ref = pattern;
    }

    let mut results = Vec::new();
    let mut start = 0;

    while let Some(pos) = text_ref[start..].find(pattern_ref) {
        let absolute_pos = start + pos;
        let matched = &text[absolute_pos..absolute_pos + pattern.len()];
        results.push(serde_json::json!({
            "position": absolute_pos,
            "match": matched,
        }));
        if results.len() >= max_results {
            break;
        }
        start = absolute_pos + 1;
    }
    results
}

/// Replace all occurrences of pattern with replacement
fn replace_all(text: &str, pattern: &str, replacement: &str) -> String {
    if pattern.is_empty() {
        return String::from(text);
    }
    let mut result = String::new();
    let mut remaining = text;
    while let Some(pos) = remaining.find(pattern) {
        result.push_str(&remaining[..pos]);
        result.push_str(replacement);
        remaining = &remaining[pos + pattern.len()..];
    }
    result.push_str(remaining);
    result
}

/// Extract common patterns from text (emails, numbers)
fn extract_patterns(text: &str) -> serde_json::Value {
    let mut numbers = Vec::new();
    let mut current_num = String::new();
    let mut in_number = false;

    for c in text.chars() {
        if c.is_ascii_digit() || (c == '.' && in_number && !current_num.contains('.')) {
            current_num.push(c);
            in_number = true;
        } else if c == '-' && !in_number {
            current_num.push(c);
            in_number = true;
        } else {
            if in_number && !current_num.is_empty() && current_num != "-" && current_num != "." {
                numbers.push(serde_json::Value::String(current_num.clone()));
            }
            current_num.clear();
            in_number = false;
        }
    }
    if in_number && !current_num.is_empty() && current_num != "-" && current_num != "." {
        numbers.push(serde_json::Value::String(current_num));
    }

    // Simple email detection: look for word@word.word pattern
    let mut emails = Vec::new();
    let words: Vec<&str> = text.split_whitespace().collect();
    for word in &words {
        let trimmed = word.trim_matches(|c: char| {
            !c.is_alphanumeric() && c != '@' && c != '.' && c != '_' && c != '-'
        });
        if trimmed.contains('@') && trimmed.contains('.') {
            let parts: Vec<&str> = trimmed.split('@').collect();
            if parts.len() == 2 && !parts[0].is_empty() && parts[1].contains('.') {
                emails.push(serde_json::Value::String(String::from(trimmed)));
            }
        }
    }

    serde_json::json!({
        "numbers": numbers,
        "emails": emails,
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
        "match" | "glob" => {
            if input.params.pattern.is_empty() {
                return SkillOutput::error("Pattern is required");
            }
            let text = if input.params.case_insensitive {
                input
                    .params
                    .text
                    .chars()
                    .map(|c| c.to_lowercase().next().unwrap_or(c))
                    .collect::<String>()
            } else {
                input.params.text.clone()
            };
            let pattern = if input.params.case_insensitive {
                input
                    .params
                    .pattern
                    .chars()
                    .map(|c| c.to_lowercase().next().unwrap_or(c))
                    .collect::<String>()
            } else {
                input.params.pattern.clone()
            };
            let matches = glob_match(&pattern, &text);
            SkillOutput::success_val(serde_json::json!({"matches": matches}))
        }
        "find_all" => {
            if input.params.pattern.is_empty() {
                return SkillOutput::error("Pattern is required for find_all");
            }
            let max = input.params.max_results.unwrap_or(100);
            let results = find_all_occurrences(
                &input.params.text,
                &input.params.pattern,
                input.params.case_insensitive,
                max,
            );
            SkillOutput::success_val(serde_json::json!({
                "count": results.len(),
                "matches": results,
            }))
        }
        "replace" => {
            if input.params.pattern.is_empty() {
                return SkillOutput::error("Pattern is required for replace");
            }
            let result = replace_all(
                &input.params.text,
                &input.params.pattern,
                &input.params.replacement,
            );
            SkillOutput::success_val(serde_json::json!({"result": result}))
        }
        "split" => {
            let delimiter = if input.params.delimiter.is_empty() {
                " "
            } else {
                &input.params.delimiter
            };
            let parts: Vec<serde_json::Value> = input
                .params
                .text
                .split(delimiter)
                .map(|s| serde_json::Value::String(String::from(s)))
                .collect();
            SkillOutput::success_val(serde_json::json!({
                "count": parts.len(),
                "parts": parts,
            }))
        }
        "extract_patterns" => SkillOutput::success_val(extract_patterns(&input.params.text)),
        _ => SkillOutput::error(
            "Unknown action. Supported: match, glob, find_all, replace, split, extract_patterns",
        ),
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
    fn test_glob_match_star() {
        assert!(glob_match("hello*", "hello world"));
        assert!(glob_match("*world", "hello world"));
        assert!(glob_match("*llo*", "hello world"));
        assert!(!glob_match("foo*", "hello world"));
    }

    #[test]
    fn test_glob_match_question() {
        assert!(glob_match("h?llo", "hello"));
        assert!(!glob_match("h?llo", "heello"));
    }

    #[test]
    fn test_find_all() {
        let input =
            r#"{"action":"find_all","params":{"text":"the cat sat on the mat","pattern":"the"}}"#;
        let output = process_input(input);
        assert!(output.success);
    }

    #[test]
    fn test_find_all_case_insensitive() {
        let input = r#"{"action":"find_all","params":{"text":"Hello HELLO hello","pattern":"hello","case_insensitive":true}}"#;
        let output = process_input(input);
        assert!(output.success);
    }

    #[test]
    fn test_replace() {
        let input = r#"{"action":"replace","params":{"text":"hello world","pattern":"world","replacement":"rust"}}"#;
        let output = process_input(input);
        assert!(output.success);
    }

    #[test]
    fn test_split() {
        let input = r#"{"action":"split","params":{"text":"a,b,c,d","delimiter":","}}"#;
        let output = process_input(input);
        assert!(output.success);
    }

    #[test]
    fn test_extract_patterns() {
        let input = r#"{"action":"extract_patterns","params":{"text":"Contact user@example.com or call 555-1234. Price is 99.99"}}"#;
        let output = process_input(input);
        assert!(output.success);
    }

    #[test]
    fn test_glob_action() {
        let input = r#"{"action":"glob","params":{"text":"hello.rs","pattern":"*.rs"}}"#;
        let output = process_input(input);
        assert!(output.success);
    }
}

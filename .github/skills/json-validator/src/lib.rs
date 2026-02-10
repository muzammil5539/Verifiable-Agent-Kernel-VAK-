//! JSON Validator Skill for VAK
//!
//! Provides JSON validation, schema checking, and transformation operations.
//!
//! # Actions
//!
//! - `validate`: Check if input is valid JSON
//! - `pretty`: Pretty-print JSON
//! - `minify`: Minify JSON (remove whitespace)
//! - `extract`: Extract a value by JSON path (dot notation)
//! - `merge`: Merge two JSON objects
//! - `diff`: Compare two JSON values for equality

#![no_std]

extern crate alloc;

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
    params: JsonParams,
}

#[derive(Deserialize)]
struct JsonParams {
    #[serde(default)]
    json: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    second: String,
    #[serde(default)]
    schema: Option<SchemaRule>,
}

#[derive(Deserialize)]
struct SchemaRule {
    #[serde(default)]
    required_fields: Vec<String>,
    #[serde(default)]
    max_depth: Option<usize>,
}

#[derive(Serialize)]
struct SkillOutput {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl SkillOutput {
    fn success(result: String) -> Self {
        Self {
            success: true,
            result: Some(result),
            valid: None,
            error: None,
        }
    }
    fn validation(valid: bool, message: String) -> Self {
        Self {
            success: true,
            result: Some(message),
            valid: Some(valid),
            error: None,
        }
    }
    fn error(msg: &str) -> Self {
        Self {
            success: false,
            result: None,
            valid: None,
            error: Some(String::from(msg)),
        }
    }
}

// =============================================================================
// JSON Operations
// =============================================================================

fn json_depth(val: &serde_json::Value) -> usize {
    match val {
        serde_json::Value::Array(arr) => 1 + arr.iter().map(json_depth).max().unwrap_or(0),
        serde_json::Value::Object(obj) => 1 + obj.values().map(json_depth).max().unwrap_or(0),
        _ => 0,
    }
}

fn extract_path(val: &serde_json::Value, path: &str) -> Option<serde_json::Value> {
    let parts: Vec<&str> = path.split('.').filter(|p| !p.is_empty()).collect();
    let mut current = val;
    for part in parts {
        match current {
            serde_json::Value::Object(map) => {
                current = map.get(part)?;
            }
            serde_json::Value::Array(arr) => {
                let idx: usize = part.parse().ok()?;
                current = arr.get(idx)?;
            }
            _ => return None,
        }
    }
    Some(current.clone())
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
        "validate" => {
            match serde_json::from_str::<serde_json::Value>(&input.params.json) {
                Ok(val) => {
                    if let Some(schema) = &input.params.schema {
                        // Check required fields
                        if let serde_json::Value::Object(obj) = &val {
                            for field in &schema.required_fields {
                                if !obj.contains_key(field.as_str()) {
                                    return SkillOutput::validation(
                                        false,
                                        format!("Missing required field: {}", field),
                                    );
                                }
                            }
                        }
                        // Check max depth
                        if let Some(max_d) = schema.max_depth {
                            let depth = json_depth(&val);
                            if depth > max_d {
                                return SkillOutput::validation(
                                    false,
                                    format!("JSON depth {} exceeds max {}", depth, max_d),
                                );
                            }
                        }
                    }
                    SkillOutput::validation(true, String::from("Valid JSON"))
                }
                Err(e) => SkillOutput::validation(false, format!("Invalid JSON: {}", e)),
            }
        }
        "pretty" => match serde_json::from_str::<serde_json::Value>(&input.params.json) {
            Ok(val) => match serde_json::to_string_pretty(&val) {
                Ok(pretty) => SkillOutput::success(pretty),
                Err(e) => SkillOutput::error(&format!("Formatting error: {}", e)),
            },
            Err(e) => SkillOutput::error(&format!("Parse error: {}", e)),
        },
        "minify" => match serde_json::from_str::<serde_json::Value>(&input.params.json) {
            Ok(val) => match serde_json::to_string(&val) {
                Ok(minified) => SkillOutput::success(minified),
                Err(e) => SkillOutput::error(&format!("Formatting error: {}", e)),
            },
            Err(e) => SkillOutput::error(&format!("Parse error: {}", e)),
        },
        "extract" => {
            if input.params.path.is_empty() {
                return SkillOutput::error("Path is required for extract action");
            }
            match serde_json::from_str::<serde_json::Value>(&input.params.json) {
                Ok(val) => match extract_path(&val, &input.params.path) {
                    Some(extracted) => match serde_json::to_string(&extracted) {
                        Ok(s) => SkillOutput::success(s),
                        Err(e) => SkillOutput::error(&format!("Serialize error: {}", e)),
                    },
                    None => SkillOutput::error(&format!("Path '{}' not found", input.params.path)),
                },
                Err(e) => SkillOutput::error(&format!("Parse error: {}", e)),
            }
        }
        "merge" => {
            let val1: serde_json::Value = match serde_json::from_str(&input.params.json) {
                Ok(v) => v,
                Err(e) => return SkillOutput::error(&format!("First JSON parse error: {}", e)),
            };
            let val2: serde_json::Value = match serde_json::from_str(&input.params.second) {
                Ok(v) => v,
                Err(e) => return SkillOutput::error(&format!("Second JSON parse error: {}", e)),
            };
            match (&val1, &val2) {
                (serde_json::Value::Object(a), serde_json::Value::Object(b)) => {
                    let mut merged = a.clone();
                    for (k, v) in b {
                        merged.insert(k.clone(), v.clone());
                    }
                    match serde_json::to_string(&serde_json::Value::Object(merged)) {
                        Ok(s) => SkillOutput::success(s),
                        Err(e) => SkillOutput::error(&format!("Serialize error: {}", e)),
                    }
                }
                _ => SkillOutput::error("Both inputs must be JSON objects for merge"),
            }
        }
        "diff" => {
            let val1: Result<serde_json::Value, _> = serde_json::from_str(&input.params.json);
            let val2: Result<serde_json::Value, _> = serde_json::from_str(&input.params.second);
            match (val1, val2) {
                (Ok(a), Ok(b)) => {
                    let equal = a == b;
                    SkillOutput::success(format!("{}", equal))
                }
                _ => SkillOutput::error("Could not parse one or both JSON inputs"),
            }
        }
        _ => SkillOutput::error(
            "Unknown action. Supported: validate, pretty, minify, extract, merge, diff",
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
    fn test_validate_valid() {
        let input = r#"{"action":"validate","params":{"json":"{\"name\":\"test\",\"value\":42}"}}"#;
        let output = process_input(input);
        assert!(output.success);
        assert_eq!(output.valid, Some(true));
    }

    #[test]
    fn test_validate_invalid() {
        let input = r#"{"action":"validate","params":{"json":"not json at all"}}"#;
        let output = process_input(input);
        assert!(output.success);
        assert_eq!(output.valid, Some(false));
    }

    #[test]
    fn test_validate_required_fields() {
        let input = r#"{"action":"validate","params":{"json":"{\"name\":\"test\"}","schema":{"required_fields":["name","age"]}}}"#;
        let output = process_input(input);
        assert!(output.success);
        assert_eq!(output.valid, Some(false));
    }

    #[test]
    fn test_pretty() {
        let input = r#"{"action":"pretty","params":{"json":"{\"a\":1}"}}"#;
        let output = process_input(input);
        assert!(output.success);
        assert!(output.result.unwrap().contains('\n'));
    }

    #[test]
    fn test_minify() {
        let input = r#"{"action":"minify","params":{"json":"{ \"a\" : 1 }"}}"#;
        let output = process_input(input);
        assert!(output.success);
        assert_eq!(output.result.unwrap(), "{\"a\":1}");
    }

    #[test]
    fn test_extract() {
        let input = r#"{"action":"extract","params":{"json":"{\"user\":{\"name\":\"Alice\"}}","path":"user.name"}}"#;
        let output = process_input(input);
        assert!(output.success);
        assert_eq!(output.result.unwrap(), "\"Alice\"");
    }

    #[test]
    fn test_merge() {
        let input = r#"{"action":"merge","params":{"json":"{\"a\":1}","second":"{\"b\":2}"}}"#;
        let output = process_input(input);
        assert!(output.success);
        let result = output.result.unwrap();
        assert!(result.contains("\"a\":1") || result.contains("\"a\": 1"));
        assert!(result.contains("\"b\":2") || result.contains("\"b\": 2"));
    }

    #[test]
    fn test_diff_equal() {
        let input = r#"{"action":"diff","params":{"json":"{\"a\":1}","second":"{\"a\":1}"}}"#;
        let output = process_input(input);
        assert!(output.success);
        assert_eq!(output.result.unwrap(), "true");
    }

    #[test]
    fn test_diff_not_equal() {
        let input = r#"{"action":"diff","params":{"json":"{\"a\":1}","second":"{\"a\":2}"}}"#;
        let output = process_input(input);
        assert!(output.success);
        assert_eq!(output.result.unwrap(), "false");
    }
}

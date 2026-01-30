//! Calculator Skill for VAK
//!
//! A simple calculator demonstrating the skill interface pattern.
//! Supports basic arithmetic operations: add, subtract, multiply, divide.

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use alloc::vec;
use alloc::format;
use core::slice;
use serde::{Deserialize, Serialize};

// =============================================================================
// Memory Allocation Helpers for WASM
// =============================================================================

/// Allocate memory for the host to write input data.
/// Returns a pointer to the allocated memory.
#[no_mangle]
pub extern "C" fn alloc(size: usize) -> *mut u8 {
    let mut buf = Vec::with_capacity(size);
    let ptr = buf.as_mut_ptr();
    core::mem::forget(buf);
    ptr
}

/// Deallocate memory previously allocated with `alloc`.
#[no_mangle]
pub extern "C" fn dealloc(ptr: *mut u8, size: usize) {
    if !ptr.is_null() && size > 0 {
        unsafe {
            let _ = Vec::from_raw_parts(ptr, 0, size);
        }
    }
}

// =============================================================================
// Input/Output Data Structures
// =============================================================================

/// Input format for skill invocation
#[derive(Deserialize)]
struct SkillInput {
    action: String,
    params: CalculatorParams,
}

/// Parameters for calculator operations
#[derive(Deserialize)]
struct CalculatorParams {
    a: f64,
    b: f64,
}

/// Output format for skill response
#[derive(Serialize)]
struct SkillOutput {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl SkillOutput {
    fn success(result: f64) -> Self {
        Self {
            success: true,
            result: Some(result),
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
// Calculator Operations
// =============================================================================

/// Add two numbers
#[inline]
fn add(a: f64, b: f64) -> f64 {
    a + b
}

/// Subtract b from a
#[inline]
fn subtract(a: f64, b: f64) -> f64 {
    a - b
}

/// Multiply two numbers
#[inline]
fn multiply(a: f64, b: f64) -> f64 {
    a * b
}

/// Divide a by b, returns None if b is zero
#[inline]
fn divide(a: f64, b: f64) -> Option<f64> {
    if b == 0.0 {
        None
    } else {
        Some(a / b)
    }
}

// =============================================================================
// Main Entry Point
// =============================================================================

/// Process the input JSON and execute the requested operation
fn process_input(input: &str) -> SkillOutput {
    // Parse input JSON
    let parsed: Result<SkillInput, _> = serde_json::from_str(input);
    
    let input = match parsed {
        Ok(i) => i,
        Err(_) => return SkillOutput::error("Invalid JSON input"),
    };

    let a = input.params.a;
    let b = input.params.b;

    // Dispatch to appropriate operation
    match input.action.as_str() {
        "add" => SkillOutput::success(add(a, b)),
        "subtract" => SkillOutput::success(subtract(a, b)),
        "multiply" => SkillOutput::success(multiply(a, b)),
        "divide" => {
            match divide(a, b) {
                Some(result) => SkillOutput::success(result),
                None => SkillOutput::error("Division by zero"),
            }
        }
        _ => SkillOutput::error("Unknown action. Supported: add, subtract, multiply, divide"),
    }
}

/// Main entry point for the skill.
/// 
/// Receives a pointer to JSON input and its length.
/// Returns a pointer to the output buffer where:
/// - First 4 bytes: length of the JSON output (little-endian u32)
/// - Remaining bytes: JSON output string
#[no_mangle]
pub extern "C" fn execute(input_ptr: *const u8, input_len: usize) -> *const u8 {
    // Safety: We trust the host to provide valid pointer and length
    let input_bytes = unsafe { slice::from_raw_parts(input_ptr, input_len) };
    
    // Convert to string (UTF-8)
    let input_str = match core::str::from_utf8(input_bytes) {
        Ok(s) => s,
        Err(_) => {
            return create_output_buffer(&SkillOutput::error("Invalid UTF-8 input"));
        }
    };

    // Process and create output
    let output = process_input(input_str);
    create_output_buffer(&output)
}

/// Create the output buffer with length prefix
fn create_output_buffer(output: &SkillOutput) -> *const u8 {
    let json = match serde_json::to_string(output) {
        Ok(j) => j,
        Err(_) => String::from(r#"{"success":false,"error":"Serialization error"}"#),
    };

    let json_bytes = json.as_bytes();
    let len = json_bytes.len() as u32;
    
    // Create buffer: 4 bytes for length + JSON bytes
    let mut buffer: Vec<u8> = vec![0u8; 4 + json_bytes.len()];
    
    // Write length as little-endian u32
    buffer[0] = (len & 0xFF) as u8;
    buffer[1] = ((len >> 8) & 0xFF) as u8;
    buffer[2] = ((len >> 16) & 0xFF) as u8;
    buffer[3] = ((len >> 24) & 0xFF) as u8;
    
    // Copy JSON bytes
    buffer[4..].copy_from_slice(json_bytes);
    
    let ptr = buffer.as_ptr();
    core::mem::forget(buffer);
    ptr
}

// =============================================================================
// Tests (run with `cargo test`)
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        let input = r#"{"action":"add","params":{"a":2,"b":3}}"#;
        let output = process_input(input);
        assert!(output.success);
        assert_eq!(output.result, Some(5.0));
    }

    #[test]
    fn test_subtract() {
        let input = r#"{"action":"subtract","params":{"a":10,"b":4}}"#;
        let output = process_input(input);
        assert!(output.success);
        assert_eq!(output.result, Some(6.0));
    }

    #[test]
    fn test_multiply() {
        let input = r#"{"action":"multiply","params":{"a":3,"b":7}}"#;
        let output = process_input(input);
        assert!(output.success);
        assert_eq!(output.result, Some(21.0));
    }

    #[test]
    fn test_divide() {
        let input = r#"{"action":"divide","params":{"a":20,"b":4}}"#;
        let output = process_input(input);
        assert!(output.success);
        assert_eq!(output.result, Some(5.0));
    }

    #[test]
    fn test_divide_by_zero() {
        let input = r#"{"action":"divide","params":{"a":10,"b":0}}"#;
        let output = process_input(input);
        assert!(!output.success);
        assert!(output.error.is_some());
    }

    #[test]
    fn test_invalid_action() {
        let input = r#"{"action":"power","params":{"a":2,"b":3}}"#;
        let output = process_input(input);
        assert!(!output.success);
        assert!(output.error.is_some());
    }

    #[test]
    fn test_invalid_json() {
        let input = "not valid json";
        let output = process_input(input);
        assert!(!output.success);
    }
}

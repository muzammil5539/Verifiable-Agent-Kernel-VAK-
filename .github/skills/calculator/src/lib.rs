#![no_std]
extern crate alloc;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::slice;
use serde::{Deserialize, Serialize};

#[no_mangle]
pub extern "C" fn alloc(size: usize) -> *mut u8 {
    let mut buf = Vec::with_capacity(size);
    let ptr = buf.as_mut_ptr();
    core::mem::forget(buf);
    ptr
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn dealloc(ptr: *mut u8, size: usize) {
    if !ptr.is_null() && size > 0 {
        unsafe {
            let _ = Vec::from_raw_parts(ptr, 0, size);
        }
    }
}

#[derive(Deserialize)]
struct SkillInput {
    action: String,
    params: CalculatorParams,
}

#[derive(Deserialize)]
struct CalculatorParams {
    a: f64,
    b: f64,
}

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
        Self { success: true, result: Some(result), error: None }
    }
    fn error(msg: &str) -> Self {
        Self { success: false, result: None, error: Some(String::from(msg)) }
    }
}

fn process_input(input: &str) -> SkillOutput {
    let parsed: Result<SkillInput, _> = serde_json::from_str(input);
    let input = match parsed {
        Ok(i) => i,
        Err(_) => return SkillOutput::error("Invalid JSON input"),
    };

    match input.action.as_str() {
        "add" => SkillOutput::success(input.params.a + input.params.b),
        "subtract" => SkillOutput::success(input.params.a - input.params.b),
        "multiply" => SkillOutput::success(input.params.a * input.params.b),
        "divide" => {
            if input.params.b == 0.0 {
                SkillOutput::error("Division by zero")
            } else {
                SkillOutput::success(input.params.a / input.params.b)
            }
        }
        _ => SkillOutput::error("Unknown action. Supported: add, subtract, multiply, divide"),
    }
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn execute(input_ptr: *const u8, input_len: usize) -> *const u8 {
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

#[cfg(all(not(test), target_arch = "wasm32"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

#[cfg(all(not(test), target_arch = "wasm32"))]
#[global_allocator]
static ALLOC: lol_alloc::AssumeSingleThreaded<lol_alloc::FreeListAllocator> = unsafe { lol_alloc::AssumeSingleThreaded::new(lol_alloc::FreeListAllocator::new()) };

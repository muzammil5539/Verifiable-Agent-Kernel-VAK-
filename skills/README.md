# VAK Skills

Skills are sandboxed WebAssembly (WASM) modules that extend the Verifiable Agent Kernel with domain-specific capabilities. Each skill runs in an isolated environment with controlled access to resources.

## What are Skills?

Skills are:
- **Sandboxed WASM modules** - Isolated execution with no direct system access
- **Deterministic** - Same input always produces same output
- **Verifiable** - Execution can be audited and formally verified
- **Composable** - Multiple skills can be chained together

## Building Skills from Rust

### Prerequisites

1. Install the WASM target:
   ```bash
   rustup target add wasm32-unknown-unknown
   ```

2. Install wasm-bindgen-cli (optional, for JS interop):
   ```bash
   cargo install wasm-bindgen-cli
   ```

### Project Setup

Create a new skill project:

```bash
cargo new --lib my_skill
cd my_skill
```

Configure `Cargo.toml`:

```toml
[package]
name = "my_skill"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
# Minimal dependencies for WASM compatibility

[profile.release]
opt-level = "s"      # Optimize for size
lto = true           # Link-time optimization
strip = true         # Strip symbols
```

### Building

```bash
cargo build --target wasm32-unknown-unknown --release
```

The compiled WASM module will be at:
`target/wasm32-unknown-unknown/release/my_skill.wasm`

## Interface Requirements

Every skill must implement the following interface:

### Memory Management

```rust
/// Allocate memory for the host to write input data
#[no_mangle]
pub extern "C" fn alloc(size: usize) -> *mut u8 {
    let mut buf = Vec::with_capacity(size);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// Deallocate memory after use
#[no_mangle]
pub extern "C" fn dealloc(ptr: *mut u8, size: usize) {
    unsafe {
        let _ = Vec::from_raw_parts(ptr, 0, size);
    }
}
```

### Entry Point

```rust
/// Main entry point - receives JSON input, returns JSON output
/// Returns a pointer to the result (first 4 bytes = length)
#[no_mangle]
pub extern "C" fn execute(input_ptr: *const u8, input_len: usize) -> *const u8 {
    // Parse input, process, return output
}
```

### Input/Output Format

Skills receive and return JSON data:

**Input:**
```json
{
  "action": "function_name",
  "params": {
    "key": "value"
  }
}
```

**Output:**
```json
{
  "success": true,
  "result": "...",
  "error": null
}
```

## Skill Manifest Format

Each skill should include a `skill.yaml` manifest:

```yaml
# skill.yaml
name: my_skill
version: "0.1.0"
description: "Brief description of the skill"

# Skill metadata
author: "Your Name"
license: "MIT"

# WASM module location
module: target/wasm32-unknown-unknown/release/my_skill.wasm

# Capabilities required (for policy enforcement)
capabilities:
  - compute        # Basic computation
  # - network      # Network access (requires approval)
  # - filesystem   # File system access (requires approval)
  # - crypto       # Cryptographic operations

# Memory limits
limits:
  max_memory_pages: 16    # 16 pages = 1MB
  max_execution_time_ms: 1000

# Exported functions
exports:
  - name: execute
    description: "Main entry point"
    input_schema:
      type: object
      properties:
        action:
          type: string
        params:
          type: object
    output_schema:
      type: object
      properties:
        success:
          type: boolean
        result: {}
        error:
          type: string
          nullable: true

# Dependencies on other skills (optional)
dependencies: []

# Policy requirements
policies:
  - name: "input_validation"
    enforce: true
  - name: "output_sanitization"
    enforce: true
```

## Signing & Verification (required by default)

- The skill registry now enforces signature verification by default. Unsigned manifests are rejected unless you explicitly opt into development mode.
- To allow unsigned skills while iterating locally, construct the registry with `SignatureConfig::permissive_dev()` (or `SkillRegistry::new_permissive_dev(...)`).
- Make sure your published skills are signed; a signing helper (`vak-skill-sign`) should be used once available to generate the manifest signature before distribution.

## Example Skills

See the following example skills in this directory:

- **calculator/** - Basic arithmetic operations
- More examples coming soon...

## Best Practices

1. **Keep skills focused** - One skill, one responsibility
2. **Minimize dependencies** - Smaller WASM = faster loading
3. **Use no_std when possible** - Reduces binary size significantly
4. **Validate all inputs** - Never trust external data
5. **Return structured errors** - Use the standard error format
6. **Document your interface** - Update skill.yaml with all exports

## Testing Skills

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        let input = r#"{"action":"add","params":{"a":2,"b":3}}"#;
        let result = process_input(input);
        assert!(result.contains("\"result\":5"));
    }
}
```

Run tests:
```bash
cargo test
```

## Security Considerations

- Skills run in a sandboxed WASM environment
- No direct access to host filesystem, network, or system calls
- Memory is isolated per skill instance
- All inter-skill communication goes through the kernel
- Execution time and memory usage are bounded by policy

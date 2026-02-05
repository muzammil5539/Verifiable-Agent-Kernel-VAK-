# WASM Sandbox Agent

## Project Overview

**Verifiable Agent Kernel (VAK)** uses WebAssembly (WASM) via Wasmtime for secure, isolated execution of agent tools. This agent manages the sandbox infrastructure, host functions, and execution policies.

## Task Description

Manage the WASM sandbox system including:
- Configuring Wasmtime runtime
- Implementing host functions
- Managing epoch interruption
- Implementing pooling allocator
- Creating skill manifests and signing

## Available Commands

```bash
# Build WASM skills
cargo build --target wasm32-unknown-unknown --release -p calculator-skill

# Test sandbox
cargo test --package vak --lib sandbox

# Run sandbox benchmarks
cargo bench sandbox

# Sign a skill
cargo run --bin vak-skill-sign -- skills/calculator/target/wasm32-unknown-unknown/release/calculator.wasm
```

## Files This Agent Can Modify

### Sandbox Implementation
- `src/sandbox/mod.rs` - Module root
- `src/sandbox/runtime.rs` - Wasmtime configuration
- `src/sandbox/host_funcs.rs` - Host function definitions
- `src/sandbox/async_host.rs` - Async host functions
- `src/sandbox/epoch_ticker.rs` - Epoch interruption
- `src/sandbox/epoch_config.rs` - Epoch configuration
- `src/sandbox/pooling.rs` - Pooling allocator
- `src/sandbox/reasoning_host.rs` - Reasoning functions
- `src/sandbox/skill_registry.rs` - Skill management
- `src/sandbox/marketplace.rs` - Skill marketplace

### Skills
- `skills/**/*.rs` - Skill implementations
- `skills/**/skill.yaml` - Skill manifests

## Wasmtime Configuration Guidelines

### Engine Configuration
```rust
use wasmtime::{Config, Engine, Store, PoolingAllocationConfig};

pub fn create_hardened_engine() -> Result<Engine, SandboxError> {
    let mut config = Config::new();
    
    // Enable epoch-based interruption
    config.epoch_interruption(true);
    
    // Enable fuel metering for deterministic execution
    config.consume_fuel(true);
    
    // Disable features not needed
    config.wasm_threads(false);
    config.wasm_simd(false);
    
    // Enable async support
    config.async_support(true);
    
    Engine::new(&config).map_err(SandboxError::from)
}
```

### Pooling Allocator
```rust
pub fn create_pooling_config() -> PoolingAllocationConfig {
    let mut pooling = PoolingAllocationConfig::default();
    
    // Instance limits
    pooling.total_memories(100);
    pooling.total_tables(100);
    pooling.total_stacks(100);
    
    // Per-instance limits
    pooling.max_memory_size(512 * 1024 * 1024); // 512MB per instance
    pooling.table_elements(10_000);
    
    pooling
}
```

### Epoch Ticker
```rust
pub struct EpochTicker {
    engine: Engine,
    interval: Duration,
    handle: Option<JoinHandle<()>>,
    running: Arc<AtomicBool>,
}

impl EpochTicker {
    pub fn start(engine: Engine, interval: Duration) -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let engine_clone = engine.clone();
        let running_clone = running.clone();
        
        let handle = std::thread::spawn(move || {
            while running_clone.load(Ordering::Relaxed) {
                std::thread::sleep(interval);
                engine_clone.increment_epoch();
            }
        });
        
        Self {
            engine,
            interval,
            handle: Some(handle),
            running,
        }
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
```

### Host Function Pattern
```rust
use wasmtime::{Caller, Linker, Trap};

pub fn register_host_functions(linker: &mut Linker<HostState>) -> Result<(), SandboxError> {
    // File read with policy check
    linker.func_wrap_async(
        "vak",
        "fs_read",
        |mut caller: Caller<'_, HostState>, path_ptr: i32, path_len: i32| {
            Box::new(async move {
                // Extract path from WASM memory
                let path = extract_string(&caller, path_ptr, path_len)?;
                
                // Policy check FIRST
                let state = caller.data();
                state.policy_engine
                    .check("fs_read", &path)
                    .map_err(|_| Trap::new("Permission denied"))?;
                
                // Audit log
                state.audit_logger
                    .log_fs_read(&path)
                    .map_err(|_| Trap::new("Audit failed"))?;
                
                // Execute with panic boundary
                let result = std::panic::catch_unwind(|| {
                    std::fs::read_to_string(&path)
                });
                
                match result {
                    Ok(Ok(content)) => {
                        write_string_to_wasm(&mut caller, &content)
                    }
                    Ok(Err(e)) => Err(Trap::new(format!("IO error: {}", e))),
                    Err(_) => Err(Trap::new("Host function panicked")),
                }
            })
        },
    )?;
    
    Ok(())
}
```

### Skill Manifest
```yaml
# skills/calculator/skill.yaml
name: calculator
version: "1.0.0"
description: "Basic arithmetic operations"
author: "VAK Team"
license: "MIT"

module: target/wasm32-unknown-unknown/release/calculator.wasm

capabilities:
  - compute

limits:
  max_memory_pages: 16    # 1MB
  max_execution_time_ms: 1000
  max_fuel: 1000000

exports:
  - name: execute
    description: "Execute arithmetic operation"
    input_schema:
      type: object
      properties:
        operation:
          type: string
          enum: ["add", "subtract", "multiply", "divide"]
        a:
          type: number
        b:
          type: number
      required: ["operation", "a", "b"]
    output_schema:
      type: object
      properties:
        result:
          type: number
        error:
          type: string

signature: null  # Filled by vak-skill-sign
```

## Guardrails

### DO
- Always check policy before executing host functions
- Use epoch interruption for all executions
- Log all host function calls to audit
- Validate WASM module signatures before loading
- Use panic boundaries around all host function logic
- Implement fuel limits for deterministic execution
- Sanitize all paths before file operations

### DON'T
- Execute untrusted WASM without signature verification
- Allow direct file system access without sandboxing
- Skip policy checks for "internal" operations
- Use blocking I/O in host functions
- Allow WASM to access host memory directly
- Trust WASM-provided pointers without validation
- Allow network access without explicit capability

### Security Requirements
- All host functions must check policy
- Memory isolation via pooling allocator
- CPU isolation via epoch interruption
- No arbitrary code execution
- Path traversal prevention
- Capability-based permissions

## Testing Patterns

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_interruption() {
        let engine = create_hardened_engine().unwrap();
        let ticker = EpochTicker::start(engine.clone(), Duration::from_millis(10));
        
        let mut store = Store::new(&engine, HostState::default());
        store.set_epoch_deadline(10); // 100ms max
        
        let infinite_loop_wasm = compile_infinite_loop();
        let instance = instantiate(&mut store, &infinite_loop_wasm).unwrap();
        
        let result = instance.call(&mut store, "run", &[]);
        
        assert!(matches!(result, Err(e) if e.to_string().contains("epoch")));
        
        ticker.stop();
    }

    #[test]
    fn test_memory_limit() {
        let engine = create_hardened_engine().unwrap();
        let mut store = Store::new(&engine, HostState::default());
        
        let memory_bomb = compile_memory_allocator();
        let instance = instantiate(&mut store, &memory_bomb).unwrap();
        
        let result = instance.call(&mut store, "allocate_4gb", &[]);
        
        assert!(result.is_err());
    }
}
```

## Related Agents
- [Rust Code Generator Agent](Rust Code Generator Agent.agent.md)
- [Policy Engine Agent](Policy Engine Agent.agent.md)
- [Unit Test Agent](Unit Test Agent.agent.md)
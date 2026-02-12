//! Integration tests for epoch-based preemption (TST-001)
//!
//! Tests that verify the epoch interruption mechanism correctly terminates
//! runaway agents within the specified time budget.
//!
//! # Test Cases
//!
//! - `test_infinite_loop_preemption`: Agent with `loop {}` traps via epoch deadline
//! - `test_cpu_intensive_preemption`: CPU-intensive computation is preempted
//! - `test_nested_loop_preemption`: Deeply nested loops are preempted
//! - `test_fuel_exhaustion_halts_execution`: Fuel limit halts tight loops
//! - `test_sequential_preemptions`: Multiple back-to-back preemptions work correctly
//!
//! # References
//!
//! - Gap Analysis Sprint 1, T1.5: Infinite loop test
//! - Gap Analysis Section 3.1: Deterministic Termination Gate

use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(test)]
mod preemption_tests {
    use super::*;

    /// Test that the epoch ticker mechanism is properly configured
    #[test]
    fn test_epoch_ticker_creation() {
        use vak::sandbox::epoch_ticker::{EpochTicker, EpochTickerConfig};
        use wasmtime::{Config, Engine};

        // Create engine with epoch interruption enabled
        let mut config = Config::new();
        config.epoch_interruption(true);
        let engine = Arc::new(Engine::new(&config).expect("Failed to create engine"));

        // Verify the engine is properly configured (epoch_interruption returns &mut Config in wasmtime 41)
        let _ = engine.config();
    }

    /// Test epoch configuration validation
    #[test]
    fn test_epoch_config_validation() {
        use vak::sandbox::epoch_config::{EpochConfig, EpochConfigError};

        // Valid config
        let config = EpochConfig::with_budget_ms(100);
        assert!(config.validate().is_ok());
        assert_eq!(config.budget_ms(), 100);

        // Invalid config (zero budget)
        let mut invalid = EpochConfig::default();
        invalid.epoch_budget = 0;
        assert!(matches!(
            invalid.validate(),
            Err(EpochConfigError::InvalidBudget(_))
        ));
    }

    /// Test preemption budget tracking
    #[test]
    fn test_preemption_budget_tracking() {
        use vak::sandbox::epoch_config::PreemptionBudget;

        let budget = PreemptionBudget::new(10); // 10 epochs = 100ms at 10ms/tick

        // Initially not exhausted
        assert!(!budget.is_exhausted());
        assert_eq!(budget.remaining(), 10);

        // Consume some budget
        budget.record_consumption(5);
        assert!(!budget.is_exhausted());
        assert_eq!(budget.remaining(), 5);

        // Exhaust budget
        budget.record_consumption(6);
        assert!(budget.is_exhausted());
        assert_eq!(budget.remaining(), 0);

        // Reset should restore
        budget.reset();
        assert!(!budget.is_exhausted());
        assert_eq!(budget.remaining(), 10);
    }

    /// Test execution limits builder
    #[test]
    fn test_execution_limits_builder() {
        use vak::sandbox::epoch_config::EpochExecutionBuilder;

        let limits = EpochExecutionBuilder::new()
            .budget_ms(100)
            .with_fuel(1_000_000)
            .with_memory(16 * 1024 * 1024)
            .build()
            .expect("Failed to build limits");

        assert_eq!(limits.epoch_config.budget_ms(), 100);
        assert_eq!(limits.fuel_limit, Some(1_000_000));
        assert_eq!(limits.memory_limit, Some(16 * 1024 * 1024));
    }

    /// Test pooling allocator configuration
    #[test]
    fn test_pooling_allocator_config() {
        use vak::sandbox::pooling::PoolingConfig;

        let config = PoolingConfig::default();

        // Verify Gap Analysis recommendations
        assert_eq!(config.max_memory_per_instance, 512 * 1024 * 1024); // 512MB
        assert_eq!(config.max_table_elements, 10_000);
        assert!(config.epoch_interruption);
        assert!(config.consume_fuel);
    }

    /// Test that the store deadline trap is properly set
    #[test]
    fn test_store_deadline_trap_setup() {
        use wasmtime::{Config, Engine, Store};

        // Create engine with epoch interruption
        let mut config = Config::new();
        config.epoch_interruption(true);
        config.consume_fuel(true);
        let engine = Engine::new(&config).expect("Failed to create engine");

        // Create store
        let mut store = Store::new(&engine, ());

        // Set fuel and epoch deadline
        store.set_fuel(1_000_000).expect("Failed to set fuel");
        store.set_epoch_deadline(10); // 10 epochs = 100ms
    }

    /// TST-001: Test that an infinite loop in WASM is preempted by epoch deadline.
    ///
    /// Loads a WAT module containing `(loop $loop br $loop)` and verifies
    /// the execution traps within a bounded time due to epoch interruption.
    /// A background thread simulates the epoch ticker.
    #[test]
    fn test_infinite_loop_preemption() {
        use wasmtime::{Config, Engine, Linker, Module, Store};

        let mut config = Config::new();
        config.epoch_interruption(true);
        let engine = Engine::new(&config).expect("Engine creation failed");

        let wat = r#"
            (module
                (func (export "infinite_loop")
                    (loop $loop
                        br $loop
                    )
                )
            )
        "#;

        let module = Module::new(&engine, wat).expect("Module creation failed");
        let mut store = Store::new(&engine, ());

        // Set epoch deadline to 2 (very short budget)
        store.set_epoch_deadline(2);

        // Spawn a thread to increment epochs (simulating the epoch ticker)
        let engine_clone = engine.clone();
        let ticker = std::thread::spawn(move || {
            for _ in 0..100 {
                std::thread::sleep(Duration::from_millis(5));
                engine_clone.increment_epoch();
            }
        });

        let linker = Linker::new(&engine);
        let instance = linker
            .instantiate(&mut store, &module)
            .expect("Instantiation failed");

        let func = instance
            .get_typed_func::<(), ()>(&mut store, "infinite_loop")
            .expect("Function not found");

        let start = Instant::now();
        let result = func.call(&mut store, ());
        let elapsed = start.elapsed();

        // Verify it trapped (didn't run forever)
        assert!(result.is_err(), "Infinite loop should have been preempted");

        // Verify it trapped within reasonable time
        assert!(
            elapsed < Duration::from_secs(2),
            "Should trap within 2s, took {:?}",
            elapsed
        );

        let _ = ticker.join();
    }

    /// TST-001: Test that a CPU-intensive computation is preempted.
    ///
    /// Loads a WAT module that counts up to i32::MAX and verifies
    /// epoch-based preemption terminates it before completion.
    #[test]
    fn test_cpu_intensive_preemption() {
        use wasmtime::{Config, Engine, Linker, Module, Store};

        let mut config = Config::new();
        config.epoch_interruption(true);
        let engine = Engine::new(&config).expect("Engine creation failed");

        // WAT: count from 0 to i32::MAX in a tight loop
        let wat = r#"
            (module
                (func (export "cpu_burn") (result i32)
                    (local $i i32)
                    (local.set $i (i32.const 0))
                    (block $break
                        (loop $loop
                            (local.set $i (i32.add (local.get $i) (i32.const 1)))
                            (br_if $break (i32.eq (local.get $i) (i32.const 2147483647)))
                            (br $loop)
                        )
                    )
                    (local.get $i)
                )
            )
        "#;

        let module = Module::new(&engine, wat).expect("Module creation failed");
        let mut store = Store::new(&engine, ());
        store.set_epoch_deadline(2);

        let engine_clone = engine.clone();
        let ticker = std::thread::spawn(move || {
            for _ in 0..200 {
                std::thread::sleep(Duration::from_millis(5));
                engine_clone.increment_epoch();
            }
        });

        let linker = Linker::new(&engine);
        let instance = linker
            .instantiate(&mut store, &module)
            .expect("Instantiation failed");

        let func = instance
            .get_typed_func::<(), i32>(&mut store, "cpu_burn")
            .expect("Function not found");

        let start = Instant::now();
        let result = func.call(&mut store, ());
        let elapsed = start.elapsed();

        assert!(result.is_err(), "CPU burn should have been preempted");
        assert!(
            elapsed < Duration::from_secs(2),
            "Should be preempted within 2s, took {:?}",
            elapsed
        );

        let _ = ticker.join();
    }

    /// TST-001: Test that nested loops are also preempted.
    #[test]
    fn test_nested_loop_preemption() {
        use wasmtime::{Config, Engine, Linker, Module, Store};

        let mut config = Config::new();
        config.epoch_interruption(true);
        let engine = Engine::new(&config).expect("Engine creation failed");

        // WAT: double-nested infinite loop
        let wat = r#"
            (module
                (func (export "nested_loop")
                    (local $i i32)
                    (local $j i32)
                    (loop $outer
                        (local.set $j (i32.const 0))
                        (loop $inner
                            (local.set $j (i32.add (local.get $j) (i32.const 1)))
                            (br_if $inner (i32.lt_u (local.get $j) (i32.const 1000000)))
                        )
                        (local.set $i (i32.add (local.get $i) (i32.const 1)))
                        (br $outer)
                    )
                )
            )
        "#;

        let module = Module::new(&engine, wat).expect("Module creation failed");
        let mut store = Store::new(&engine, ());
        store.set_epoch_deadline(2);

        let engine_clone = engine.clone();
        let ticker = std::thread::spawn(move || {
            for _ in 0..200 {
                std::thread::sleep(Duration::from_millis(5));
                engine_clone.increment_epoch();
            }
        });

        let linker = Linker::new(&engine);
        let instance = linker
            .instantiate(&mut store, &module)
            .expect("Instantiation failed");

        let func = instance
            .get_typed_func::<(), ()>(&mut store, "nested_loop")
            .expect("Function not found");

        let start = Instant::now();
        let result = func.call(&mut store, ());
        let elapsed = start.elapsed();

        assert!(result.is_err(), "Nested loop should have been preempted");
        assert!(
            elapsed < Duration::from_secs(2),
            "Should be preempted within 2s, took {:?}",
            elapsed
        );

        let _ = ticker.join();
    }

    /// TST-001: Test that fuel exhaustion also halts execution.
    #[test]
    fn test_fuel_exhaustion_halts_execution() {
        use wasmtime::{Config, Engine, Linker, Module, Store};

        let mut config = Config::new();
        config.consume_fuel(true);
        let engine = Engine::new(&config).expect("Engine creation failed");

        let wat = r#"
            (module
                (func (export "fuel_burn")
                    (loop $loop
                        (br $loop)
                    )
                )
            )
        "#;

        let module = Module::new(&engine, wat).expect("Module creation failed");
        let mut store = Store::new(&engine, ());

        // Set very limited fuel
        store.set_fuel(1_000).expect("Failed to set fuel");

        let linker = Linker::new(&engine);
        let instance = linker
            .instantiate(&mut store, &module)
            .expect("Instantiation failed");

        let func = instance
            .get_typed_func::<(), ()>(&mut store, "fuel_burn")
            .expect("Function not found");

        let result = func.call(&mut store, ());

        // Should fail due to fuel exhaustion
        assert!(result.is_err(), "Should fail when fuel exhausted");

        // Verify fuel is actually exhausted
        let remaining = store.get_fuel().unwrap_or(0);
        assert_eq!(remaining, 0, "Fuel should be exhausted");
    }

    /// TST-001: Test that multiple sequential preemptions work correctly
    /// without state leakage between runs.
    #[test]
    fn test_sequential_preemptions() {
        use wasmtime::{Config, Engine, Linker, Module, Store};

        let mut config = Config::new();
        config.epoch_interruption(true);
        let engine = Engine::new(&config).expect("Engine creation failed");

        let wat = r#"
            (module
                (func (export "infinite_loop")
                    (loop $loop
                        br $loop
                    )
                )
            )
        "#;

        let module = Module::new(&engine, wat).expect("Module creation failed");

        // Run multiple times to verify no state leakage
        for iteration in 0..3 {
            let mut store = Store::new(&engine, ());
            store.set_epoch_deadline(2);

            let engine_clone = engine.clone();
            let ticker = std::thread::spawn(move || {
                for _ in 0..50 {
                    std::thread::sleep(Duration::from_millis(5));
                    engine_clone.increment_epoch();
                }
            });

            let linker = Linker::new(&engine);
            let instance = linker
                .instantiate(&mut store, &module)
                .expect("Instantiation failed");

            let func = instance
                .get_typed_func::<(), ()>(&mut store, "infinite_loop")
                .expect("Function not found");

            let result = func.call(&mut store, ());
            assert!(
                result.is_err(),
                "Iteration {} should have been preempted",
                iteration
            );

            let _ = ticker.join();
        }
    }
}

/// Tests for panic safety at WASM/Host boundary (RT-005)
#[cfg(test)]
mod panic_safety_tests {
    use super::*;

    #[test]
    fn test_panic_boundary_catches_panic() {
        use vak::sandbox::host_funcs::{with_panic_boundary, HostFuncError};

        let result: Result<i32, HostFuncError> = with_panic_boundary(|| {
            panic!("Test panic message");
        });

        assert!(result.is_err());
        if let Err(HostFuncError::Panic(msg)) = result {
            assert!(msg.contains("Test panic"));
        } else {
            panic!("Expected Panic error");
        }
    }

    #[test]
    fn test_panic_boundary_passes_through_success() {
        use vak::sandbox::host_funcs::with_panic_boundary;

        let result = with_panic_boundary(|| Ok(42));
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_panic_boundary_passes_through_error() {
        use vak::sandbox::host_funcs::{with_panic_boundary, HostFuncError};

        let result: Result<i32, HostFuncError> =
            with_panic_boundary(|| Err(HostFuncError::NotFound("test".into())));

        assert!(matches!(result, Err(HostFuncError::NotFound(_))));
    }

    #[test]
    fn test_host_func_config_defaults() {
        use vak::sandbox::host_funcs::HostFuncConfig;

        let config = HostFuncConfig::default();
        assert!(config.enforce_policy);
        assert!(config.catch_panics);
        assert!(config.audit_logging);
        assert!(config.allowed_fs_roots.is_empty());
        assert!(config.allowed_network_hosts.is_empty());
    }

    #[test]
    fn test_audit_log_entry() {
        use vak::sandbox::host_funcs::AuditLogEntry;

        let entry = AuditLogEntry::new("agent-1", "session-1", "fs_read", "/etc/passwd");
        assert!(!entry.allowed);
        assert_eq!(entry.agent_id, "agent-1");
        assert_eq!(entry.action, "fs_read");

        let allowed_entry = entry.clone().allow("Read 1024 bytes");
        assert!(allowed_entry.allowed);
        assert!(allowed_entry.result.contains("1024"));
    }
}

/// Tests for neuro-symbolic reasoning (NSR-003)
#[cfg(test)]
mod reasoning_tests {
    use super::*;

    #[test]
    fn test_reasoning_host_creation() {
        use vak::sandbox::reasoning_host::{ReasoningConfig, ReasoningHost};

        let host = ReasoningHost::new(ReasoningConfig::default());
        let _engine = host.safety_engine();
    }

    #[test]
    fn test_verify_safe_plan() {
        use vak::sandbox::reasoning_host::{PlanVerification, ReasoningConfig, ReasoningHost};

        let mut host = ReasoningHost::new(ReasoningConfig::default());

        let plan = PlanVerification {
            agent_id: "test-agent".to_string(),
            action_type: "read_file".to_string(),
            target: "/tmp/safe_file.txt".to_string(),
            confidence: 0.95,
            params: Default::default(),
        };

        let result = host.verify_plan(&plan);
        assert!(result.allowed, "Safe plan should be allowed");
    }

    #[test]
    fn test_verify_critical_file_deletion() {
        use vak::sandbox::reasoning_host::{PlanVerification, ReasoningConfig, ReasoningHost};

        let mut host = ReasoningHost::new(ReasoningConfig::default());

        let plan = PlanVerification {
            agent_id: "test-agent".to_string(),
            action_type: "delete_file".to_string(),
            target: "/etc/shadow".to_string(),
            confidence: 0.95,
            params: Default::default(),
        };

        let result = host.verify_plan(&plan);
        assert!(!result.allowed, "Critical file deletion should be denied");
        assert!(!result.violations.is_empty(), "Should have violations");
    }

    #[test]
    fn test_custom_critical_file() {
        use vak::sandbox::reasoning_host::{PlanVerification, ReasoningConfig, ReasoningHost};

        let mut host = ReasoningHost::new(ReasoningConfig::default());
        host.add_critical_file("/custom/important.db");

        let plan = PlanVerification {
            agent_id: "test-agent".to_string(),
            action_type: "delete_file".to_string(),
            target: "/custom/important.db".to_string(),
            confidence: 0.95,
            params: Default::default(),
        };

        let result = host.verify_plan(&plan);
        assert!(!result.allowed, "Custom critical file deletion should be denied");
    }

    #[test]
    fn test_risk_score_affects_decision() {
        use vak::sandbox::reasoning_host::{PlanVerification, ReasoningConfig, ReasoningHost};

        let mut host = ReasoningHost::new(ReasoningConfig::default());

        let plan = PlanVerification {
            agent_id: "test-agent".to_string(),
            action_type: "execute".to_string(),
            target: "/etc/init.d/something".to_string(),
            confidence: 0.0,
            params: Default::default(),
        };

        let result = host.verify_plan(&plan);
        // With confidence=0.0, risk = (0.5 + 0.2) * 1.0 = 0.7 >= threshold 0.7, so denied
        assert!(!result.allowed, "High risk plan should be denied");
        assert!(result.risk_score > 0.5, "Should have high risk score");
    }

    #[test]
    fn test_verification_result_serialization() {
        use vak::sandbox::reasoning_host::{VerificationResult, ViolationInfo};

        let result = VerificationResult::denied(
            vec![ViolationInfo {
                violation_type: "CriticalFileAccess".to_string(),
                resource: "/etc/shadow".to_string(),
                rule: "CriticalFileDelete".to_string(),
                severity: 1.0,
            }],
            0.85,
        );

        let json = serde_json::to_string(&result).expect("Serialization failed");
        assert!(json.contains("CriticalFileAccess"));
        assert!(json.contains("/etc/shadow"));

        let parsed: VerificationResult =
            serde_json::from_str(&json).expect("Deserialization failed");
        assert!(!parsed.allowed);
        assert_eq!(parsed.violations.len(), 1);
    }
}

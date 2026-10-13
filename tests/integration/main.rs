//! Integration tests for the VAK Kernel
//!
//! This module contains end-to-end integration tests that verify
//! the complete workflow: agent request → policy check → audit log → tool execution → response.

#[cfg(feature = "wasm")]
mod preemption_tests;
mod test_audit_integrity;
mod test_cedar_policy;
mod test_full_workflow;
mod test_kernel_workflow;
#[cfg(all(feature = "memory", feature = "wasm"))]
mod test_memory_containment;
mod test_policy_enforcement;
#[cfg(feature = "reasoner")]
mod test_policy_verification;
#[cfg(all(feature = "memory", feature = "wasm"))]
mod test_python_sdk;

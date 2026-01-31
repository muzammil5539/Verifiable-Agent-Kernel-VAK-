//! External Framework Integrations
//!
//! This module provides middleware adapters for popular agent frameworks,
//! allowing VAK to be used as a verification and security layer.
//!
//! # Supported Frameworks
//!
//! - **LangChain**: Tool and chain execution hooks
//! - **AutoGPT**: Task planning and execution interception
//! - **LlamaIndex**: Query engine integration
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐     ┌──────────────────┐     ┌─────────────┐
//! │   LangChain     │────▶│   VAK Adapter    │────▶│   VAK       │
//! │   / AutoGPT     │     │   (Middleware)   │     │   Kernel    │
//! └─────────────────┘     └──────────────────┘     └─────────────┘
//!                                │
//!                                ▼
//!                        ┌──────────────────┐
//!                        │  Policy Engine   │
//!                        │  Audit Logging   │
//!                        │  PRM Scoring     │
//!                        └──────────────────┘
//! ```

pub mod langchain;
pub mod autogpt;
pub mod common;

pub use langchain::{LangChainAdapter, LangChainConfig, ToolCall, ChainExecution};
pub use autogpt::{AutoGPTAdapter, AutoGPTConfig, TaskPlan, ExecutionResult};
pub use common::{AdapterError, AdapterResult, InterceptionHook, HookDecision};

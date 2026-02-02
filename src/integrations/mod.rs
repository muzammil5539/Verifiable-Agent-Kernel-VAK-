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
//! - **MCP**: Model Context Protocol server (INT-001, INT-002)
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

pub mod autogpt;
pub mod common;
pub mod langchain;
pub mod mcp;

pub use autogpt::{AutoGPTAdapter, AutoGPTConfig, ExecutionResult, TaskPlan};
pub use common::{AdapterError, AdapterResult, HookDecision, InterceptionHook};
pub use langchain::{ChainExecution, LangChainAdapter, LangChainConfig, ToolCall};
pub use mcp::{
    ContentItem, JsonRpcError, JsonRpcRequest, JsonRpcResponse, McpConfig, McpError,
    McpResource, McpResult, McpServer, McpTool, ServerCapabilities, ServerInfo,
    ToolCallResult, ToolHandler, create_vak_mcp_server,
};

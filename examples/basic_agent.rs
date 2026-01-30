//! # Basic VAK Agent Example
//!
//! This example demonstrates the fundamental operations of the Verifiable Agent Kernel:
//! - Creating and configuring a kernel instance
//! - Creating tool requests
//! - Executing tools through the kernel
//! - Inspecting the audit log
//!
//! Run with: `cargo run --example basic_agent`

// Import from the VAK crate
// The prelude module provides convenient re-exports of common types
use vak::prelude::*;
use vak::kernel::config::KernelConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // =========================================================================
    // Step 1: Initialize Tracing (Optional but Recommended)
    // =========================================================================
    // VAK uses the `tracing` crate for structured logging.
    // This helps you observe kernel operations in real-time.
    
    tracing_subscriber::fmt()
        .with_env_filter("vak=info")
        .init();

    println!("=== VAK Basic Agent Example ===\n");

    // =========================================================================
    // Step 2: Create Kernel with Configuration
    // =========================================================================
    // The kernel is the central component that manages agents, enforces policies,
    // executes tools, and maintains audit logs.
    
    println!("Step 1: Creating kernel instance...");
    
    // Option A: Create kernel with default configuration
    let config = KernelConfig::default();
    let kernel = Kernel::new(config).await?;
    
    // Option B: Create kernel with custom configuration (alternative)
    // let config = KernelConfig::builder()
    //     .name("my-custom-kernel")
    //     .max_concurrent_agents(50)
    //     .build();
    // let kernel = Kernel::new(config).await?;
    
    println!("✓ Kernel initialized successfully\n");

    // =========================================================================
    // Step 3: Register an Agent
    // =========================================================================
    // Agents are the entities that interact with the kernel.
    // Each agent has:
    // - A unique identifier (AgentId or String)
    // - A human-readable name
    // - A list of capabilities that define what it can do
    
    println!("Step 2: Creating agent and session...");
    
    // Create a unique agent ID
    let agent_id = AgentId::new();
    
    // Create a session ID for tracking
    let session_id = SessionId::new();
    
    println!("✓ Agent ID: {}", agent_id);
    println!("✓ Session ID: {}\n", session_id);

    // =========================================================================
    // Step 4: Execute a Tool Request
    // =========================================================================
    // Tools are sandboxed functions that agents can invoke.
    // The kernel validates each tool call against policies before execution.
    
    println!("Step 3: Executing tool request...");
    
    // Create a tool request
    // This represents an agent's intention to use a specific tool
    let tool_request = ToolRequest::new(
        "calculator",
        serde_json::json!({
            "operation": "add",
            "operands": [42, 58]
        }),
    );
    
    // Execute the tool through the kernel
    // The kernel will:
    // 1. Check policies to ensure the action is allowed
    // 2. Execute the tool in a sandboxed environment
    // 3. Log the action to the audit trail
    let result = kernel.execute(&agent_id, &session_id, tool_request).await?;
    
    println!("✓ Tool executed successfully");
    println!("  Request ID: {}", result.request_id);
    println!("  Success: {}", result.success);
    if let Some(res) = &result.result {
        println!("  Output: {}\n", res);
    }

    // =========================================================================
    // Step 5: Execute Another Tool (Demonstrating Multiple Operations)
    // =========================================================================
    
    println!("Step 4: Executing another tool...");
    
    let data_tool_request = ToolRequest::new(
        "data_processor",
        serde_json::json!({
            "action": "summarize",
            "data": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        }),
    );
    
    let data_result = kernel.execute(&agent_id, &session_id, data_tool_request).await?;
    
    println!("✓ Data processing tool executed");
    if let Some(res) = &data_result.result {
        println!("  Output: {}\n", res);
    }

    // =========================================================================
    // Step 6: Inspect the Audit Log
    // =========================================================================
    // Every significant action in VAK is logged to an immutable audit trail.
    // This is crucial for security, compliance, and debugging.
    
    println!("Step 5: Checking audit logs...");
    
    // Retrieve all audit entries
    let entries = kernel.get_audit_log().await;
    
    println!("✓ Found {} audit entries:\n", entries.len());
    
    for (i, entry) in entries.iter().enumerate() {
        println!("  Entry {}:", i + 1);
        println!("    Audit ID: {}", entry.audit_id);
        println!("    Timestamp: {}", entry.timestamp);
        println!("    Agent: {}", entry.agent_id);
        println!("    Action: {}", entry.action);
        println!("    Hash: {}...", &entry.hash[..16]);
        println!();
    }

    println!("=== Example Complete ===");
    
    Ok(())
}

// =============================================================================
// Additional Examples: Error Handling
// =============================================================================

/// Demonstrates handling common error cases
#[allow(dead_code)]
async fn error_handling_examples() -> Result<(), Box<dyn std::error::Error>> {
    let config = KernelConfig::default();
    let kernel = Kernel::new(config).await?;
    
    let agent_id = AgentId::new();
    let session_id = SessionId::new();
    
    // Example: Trying to execute a tool
    let tool_request = ToolRequest::new(
        "some_tool",
        serde_json::json!({}),
    );
    
    match kernel.execute(&agent_id, &session_id, tool_request).await {
        Ok(result) => println!("Tool executed: success={}", result.success),
        Err(e) => {
            eprintln!("Error executing tool: {}", e);
        }
    }
    
    Ok(())
}

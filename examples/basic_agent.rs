//! # Basic VAK Agent Example
//!
//! This example demonstrates the fundamental operations of the Verifiable Agent Kernel:
//! - Creating and configuring a kernel instance
//! - Registering an agent with capabilities
//! - Executing tools through the kernel
//! - Inspecting the audit log
//!
//! Run with: `cargo run --example basic_agent`

// Import from the VAK crate
// The prelude module provides convenient re-exports of common types
use vak::prelude::*;
use vak::kernel::kernel::{Kernel, ToolCall, KernelError};

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
    let kernel = Kernel::new().await;
    
    // Option B: Create kernel with custom configuration (alternative)
    // let config = KernelConfig::builder()
    //     .name("my-custom-kernel")
    //     .max_concurrent_agents(50)
    //     .build();
    // let kernel = Kernel::from_config(config).await;
    
    println!("✓ Kernel initialized successfully\n");

    // =========================================================================
    // Step 3: Register an Agent
    // =========================================================================
    // Agents are the entities that interact with the kernel.
    // Each agent has:
    // - A unique identifier (AgentId or String)
    // - A human-readable name
    // - A list of capabilities that define what it can do
    
    println!("Step 2: Registering agent...");
    
    // Create a unique agent ID (can use AgentId::new() for UUID-based IDs)
    let agent_id = "data-analysis-agent-001".to_string();
    
    // Define the agent's capabilities
    // Capabilities are strings that can be checked by policies
    let capabilities = vec![
        "read".to_string(),      // Can read data
        "compute".to_string(),   // Can perform calculations
        "network".to_string(),   // Can make network requests
    ];
    
    // Register the agent with the kernel
    kernel
        .register_agent(
            agent_id.clone(),
            "DataAnalysisAgent".to_string(),
            capabilities,
        )
        .await?;
    
    println!("✓ Agent '{}' registered with capabilities: read, compute, network\n", agent_id);

    // =========================================================================
    // Step 4: Execute a Tool Request
    // =========================================================================
    // Tools are sandboxed functions that agents can invoke.
    // The kernel validates each tool call against policies before execution.
    
    println!("Step 3: Executing tool request...");
    
    // Create a tool call request
    // This represents an agent's intention to use a specific tool
    let tool_call = ToolCall {
        tool_name: "calculator".to_string(),
        parameters: serde_json::json!({
            "operation": "add",
            "operands": [42, 58]
        }),
    };
    
    // Execute the tool through the kernel
    // The kernel will:
    // 1. Verify the agent is registered
    // 2. Check policies to ensure the action is allowed
    // 3. Execute the tool in a sandboxed environment
    // 4. Log the action to the audit trail
    let result = kernel.execute_tool(agent_id.clone(), tool_call).await?;
    
    println!("✓ Tool executed successfully");
    println!("  Tool: {}", result.tool_name);
    println!("  Output: {}", result.output);
    println!("  Success: {}\n", result.success);

    // =========================================================================
    // Step 5: Execute Another Tool (Demonstrating Multiple Operations)
    // =========================================================================
    
    println!("Step 4: Executing another tool...");
    
    let data_tool_call = ToolCall {
        tool_name: "data_processor".to_string(),
        parameters: serde_json::json!({
            "action": "summarize",
            "data": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        }),
    };
    
    let data_result = kernel.execute_tool(agent_id.clone(), data_tool_call).await?;
    
    println!("✓ Data processing tool executed");
    println!("  Output: {}\n", data_result.output);

    // =========================================================================
    // Step 6: Inspect the Audit Log
    // =========================================================================
    // Every significant action in VAK is logged to an immutable audit trail.
    // This is crucial for security, compliance, and debugging.
    
    println!("Step 5: Checking audit logs...");
    
    // Get access to the audit logger
    let audit_logger = kernel.audit_logger();
    let logger = audit_logger.read().await;
    
    // Retrieve all audit entries
    let entries = logger.entries();
    
    println!("✓ Found {} audit entries:\n", entries.len());
    
    for (i, entry) in entries.iter().enumerate() {
        println!("  Entry {}:", i + 1);
        println!("    Timestamp: {}", entry.timestamp);
        println!("    Agent: {}", entry.agent_id);
        println!("    Action: {}", entry.action);
        println!("    Details: {}", entry.details);
        println!("    Success: {}", entry.success);
        println!();
    }

    // =========================================================================
    // Step 7: Graceful Shutdown
    // =========================================================================
    // Always shutdown the kernel properly to ensure all resources are released
    // and final audit entries are written.
    
    println!("Step 6: Shutting down kernel...");
    kernel.shutdown().await?;
    println!("✓ Kernel shutdown complete\n");

    println!("=== Example Complete ===");
    
    Ok(())
}

// =============================================================================
// Additional Examples: Error Handling
// =============================================================================

/// Demonstrates handling common error cases
#[allow(dead_code)]
async fn error_handling_examples() -> Result<(), Box<dyn std::error::Error>> {
    use vak::kernel::kernel::{Kernel, ToolCall};
    
    let kernel = Kernel::new().await;
    
    // Example 1: Trying to execute a tool with an unregistered agent
    let unknown_agent = "unknown-agent-999".to_string();
    let tool_call = ToolCall {
        tool_name: "some_tool".to_string(),
        parameters: serde_json::json!({}),
    };
    
    match kernel.execute_tool(unknown_agent, tool_call).await {
        Ok(_) => println!("Tool executed"),
        Err(e) => {
            // This will print: "Agent 'agent-xxx' is not registered"
            eprintln!("Expected error: {}", e);
        }
    }
    
    // Example 2: Trying to register an agent twice
    let agent_id = "duplicate-agent".to_string();
    kernel.register_agent(agent_id.clone(), "Agent1".to_string(), vec![]).await?;
    
    match kernel.register_agent(agent_id.clone(), "Agent1Duplicate".to_string(), vec![]).await {
        Ok(_) => println!("Agent registered"),
        Err(e) => {
            // This will print: "Agent 'agent-xxx' is already registered"
            eprintln!("Expected error: {}", e);
        }
    }
    
    kernel.shutdown().await?;
    Ok(())
}

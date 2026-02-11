#!/usr/bin/env python3
"""
VAK Python Quickstart Example

This example demonstrates how to use the VAK (Verifiable Agent Kernel) 
Python SDK for:
- Creating and initializing a kernel
- Registering agents with capabilities
- Executing tools
- Querying the audit trail
- Handling policy violations

Prerequisites:
    pip install vak

Run with:
    python examples/python_quickstart.py
"""

from datetime import datetime, timedelta
from typing import Any

# =============================================================================
# Import VAK SDK Components (modular imports)
# =============================================================================

# Core kernel
from vak.kernel import VakKernel

# Agent configuration
from vak.agent import AgentConfig

# Tool types
from vak.tools import ToolRequest, ToolResponse

# Audit types
from vak.audit import AuditEntry, AuditLevel

# Policy types and helpers
from vak.policy import PolicyDecision, PolicyEffect, permit, deny

# Exception types
from vak.exceptions import (
    VakError,
    PolicyViolationError,
    AgentNotFoundError,
    ToolExecutionError,
)

# Configuration (for custom kernel settings)
from vak.config import KernelConfig, SecurityConfig


def main():
    """Main entry point demonstrating VAK SDK usage."""
    
    print("=" * 60)
    print("VAK Python SDK Quickstart")
    print("=" * 60)
    print()

    # =========================================================================
    # Step 1: Create and Initialize the Kernel
    # =========================================================================
    
    print("Step 1: Initializing the VAK Kernel")
    print("-" * 40)
    
    # Option A: Create kernel with default configuration
    kernel = VakKernel.default()
    
    # Option B: Create kernel from a configuration file
    # kernel = VakKernel.from_config("config/kernel.yaml")
    
    # Option C: Create kernel and initialize manually
    # kernel = VakKernel(config_path="config/kernel.yaml")
    # kernel.initialize()
    
    print(f"✓ Kernel initialized: {kernel.is_initialized}")
    print()

    # =========================================================================
    # Step 2: Register an Agent with Capabilities
    # =========================================================================
    
    print("Step 2: Registering an Agent")
    print("-" * 40)
    
    # Create an agent configuration
    # Agents are the entities that interact with the kernel
    agent_config = AgentConfig(
        agent_id="data-processor-001",
        name="Data Processing Agent",
        description="An agent that processes and analyzes data",
        capabilities=[
            "data.read",      # Can read data
            "data.write",     # Can write data
            "compute.basic",  # Can perform basic computations
        ],
        allowed_tools=[
            "calculator",     # Access to calculator tool
            "data_processor", # Access to data processing tool
            "file_reader",    # Access to file reading tool
        ],
        memory_limit_bytes=256 * 1024 * 1024,  # 256 MB
        max_concurrent_requests=5,
        trusted=False,  # Not a trusted/privileged agent
        metadata={
            "owner": "data-team",
            "version": "1.0.0",
        },
    )
    
    # Register the agent with the kernel
    kernel.register_agent(agent_config)
    
    print(f"✓ Agent registered: {agent_config.agent_id}")
    print(f"  Name: {agent_config.name}")
    print(f"  Capabilities: {agent_config.capabilities}")
    print(f"  Allowed Tools: {agent_config.allowed_tools}")
    print()
    
    # You can add capabilities or tools using fluent methods
    updated_config = (
        agent_config
        .with_capability("network.limited")
        .with_tool_access("http_client")
    )
    print(f"✓ Extended capabilities: {updated_config.capabilities}")
    print()

    # =========================================================================
    # Step 3: Execute Tools
    # =========================================================================
    
    print("Step 3: Executing Tools")
    print("-" * 40)
    
    # Example 3a: Execute a calculator tool
    print("\n3a. Calculator Tool:")
    
    response = kernel.execute_tool(
        agent_id="data-processor-001",
        tool_id="calculator",
        action="add",
        parameters={
            "a": 42,
            "b": 58,
        },
        timeout_ms=5000,  # 5 second timeout
    )
    
    print(f"  Request ID: {response.request_id}")
    print(f"  Success: {response.success}")
    print(f"  Result: {response.result}")
    print(f"  Execution Time: {response.execution_time_ms:.2f}ms")
    
    # Example 3b: Execute using ToolRequest object
    print("\n3b. Data Processor Tool (using ToolRequest):")
    
    request = ToolRequest(
        tool_id="data_processor",
        agent_id="data-processor-001",
        action="summarize",
        parameters={
            "data": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            "metrics": ["mean", "sum", "count"],
        },
        timeout_ms=10000,
        memory_limit_bytes=64 * 1024 * 1024,  # 64 MB
    )
    
    response = kernel.execute_tool_request(request)
    
    print(f"  Success: {response.success}")
    print(f"  Result: {response.result}")
    
    # Example 3c: Using unwrap() to get result or raise exception
    print("\n3c. Using unwrap() for result extraction:")
    
    try:
        result = response.unwrap()
        print(f"  Unwrapped result: {result}")
    except RuntimeError as e:
        print(f"  Error: {e}")
    
    print()

    # =========================================================================
    # Step 4: Policy Evaluation
    # =========================================================================
    
    print("Step 4: Policy Evaluation")
    print("-" * 40)
    
    # Manually evaluate a policy decision
    decision = kernel.evaluate_policy(
        agent_id="data-processor-001",
        action="tool.execute",
        context={
            "tool_id": "calculator",
            "action": "multiply",
            "parameters": {"a": 10, "b": 20},
        },
    )
    
    print(f"  Effect: {decision.effect.value}")
    print(f"  Policy ID: {decision.policy_id}")
    print(f"  Reason: {decision.reason}")
    print(f"  Is Allowed: {decision.is_allowed()}")
    print(f"  Is Denied: {decision.is_denied()}")
    print()

    # =========================================================================
    # Step 5: Query Audit Trail
    # =========================================================================
    
    print("Step 5: Querying Audit Trail")
    print("-" * 40)
    
    # Get all audit logs for our agent
    audit_entries = kernel.get_audit_logs(
        agent_id="data-processor-001",
        limit=10,
    )
    
    print(f"  Found {len(audit_entries)} audit entries")
    
    for i, entry in enumerate(audit_entries, 1):
        print(f"\n  Entry {i}:")
        print(f"    ID: {entry.entry_id}")
        print(f"    Timestamp: {entry.timestamp}")
        print(f"    Level: {entry.level.value}")
        print(f"    Action: {entry.action}")
        print(f"    Resource: {entry.resource}")
        if entry.policy_decision:
            print(f"    Policy: {entry.policy_decision.effect.value}")
    
    # Get audit logs with time filtering
    print("\n  Filtering by time range:")
    recent_entries = kernel.get_audit_logs(
        start_time=datetime.now() - timedelta(hours=1),
        end_time=datetime.now(),
        level=AuditLevel.INFO,
        limit=5,
    )
    print(f"  Found {len(recent_entries)} entries in the last hour")
    print()

    # =========================================================================
    # Step 6: Handle Policy Violations (Error Handling)
    # =========================================================================
    
    print("Step 6: Handling Policy Violations")
    print("-" * 40)
    
    # Register a restricted agent with limited capabilities
    restricted_agent = AgentConfig(
        agent_id="restricted-agent-001",
        name="Restricted Agent",
        description="An agent with limited permissions",
        capabilities=["data.read"],  # Only read capability
        allowed_tools=["file_reader"],  # Only file reader access
    )
    kernel.register_agent(restricted_agent)
    
    # Attempt to execute a tool the agent doesn't have access to
    print("\n  Attempting unauthorized tool execution...")
    
    try:
        # This should fail because the agent doesn't have access to calculator
        kernel.execute_tool(
            agent_id="restricted-agent-001",
            tool_id="calculator",  # Not in allowed_tools!
            action="add",
            parameters={"a": 1, "b": 2},
        )
        print("  ✗ Unexpected: Tool execution succeeded")
    except PolicyViolationError as e:
        print(f"  ✓ Policy violation caught!")
        print(f"    Effect: {e.decision.effect.value}")
        print(f"    Reason: {e.decision.reason}")
    except VakError as e:
        print(f"  ✓ VAK error caught: {e}")
    
    # Attempt to use an unregistered agent
    print("\n  Attempting with unregistered agent...")
    
    try:
        kernel.execute_tool(
            agent_id="unknown-agent-999",
            tool_id="calculator",
            action="add",
            parameters={"a": 1, "b": 2},
        )
        print("  ✗ Unexpected: Tool execution succeeded")
    except AgentNotFoundError as e:
        print(f"  ✓ Agent not found error caught!")
        print(f"    Agent ID: {e.agent_id}")
    except VakError as e:
        print(f"  ✓ VAK error caught: {e}")
    
    print()

    # =========================================================================
    # Step 7: Custom Policy Hooks
    # =========================================================================
    
    print("Step 7: Custom Policy Hooks")
    print("-" * 40)
    
    # Define a custom policy hook
    def my_policy_hook(
        agent_id: str,
        action: str,
        context: dict[str, Any]
    ) -> PolicyDecision | None:
        """
        Custom policy hook that denies all actions containing 'dangerous'.

        Returns None to continue to next hook/native engine,
        or a PolicyDecision to use that decision.
        """
        # Check if the action contains 'dangerous'
        if "dangerous" in action.lower():
            return deny(
                policy_id="custom-dangerous-block",
                reason="Actions containing 'dangerous' are blocked by custom hook",
            )

        # Check tool_id in context if present
        tool_id = context.get("tool_id", "")
        if tool_id == "nuclear_launcher":
            return deny(
                policy_id="custom-nuclear-block",
                reason="Nuclear launcher tool is forbidden",
            )

        # Return None to continue evaluation
        return None
    
    # Add the custom policy hook
    kernel.add_policy_hook(my_policy_hook)
    print("  ✓ Custom policy hook added")
    
    # Test the custom hook
    decision = kernel.evaluate_policy(
        agent_id="data-processor-001",
        action="dangerous_operation",
        context={},
    )
    print(f"  Testing 'dangerous_operation': {decision.effect.value}")
    print(f"    Reason: {decision.reason}")
    
    # Remove the hook when done
    kernel.remove_policy_hook(my_policy_hook)
    print("  ✓ Custom policy hook removed")
    print()

    # =========================================================================
    # Step 8: Agent Management
    # =========================================================================
    
    print("Step 8: Agent Management")
    print("-" * 40)
    
    # List all registered agents
    agents = kernel.list_agents()
    print(f"  Registered agents: {agents}")
    
    # Get specific agent configuration
    agent = kernel.get_agent("data-processor-001")
    print(f"  Agent details: {agent.name}")
    
    # Unregister an agent
    kernel.unregister_agent("restricted-agent-001")
    print("  ✓ Unregistered: restricted-agent-001")
    
    # Updated list
    agents = kernel.list_agents()
    print(f"  Remaining agents: {agents}")
    print()

    # =========================================================================
    # Step 9: Graceful Shutdown
    # =========================================================================
    
    print("Step 9: Shutting Down")
    print("-" * 40)
    
    # Always shutdown the kernel properly
    # This flushes audit logs and releases resources
    kernel.shutdown()
    
    print("  ✓ Kernel shutdown complete")
    print(f"  Kernel initialized: {kernel.is_initialized}")
    print()
    
    print("=" * 60)
    print("Quickstart Complete!")
    print("=" * 60)


# =============================================================================
# Additional Examples
# =============================================================================

def context_manager_example():
    """
    Example using context manager for automatic cleanup.
    
    This ensures the kernel is properly shut down even if an exception occurs.
    """
    from contextlib import contextmanager
    
    @contextmanager
    def managed_kernel(config_path: str | None = None):
        """Context manager for VAK kernel lifecycle."""
        kernel = VakKernel(config_path)
        kernel.initialize()
        try:
            yield kernel
        finally:
            kernel.shutdown()
    
    # Usage:
    # with managed_kernel() as kernel:
    #     kernel.register_agent(...)
    #     kernel.execute_tool(...)
    # # Kernel is automatically shut down here


def async_example():
    """
    Example for async usage patterns.
    
    Note: The actual VAK SDK may provide async methods.
    This shows a pattern for wrapping synchronous calls.
    """
    import asyncio
    from concurrent.futures import ThreadPoolExecutor
    
    async def execute_tool_async(
        kernel: VakKernel,
        agent_id: str,
        tool_id: str,
        action: str,
        parameters: dict,
    ) -> ToolResponse:
        """Execute a tool asynchronously using a thread pool."""
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor() as executor:
            return await loop.run_in_executor(
                executor,
                lambda: kernel.execute_tool(
                    agent_id=agent_id,
                    tool_id=tool_id,
                    action=action,
                    parameters=parameters,
                ),
            )
    
    # Usage:
    # response = await execute_tool_async(kernel, "agent-1", "calc", "add", {"a": 1, "b": 2})


def batch_operations_example():
    """
    Example showing batch operations with multiple agents and tools.
    """
    kernel = VakKernel.default()
    
    # Register multiple agents
    agent_configs = [
        AgentConfig(
            agent_id=f"batch-agent-{i:03d}",
            name=f"Batch Agent {i}",
            capabilities=["compute.basic"],
            allowed_tools=["calculator"],
        )
        for i in range(5)
    ]
    
    for config in agent_configs:
        kernel.register_agent(config)
    
    # Execute tools for all agents
    results = []
    for i, config in enumerate(agent_configs):
        response = kernel.execute_tool(
            agent_id=config.agent_id,
            tool_id="calculator",
            action="add",
            parameters={"a": i, "b": i * 2},
        )
        results.append((config.agent_id, response))
    
    # Process results
    for agent_id, response in results:
        print(f"{agent_id}: {response.result}")
    
    kernel.shutdown()


if __name__ == "__main__":
    main()

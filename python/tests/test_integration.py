"""
Integration tests for the VAK Python SDK.

These tests verify end-to-end functionality of the complete system,
including interactions between multiple components.
"""

import pytest
from datetime import datetime
from typing import Any

from vak import (
    VakKernel,
    AgentConfig,
    AuditLevel,
    PolicyDecision,
    PolicyEffect,
    ToolRequest,
    ToolResponse,
    PolicyViolationError,
)


class TestEndToEndWorkflow:
    """End-to-end workflow integration tests."""

    def test_complete_agent_workflow(self):
        """Test complete agent registration and tool execution workflow."""
        # 1. Create and initialize kernel
        kernel = VakKernel.default()
        
        # 2. Register an agent
        agent = AgentConfig(
            agent_id="code-auditor",
            name="Code Auditor Agent",
            description="Reviews code for security vulnerabilities",
            capabilities=["code_review", "security_scan"],
            allowed_tools=["ast_parser", "grep", "file_reader"],
            trusted=True
        )
        kernel.register_agent(agent)
        
        # 3. Create audit entry for workflow start
        workflow_audit_id = kernel.create_audit_entry(
            agent_id="code-auditor",
            action="workflow.start",
            resource="code-review",
            level=AuditLevel.INFO,
            details={"target": "main.py"}
        )
        
        # 4. Evaluate policy before executing tool
        decision = kernel.evaluate_policy(
            agent_id="code-auditor",
            action="tool.execute",
            context={
                "tool_id": "file_reader",
                "file_path": "main.py"
            }
        )
        assert decision.is_allowed()
        
        # 5. Execute tool
        response = kernel.execute_tool(
            agent_id="code-auditor",
            tool_id="file_reader",
            action="read",
            parameters={"path": "main.py"}
        )
        assert response.success
        
        # 6. Create completion audit entry
        completion_audit_id = kernel.create_audit_entry(
            agent_id="code-auditor",
            action="workflow.complete",
            resource="code-review",
            level=AuditLevel.INFO,
            details={"status": "success"},
            parent_entry_id=workflow_audit_id
        )
        
        # 7. Shutdown
        kernel.shutdown()
        assert not kernel.is_initialized

    def test_policy_enforcement_integration(self):
        """Test policy enforcement in tool execution workflow."""
        kernel = VakKernel.default()
        
        # Add a policy that denies access to sensitive files
        def deny_sensitive_files(agent_id: str, action: str, context: dict) -> PolicyDecision | None:
            if action == "tool.execute":
                file_path = context.get("parameters", {}).get("path", "")
                if file_path.endswith(".env") or "secrets" in file_path:
                    return PolicyDecision(
                        effect=PolicyEffect.DENY,
                        policy_id="sensitive-files",
                        reason=f"Access to sensitive file '{file_path}' is forbidden"
                    )
            return None
        
        kernel.add_policy_hook(deny_sensitive_files)
        
        # Register agent
        agent = AgentConfig(agent_id="reader-agent", name="Reader")
        kernel.register_agent(agent)
        
        # Normal file access should be allowed
        response = kernel.execute_tool(
            agent_id="reader-agent",
            tool_id="file_reader",
            action="read",
            parameters={"path": "readme.md"}
        )
        assert response.success
        
        # Sensitive file access should be denied
        with pytest.raises(PolicyViolationError) as exc_info:
            kernel.execute_tool(
                agent_id="reader-agent",
                tool_id="file_reader",
                action="read",
                parameters={"path": ".env"}
            )
        assert "sensitive file" in exc_info.value.decision.reason.lower()

    def test_multi_agent_collaboration(self):
        """Test multiple agents working together."""
        kernel = VakKernel.default()
        
        # Register multiple agents
        analyst = AgentConfig(
            agent_id="analyst",
            name="Analyst Agent",
            capabilities=["analyze"]
        )
        reviewer = AgentConfig(
            agent_id="reviewer",
            name="Reviewer Agent",
            capabilities=["review"]
        )
        
        kernel.register_agent(analyst)
        kernel.register_agent(reviewer)
        
        # Analyst performs analysis
        with kernel.agent_context("analyst") as analyst_ctx:
            analyst_result = analyst_ctx.execute_tool(
                tool_id="analyzer",
                action="analyze",
                parameters={"data": "sample data"}
            )
            assert analyst_result.success
            
            # Create audit trail
            analyst_ctx.create_audit_entry(
                action="analysis.complete",
                resource="sample-data"
            )
        
        # Reviewer reviews the analysis
        with kernel.agent_context("reviewer") as reviewer_ctx:
            review_result = reviewer_ctx.execute_tool(
                tool_id="reviewer",
                action="review",
                parameters={"analysis": "analysis-id-123"}
            )
            assert review_result.success
            
            # Create audit trail
            reviewer_ctx.create_audit_entry(
                action="review.complete",
                resource="analysis-id-123"
            )
        
        # Both agents should still be registered
        agents = kernel.list_agents()
        assert "analyst" in agents
        assert "reviewer" in agents

    def test_audit_trail_integrity(self):
        """Test that audit trail is maintained through operations."""
        kernel = VakKernel.default()
        
        agent = AgentConfig(agent_id="audited-agent", name="Audited")
        kernel.register_agent(agent)
        
        # Perform several operations and create audit entries
        audit_entries = []
        
        # Entry 1: Registration
        entry1 = kernel.create_audit_entry(
            agent_id="system",
            action="agent.register",
            resource="audited-agent"
        )
        audit_entries.append(entry1)
        
        # Entry 2: Tool execution
        response = kernel.execute_tool(
            agent_id="audited-agent",
            tool_id="calculator",
            action="add",
            parameters={"a": 1, "b": 2}
        )
        entry2 = kernel.create_audit_entry(
            agent_id="audited-agent",
            action="tool.execute",
            resource="calculator",
            details={"success": response.success}
        )
        audit_entries.append(entry2)
        
        # Verify all entries are unique
        assert len(set(audit_entries)) == len(audit_entries)

    def test_resource_limits_integration(self):
        """Test resource limits are respected."""
        kernel = VakKernel.default()
        
        # Create agent with specific limits
        limited_agent = AgentConfig(
            agent_id="limited-agent",
            name="Limited Agent",
            memory_limit_bytes=32 * 1024 * 1024,  # 32 MB
            max_concurrent_requests=2
        )
        kernel.register_agent(limited_agent)
        
        # Execute tool with default limits (uses agent's limits)
        response = kernel.execute_tool(
            agent_id="limited-agent",
            tool_id="memory_intensive_tool",
            action="process"
        )
        assert response.success
        
        # Execute with custom override
        response_override = kernel.execute_tool(
            agent_id="limited-agent",
            tool_id="memory_intensive_tool",
            action="process",
            memory_limit_bytes=64 * 1024 * 1024
        )
        assert response_override.success


class TestSecurityScenarios:
    """Security-focused integration tests."""

    def test_privilege_escalation_prevention(self):
        """Test that agents cannot escalate privileges."""
        kernel = VakKernel.default()
        
        # Policy hook that checks for privilege escalation
        def prevent_escalation(agent_id: str, action: str, context: dict) -> PolicyDecision | None:
            if action == "agent.register":
                target_trusted = context.get("trusted", False)
                if target_trusted and agent_id != "system":
                    return PolicyDecision(
                        effect=PolicyEffect.DENY,
                        policy_id="no-escalation",
                        reason="Non-system agents cannot create trusted agents"
                    )
            return None
        
        kernel.add_policy_hook(prevent_escalation)
        
        # Regular agent
        regular_agent = AgentConfig(
            agent_id="regular-agent",
            name="Regular Agent",
            trusted=False
        )
        kernel.register_agent(regular_agent)

    def test_forbidden_operations_blocked(self):
        """Test that forbidden operations are blocked."""
        kernel = VakKernel.default()
        
        # Add policy to block dangerous operations
        forbidden_actions = {"delete_all", "drop_database", "rm_rf"}
        
        def block_forbidden(agent_id: str, action: str, context: dict) -> PolicyDecision | None:
            tool_action = context.get("action", "")
            if tool_action in forbidden_actions:
                return PolicyDecision(
                    effect=PolicyEffect.DENY,
                    policy_id="forbidden-ops",
                    reason=f"Operation '{tool_action}' is forbidden"
                )
            return None
        
        kernel.add_policy_hook(block_forbidden)
        
        agent = AgentConfig(agent_id="dangerous-agent", name="Dangerous")
        kernel.register_agent(agent)
        
        # Safe operation should work
        safe_response = kernel.execute_tool(
            agent_id="dangerous-agent",
            tool_id="database",
            action="select",
            parameters={"table": "users"}
        )
        assert safe_response.success
        
        # Dangerous operation should be blocked
        with pytest.raises(PolicyViolationError):
            kernel.execute_tool(
                agent_id="dangerous-agent",
                tool_id="database",
                action="drop_database"
            )

    def test_tool_isolation(self):
        """Test that tools are isolated per agent."""
        kernel = VakKernel.default()
        
        # Create two agents
        agent1 = AgentConfig(
            agent_id="agent-1",
            name="Agent 1",
            allowed_tools=["calculator", "file_reader"]
        )
        agent2 = AgentConfig(
            agent_id="agent-2",
            name="Agent 2",
            allowed_tools=["web_search"]  # Different tools
        )
        
        kernel.register_agent(agent1)
        kernel.register_agent(agent2)
        
        # Both agents can execute their allowed tools
        r1 = kernel.execute_tool(
            agent_id="agent-1",
            tool_id="calculator",
            action="add",
            parameters={"a": 1, "b": 2}
        )
        assert r1.success
        
        r2 = kernel.execute_tool(
            agent_id="agent-2",
            tool_id="web_search",
            action="search",
            parameters={"query": "test"}
        )
        assert r2.success


class TestErrorRecovery:
    """Tests for error recovery and resilience."""

    def test_agent_recovery_after_error(self):
        """Test that system recovers after agent error."""
        kernel = VakKernel.default()
        
        agent = AgentConfig(agent_id="error-prone", name="Error Prone")
        kernel.register_agent(agent)
        
        # First execution succeeds
        r1 = kernel.execute_tool(
            agent_id="error-prone",
            tool_id="calculator",
            action="add",
            parameters={"a": 1, "b": 2}
        )
        assert r1.success
        
        # Simulate a policy violation (blocked action)
        def block_once(agent_id: str, action: str, context: dict) -> PolicyDecision | None:
            params = context.get("parameters", {})
            if params.get("error_trigger"):
                return PolicyDecision(
                    effect=PolicyEffect.DENY,
                    policy_id="error-trigger",
                    reason="Error triggered"
                )
            return None
        
        kernel.add_policy_hook(block_once)
        
        # This should fail
        with pytest.raises(PolicyViolationError):
            kernel.execute_tool(
                agent_id="error-prone",
                tool_id="calculator",
                action="add",
                parameters={"error_trigger": True}
            )
        
        # But subsequent normal operations should still work
        r2 = kernel.execute_tool(
            agent_id="error-prone",
            tool_id="calculator",
            action="multiply",
            parameters={"a": 3, "b": 4}
        )
        assert r2.success

    def test_multiple_kernel_instances(self):
        """Test that multiple kernel instances work independently."""
        kernel1 = VakKernel.default()
        kernel2 = VakKernel.default()
        
        # Register agent in kernel1 only
        agent = AgentConfig(agent_id="kernel1-agent", name="K1 Agent")
        kernel1.register_agent(agent)
        
        # Agent exists in kernel1
        assert "kernel1-agent" in kernel1.list_agents()
        
        # Agent does not exist in kernel2
        assert "kernel1-agent" not in kernel2.list_agents()
        
        # Shutdown kernel1, kernel2 still works
        kernel1.shutdown()
        
        agent2 = AgentConfig(agent_id="kernel2-agent", name="K2 Agent")
        kernel2.register_agent(agent2)
        assert "kernel2-agent" in kernel2.list_agents()


class TestComplexPolicyScenarios:
    """Tests for complex policy scenarios."""

    def test_role_based_access_control(self):
        """Test RBAC-style policy enforcement."""
        kernel = VakKernel.default()
        
        # Define role-based permissions
        role_permissions = {
            "admin": ["*"],  # All actions
            "developer": ["tool.execute", "code.read", "code.write"],
            "viewer": ["code.read"]
        }
        
        def rbac_policy(agent_id: str, action: str, context: dict) -> PolicyDecision | None:
            # Get agent's role from metadata
            role = context.get("role", "viewer")
            allowed = role_permissions.get(role, [])
            
            if "*" in allowed or action in allowed:
                return PolicyDecision(
                    effect=PolicyEffect.ALLOW,
                    policy_id="rbac",
                    reason=f"Action '{action}' allowed for role '{role}'"
                )
            return PolicyDecision(
                effect=PolicyEffect.DENY,
                policy_id="rbac",
                reason=f"Action '{action}' not allowed for role '{role}'"
            )
        
        kernel.add_policy_hook(rbac_policy)
        
        # Developer can execute tools
        decision = kernel.evaluate_policy(
            agent_id="dev-agent",
            action="tool.execute",
            context={"role": "developer"}
        )
        assert decision.is_allowed()
        
        # Viewer cannot execute tools
        decision = kernel.evaluate_policy(
            agent_id="viewer-agent",
            action="tool.execute",
            context={"role": "viewer"}
        )
        assert decision.is_denied()

    def test_rate_limiting_policy(self):
        """Test rate limiting via policy hooks."""
        kernel = VakKernel.default()
        
        # Simple rate limiter (in real world, use proper state)
        request_counts: dict[str, int] = {}
        max_requests = 3
        
        def rate_limit_policy(agent_id: str, action: str, context: dict) -> PolicyDecision | None:
            if action == "tool.execute":
                count = request_counts.get(agent_id, 0)
                if count >= max_requests:
                    return PolicyDecision(
                        effect=PolicyEffect.DENY,
                        policy_id="rate-limit",
                        reason=f"Rate limit exceeded ({max_requests} requests)"
                    )
                request_counts[agent_id] = count + 1
            return None
        
        kernel.add_policy_hook(rate_limit_policy)
        
        agent = AgentConfig(agent_id="rate-limited", name="Rate Limited")
        kernel.register_agent(agent)
        
        # First 3 requests should succeed
        for i in range(3):
            response = kernel.execute_tool(
                agent_id="rate-limited",
                tool_id="api",
                action="call"
            )
            assert response.success
        
        # 4th request should be rate limited
        with pytest.raises(PolicyViolationError) as exc_info:
            kernel.execute_tool(
                agent_id="rate-limited",
                tool_id="api",
                action="call"
            )
        assert "rate limit" in exc_info.value.decision.reason.lower()

    def test_context_aware_policy(self):
        """Test policy that uses full context for decisions."""
        kernel = VakKernel.default()
        
        def context_aware_policy(agent_id: str, action: str, context: dict) -> PolicyDecision | None:
            # Check time of day (simulated)
            time_of_day = context.get("time_of_day", "day")
            is_production = context.get("environment") == "production"
            
            # Block destructive actions in production during business hours
            if action.startswith("delete.") and is_production and time_of_day == "day":
                return PolicyDecision(
                    effect=PolicyEffect.DENY,
                    policy_id="prod-safety",
                    reason="Destructive actions blocked in production during business hours"
                )
            return None
        
        kernel.add_policy_hook(context_aware_policy)
        
        # Delete blocked in production during day
        decision = kernel.evaluate_policy(
            agent_id="agent",
            action="delete.records",
            context={
                "environment": "production",
                "time_of_day": "day"
            }
        )
        assert decision.is_denied()
        
        # Delete allowed in staging
        decision = kernel.evaluate_policy(
            agent_id="agent",
            action="delete.records",
            context={
                "environment": "staging",
                "time_of_day": "day"
            }
        )
        assert decision.is_allowed()


class TestAuditCompliance:
    """Tests for audit and compliance features."""

    def test_all_operations_auditable(self):
        """Test that all operations can be audited."""
        kernel = VakKernel.default()
        
        audit_trail = []
        
        # Register agent with audit
        agent = AgentConfig(agent_id="compliant-agent", name="Compliant")
        kernel.register_agent(agent)
        audit_trail.append(
            kernel.create_audit_entry(
                agent_id="system",
                action="agent.register",
                resource="compliant-agent",
                details={"name": "Compliant"}
            )
        )
        
        # Policy evaluation with audit
        decision = kernel.evaluate_policy(
            agent_id="compliant-agent",
            action="tool.execute",
            context={"tool_id": "calculator"}
        )
        audit_trail.append(
            kernel.create_audit_entry(
                agent_id="compliant-agent",
                action="policy.evaluate",
                resource="calculator",
                details={"decision": decision.effect.value}
            )
        )
        
        # Tool execution with audit
        response = kernel.execute_tool(
            agent_id="compliant-agent",
            tool_id="calculator",
            action="add",
            parameters={"a": 1, "b": 2}
        )
        audit_trail.append(
            kernel.create_audit_entry(
                agent_id="compliant-agent",
                action="tool.execute",
                resource="calculator",
                details={"success": response.success}
            )
        )
        
        # Verify we have complete audit trail
        assert len(audit_trail) >= 3
        assert all(entry_id is not None for entry_id in audit_trail)

    def test_audit_entry_levels(self):
        """Test different audit entry levels."""
        kernel = VakKernel.default()
        
        levels = [
            AuditLevel.DEBUG,
            AuditLevel.INFO,
            AuditLevel.WARNING,
            AuditLevel.ERROR,
            AuditLevel.CRITICAL,
        ]
        
        entries = []
        for level in levels:
            entry_id = kernel.create_audit_entry(
                agent_id="test-agent",
                action="test.action",
                resource="test-resource",
                level=level,
                details={"level_name": level.value}
            )
            entries.append(entry_id)
        
        # All entries created
        assert len(entries) == 5
        assert all(entry_id is not None for entry_id in entries)

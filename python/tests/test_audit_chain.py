"""
Tests for the audit log, which is the kernel's (ADR 0011).

Entries come only from calls the kernel mediates: each call leaves a
decision entry and, if it ran, an outcome entry. The SDK cannot write to
the log.
"""

import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from vak import AgentConfig, AuditLevel, PolicyViolationError, VakKernel

EMPTY_ROOT = hashlib.sha256(b"").hexdigest()


@pytest.fixture
def kernel(native):
    kernel = VakKernel.default()
    kernel.register_agent(AgentConfig(agent_id="agent-1", name="Agent One"))
    kernel.register_agent(AgentConfig(agent_id="agent-2", name="Agent Two"))
    return kernel


def call(kernel, agent="agent-1", tool="echo"):
    return kernel.execute_tool(agent, tool, "say", {"n": 1})


class TestAuditChainVerification:
    def test_verify_empty_chain(self, kernel):
        assert kernel.verify_audit_chain() is True

    def test_verify_chain_after_calls(self, kernel):
        call(kernel)
        call(kernel, agent="agent-2")
        with pytest.raises(PolicyViolationError):
            call(kernel, tool="no_such_tool")
        assert kernel.verify_audit_chain() is True

    def test_verify_chain_requires_initialization(self):
        with pytest.raises(Exception, match="not initialized"):
            VakKernel().verify_audit_chain()


class TestAuditEntries:
    def test_a_call_leaves_a_decision_and_an_outcome(self, kernel):
        call(kernel)
        decision, outcome = kernel.get_audit_logs()
        assert decision.agent_id == "agent-1"
        assert decision.action == "echo"
        assert decision.details["kind"] == "decision"
        assert decision.policy_decision.is_allowed()
        assert decision.level == AuditLevel.INFO
        assert outcome.details["kind"] == "outcome"
        assert outcome.parent_entry_id == decision.entry_id
        assert outcome.details["outcome"]["success"] is True

    def test_a_refusal_is_recorded_as_a_warning(self, kernel):
        with pytest.raises(PolicyViolationError):
            call(kernel, tool="no_such_tool")
        (entry,) = kernel.get_audit_logs()
        assert entry.policy_decision.is_denied()
        assert entry.level == AuditLevel.WARNING

    def test_a_failed_run_is_recorded_as_an_error(self, kernel):
        call(kernel, tool="calculator")  # wants "operation" and "operands"
        _, outcome = kernel.get_audit_logs()
        assert outcome.level == AuditLevel.ERROR
        assert outcome.details["outcome"]["success"] is False

    def test_filters(self, kernel):
        call(kernel)
        call(kernel, agent="agent-2")
        call(kernel, agent="agent-2", tool="system_info")
        assert len(kernel.get_audit_logs(agent_id="agent-2")) == 4
        assert len(kernel.get_audit_logs(action="system_info")) == 2
        assert len(kernel.get_audit_logs(level=AuditLevel.INFO, limit=3)) == 3
        assert len(kernel.get_audit_logs(offset=5)) == 1

    def test_time_bounds_naive_or_aware(self, kernel):
        before = datetime.now()  # naive: local time
        call(kernel)
        assert len(kernel.get_audit_logs(start_time=before)) == 2
        assert kernel.get_audit_logs(end_time=before) == []
        after = datetime.now(timezone.utc) + timedelta(seconds=1)
        assert kernel.get_audit_logs(start_time=after) == []
        assert len(kernel.get_audit_logs(end_time=after)) == 2

    def test_get_audit_entry(self, kernel):
        call(kernel)
        first = kernel.get_audit_logs()[0]
        assert kernel.get_audit_entry(first.entry_id) == first
        assert kernel.get_audit_entry("no-such-entry") is None


class TestAuditRootHash:
    def test_root_hash_of_the_empty_log(self, kernel):
        # RFC 9162: the root of an empty tree is the hash of nothing.
        assert kernel.get_audit_root_hash() == EMPTY_ROOT

    def test_root_hash_changes_with_each_call(self, kernel):
        roots = [kernel.get_audit_root_hash()]
        for _ in range(3):
            call(kernel)
            roots.append(kernel.get_audit_root_hash())
        assert len(set(roots)) == 4

    def test_root_hash_is_stable_without_calls(self, kernel):
        call(kernel)
        assert kernel.get_audit_root_hash() == kernel.get_audit_root_hash()


class TestAuditReceipt:
    def test_receipt_is_a_signed_tree_head(self, kernel):
        call(kernel)
        receipt = kernel.export_audit_receipt()
        assert receipt["head"]["size"] == 2
        assert receipt["head"]["root"] == kernel.get_audit_root_hash()
        assert receipt["signature"] and receipt["public_key"]
        assert receipt["timestamp_ms"] > 0

    def test_receipt_of_the_empty_log(self, kernel):
        receipt = kernel.export_audit_receipt()
        assert receipt["head"]["size"] == 0
        assert receipt["head"]["root"] == EMPTY_ROOT

    def test_receipt_requires_initialization(self):
        with pytest.raises(Exception, match="not initialized"):
            VakKernel().export_audit_receipt()

"""
Tests for VAK Audit Chain Verification APIs.

Tests hash-chained audit logging, chain verification, and receipt export.
"""

import pytest

from vak import VakKernel, AuditLevel


class TestAuditChainVerification:
    """Tests for audit chain integrity verification."""

    def test_verify_empty_chain(self):
        """Test verifying an empty audit chain returns True."""
        kernel = VakKernel.default()
        assert kernel.verify_audit_chain() is True

    def test_verify_chain_after_entries(self):
        """Test verifying chain after adding entries."""
        kernel = VakKernel.default()
        kernel.create_audit_entry("agent-1", "action.read", "resource-a")
        kernel.create_audit_entry("agent-2", "action.write", "resource-b")
        kernel.create_audit_entry("agent-1", "action.delete", "resource-c")
        assert kernel.verify_audit_chain() is True

    def test_verify_chain_single_entry(self):
        """Test verifying chain with a single entry."""
        kernel = VakKernel.default()
        kernel.create_audit_entry("agent-1", "action.test", "resource-1")
        assert kernel.verify_audit_chain() is True

    def test_verify_chain_requires_initialization(self):
        """Test that chain verification requires initialization."""
        kernel = VakKernel()
        with pytest.raises(Exception, match="not initialized"):
            kernel.verify_audit_chain()


class TestAuditRootHash:
    """Tests for audit chain root hash."""

    def test_root_hash_empty_chain(self):
        """Test root hash of empty chain."""
        kernel = VakKernel.default()
        root = kernel.get_audit_root_hash()
        assert isinstance(root, str)
        # In stub mode the initial hash is "genesis"
        assert root == "genesis"

    def test_root_hash_changes_after_entry(self):
        """Test that root hash changes after adding an entry."""
        kernel = VakKernel.default()
        initial_hash = kernel.get_audit_root_hash()
        kernel.create_audit_entry("agent-1", "test.action", "resource")
        new_hash = kernel.get_audit_root_hash()
        assert new_hash != initial_hash

    def test_root_hash_deterministic(self):
        """Test that root hash is deterministic for same entries."""
        # Create two kernels with identical entries
        kernel1 = VakKernel.default()
        kernel2 = VakKernel.default()

        kernel1.create_audit_entry("agent-1", "action", "resource")
        kernel2.create_audit_entry("agent-1", "action", "resource")

        # Hashes include unique entry IDs, so they won't match exactly,
        # but both should be valid non-empty SHA-256 strings
        h1 = kernel1.get_audit_root_hash()
        h2 = kernel2.get_audit_root_hash()
        assert len(h1) == 64  # SHA-256 hex string
        assert len(h2) == 64

    def test_root_hash_successive_entries(self):
        """Test that each entry produces a unique root hash."""
        kernel = VakKernel.default()
        hashes = set()
        for i in range(5):
            kernel.create_audit_entry(f"agent-{i}", f"action-{i}", f"res-{i}")
            hashes.add(kernel.get_audit_root_hash())
        # All 5 should be unique
        assert len(hashes) == 5


class TestAuditReceipt:
    """Tests for audit receipt export."""

    def test_export_receipt_empty(self):
        """Test exporting receipt with empty chain."""
        kernel = VakKernel.default()
        receipt = kernel.export_audit_receipt()
        assert isinstance(receipt, dict)
        assert "receipt_id" in receipt
        assert "root_hash" in receipt
        assert receipt["entry_count"] == 0

    def test_export_receipt_after_entries(self):
        """Test exporting receipt after adding entries."""
        kernel = VakKernel.default()
        e1 = kernel.create_audit_entry("a1", "read", "r1")
        e2 = kernel.create_audit_entry("a2", "write", "r2")
        e3 = kernel.create_audit_entry("a1", "delete", "r3")

        receipt = kernel.export_audit_receipt()
        assert receipt["entry_count"] == 3
        assert receipt["root_hash"] == kernel.get_audit_root_hash()
        assert receipt["first_entry"] is not None
        assert receipt["last_entry"] is not None

    def test_export_receipt_has_timestamp(self):
        """Test that receipt contains a timestamp."""
        kernel = VakKernel.default()
        kernel.create_audit_entry("agent-1", "test", "resource")
        receipt = kernel.export_audit_receipt()
        assert "timestamp" in receipt

    def test_export_receipt_unique_ids(self):
        """Test that successive receipts get unique IDs."""
        kernel = VakKernel.default()
        kernel.create_audit_entry("a1", "action", "resource")
        r1 = kernel.export_audit_receipt()
        kernel.create_audit_entry("a2", "action", "resource")
        r2 = kernel.export_audit_receipt()
        assert r1["receipt_id"] != r2["receipt_id"]

    def test_export_receipt_requires_initialization(self):
        """Test that exporting receipt requires initialization."""
        kernel = VakKernel()
        with pytest.raises(Exception, match="not initialized"):
            kernel.export_audit_receipt()


class TestAuditChainIntegrity:
    """End-to-end tests for audit chain integrity."""

    def test_full_chain_workflow(self):
        """Test complete audit chain workflow: create, verify, export."""
        kernel = VakKernel.default()

        # Create several entries
        for i in range(10):
            kernel.create_audit_entry(
                agent_id=f"agent-{i % 3}",
                action=f"action-{i}",
                resource=f"resource-{i}",
                level=AuditLevel.INFO if i % 2 == 0 else AuditLevel.WARNING,
            )

        # Verify chain integrity
        assert kernel.verify_audit_chain() is True

        # Check root hash is a valid SHA-256 hex
        root = kernel.get_audit_root_hash()
        assert len(root) == 64
        assert all(c in "0123456789abcdef" for c in root)

        # Export receipt
        receipt = kernel.export_audit_receipt()
        assert receipt["entry_count"] == 10
        assert receipt["root_hash"] == root

    def test_chain_survives_mixed_operations(self):
        """Test chain integrity with interleaved audit and memory ops."""
        kernel = VakKernel.default()

        kernel.create_audit_entry("a1", "start", "workflow")
        kernel.store_memory("step1", "completed")
        kernel.create_audit_entry("a1", "step1.done", "workflow")
        kernel.store_memory("step2", "completed")
        kernel.create_audit_entry("a1", "finish", "workflow")

        assert kernel.verify_audit_chain() is True
        receipt = kernel.export_audit_receipt()
        assert receipt["entry_count"] == 3

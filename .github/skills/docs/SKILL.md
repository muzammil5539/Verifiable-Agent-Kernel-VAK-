---
name: docs
description: Instructions for managing documentation for the VAK project.
---

# Documentation

This skill provides instructions for generating and maintaining documentation.

## Documentation Status

| ID | Feature | Status | Notes |
|----|---------|--------|-------|
| DOC-001 | Architecture Documentation | ⏳ Pending | README.md has overview |
| DOC-002 | API Reference | ⏳ Pending | Rustdoc available |
| DOC-003 | Runbook/Operations Guide | ⏳ Pending | - |
| DOC-004 | Policy Authoring Guide | ⏳ Pending | - |

## Key Documentation Files

| File | Description |
|------|-------------|
| `README.md` | Project overview, architecture, quick start |
| `TODO.md` | Comprehensive task list with status |
| `AGENTS_README.md` | Agent development guide |
| `AI Kernel Gap Analysis & Roadmap.md` | Technical roadmap |
| `AI Agent Blue Ocean Opportunity.md` | Business/market analysis |
| `Project Feasibility.md` | Feasibility assessment |

## Prerequisites

- `rustdoc` (part of Rust toolchain)
- `mdbook` (optional, for book-style docs): `cargo install mdbook`

## Instructions

### Generate Rust API Docs

To generate documentation for the main crate:

```bash
cargo doc --no-deps --open
```

To generate documentation for all workspace members:

```bash
cargo doc --workspace --no-deps --open
```

### Check Doc Tests

To ensure code examples in documentation are valid:

```bash
cargo test --doc
```

### Update Key Documents

When changing functionality, update:
- `README.md` - Main project documentation
- `TODO.md` - Update task status
- Module-level `mod.rs` files - Update module documentation
- `.github/skills/` - Update relevant skill files

### Generate Coverage Report

To see which items are documented:

```bash
cargo doc --document-private-items 2>&1 | grep -i "missing"
```

## Documentation Structure

### Module Documentation

Each module in `src/` should have documentation in its `mod.rs`:

```rust
//! # Memory Module
//!
//! This module implements the Cryptographic Memory Fabric (CMF) for VAK.
//!
//! ## Overview
//!
//! The memory system provides:
//! - **Working Memory**: Hot cache for current context
//! - **Episodic Memory**: Time-ordered Merkle chain
//! - **Semantic Memory**: Knowledge graph + vector store
//!
//! ## Completed Features
//!
//! | ID | Feature | Status |
//! |----|---------|--------|
//! | MEM-001 | rs_merkle Integration | ✅ |
//! | MEM-002 | Sparse Merkle Tree | ✅ |
//!
//! ## Usage
//!
//! \`\`\`rust,ignore
//! use vak::memory::MerkleStore;
//! let store = MerkleStore::new();
//! \`\`\`
```

### Function Documentation

Use triple slashes (`///`) for documentation comments:

```rust
/// Calculates the sum of two numbers.
///
/// # Arguments
///
/// * `a` - First number
/// * `b` - Second number
///
/// # Returns
///
/// The sum of `a` and `b`.
///
/// # Examples
///
/// \`\`\`
/// use vak::add;
/// let result = add(2, 3);
/// assert_eq!(result, 5);
/// \`\`\`
///
/// # Errors
///
/// Returns `Err` if the sum would overflow.
pub fn add(a: i32, b: i32) -> Result<i32, OverflowError> {
    a.checked_add(b).ok_or(OverflowError)
}
```

### Unsafe Code Documentation

```rust
/// Reads a value from raw memory.
///
/// # Safety
///
/// - `ptr` must be valid for reads of `size` bytes.
/// - `ptr` must be properly aligned.
/// - The memory at `ptr` must be initialized.
/// - The caller must ensure no data races.
///
/// # Panics
///
/// Panics if `size` is zero.
pub unsafe fn read_raw(ptr: *const u8, size: usize) -> Vec<u8> {
    // SAFETY: Caller guarantees ptr validity
    // ...
}
```

## Examples

### Generating Docs with All Features

```bash
cargo doc --all-features --no-deps --open
```

### Documenting Error Types

```rust
/// Errors that can occur during policy evaluation.
///
/// # Variants
///
/// * `NotFound` - The requested policy does not exist
/// * `Denied` - Access denied by policy
/// * `InvalidContext` - Context attributes are invalid
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// The requested policy does not exist.
    #[error("policy not found: {0}")]
    NotFound(String),
    
    /// Access denied by policy.
    #[error("access denied: {reason}")]
    Denied { reason: String },
    
    /// Context attributes are invalid.
    #[error("invalid context: {0}")]
    InvalidContext(String),
}
```

### Building mdBook Documentation

If using mdBook for extended documentation:

```bash
mdbook build docs/
mdbook serve docs/
```

## Guidelines

-   **Public Items**: All `pub` structs, enums, functions, and modules MUST have documentation.
-   **Examples**: Include usage examples in documentation where possible.
-   **Errors**: Document error conditions in a `# Errors` section.
-   **Panics**: Document any potential panics in a `# Panics` section.
-   **Safety**: Document safety contracts for `unsafe` code in a `# Safety` section.
-   **Feature Flags**: Document conditional compilation with `cfg` attributes.
-   **Links**: Use intra-doc links for cross-references.
-   **Keep Updated**: Update docs when code changes, especially TODO.md status.

## TODO: Documentation Needs

- [ ] DOC-001: Create comprehensive architecture diagrams
- [ ] DOC-002: Generate and publish API documentation to docs.rs
- [ ] DOC-003: Create operations runbook with deployment procedures
- [ ] DOC-004: Create Cedar policy authoring guide with best practices

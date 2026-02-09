---
name: manage-docs
description: Instructions for managing documentation for the VAK project.
---

# Documentation

This skill provides instructions for generating and maintaining documentation.

## Prerequisites

- `rustdoc` (part of Rust toolchain)
- `mdbook` (optional, for book-style docs)

## Instructions

### Generate Rust API Docs

To generate documentation for Rust crates:

```bash
cargo doc --no-deps --open
```

### Check Doc Tests

To ensure code examples in documentation are valid:

```bash
cargo test --doc
```

### Update README

When changing functionality, update the root `README.md` and any relevant module `README.md`.

### Update Architecture Diagrams

If the architecture changes, update the diagrams in `docs/architecture/` (if present) or `README.md`.

## Examples

### Generating Docs for All Crates

```bash
cargo doc --workspace --no-deps
```

### Documenting a Function

Use triple slashes (`///`) for documentation comments.

```rust
/// Calculates the sum of two numbers.
///
/// # Examples
///
/// ```
/// let result = add(2, 3);
/// assert_eq!(result, 5);
/// ```
pub fn add(a: i32, b: i32) -> i32 {
    a + b
}
```

## Guidelines

-   **Public Items**: All `pub` structs, enums, functions, and modules MUST have documentation.
-   **Examples**: Include usage examples in documentation where possible.
-   **Panics**: Document any potential panics in a `# Panics` section.
-   **Safety**: Document safety contracts for `unsafe` code in a `# Safety` section.

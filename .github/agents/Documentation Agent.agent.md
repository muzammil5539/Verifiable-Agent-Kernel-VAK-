# Documentation Agent

## Project Overview

**Verifiable Agent Kernel (VAK)** requires comprehensive documentation for developers and operators. This agent manages README files, API documentation, guides, and architecture diagrams.

## Task Description

Manage VAK documentation including:
- README and getting started guides
- API reference documentation
- Architecture documentation
- Operations runbooks
- Policy authoring guides

## Available Commands

```bash
# Generate Rust docs
cargo doc --no-deps --open

# Check documentation
cargo doc --no-deps 2>&1 | grep -i warning

# Serve docs locally
python -m http.server 8000 --directory target/doc

# Check links
cargo install cargo-deadlinks
cargo deadlinks
```

## Files This Agent Can Modify

### Core Documentation
- `README.md` - Main readme
- `CONTRIBUTING.md` - Contribution guide
- `CHANGELOG.md` - Version history
- `AGENTS_README.md` - Agent system docs
- `TODO.md` - Implementation tracking

### Guides
- `docs/getting-started.md`
- `docs/architecture.md`
- `docs/policy-authoring.md`
- `docs/operations-runbook.md`
- `docs/security.md`

### API Documentation
- `src/**/*.rs` - Rustdoc comments

### Examples
- `examples/*.rs` - Code examples
- `examples/*.md` - Example documentation

## Documentation Standards

### Module Documentation
```rust
//! # Module Name
//!
//! Brief description of what this module provides.
//!
//! ## Overview
//!
//! More detailed explanation of the module's purpose and how it fits
//! into the larger system.
//!
//! ## Examples
//!
//! ```rust
//! use vak::module::Type;
//!
//! let instance = Type::new();
//! instance.do_something();
//! ```
//!
//! ## Architecture
//!
//! Explanation of key design decisions and patterns used.
//!
//! ## See Also
//!
//! - [`RelatedModule`] - For related functionality
//! - [Guide](../docs/guide.md) - For detailed usage guide
```

### Function Documentation
```rust
/// Brief one-line description.
///
/// More detailed explanation of what this function does, when to use it,
/// and any important considerations.
///
/// # Arguments
///
/// * `param1` - Description of first parameter
/// * `param2` - Description of second parameter
///
/// # Returns
///
/// Description of what is returned on success.
///
/// # Errors
///
/// * [`ErrorType::Variant1`] - When this condition occurs
/// * [`ErrorType::Variant2`] - When that condition occurs
///
/// # Panics
///
/// Describe any panic conditions (or state "This function does not panic").
///
/// # Examples
///
/// ```rust
/// use vak::module::function;
///
/// let result = function(arg1, arg2)?;
/// assert!(result.is_valid());
/// ```
///
/// # Safety
///
/// (Only for unsafe functions) Explain invariants that must be upheld.
pub fn function(param1: Type1, param2: Type2) -> Result<Output, Error> {
    // ...
}
```

### README Structure
```markdown
# Project Name

Brief description (one paragraph).

## Features

- Feature 1
- Feature 2

## Quick Start

\`\`\`bash
# Installation
cargo install vak

# Basic usage
vak run agent.yaml
\`\`\`

## Documentation

- [Getting Started](docs/getting-started.md)
- [API Reference](https://docs.rs/vak)
- [Architecture](docs/architecture.md)

## Examples

See the [examples/](examples/) directory.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT OR Apache-2.0
```

### Architecture Documentation
```markdown
# VAK Architecture

## Overview

High-level description of the system.

## Components

### Component 1

Description and responsibilities.

\`\`\`
┌─────────────┐
│ Component 1 │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ Component 2 │
└─────────────┘
\`\`\`

### Data Flow

1. Step 1
2. Step 2
3. Step 3

## Design Decisions

### Decision 1

**Context:** What problem were we solving?

**Decision:** What did we decide?

**Consequences:** What are the tradeoffs?
```

## Guardrails

### DO
- Keep documentation up to date with code
- Include working code examples
- Use consistent terminology
- Provide context for decisions
- Link to related resources
- Include diagrams for complex concepts

### DON'T
- Document implementation details that may change
- Use jargon without explanation
- Leave broken links
- Skip error documentation
- Assume reader knowledge
- Copy-paste outdated examples

### Quality Checks
- All public items have documentation
- All examples compile and run
- No broken links
- Consistent formatting
- Spell-checked

## Documentation Templates

### Guide Template
```markdown
# Guide Title

## Prerequisites

- Prerequisite 1
- Prerequisite 2

## Overview

What this guide covers and who it's for.

## Steps

### Step 1: Description

Explanation.

\`\`\`bash
command
\`\`\`

### Step 2: Description

Explanation.

## Troubleshooting

### Common Issue 1

**Symptom:** What the user sees
**Cause:** Why it happens
**Solution:** How to fix it

## Next Steps

- Link to next guide
- Link to related topics
```

### API Reference Template
```markdown
# API Reference: ModuleName

## Overview

Brief description.

## Types

### `TypeName`

Description.

| Field | Type | Description |
|-------|------|-------------|
| field1 | Type | Description |

## Functions

### `function_name`

Description.

**Signature:**
\`\`\`rust
fn function_name(param: Type) -> Result<Output, Error>
\`\`\`

**Parameters:**
- `param` - Description

**Returns:** Description

**Errors:** When it can fail
```

## Related Agents
- [Rust Code Generator Agent](Rust%20Code%20Generator%20Agent.agent.md)
- [CI/CD Agent](CI-CD%20Agent.agent.md)
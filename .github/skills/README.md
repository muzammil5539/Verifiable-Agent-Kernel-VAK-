# Skills

This directory contains skills for the Verifiable Agent Kernel (VAK) project.

## Agent Skills (for Claude/AI)

These skills are designed to help AI agents (like Claude) work with the VAK codebase. They provide instructions and guidelines for common development tasks.

-   [**Build Project**](build/SKILL.md) (`build-project`): Instructions for building Rust, WASM, and Python components.
-   [**Run Tests**](test/SKILL.md) (`run-tests`): Instructions for running unit tests, integration tests, and benchmarks.
-   [**Security Checks**](security/SKILL.md) (`check-security`): Instructions for security audits, license compliance, and unsafe code scans.
-   [**Code Review**](review/SKILL.md) (`review-code`): Guidelines and checklist for reviewing code changes.
-   [**Documentation**](docs/SKILL.md) (`manage-docs`): Instructions for generating and maintaining documentation.
-   [**Release Project**](release/SKILL.md) (`release-project`): Instructions for publishing releases.

## Runtime Skills (for VAK Kernel)

These are WASM modules that run inside the VAK kernel sandbox.

-   **Calculator** (`calculator/`): Basic arithmetic operations (add, subtract, multiply, divide).
-   **Crypto Hash** (`crypto-hash/`): Cryptographic hashing (SHA-256, HMAC-SHA256, hash verification).
-   **JSON Validator** (`json-validator/`): JSON validation, pretty-printing, minification, extraction, merging, and diffing.
-   **Text Analyzer** (`text-analyzer/`): Text analysis (word count, character stats, frequency, similarity, entropy).
-   **Regex Matcher** (`regex-matcher/`): Pattern matching (glob patterns, find-all, replace, split, pattern extraction).

## Usage

AI agents can read the `SKILL.md` files in each directory to understand how to perform specific tasks. Each skill definition includes:
-   **Name**: Unique identifier.
-   **Description**: What the skill does.
-   **Instructions**: Step-by-step commands.
-   **Examples**: Common usage scenarios.
-   **Guidelines**: Best practices and rules.

## Input Sanitization Guide for Skill Developers

All WASM runtime skills receive untrusted input from agents. Follow these rules to prevent injection attacks, crashes, and sandbox escapes.

### General Rules

1. **Validate all input before processing.** Never trust the `input` string from the host. Parse it as JSON and check the schema before acting on it.
2. **Bound all sizes.** Reject inputs that exceed expected lengths. For example, a calculator skill should reject expressions longer than 1 KB.
3. **Avoid unbounded allocations.** Never allocate memory proportional to user input without a cap. Use `Vec::with_capacity(min(n, MAX))` patterns.
4. **Return errors, never panic.** Use `Result` types and return error JSON instead of panicking. A panic in WASM terminates the instance.
5. **No filesystem or network access.** WASM skills run in a sandboxed environment. Do not attempt to access the filesystem, network, or environment variables.

### String Input Sanitization

```rust
// Good: validate and bound input
fn process_input(raw: &str) -> Result<Output, SkillError> {
    if raw.len() > MAX_INPUT_SIZE {
        return Err(SkillError::InputTooLarge);
    }

    let request: Request = serde_json::from_str(raw)
        .map_err(|e| SkillError::InvalidJson(e.to_string()))?;

    // Validate fields
    if request.field.is_empty() {
        return Err(SkillError::MissingField("field"));
    }

    // Process validated input...
    Ok(output)
}
```

### Numeric Input Sanitization

```rust
// Good: check for overflow, NaN, infinity
fn safe_divide(a: f64, b: f64) -> Result<f64, SkillError> {
    if b == 0.0 {
        return Err(SkillError::DivisionByZero);
    }
    if a.is_nan() || b.is_nan() || a.is_infinite() || b.is_infinite() {
        return Err(SkillError::InvalidNumber);
    }
    Ok(a / b)
}
```

### Regex Input Sanitization

```rust
// Good: limit regex complexity to prevent ReDoS
fn safe_regex(pattern: &str) -> Result<Regex, SkillError> {
    if pattern.len() > 256 {
        return Err(SkillError::PatternTooLong);
    }
    // Reject known ReDoS patterns (nested quantifiers)
    if pattern.contains("**") || pattern.contains("++") || pattern.contains("??") {
        return Err(SkillError::UnsafePattern);
    }
    regex::Regex::new(pattern)
        .map_err(|e| SkillError::InvalidPattern(e.to_string()))
}
```

### JSON Input Sanitization

```rust
// Good: limit nesting depth to prevent stack overflow
fn safe_parse(input: &str, max_depth: usize) -> Result<Value, SkillError> {
    if input.len() > MAX_JSON_SIZE {
        return Err(SkillError::InputTooLarge);
    }
    let value: serde_json::Value = serde_json::from_str(input)
        .map_err(|e| SkillError::InvalidJson(e.to_string()))?;
    if json_depth(&value) > max_depth {
        return Err(SkillError::NestingTooDeep);
    }
    Ok(value)
}
```

### Output Sanitization

1. **Structured output only.** Always return well-formed JSON with `success`, `result`, and `error` fields.
2. **Limit output size.** Truncate or paginate results that could be excessively large.
3. **No sensitive data.** Never include internal errors, stack traces, or memory addresses in output.

### Checklist for New Skills

- [ ] All inputs parsed and validated before use
- [ ] Maximum input size enforced
- [ ] No panics in any code path (use `Result` everywhere)
- [ ] Output is well-formed JSON
- [ ] No unbounded loops or recursion
- [ ] Regex patterns checked for ReDoS vulnerability
- [ ] Numeric inputs checked for NaN/Infinity/overflow
- [ ] Skill signed with `vak-skill-sign` before deployment


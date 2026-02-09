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

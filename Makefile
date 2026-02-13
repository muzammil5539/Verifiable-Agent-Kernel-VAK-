# VAK - Verifiable Agent Kernel
# Makefile for common development and infrastructure tasks (v0.3)

.PHONY: all build test bench coverage lint security clean skills python help

# Default target
all: lint build test

# ===========================================================================
# Build Targets
# ===========================================================================

## Build the project in release mode
build:
	cargo build --release

## Build in debug mode
build-debug:
	cargo build

## Build WASM skills
skills:
	@echo "Building WASM skills..."
	cargo build -p calculator --target wasm32-unknown-unknown --release
	cargo build -p crypto-hash --target wasm32-unknown-unknown --release
	cargo build -p json-validator --target wasm32-unknown-unknown --release
	cargo build -p text-analyzer --target wasm32-unknown-unknown --release
	cargo build -p regex-matcher --target wasm32-unknown-unknown --release
	@echo "All WASM skills built successfully."

## Build Python SDK
python:
	cd python && pip install -e ".[dev]" || pip install -e .

# ===========================================================================
# Test Targets
# ===========================================================================

## Run all tests
test:
	cargo test --verbose

## Run unit tests only
test-unit:
	cargo test --lib --verbose

## Run integration tests only
test-integration:
	cargo test --test '*' --verbose

## Run doc tests only
test-doc:
	cargo test --doc --verbose

## Run property-based tests with extended cases
test-property:
	PROPTEST_CASES=512 cargo test --test property_tests --verbose

## Run Python SDK tests
test-python:
	python -m pytest python/tests/ -v --tb=short

## Run stress tests
test-stress:
	cargo test --test integration_root test_stress --verbose -- --test-threads=1

## Run all tests including Python
test-all: test test-python

# ===========================================================================
# Code Quality
# ===========================================================================

## Run all lints and formatting checks
lint: fmt-check clippy

## Check formatting
fmt-check:
	cargo fmt --all -- --check

## Format code
fmt:
	cargo fmt --all

## Run clippy lints
clippy:
	cargo clippy --all-targets --all-features -- -D warnings

## Run security-focused clippy lints
clippy-security:
	cargo clippy --all-targets --all-features -- \
		-D clippy::unwrap_used \
		-D clippy::expect_used \
		-D clippy::panic \
		-W clippy::cognitive_complexity \
		-W clippy::too_many_arguments

# ===========================================================================
# Coverage
# ===========================================================================

## Run code coverage with tarpaulin
coverage:
	cargo tarpaulin --config tarpaulin.toml --out Html --out Xml --output-dir coverage/

## Run coverage and enforce 80% threshold
coverage-check:
	cargo tarpaulin --config tarpaulin.toml --fail-under 80

# ===========================================================================
# Benchmarks
# ===========================================================================

## Run all benchmarks
bench:
	cargo bench

## Run kernel benchmarks only
bench-kernel:
	cargo bench --bench kernel_benchmarks

## Run audit benchmarks only
bench-audit:
	cargo bench --bench audit_benchmarks

# ===========================================================================
# Security Auditing
# ===========================================================================

## Run all security checks
security: audit deny geiger

## Run cargo-audit vulnerability scan
audit:
	cargo audit --deny warnings

## Run cargo-deny license and dependency checks
deny:
	cargo deny check

## Run cargo-geiger unsafe code audit
geiger:
	cargo geiger --all-features --all-targets || true

## Generate SBOM
sbom:
	cargo sbom > sbom.json

# ===========================================================================
# Documentation
# ===========================================================================

## Generate Rust documentation
doc:
	cargo doc --no-deps --all-features

## Open generated documentation
doc-open:
	cargo doc --no-deps --all-features --open

# ===========================================================================
# Docker
# ===========================================================================

## Build production Docker image
docker-build:
	docker build --target production -t vak:latest .

## Build development Docker image
docker-build-dev:
	docker build --target dev -t vak:dev .

## Run production container
docker-run:
	docker compose up vak

## Run development container
docker-run-dev:
	docker compose up vak-dev

# ===========================================================================
# Performance Profiling
# ===========================================================================

## Run full performance profiling suite
perf:
	./scripts/perf-profile.sh all

## Run benchmarks and save results
perf-bench:
	./scripts/perf-profile.sh bench

## Generate flamegraph
perf-flamegraph:
	./scripts/perf-profile.sh flamegraph

# ===========================================================================
# Cleanup
# ===========================================================================

## Clean build artifacts
clean:
	cargo clean
	rm -rf coverage/ perf-results/

## Clean and rebuild
rebuild: clean build

# ===========================================================================
# Help
# ===========================================================================

## Show this help message
help:
	@echo "VAK - Verifiable Agent Kernel (v0.3)"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Build:"
	@echo "  build            Build the project in release mode"
	@echo "  build-debug      Build in debug mode"
	@echo "  skills           Build WASM skills"
	@echo "  python           Build Python SDK"
	@echo ""
	@echo "Test:"
	@echo "  test             Run all Rust tests"
	@echo "  test-unit        Run unit tests only"
	@echo "  test-integration Run integration tests only"
	@echo "  test-doc         Run doc tests only"
	@echo "  test-property    Run property-based tests (extended)"
	@echo "  test-python      Run Python SDK tests"
	@echo "  test-stress      Run stress tests"
	@echo "  test-all         Run all tests including Python"
	@echo ""
	@echo "Quality:"
	@echo "  lint             Run all lints and formatting checks"
	@echo "  fmt              Format code"
	@echo "  clippy           Run clippy lints"
	@echo "  clippy-security  Run security-focused clippy lints"
	@echo ""
	@echo "Coverage:"
	@echo "  coverage         Generate coverage report"
	@echo "  coverage-check   Check coverage meets 80% threshold"
	@echo ""
	@echo "Benchmarks:"
	@echo "  bench            Run all benchmarks"
	@echo "  bench-kernel     Run kernel benchmarks"
	@echo "  bench-audit      Run audit benchmarks"
	@echo ""
	@echo "Security:"
	@echo "  security         Run all security checks"
	@echo "  audit            Run cargo-audit"
	@echo "  deny             Run cargo-deny"
	@echo "  geiger           Run cargo-geiger"
	@echo "  sbom             Generate SBOM"
	@echo ""
	@echo "Docker:"
	@echo "  docker-build     Build production Docker image"
	@echo "  docker-build-dev Build development Docker image"
	@echo "  docker-run       Run production container"
	@echo "  docker-run-dev   Run development container"
	@echo ""
	@echo "Performance:"
	@echo "  perf             Run full profiling suite"
	@echo "  perf-bench       Run benchmarks with results"
	@echo "  perf-flamegraph  Generate flamegraph"
	@echo ""
	@echo "Other:"
	@echo "  doc              Generate documentation"
	@echo "  doc-open         Open documentation in browser"
	@echo "  clean            Clean build artifacts"
	@echo "  rebuild          Clean and rebuild"
	@echo "  help             Show this help message"

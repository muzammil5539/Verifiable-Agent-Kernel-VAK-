#!/usr/bin/env bash
# VAK Performance Profiling & Optimization Script (v0.3)
#
# Usage:
#   ./scripts/perf-profile.sh [command]
#
# Commands:
#   bench          Run all benchmarks and save results
#   compare        Compare current benchmarks against baseline
#   flamegraph     Generate flamegraph for kernel operations
#   coverage       Run test coverage and generate reports
#   all            Run all profiling tasks

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$PROJECT_DIR/perf-results"
BASELINE_FILE="$RESULTS_DIR/baseline.json"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Ensure results directory exists
mkdir -p "$RESULTS_DIR"

# ===========================================================================
# Benchmarks
# ===========================================================================

run_benchmarks() {
    log_info "Running Criterion benchmarks..."

    cd "$PROJECT_DIR"

    # Run kernel benchmarks
    log_info "Running kernel benchmarks..."
    cargo bench --bench kernel_benchmarks 2>&1 | tee "$RESULTS_DIR/kernel_bench_$(date +%Y%m%d_%H%M%S).txt"

    # Run audit benchmarks
    log_info "Running audit benchmarks..."
    cargo bench --bench audit_benchmarks 2>&1 | tee "$RESULTS_DIR/audit_bench_$(date +%Y%m%d_%H%M%S).txt"

    log_success "Benchmarks complete. Results in $RESULTS_DIR/"

    # Save baseline if none exists
    if [ ! -f "$BASELINE_FILE" ]; then
        log_info "No baseline found, saving current results as baseline..."
        save_baseline
    fi
}

save_baseline() {
    cd "$PROJECT_DIR"
    cargo bench --bench kernel_benchmarks -- --save-baseline main 2>&1 || true
    log_success "Baseline saved"
}

compare_benchmarks() {
    log_info "Comparing against baseline..."
    cd "$PROJECT_DIR"

    if [ ! -d "$PROJECT_DIR/target/criterion" ]; then
        log_warn "No previous benchmark results found. Run 'bench' first."
        return 1
    fi

    cargo bench --bench kernel_benchmarks -- --baseline main 2>&1 | tee "$RESULTS_DIR/comparison_$(date +%Y%m%d_%H%M%S).txt"

    log_success "Comparison complete"
}

# ===========================================================================
# Flamegraph Generation
# ===========================================================================

generate_flamegraph() {
    log_info "Generating flamegraph..."
    cd "$PROJECT_DIR"

    # Check if cargo-flamegraph is installed
    if ! command -v cargo-flamegraph &> /dev/null; then
        log_warn "cargo-flamegraph not found. Installing..."
        cargo install flamegraph
    fi

    # Generate flamegraph from benchmark
    log_info "Generating flamegraph from kernel benchmarks..."
    cargo flamegraph --bench kernel_benchmarks -o "$RESULTS_DIR/flamegraph_$(date +%Y%m%d_%H%M%S).svg" -- --bench 2>&1 || {
        log_warn "Flamegraph generation requires perf. On Linux, ensure linux-tools is installed."
        log_warn "Try: sudo apt install linux-tools-common linux-tools-generic"
    }

    log_success "Flamegraph saved to $RESULTS_DIR/"
}

# ===========================================================================
# Code Coverage
# ===========================================================================

run_coverage() {
    log_info "Running code coverage analysis..."
    cd "$PROJECT_DIR"

    # Check if cargo-tarpaulin is installed
    if ! command -v cargo-tarpaulin &> /dev/null; then
        log_warn "cargo-tarpaulin not found. Installing..."
        cargo install cargo-tarpaulin
    fi

    # Run coverage with HTML and XML output
    log_info "Generating coverage report..."
    cargo tarpaulin \
        --config tarpaulin.toml \
        --out Html \
        --out Xml \
        --output-dir "$RESULTS_DIR/coverage/" \
        2>&1 | tee "$RESULTS_DIR/coverage_$(date +%Y%m%d_%H%M%S).txt"

    log_success "Coverage report saved to $RESULTS_DIR/coverage/"

    # Check coverage threshold
    log_info "Checking coverage threshold (80%)..."
    cargo tarpaulin --config tarpaulin.toml --fail-under 80 2>&1 && \
        log_success "Coverage threshold met (>= 80%)" || \
        log_error "Coverage below 80% threshold"
}

# ===========================================================================
# Compilation Performance
# ===========================================================================

check_compile_times() {
    log_info "Analyzing compilation times..."
    cd "$PROJECT_DIR"

    # Clean build timing
    cargo clean 2>/dev/null || true
    log_info "Running clean build with timing..."

    # Use cargo build with timings
    cargo build --timings --release 2>&1 | tee "$RESULTS_DIR/compile_timing_$(date +%Y%m%d_%H%M%S).txt"

    if [ -f "$PROJECT_DIR/target/cargo-timings/cargo-timing.html" ]; then
        cp "$PROJECT_DIR/target/cargo-timings/cargo-timing.html" "$RESULTS_DIR/"
        log_success "Build timing report saved to $RESULTS_DIR/cargo-timing.html"
    fi
}

# ===========================================================================
# Binary Size Analysis
# ===========================================================================

analyze_binary_size() {
    log_info "Analyzing binary sizes..."
    cd "$PROJECT_DIR"

    cargo build --release 2>/dev/null

    echo ""
    echo "Binary Size Report"
    echo "==================="

    if [ -f "$PROJECT_DIR/target/release/libvak.rlib" ]; then
        SIZE=$(du -h "$PROJECT_DIR/target/release/libvak.rlib" | cut -f1)
        echo "  libvak.rlib: $SIZE"
    fi

    # Check WASM skill sizes
    echo ""
    echo "WASM Skill Sizes:"
    echo "-----------------"
    for skill_dir in "$PROJECT_DIR/.github/skills"/*/; do
        skill_name=$(basename "$skill_dir")
        wasm_file="$PROJECT_DIR/target/wasm32-unknown-unknown/release/${skill_name//-/_}.wasm"
        if [ -f "$wasm_file" ]; then
            SIZE=$(du -h "$wasm_file" | cut -f1)
            echo "  $skill_name: $SIZE"
        fi
    done

    echo ""
    log_success "Binary size analysis complete"
}

# ===========================================================================
# Full Profiling Suite
# ===========================================================================

run_all() {
    log_info "Running full performance profiling suite..."
    echo ""

    run_benchmarks
    echo ""

    run_coverage
    echo ""

    analyze_binary_size
    echo ""

    log_success "Full profiling suite complete. Results in $RESULTS_DIR/"
}

# ===========================================================================
# Main Entry Point
# ===========================================================================

print_usage() {
    echo "VAK Performance Profiling Script (v0.3)"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  bench          Run all benchmarks and save results"
    echo "  compare        Compare current benchmarks against baseline"
    echo "  flamegraph     Generate flamegraph for kernel operations"
    echo "  coverage       Run test coverage and generate reports"
    echo "  compile-times  Analyze compilation times"
    echo "  binary-size    Analyze binary sizes"
    echo "  save-baseline  Save current benchmark results as baseline"
    echo "  all            Run all profiling tasks"
    echo ""
}

COMMAND="${1:-help}"

case "$COMMAND" in
    bench)
        run_benchmarks
        ;;
    compare)
        compare_benchmarks
        ;;
    flamegraph)
        generate_flamegraph
        ;;
    coverage)
        run_coverage
        ;;
    compile-times)
        check_compile_times
        ;;
    binary-size)
        analyze_binary_size
        ;;
    save-baseline)
        save_baseline
        ;;
    all)
        run_all
        ;;
    help|--help|-h|*)
        print_usage
        ;;
esac

# Stage 1: Build the Rust binary
FROM rust:1.75-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace configuration first for dependency caching
COPY Cargo.toml Cargo.lock ./
COPY .github/skills/calculator/Cargo.toml .github/skills/calculator/Cargo.toml
COPY .github/skills/crypto-hash/Cargo.toml .github/skills/crypto-hash/Cargo.toml
COPY .github/skills/json-validator/Cargo.toml .github/skills/json-validator/Cargo.toml
COPY .github/skills/text-analyzer/Cargo.toml .github/skills/text-analyzer/Cargo.toml
COPY .github/skills/regex-matcher/Cargo.toml .github/skills/regex-matcher/Cargo.toml

# Create stub source files for dependency caching
RUN mkdir -p src && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs
RUN mkdir -p .github/skills/calculator/src && echo "" > .github/skills/calculator/src/lib.rs
RUN mkdir -p .github/skills/crypto-hash/src && echo "" > .github/skills/crypto-hash/src/lib.rs
RUN mkdir -p .github/skills/json-validator/src && echo "" > .github/skills/json-validator/src/lib.rs
RUN mkdir -p .github/skills/text-analyzer/src && echo "" > .github/skills/text-analyzer/src/lib.rs
RUN mkdir -p .github/skills/regex-matcher/src && echo "" > .github/skills/regex-matcher/src/lib.rs

# Cache dependencies
RUN cargo build --release 2>/dev/null || true

# Copy actual source code
COPY src/ src/
COPY .github/skills/ .github/skills/
COPY tests/ tests/
COPY benches/ benches/
COPY examples/ examples/
COPY policies/ policies/
COPY prompts/ prompts/
COPY deny.toml ./

# Build the project
RUN cargo build --release

# Stage 2: Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libgcc-s1 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r vak && useradd -r -g vak -d /app -s /sbin/nologin vak

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/libvak.so /usr/local/lib/
COPY --from=builder /app/policies/ /app/policies/
COPY --from=builder /app/prompts/ /app/prompts/

# Create directories for runtime data
RUN mkdir -p /app/data /app/audit /app/skills /app/config \
    && chown -R vak:vak /app

USER vak

# Environment configuration
ENV VAK_POLICY_PATH=/app/policies
ENV VAK_AUDIT_PATH=/app/audit
ENV VAK_SKILLS_PATH=/app/skills
ENV VAK_LOG_LEVEL=info
ENV RUST_LOG=vak=info

EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Default command (library mode - override in docker-compose or k8s)
CMD ["echo", "VAK kernel loaded. Use as a library or override CMD with your application."]

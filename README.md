# TP1 - Secure Log Analyzer in Rust

## Objective

A command-line tool that reads a simplified Linux authentication log file
and produces a summary of suspicious login activity.
It counts failed login attempts by source IP address and by username,
and handles malformed lines without crashing.

## Environment Requirements

- Docker
- Docker Compose

## Setup

Start the Docker environment:

```bash
mkdir -p workspace
docker compose up -d --build
docker compose exec rustlab bash
cd /workspace/TPs/tp1_log_analyzer
```

## Build

```bash
cargo build
```

## Run

```bash
cargo run -- samples/auth_sample.log
```

## Test

```bash
cargo test
```

## Lint

```bash
cargo fmt --check
cargo clippy -- -D warnings
```

## Author

Taher Ahmedou - Module 7.1 Programming with Rust - 2025-2026

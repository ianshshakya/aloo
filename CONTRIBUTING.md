# Contributing to Aloo

First off, thank you for considering contributing to Aloo! It's people like you that make open-source security tools better for everyone.

This document serves as a guide for developers looking to understand the Aloo architecture and contribute code.

## 🛠️ Developer Setup

### Windows (WSL2)
Aloo utilizes raw sockets and advanced networking capabilities that are heavily restricted by the native Windows networking stack. **If you are developing on Windows, you MUST use WSL2 (Ubuntu).**

1. Install WSL2 and Ubuntu.
2. Clone the repository **inside the Linux filesystem** (e.g., `~/Aloo`), NOT the mounted Windows filesystem (`/mnt/c/...`). Compiling SQLite bindings on the Windows mount will fail with permission errors.
3. Install dependencies: `sudo apt update && sudo apt install build-essential curl`
4. Install Rust: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`

### macOS / Linux
1. Install Rust via `rustup`.
2. Clone the repository and run `cargo build`.

## 🏗️ Workspace Architecture

Aloo is split into 16+ crates to enforce strict boundaries (Hexagonal Architecture). 

- **`aloo-core`**: The absolute center. Contains only pure data types, enums, and ID wrappers. No I/O, no async.
- **`aloo-traits`**: Defines the interfaces (Ports) for the system (e.g., `AssetRepository`, `Plugin`).
- **`aloo-engine`**: The central orchestrator. Wires together worker pools and the event bus.
- **`aloo-storage`**: The SQLite (sqlx) implementation of the traits.
- **`aloo-probes`**: Application-layer (L7) probes (HTTP, TLS, SSH). If you are adding a new protocol detector, it goes here!

## 🧪 Testing

We expect high test coverage. Every component should be testable without bringing up a real network interface or database.

- **Unit tests:** Run `cargo test --workspace`. Use `mockall` to mock trait boundaries.
- **Integration tests:** Located in the `tests/` directory of respective crates.

## 📝 Pull Request Process

1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. Ensure the test suite passes: `cargo test`
4. Make sure your code is formatted correctly: `cargo fmt --all -- --check`
5. Make sure your code passes the strict linter: `cargo clippy --workspace -- -D warnings`
6. Issue that pull request!

## 🏛️ Design Philosophy

Before writing code, please read the [Architecture Blueprint](docs/ARCHITECTURE.md). 
- **Zero Global State**: Never use `lazy_static` or `OnceCell` for mutable state. Pass dependencies via DI.
- **Fail Fast**: Handle errors explicitly using `thiserror` and `anyhow`. Avoid `unwrap()` in production code.
- **Defensive Focus**: Aloo is a defensive tool. Pull requests adding exploitation frameworks or offensive capabilities will be rejected.

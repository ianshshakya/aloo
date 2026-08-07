<div align="center">
  <h1>🥔 Aloo</h1>
  <p><strong>The Open Source Network Intelligence Platform</strong></p>

  <p>
    <a href="https://github.com/ianshshakya/aloo/actions"><img src="https://img.shields.io/github/actions/workflow/status/ianshshakya/aloo/release.yml?branch=main&style=flat-square" alt="Build Status"></a>
    <a href="https://crates.io/crates/aloo-cli"><img src="https://img.shields.io/crates/v/aloo-cli?style=flat-square" alt="Crates.io"></a>
    <a href="https://github.com/ianshshakya/aloo/blob/main/LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue?style=flat-square" alt="License"></a>
    <a href="https://rust-lang.org"><img src="https://img.shields.io/badge/rust-1.82+-orange.svg?style=flat-square" alt="Rust 1.82+"></a>
  </p>
</div>

---

> **Aloo is currently in active development.** The v0.1.0 network scanning engine is complete. See the [Roadmap](#roadmap) for upcoming SQLite history and vulnerability mapping features!

<div align="center">
  <!-- TODO: Replace with the GIF of the beautiful CLI scanning -->
  <img src="docs/demo.gif" alt="Aloo CLI Demo">
</div>

## 🌍 Overview

Aloo is an enterprise-grade platform designed to continuously discover, inventory, analyze, correlate, and explain network infrastructure. 

Unlike traditional port scanners that simply tell you *"Port 22 is open"*, Aloo answers:
- *"What changed since yesterday?"*
- *"What are the risks?"*
- *"What devices are related?"*
- *"What should I fix first?"*

Built in 100% safe **Rust**, Aloo combines the raw speed of Masscan/ZMap with the analytical depth of Nmap and the continuous asset tracking of enterprise EDR solutions.

## ✨ Key Features

- ⏱️ **Asset Timeline:** Every discovered device keeps history forever. Track when ports open, services change, or certificates expire.
- 🕸️ **Infrastructure Graph:** Automatically infer and build a relationship graph between your routers, load balancers, and web servers based on network telemetry.
- 🧠 **Risk Correlation:** Correlates weak TLS, exposed ports, and outdated service banners to prioritize findings.
- 🔄 **Change Detection (Diff Engine):** Instantly diff two scans to find newly exposed endpoints or retired hardware.
- 🔌 **Extensible Plugin System:** Write custom L7 probes and risk correlators in Rust or WebAssembly (Wasm).

## 🚀 Quickstart

### Installation

Aloo requires **Rust 1.82+**. 
Install it globally on your machine using Cargo:

```bash
cargo install aloo-cli
```

### Run a Scan

```bash
# Run a blazing fast scan against the top 1024 ports
aloo scan --profile quick scanme.nmap.org

# Scan an entire local subnet with rate limits
aloo scan -r 5000 -j 2000 192.168.1.0/24
```

## 🏗️ Architecture

Aloo is a highly concurrent, event-driven system built on `tokio` and `sqlx`. It uses a **Hexagonal Architecture** across a 19-crate workspace to ensure every component (scanning, storage, diffing, AI generation) is modular and independently testable.

Read our full [Architecture Blueprint](docs/ARCHITECTURE.md) to see how the Engine, Event Bus, and SQLite WAL storage fit together.

## 🗺️ Roadmap

- [x] **Phase 1: The Foundation** - Workspace, Domain models, Storage interfaces.
- [x] **Phase 2: The Network Engine** - Tokio JoinSet concurrency, DNS resolution, TCP connect scanning, Global rate limiter.
- [ ] **Phase 3: The Intelligence Engine** - Banner grabbing, TLS inspection, CVE mapping.
- [ ] **Phase 4: The Time Machine** - SQLite schema, Diff Engine, Asset Timeline.
- [ ] **Phase 5: The Enterprise Layer** - Infrastructure Graph, AI Extension points, REST API, Plugins.

## 🤝 Contributing

We want Aloo to become one of the most impressive Rust cybersecurity tools on GitHub, and we need your help!

Whether you are fixing bugs, adding new L7 protocol probes, or improving documentation, all contributions are welcome.

1. Read the [Contributing Guide](CONTRIBUTING.md) to learn how to set up your dev environment.
2. Check out the [Good First Issues](https://github.com/ianshshakya/aloo/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) to find something to work on.
3. Review our [Code of Conduct](CODE_OF_CONDUCT.md).

## 🛡️ Security

If you find a security vulnerability within Aloo, please refer to our [Security Policy](SECURITY.md) for reporting instructions.

## 📄 License

Aloo is dual-licensed under either the [MIT License](LICENSE-MIT) or the [Apache License, Version 2.0](LICENSE-APACHE), at your option.

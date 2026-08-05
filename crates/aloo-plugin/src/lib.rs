//! `aloo-plugin` — Plugin manifest, registry, and context types.
//!
//! This crate is the **data layer only** — no wasmtime, no libloading.
//! The runtime loading of plugins is deferred to the plugin-runtime milestone.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::net::IpAddr;
use std::path::PathBuf;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Error types ───────────────────────────────────────────────────────────────

/// Plugin registry errors.
#[derive(Debug, Error)]
pub enum PluginError {
    /// Plugin with the given ID not found.
    #[error("Plugin not found: {0}")]
    NotFound(String),
    /// Plugin manifest is invalid.
    #[error("Invalid plugin manifest: {0}")]
    InvalidManifest(String),
    /// Plugin API version mismatch.
    #[error("API version mismatch: expected {expected}, got {got}")]
    ApiVersionMismatch { expected: u32, got: u32 },
}

// ── Plugin kinds ──────────────────────────────────────────────────────────────

/// The runtime kind of a plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginKind {
    /// WebAssembly plugin (sandboxed, cross-platform).
    Wasm,
    /// Native shared library (.so / .dll / .dylib).
    Native,
}

impl std::fmt::Display for PluginKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PluginKind::Wasm   => write!(f, "wasm"),
            PluginKind::Native => write!(f, "native"),
        }
    }
}

// ── Plugin manifest ───────────────────────────────────────────────────────────

/// Describes a plugin and how to load it.
///
/// Serialisable from a TOML `[plugin]` section in the plugin's manifest file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Unique plugin identifier (reverse-DNS recommended, e.g. `io.aloo.http-probe`).
    pub id: String,
    /// Human-readable plugin name.
    pub name: String,
    /// Plugin version string (SemVer recommended).
    pub version: String,
    /// Runtime kind.
    pub kind: PluginKind,
    /// Entry point: path to `.wasm` or shared library.
    pub entry: PathBuf,
    /// Aloo plugin API version this plugin was built against.
    pub api_version: u32,
    /// Optional description.
    pub description: Option<String>,
    /// Optional author information.
    pub author: Option<String>,
}

impl PluginManifest {
    /// Parse a manifest from a TOML string.
    pub fn from_toml(s: &str) -> Result<Self, PluginError> {
        toml::from_str(s).map_err(|e| PluginError::InvalidManifest(e.to_string()))
    }

    /// Verify the API version is compatible with the current host API version.
    pub fn check_api_version(&self, host_api_version: u32) -> Result<(), PluginError> {
        if self.api_version != host_api_version {
            return Err(PluginError::ApiVersionMismatch {
                expected: host_api_version,
                got: self.api_version,
            });
        }
        Ok(())
    }
}

// ── Plugin registry ───────────────────────────────────────────────────────────

/// Current host plugin API version.
pub const HOST_API_VERSION: u32 = 1;

/// Thread-safe registry of loaded plugin manifests.
pub struct PluginRegistry {
    plugins: DashMap<String, PluginManifest>,
}

impl PluginRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self { plugins: DashMap::new() }
    }

    /// Register a plugin manifest.
    ///
    /// Returns an error if the API version is incompatible.
    pub fn register(&self, manifest: PluginManifest) -> Result<(), PluginError> {
        manifest.check_api_version(HOST_API_VERSION)?;
        tracing::info!(id = %manifest.id, kind = %manifest.kind, "Plugin registered");
        self.plugins.insert(manifest.id.clone(), manifest);
        Ok(())
    }

    /// Retrieve a manifest by plugin ID.
    pub fn get(&self, id: &str) -> Option<PluginManifest> {
        self.plugins.get(id).map(|m| m.clone())
    }

    /// Remove a plugin by ID. Returns true if it existed.
    pub fn remove(&self, id: &str) -> bool {
        self.plugins.remove(id).is_some()
    }

    /// List all registered plugin IDs.
    pub fn ids(&self) -> Vec<String> {
        self.plugins.iter().map(|e| e.key().clone()).collect()
    }

    /// Total number of registered plugins.
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// True if no plugins are registered.
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Plugin context ────────────────────────────────────────────────────────────

/// Context passed to a plugin during execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginContext {
    /// Target host IP address.
    pub target_ip: IpAddr,
    /// Target port number.
    pub target_port: u16,
    /// Session ID string.
    pub session_id: String,
    /// Arbitrary key-value metadata.
    pub metadata: std::collections::HashMap<String, String>,
}

impl PluginContext {
    /// Create a minimal context for a target.
    pub fn new(target_ip: IpAddr, target_port: u16, session_id: impl Into<String>) -> Self {
        Self {
            target_ip,
            target_port,
            session_id: session_id.into(),
            metadata: std::collections::HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest_toml() -> &'static str {
        r#"
id          = "io.aloo.http-probe"
name        = "HTTP Probe"
version     = "0.1.0"
kind        = "wasm"
entry       = "plugins/http_probe.wasm"
api_version = 1
description = "Probes HTTP endpoints"
author      = "Aloo Contributors"
"#
    }

    #[test]
    fn manifest_parses_from_toml() {
        let m = PluginManifest::from_toml(sample_manifest_toml()).unwrap();
        assert_eq!(m.id, "io.aloo.http-probe");
        assert_eq!(m.kind, PluginKind::Wasm);
        assert_eq!(m.api_version, 1);
        assert_eq!(m.description.as_deref(), Some("Probes HTTP endpoints"));
    }

    #[test]
    fn registry_register_and_get() {
        let m = PluginManifest::from_toml(sample_manifest_toml()).unwrap();
        let registry = PluginRegistry::new();
        registry.register(m.clone()).unwrap();
        let got = registry.get("io.aloo.http-probe").unwrap();
        assert_eq!(got.name, "HTTP Probe");
    }

    #[test]
    fn registry_api_version_mismatch_errors() {
        let mut m = PluginManifest::from_toml(sample_manifest_toml()).unwrap();
        m.api_version = 99;
        let registry = PluginRegistry::new();
        let err = registry.register(m).unwrap_err();
        assert!(matches!(err, PluginError::ApiVersionMismatch { .. }));
    }

    #[test]
    fn registry_remove() {
        let m = PluginManifest::from_toml(sample_manifest_toml()).unwrap();
        let registry = PluginRegistry::new();
        registry.register(m).unwrap();
        assert!(registry.remove("io.aloo.http-probe"));
        assert!(registry.is_empty());
    }

    #[test]
    fn plugin_context_new() {
        let ctx = PluginContext::new("192.168.1.1".parse().unwrap(), 443, "sess-001");
        assert_eq!(ctx.target_port, 443);
        assert_eq!(ctx.session_id, "sess-001");
    }
}

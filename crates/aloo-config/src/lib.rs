//! `aloo-config` — Configuration loading and validation.
//!
//! Priority order (highest wins): CLI flags → `ALOO_*` env vars → `aloo.toml` → defaults.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::{Path, PathBuf};

use aloo_core::{PortRange, ScanProfileKind};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Configuration errors.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// File could not be read.
    #[error("Cannot read config file '{path}': {source}")]
    FileRead { path: PathBuf, #[source] source: std::io::Error },
    /// TOML parse error.
    #[error("TOML parse error in '{path}': {source}")]
    TomlParse { path: PathBuf, #[source] source: toml::de::Error },
    /// A required value is missing or invalid.
    #[error("Invalid configuration: {0}")]
    InvalidField(String),
}

// ── Top-level config ──────────────────────────────────────────────────────────

/// Root Aloo configuration structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AlooConfig {
    /// Network scanning settings.
    pub scan: ScanConfig,
    /// Output and reporting settings.
    pub output: OutputConfig,
    /// Persistence settings.
    pub storage: StorageConfig,
    /// Plugin subsystem settings.
    pub plugins: PluginConfig,
    /// Logging / tracing settings.
    pub logging: LoggingConfig,
}

impl Default for AlooConfig {
    fn default() -> Self {
        Self {
            scan: ScanConfig::default(),
            output: OutputConfig::default(),
            storage: StorageConfig::default(),
            plugins: PluginConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

// ── Scan config ───────────────────────────────────────────────────────────────

/// Scan-specific settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    /// Preset scan profile.
    pub profile: ScanProfileKind,
    /// Maximum concurrent workers.
    pub max_parallelism: usize,
    /// Per-target connection timeout in milliseconds.
    pub timeout_ms: u64,
    /// Global rate limit in packets per second (0 = unlimited).
    pub rate_limit_pps: u32,
    /// Explicit port range. `None` means use the profile default.
    pub ports: Option<PortRange>,
    /// Run host discovery before port scanning.
    pub host_discovery: bool,
    /// Grab service banners from open ports.
    pub banner_grab: bool,
    /// Maximum banner size in bytes.
    pub banner_max_bytes: usize,
    /// Attempt TLS analysis on relevant ports.
    pub tls_analysis: bool,
    /// Attempt OS fingerprinting.
    pub os_fingerprint: bool,
    /// Run vulnerability correlation after fingerprinting.
    pub vuln_correlation: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            profile: ScanProfileKind::Full,
            max_parallelism: 1_000,
            timeout_ms: 3_000,
            rate_limit_pps: 1_000,
            ports: None,
            host_discovery: true,
            banner_grab: true,
            banner_max_bytes: 4_096,
            tls_analysis: true,
            os_fingerprint: true,
            vuln_correlation: true,
        }
    }
}

impl ScanConfig {
    /// Effective port range (explicit override or profile default).
    pub fn effective_ports(&self) -> PortRange {
        self.ports.clone().unwrap_or_else(|| match self.profile {
            ScanProfileKind::Quick   => PortRange { ranges: vec![(1, 1024)] },
            ScanProfileKind::Full    => PortRange::all(),
            ScanProfileKind::Stealth => PortRange { ranges: vec![(1, 1024)] },
            ScanProfileKind::UdpOnly => PortRange { ranges: vec![(1, 1024)] },
            ScanProfileKind::Custom  => PortRange::top_1000(),
        })
    }
}

// ── Output config ─────────────────────────────────────────────────────────────

/// Output and reporting settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OutputConfig {
    /// Directory to write report files into.
    pub output_dir: PathBuf,
    /// Emit JSON output.
    pub json: bool,
    /// Emit HTML report.
    pub html: bool,
    /// Emit Markdown summary.
    pub markdown: bool,
    /// Pretty-print JSON.
    pub json_pretty: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            output_dir: PathBuf::from("./aloo-reports"),
            json: true,
            html: false,
            markdown: false,
            json_pretty: false,
        }
    }
}

// ── Storage config ────────────────────────────────────────────────────────────

/// Persistence settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    /// Path to the SQLite history database.
    pub db_path: PathBuf,
    /// Enable persistent scan history.
    pub persist_history: bool,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self { db_path: PathBuf::from("~/.aloo/history.db"), persist_history: true }
    }
}

// ── Plugin config ─────────────────────────────────────────────────────────────

/// Plugin subsystem settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PluginConfig {
    /// Plugin search directory.
    pub plugin_dir: Option<PathBuf>,
    /// Enable the WASM plugin sandbox.
    pub enable_wasm: bool,
    /// Enable native (.so/.dll) plugins (requires trust).
    pub enable_native: bool,
    /// WASM instruction fuel limit per plugin call.
    pub wasm_fuel_limit: u64,
    /// WASM memory limit per plugin instance in bytes.
    pub wasm_memory_limit: u64,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            plugin_dir: None,
            enable_wasm: false,
            enable_native: false,
            wasm_fuel_limit: 10_000_000,
            wasm_memory_limit: 64 * 1024 * 1024,
        }
    }
}

// ── Logging config ────────────────────────────────────────────────────────────

/// Logging and tracing settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// Log level filter string (e.g. `info`, `debug`).
    pub level: String,
    /// Emit structured JSON logs.
    pub json: bool,
    /// Log file path. `None` = stderr.
    pub file: Option<PathBuf>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self { level: "info".to_string(), json: false, file: None }
    }
}

// ── Config loader ─────────────────────────────────────────────────────────────

/// Loads and merges configuration from all sources.
pub struct ConfigLoader;

impl ConfigLoader {
    /// Load from a TOML file.
    pub fn from_file(path: &Path) -> Result<AlooConfig, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::FileRead { path: path.to_owned(), source: e })?;
        toml::from_str(&text)
            .map_err(|e| ConfigError::TomlParse { path: path.to_owned(), source: e })
    }

    /// Load from the default path (`aloo.toml`), returning defaults if absent.
    pub fn load_default() -> AlooConfig {
        let p = PathBuf::from("aloo.toml");
        if p.exists() { Self::from_file(&p).unwrap_or_default() } else { AlooConfig::default() }
    }

    /// Apply `ALOO_*` environment variable overrides.
    pub fn apply_env(mut config: AlooConfig) -> AlooConfig {
        if let Ok(v) = std::env::var("ALOO_RATE_LIMIT_PPS") {
            if let Ok(n) = v.parse::<u32>() { config.scan.rate_limit_pps = n; }
        }
        if let Ok(v) = std::env::var("ALOO_MAX_PARALLELISM") {
            if let Ok(n) = v.parse::<usize>() { config.scan.max_parallelism = n; }
        }
        if let Ok(v) = std::env::var("ALOO_TIMEOUT_MS") {
            if let Ok(n) = v.parse::<u64>() { config.scan.timeout_ms = n; }
        }
        if let Ok(v) = std::env::var("ALOO_LOG_LEVEL") {
            config.logging.level = v;
        }
        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_sane() {
        let c = AlooConfig::default();
        assert_eq!(c.scan.max_parallelism, 1_000);
        assert_eq!(c.scan.rate_limit_pps, 1_000);
        assert!(c.scan.host_discovery);
        assert!(c.scan.banner_grab);
    }

    #[test]
    fn effective_ports_quick() {
        let mut c = ScanConfig::default();
        c.profile = ScanProfileKind::Quick;
        let ports = c.effective_ports();
        assert!(ports.contains(80));
        assert!(ports.contains(443));
    }

    #[test]
    fn effective_ports_explicit_override() {
        let mut c = ScanConfig::default();
        c.ports = Some(PortRange { ranges: vec![(9000, 9010)] });
        let ports = c.effective_ports();
        assert!(ports.contains(9000));
        assert!(!ports.contains(80));
    }

    #[test]
    fn parse_toml_config() {
        let raw = r#"
[scan]
max_parallelism = 500
timeout_ms      = 1000
rate_limit_pps  = 200

[logging]
level = "debug"
"#;
        let c: AlooConfig = toml::from_str(raw).unwrap();
        assert_eq!(c.scan.max_parallelism, 500);
        assert_eq!(c.logging.level, "debug");
    }

    #[test]
    fn apply_env_overrides_rate_limit() {
        std::env::set_var("ALOO_RATE_LIMIT_PPS", "42");
        let c = ConfigLoader::apply_env(AlooConfig::default());
        assert_eq!(c.scan.rate_limit_pps, 42);
        std::env::remove_var("ALOO_RATE_LIMIT_PPS");
    }
}

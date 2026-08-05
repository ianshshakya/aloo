//! `aloo-traits` — Core trait definitions.
//!
//! All traits live here. Concrete implementations live in their crates.
//! This crate depends only on `aloo-core` and async primitives.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::net::IpAddr;

use aloo_core::{
    BannerData, CpeString, DiscoveryMethod, OsFingerprint, PortRange, PortState, ProbeResult,
    ProbeTarget, Protocol, ScanResult, ServiceFingerprint, Vulnerability,
};
use thiserror::Error;

// ── Error types ───────────────────────────────────────────────────────────────

/// Error from a probe operation.
#[derive(Debug, Error)]
pub enum ProbeError {
    /// Connection timed out.
    #[error("Timeout connecting to {host}:{port}")]
    Timeout { host: IpAddr, port: u16 },
    /// Connection actively refused.
    #[error("Connection refused: {host}:{port}")]
    Refused { host: IpAddr, port: u16 },
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Protocol-level error.
    #[error("Protocol error: {0}")]
    Protocol(String),
}

/// Error from a scanning operation.
#[derive(Debug, Error)]
pub enum ScanError {
    /// No targets provided.
    #[error("No targets specified")]
    NoTargets,
    /// Rate limit exceeded.
    #[error("Rate limit exceeded: {0} PPS")]
    RateLimitExceeded(u32),
    /// Invalid scan configuration.
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Probe failed.
    #[error("Probe error: {0}")]
    Probe(#[from] ProbeError),
}

/// Error from a vulnerability source query.
#[derive(Debug, Error)]
pub enum VulnError {
    /// Database not initialised.
    #[error("Vulnerability database not initialised")]
    NotInitialised,
    /// No entries for the given CPE.
    #[error("No entries for CPE: {0}")]
    CpeNotFound(String),
    /// Storage error.
    #[error("Storage error: {0}")]
    Storage(String),
    /// Remote feed error.
    #[error("Feed fetch error: {0}")]
    FeedFetch(String),
}

/// Error from a reporter.
#[derive(Debug, Error)]
pub enum ReportError {
    /// I/O error writing output.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Template rendering failed.
    #[error("Template error: {0}")]
    Template(String),
    /// Serialisation failed.
    #[error("Serialisation error: {0}")]
    Serialisation(String),
}

/// Error from host discovery.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    /// Elevated privilege required (raw sockets).
    #[error("Privilege required for raw socket discovery")]
    PrivilegeRequired,
    /// Invalid target string.
    #[error("Invalid target: {0}")]
    InvalidTarget(String),
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Error from a storage operation.
#[derive(Debug, Error)]
pub enum StorageError {
    /// Record not found.
    #[error("Not found: {0}")]
    NotFound(String),
    /// Database error.
    #[error("Database error: {0}")]
    Database(String),
    /// Migration error.
    #[error("Migration error: {0}")]
    Migration(String),
}

// ── Context types ─────────────────────────────────────────────────────────────

/// Execution context passed to every probe invocation.
#[derive(Debug, Clone)]
pub struct ProbeContext {
    /// Max wait time in milliseconds.
    pub timeout_ms: u64,
    /// Max bytes to read for banner grabbing.
    pub max_banner_bytes: usize,
}

impl Default for ProbeContext {
    fn default() -> Self {
        Self { timeout_ms: 3_000, max_banner_bytes: 4_096 }
    }
}

/// Output format selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Machine-readable JSON.
    Json,
    /// Human-readable HTML report.
    Html,
    /// Lightweight Markdown summary.
    Markdown,
}

/// Observation of a single port from a scanner.
#[derive(Debug, Clone)]
pub struct PortObservation {
    /// IP address of the host.
    pub ip: IpAddr,
    /// Port number.
    pub port: u16,
    /// Protocol.
    pub protocol: Protocol,
    /// Observed state.
    pub state: PortState,
    /// Round-trip time in milliseconds.
    pub response_time_ms: u64,
}

/// Configuration for a TCP scan.
#[derive(Debug, Clone)]
pub struct TcpScanConfig {
    /// Connection timeout in milliseconds.
    pub timeout_ms: u64,
    /// Maximum concurrent TCP connections.
    pub max_concurrent: usize,
    /// Whether to grab the service banner.
    pub grab_banner: bool,
    /// Maximum banner read size in bytes.
    pub banner_max_bytes: usize,
}

impl Default for TcpScanConfig {
    fn default() -> Self {
        Self { timeout_ms: 3_000, max_concurrent: 1_000, grab_banner: true, banner_max_bytes: 4_096 }
    }
}

/// Configuration for a UDP scan.
#[derive(Debug, Clone)]
pub struct UdpScanConfig {
    /// Send/receive timeout in milliseconds.
    pub timeout_ms: u64,
    /// Retries per port.
    pub retries: u8,
    /// Maximum concurrent sockets.
    pub max_concurrent: usize,
}

impl Default for UdpScanConfig {
    fn default() -> Self {
        Self { timeout_ms: 5_000, retries: 2, max_concurrent: 500 }
    }
}

// ── Core traits ───────────────────────────────────────────────────────────────

/// A stateless protocol probe.
///
/// Probes are `Send + Sync`. Each call to [`Probe::probe`] is independent.
#[async_trait::async_trait]
pub trait Probe: Send + Sync {
    /// Human-readable probe name.
    fn name(&self) -> &'static str;
    /// Default port numbers this probe targets.
    fn default_ports(&self) -> &[u16];
    /// Protocol this probe operates on.
    fn protocol(&self) -> Protocol;

    /// Execute the probe.
    ///
    /// Returns `Some((result, confidence))` on a successful match,
    /// `None` when the service does not match this probe type.
    async fn probe(
        &self,
        target: &ProbeTarget,
        ctx: &ProbeContext,
    ) -> Result<Option<(ProbeResult, f32)>, ProbeError>;
}

/// TCP port scanner.
#[async_trait::async_trait]
pub trait TcpScanner: Send + Sync {
    /// Scan a range of TCP ports on the target host.
    async fn scan(
        &self,
        target: IpAddr,
        ports: &PortRange,
        config: &TcpScanConfig,
    ) -> Result<Vec<PortObservation>, ScanError>;
}

/// UDP port scanner.
#[async_trait::async_trait]
pub trait UdpScanner: Send + Sync {
    /// Scan a range of UDP ports on the target host.
    async fn scan(
        &self,
        target: IpAddr,
        ports: &PortRange,
        config: &UdpScanConfig,
    ) -> Result<Vec<PortObservation>, ScanError>;
}

/// Host liveness discoverer.
#[async_trait::async_trait]
pub trait HostDiscoverer: Send + Sync {
    /// Test whether the given IP address is alive.
    async fn is_alive(&self, ip: IpAddr) -> Result<bool, DiscoveryError>;
    /// Discovery method this implementation uses.
    fn method(&self) -> DiscoveryMethod;
}

/// Service and OS fingerprinter.
///
/// Fingerprinters are synchronous (CPU-bound). Use `tokio::task::spawn_blocking`
/// when calling from async code.
pub trait Fingerprinter: Send + Sync {
    /// Name of this fingerprinter.
    fn name(&self) -> &'static str;

    /// Attempt to identify a service from banner data.
    ///
    /// Returns `Some((fingerprint, confidence))` on a match.
    fn fingerprint_service(
        &self,
        banner: &BannerData,
    ) -> Option<(ServiceFingerprint, f32)>;

    /// Attempt to guess the OS from a probe result.
    fn fingerprint_os(&self, probe: &ProbeResult) -> Option<(OsFingerprint, f32)>;
}

/// Reporter — renders a [`ScanResult`] into a target format.
#[async_trait::async_trait]
pub trait Reporter: Send + Sync {
    /// Output format this reporter produces.
    fn format(&self) -> OutputFormat;

    /// Render the scan result to a String.
    async fn render_to_string(&self, result: &ScanResult) -> Result<String, ReportError>;
}

/// Vulnerability data source.
#[async_trait::async_trait]
pub trait VulnSource: Send + Sync {
    /// Name of this source.
    fn name(&self) -> &'static str;
    /// Priority — lower value = checked first.
    fn priority(&self) -> u8;

    /// Query for vulnerabilities matching the given CPE string.
    async fn query(&self, cpe: &CpeString) -> Result<Vec<Vulnerability>, VulnError>;
}

/// Top-level scan engine.
#[async_trait::async_trait]
pub trait ScanEngine: Send + Sync {
    /// Execute a complete scan against the given targets.
    async fn run(&self, targets: Vec<String>) -> Result<ScanResult, ScanError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_context_defaults() {
        let ctx = ProbeContext::default();
        assert_eq!(ctx.timeout_ms, 3_000);
        assert_eq!(ctx.max_banner_bytes, 4_096);
    }

    #[test]
    fn tcp_scan_config_defaults() {
        let cfg = TcpScanConfig::default();
        assert_eq!(cfg.max_concurrent, 1_000);
        assert!(cfg.grab_banner);
    }

    #[test]
    fn udp_scan_config_defaults() {
        let cfg = UdpScanConfig::default();
        assert_eq!(cfg.retries, 2);
    }

    #[test]
    fn port_observation_fields() {
        let obs = PortObservation {
            ip: "127.0.0.1".parse().unwrap(),
            port: 80,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            response_time_ms: 5,
        };
        assert_eq!(obs.port, 80);
    }
}

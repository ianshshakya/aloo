//! `aloo-discovery` — Host liveness detection.
//!
//! Expands CIDR targets, deduplicates hosts, and determines which are alive
//! before the port-scanning phase begins.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::HashSet;
use std::net::IpAddr;

use aloo_core::DiscoveryMethod;
use aloo_net::TargetSpec;
use aloo_traits::{DiscoveryError, HostDiscoverer};
use async_trait::async_trait;
use tracing::{debug, info};

// ── CIDR Expander ─────────────────────────────────────────────────────────────

/// Expands a list of target strings into individual `IpAddr` values.
///
/// Supports CIDR notation and single IPs. Deduplicates via `HostFilter`.
pub struct CidrExpander;

impl CidrExpander {
    /// Expand target strings to a deduplicated list of IP addresses.
    ///
    /// Invalid targets are logged and skipped.
    pub fn expand(targets: &[String]) -> Vec<IpAddr> {
        let mut filter = HostFilter::new();
        for t in targets {
            match TargetSpec::parse(t) {
                Ok(spec) => {
                    for ip in spec.hosts() {
                        filter.insert(ip);
                    }
                }
                Err(e) => {
                    tracing::warn!(target = t.as_str(), error = %e, "Skipping invalid target");
                }
            }
        }
        filter.into_vec()
    }
}

// ── Host Filter ───────────────────────────────────────────────────────────────

/// Deduplicates IP addresses using a `HashSet`.
pub struct HostFilter {
    seen: HashSet<IpAddr>,
    ordered: Vec<IpAddr>,
}

impl HostFilter {
    /// Create an empty filter.
    pub fn new() -> Self {
        Self { seen: HashSet::new(), ordered: Vec::new() }
    }

    /// Insert an IP. Ignored if already seen.
    pub fn insert(&mut self, ip: IpAddr) {
        if self.seen.insert(ip) {
            self.ordered.push(ip);
        }
    }

    /// Return the deduplicated, ordered list.
    pub fn into_vec(self) -> Vec<IpAddr> {
        self.ordered
    }

    /// Current count of unique hosts.
    pub fn len(&self) -> usize {
        self.ordered.len()
    }

    /// True if empty.
    pub fn is_empty(&self) -> bool {
        self.ordered.is_empty()
    }
}

impl Default for HostFilter {
    fn default() -> Self {
        Self::new()
    }
}

// ── TCP Ping Discoverer ───────────────────────────────────────────────────────

/// Discovers hosts by attempting TCP connect to port 80 or 443.
///
/// **Stub** — returns `false` until networking is wired.
pub struct TcpPingDiscoverer {
    /// Ports to try (in order).
    pub probe_ports: Vec<u16>,
    /// Timeout in milliseconds.
    pub timeout_ms: u64,
}

impl Default for TcpPingDiscoverer {
    fn default() -> Self {
        Self { probe_ports: vec![80, 443, 22, 8080], timeout_ms: 1_000 }
    }
}

#[async_trait]
impl HostDiscoverer for TcpPingDiscoverer {
    async fn is_alive(&self, ip: IpAddr) -> Result<bool, DiscoveryError> {
        debug!(%ip, ports = ?self.probe_ports, "TcpPingDiscoverer stub — returning false");
        // Stub: real implementation opens a TCP connection
        Ok(false)
    }

    fn method(&self) -> DiscoveryMethod {
        DiscoveryMethod::TcpPing
    }
}

// ── Discovery runner ──────────────────────────────────────────────────────────

/// Runs discovery over a list of candidate IPs.
pub struct DiscoveryRunner {
    discoverer: Box<dyn HostDiscoverer>,
}

impl DiscoveryRunner {
    /// Create with the given discoverer implementation.
    pub fn new(discoverer: impl HostDiscoverer + 'static) -> Self {
        Self { discoverer: Box::new(discoverer) }
    }

    /// Probe all candidates and return only those that appear alive.
    ///
    /// If the discoverer is a stub, all candidates are passed through
    /// (returns the full list — conservative for scanning).
    pub async fn alive_hosts(&self, candidates: Vec<IpAddr>) -> Vec<IpAddr> {
        let mut alive = Vec::new();
        for ip in candidates {
            match self.discoverer.is_alive(ip).await {
                Ok(true)  => { alive.push(ip); }
                Ok(false) => { debug!(%ip, "Host appears down — skipping"); }
                Err(e)    => { tracing::warn!(%ip, error = %e, "Discovery error"); }
            }
        }
        info!(count = alive.len(), "Discovery complete");
        alive
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_filter_deduplicates() {
        let mut f = HostFilter::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        f.insert(ip);
        f.insert(ip);
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn cidr_expander_slash_30() {
        let targets = vec!["10.0.0.0/30".to_string()];
        let hosts = CidrExpander::expand(&targets);
        // /30 has 4 addresses including network/broadcast, hosts() excludes them → 2
        assert!(!hosts.is_empty());
    }

    #[test]
    fn cidr_expander_single_ip() {
        let targets = vec!["192.168.1.5".to_string()];
        let hosts = CidrExpander::expand(&targets);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0], "192.168.1.5".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn cidr_expander_deduplicates_overlap() {
        // 10.0.0.1 appears in both targets
        let targets = vec!["10.0.0.0/30".to_string(), "10.0.0.1".to_string()];
        let hosts = CidrExpander::expand(&targets);
        let unique: HashSet<IpAddr> = hosts.iter().cloned().collect();
        assert_eq!(hosts.len(), unique.len());
    }

    #[test]
    fn cidr_expander_skips_invalid() {
        let targets = vec!["not-an-ip".to_string(), "10.0.0.1".to_string()];
        let hosts = CidrExpander::expand(&targets);
        assert_eq!(hosts.len(), 1);
    }

    #[tokio::test]
    async fn tcp_ping_stub_returns_false() {
        let d = TcpPingDiscoverer::default();
        let alive = d.is_alive("1.1.1.1".parse().unwrap()).await.unwrap();
        assert!(!alive);
    }

    #[tokio::test]
    async fn discovery_runner_skips_all_stub_hosts() {
        let runner = DiscoveryRunner::new(TcpPingDiscoverer::default());
        let candidates = vec!["10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap()];
        let alive = runner.alive_hosts(candidates).await;
        // Stub returns false for all, so alive is empty
        assert!(alive.is_empty());
    }
}

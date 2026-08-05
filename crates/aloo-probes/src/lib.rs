//! `aloo-probes` — Protocol probe implementations.
//!
//! Each probe is a stateless `Probe` implementor. All return stubs until
//! the networking milestone is complete.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::sync::Arc;

use aloo_core::{ProbeResult, ProbeTarget, Protocol};
use aloo_traits::{Probe, ProbeContext, ProbeError};
use async_trait::async_trait;
use tracing::debug;

// ── Banner grabber ────────────────────────────────────────────────────────────

/// Grabs the raw TCP banner from an open port.
pub struct BannerGrabber {
    /// Maximum bytes to read.
    pub max_bytes: usize,
}

impl Default for BannerGrabber {
    fn default() -> Self {
        Self { max_bytes: 4_096 }
    }
}

#[async_trait]
impl Probe for BannerGrabber {
    fn name(&self) -> &'static str { "banner" }
    fn default_ports(&self) -> &[u16] { &[] } // applies to all ports
    fn protocol(&self) -> Protocol { Protocol::Tcp }

    async fn probe(
        &self,
        target: &ProbeTarget,
        ctx: &ProbeContext,
    ) -> Result<Option<(ProbeResult, f32)>, ProbeError> {
        debug!(ip = %target.ip, port = target.port, "BannerGrabber stub");
        Ok(None)
    }
}

// ── HTTP probe ────────────────────────────────────────────────────────────────

/// Identifies HTTP/HTTPS services.
pub struct HttpProbe;

#[async_trait]
impl Probe for HttpProbe {
    fn name(&self) -> &'static str { "http" }
    fn default_ports(&self) -> &[u16] { &[80, 8080, 8000, 3000] }
    fn protocol(&self) -> Protocol { Protocol::Tcp }

    async fn probe(
        &self,
        target: &ProbeTarget,
        _ctx: &ProbeContext,
    ) -> Result<Option<(ProbeResult, f32)>, ProbeError> {
        debug!(ip = %target.ip, port = target.port, "HttpProbe stub");
        Ok(None)
    }
}

// ── SSH probe ─────────────────────────────────────────────────────────────────

/// Identifies SSH services via banner exchange.
pub struct SshProbe;

#[async_trait]
impl Probe for SshProbe {
    fn name(&self) -> &'static str { "ssh" }
    fn default_ports(&self) -> &[u16] { &[22, 2222] }
    fn protocol(&self) -> Protocol { Protocol::Tcp }

    async fn probe(
        &self,
        target: &ProbeTarget,
        _ctx: &ProbeContext,
    ) -> Result<Option<(ProbeResult, f32)>, ProbeError> {
        debug!(ip = %target.ip, port = target.port, "SshProbe stub");
        Ok(None)
    }
}

// ── FTP probe ─────────────────────────────────────────────────────────────────

/// Identifies FTP services.
pub struct FtpProbe;

#[async_trait]
impl Probe for FtpProbe {
    fn name(&self) -> &'static str { "ftp" }
    fn default_ports(&self) -> &[u16] { &[21] }
    fn protocol(&self) -> Protocol { Protocol::Tcp }

    async fn probe(
        &self,
        target: &ProbeTarget,
        _ctx: &ProbeContext,
    ) -> Result<Option<(ProbeResult, f32)>, ProbeError> {
        debug!(ip = %target.ip, port = target.port, "FtpProbe stub");
        Ok(None)
    }
}

// ── SMTP probe ────────────────────────────────────────────────────────────────

/// Identifies SMTP mail services.
pub struct SmtpProbe;

#[async_trait]
impl Probe for SmtpProbe {
    fn name(&self) -> &'static str { "smtp" }
    fn default_ports(&self) -> &[u16] { &[25, 465, 587] }
    fn protocol(&self) -> Protocol { Protocol::Tcp }

    async fn probe(
        &self,
        target: &ProbeTarget,
        _ctx: &ProbeContext,
    ) -> Result<Option<(ProbeResult, f32)>, ProbeError> {
        debug!(ip = %target.ip, port = target.port, "SmtpProbe stub");
        Ok(None)
    }
}

// ── SMB probe ─────────────────────────────────────────────────────────────────

/// Identifies SMB file sharing services.
pub struct SmbProbe;

#[async_trait]
impl Probe for SmbProbe {
    fn name(&self) -> &'static str { "smb" }
    fn default_ports(&self) -> &[u16] { &[139, 445] }
    fn protocol(&self) -> Protocol { Protocol::Tcp }

    async fn probe(
        &self,
        target: &ProbeTarget,
        _ctx: &ProbeContext,
    ) -> Result<Option<(ProbeResult, f32)>, ProbeError> {
        debug!(ip = %target.ip, port = target.port, "SmbProbe stub");
        Ok(None)
    }
}

// ── DNS probe ─────────────────────────────────────────────────────────────────

/// Identifies DNS services and tests zone transfers.
pub struct DnsProbe;

#[async_trait]
impl Probe for DnsProbe {
    fn name(&self) -> &'static str { "dns" }
    fn default_ports(&self) -> &[u16] { &[53] }
    fn protocol(&self) -> Protocol { Protocol::Udp }

    async fn probe(
        &self,
        target: &ProbeTarget,
        _ctx: &ProbeContext,
    ) -> Result<Option<(ProbeResult, f32)>, ProbeError> {
        debug!(ip = %target.ip, port = target.port, "DnsProbe stub");
        Ok(None)
    }
}

// ── Probe registry ────────────────────────────────────────────────────────────

/// Holds all registered probes and dispatches them by port number.
pub struct ProbeRegistry {
    probes: Vec<Arc<dyn Probe>>,
}

impl ProbeRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self { probes: Vec::new() }
    }

    /// Register a probe.
    pub fn register(&mut self, probe: impl Probe + 'static) {
        self.probes.push(Arc::new(probe));
    }

    /// Create a registry with all built-in probes registered.
    pub fn with_defaults() -> Self {
        let mut r = Self::new();
        r.register(BannerGrabber::default());
        r.register(HttpProbe);
        r.register(SshProbe);
        r.register(FtpProbe);
        r.register(SmtpProbe);
        r.register(SmbProbe);
        r.register(DnsProbe);
        r
    }

    /// Return probes that should run for the given port and protocol.
    pub fn probes_for(&self, port: u16, protocol: Protocol) -> Vec<Arc<dyn Probe>> {
        self.probes
            .iter()
            .filter(|p| {
                p.protocol() == protocol
                    && (p.default_ports().is_empty() || p.default_ports().contains(&port))
            })
            .cloned()
            .collect()
    }

    /// Total number of registered probes.
    pub fn len(&self) -> usize {
        self.probes.len()
    }

    /// True if no probes registered.
    pub fn is_empty(&self) -> bool {
        self.probes.is_empty()
    }
}

impl Default for ProbeRegistry {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_with_defaults_not_empty() {
        let r = ProbeRegistry::with_defaults();
        assert!(!r.is_empty());
    }

    #[test]
    fn probes_for_port_80_tcp() {
        let r = ProbeRegistry::with_defaults();
        let matching = r.probes_for(80, Protocol::Tcp);
        let names: Vec<&str> = matching.iter().map(|p| p.name()).collect();
        assert!(names.contains(&"http"));
        assert!(names.contains(&"banner"));
    }

    #[test]
    fn probes_for_port_53_udp() {
        let r = ProbeRegistry::with_defaults();
        let matching = r.probes_for(53, Protocol::Udp);
        let names: Vec<&str> = matching.iter().map(|p| p.name()).collect();
        assert!(names.contains(&"dns"));
    }

    #[tokio::test]
    async fn banner_grabber_returns_none_stub() {
        let probe = BannerGrabber::default();
        let target = ProbeTarget::tcp("127.0.0.1".parse().unwrap(), 80);
        let result = probe.probe(&target, &ProbeContext::default()).await.unwrap();
        assert!(result.is_none());
    }
}

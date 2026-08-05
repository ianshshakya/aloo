//! `aloo-tls` — TLS inspection subsystem.
//!
//! Analyses TLS handshakes, cipher suites, and X.509 certificates.
//! Network I/O is stubbed — rustls integration is a later milestone.

#![forbid(unsafe_code)]
#![warn(missing_docs)]


use aloo_core::{Certificate, CipherStrength, ProbeResult, ProbeTarget, Protocol};
use aloo_traits::{Probe, ProbeContext, ProbeError};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use thiserror::Error;
use tracing::debug;

/// TLS inspection errors.
#[derive(Debug, Error)]
pub enum TlsError {
    /// TLS handshake failed.
    #[error("TLS handshake failed: {0}")]
    HandshakeFailed(String),
    /// Certificate parse error.
    #[error("Certificate parse error: {0}")]
    CertParse(String),
    /// Certificate is expired.
    #[error("Certificate expired: common_name={cn}, expired={days} days ago")]
    CertExpired { cn: String, days: i64 },
    /// Certificate is self-signed.
    #[error("Self-signed certificate: {cn}")]
    SelfSigned { cn: String },
}

// ── Cipher evaluator ──────────────────────────────────────────────────────────

/// Evaluates cipher suite names against known strength ratings.
pub struct CipherEvaluator;

impl CipherEvaluator {
    /// Classify a cipher suite name string.
    pub fn evaluate(cipher: &str) -> CipherStrength {
        let c = cipher.to_ascii_uppercase();
        // Known-weak suites
        if c.contains("RC4")
            || c.contains("DES")
            || c.contains("NULL")
            || c.contains("EXPORT")
            || c.contains("ADH")
            || c.contains("AECDH")
        {
            return CipherStrength::Weak;
        }
        // Modern AEAD suites
        if c.contains("AES_128_GCM")
            || c.contains("AES_256_GCM")
            || c.contains("CHACHA20_POLY1305")
            || c.contains("GCM_SHA")
        {
            return CipherStrength::Strong;
        }
        // Default: acceptable
        CipherStrength::Acceptable
    }
}

// ── Certificate analyser ──────────────────────────────────────────────────────

/// Analyses X.509 certificate fields.
pub struct CertAnalyser;

impl CertAnalyser {
    /// Check whether a certificate is currently expired.
    pub fn is_expired(cert: &Certificate) -> bool {
        cert.is_expired()
    }

    /// Check whether a certificate is self-signed.
    pub fn is_self_signed(cert: &Certificate) -> bool {
        cert.self_signed
    }

    /// Days until expiry (negative = already expired).
    pub fn days_until_expiry(cert: &Certificate) -> i64 {
        cert.days_until_expiry()
    }

    /// Return a human-readable assessment of the certificate.
    pub fn assess(cert: &Certificate) -> Vec<String> {
        let mut findings = Vec::new();
        if cert.is_expired() {
            findings.push(format!(
                "Certificate expired {} days ago",
                -cert.days_until_expiry()
            ));
        } else if cert.days_until_expiry() < 30 {
            findings.push(format!(
                "Certificate expires in {} days",
                cert.days_until_expiry()
            ));
        }
        if cert.self_signed {
            findings.push("Certificate is self-signed".to_string());
        }
        findings
    }
}

// ── TLS Inspector (stub Probe) ─────────────────────────────────────────────────

/// Identifies TLS services and captures certificate / cipher information.
///
/// **Stub** — returns `None` until rustls is integrated.
pub struct TlsInspector;

#[async_trait]
impl Probe for TlsInspector {
    fn name(&self) -> &'static str { "tls" }
    fn default_ports(&self) -> &[u16] { &[443, 8443, 465, 993, 995, 5061] }
    fn protocol(&self) -> Protocol { Protocol::Tcp }

    async fn probe(
        &self,
        target: &ProbeTarget,
        _ctx: &ProbeContext,
    ) -> Result<Option<(ProbeResult, f32)>, ProbeError> {
        debug!(ip = %target.ip, port = target.port, "TlsInspector stub — returning None");
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cert(expired: bool, self_signed: bool) -> Certificate {
        let now = Utc::now();
        Certificate {
            common_name: "example.com".to_string(),
            subject_alt_names: vec!["www.example.com".to_string()],
            issuer: if self_signed { "example.com".to_string() } else { "Let's Encrypt".to_string() },
            not_before: now - Duration::days(365),
            not_after: if expired { now - Duration::days(1) } else { now + Duration::days(90) },
            self_signed,
            serial: "01020304".to_string(),
        }
    }

    #[test]
    fn cipher_evaluator_aes_gcm_is_strong() {
        assert_eq!(CipherEvaluator::evaluate("TLS_AES_256_GCM_SHA384"), CipherStrength::Strong);
    }

    #[test]
    fn cipher_evaluator_rc4_is_weak() {
        assert_eq!(CipherEvaluator::evaluate("RC4-SHA"), CipherStrength::Weak);
    }

    #[test]
    fn cipher_evaluator_3des_is_acceptable() {
        assert_eq!(CipherEvaluator::evaluate("ECDHE-RSA-DES-CBC3-SHA"), CipherStrength::Acceptable);
    }

    #[test]
    fn cert_analyser_expired_cert() {
        let cert = make_cert(true, false);
        assert!(CertAnalyser::is_expired(&cert));
        let findings = CertAnalyser::assess(&cert);
        assert!(!findings.is_empty());
        assert!(findings[0].contains("expired"));
    }

    #[test]
    fn cert_analyser_self_signed() {
        let cert = make_cert(false, true);
        assert!(CertAnalyser::is_self_signed(&cert));
        let findings = CertAnalyser::assess(&cert);
        assert!(findings.iter().any(|f| f.contains("self-signed")));
    }

    #[test]
    fn cert_analyser_valid_cert_no_findings() {
        let cert = make_cert(false, false);
        assert!(!CertAnalyser::is_expired(&cert));
        assert!(!CertAnalyser::is_self_signed(&cert));
        assert!(CertAnalyser::assess(&cert).is_empty());
    }

    #[tokio::test]
    async fn tls_inspector_stub_returns_none() {
        let probe = TlsInspector;
        let target = ProbeTarget::tcp("10.0.0.1".parse().unwrap(), 443);
        let result = probe.probe(&target, &ProbeContext::default()).await.unwrap();
        assert!(result.is_none());
    }
}

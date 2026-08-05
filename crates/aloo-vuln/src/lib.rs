//! `aloo-vuln` — Vulnerability correlation engine.
//!
//! Maps CPE strings to known CVEs and aggregates results from multiple sources.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::sync::Arc;

use aloo_core::{CpeString, CvssSeverity, ServiceFingerprint, Vulnerability};
use aloo_traits::{VulnError, VulnSource};
use async_trait::async_trait;
use tracing::debug;

// ── CPE Mapper ────────────────────────────────────────────────────────────────

/// Maps service name + version strings to CPE 2.3 identifiers.
pub struct CpeMapper;

impl CpeMapper {
    /// Build a CPE string from a service name and optional version.
    ///
    /// Returns `None` if the service name is not in the known mapping.
    pub fn map(name: &str, version: Option<&str>) -> Option<CpeString> {
        let ver = version.unwrap_or("*");
        let cpe = match name.to_ascii_lowercase().as_str() {
            "ssh" | "openssh" => {
                format!("cpe:2.3:a:openbsd:openssh:{ver}:*:*:*:*:*:*:*")
            }
            "http" | "apache" | "apache httpd" => {
                format!("cpe:2.3:a:apache:http_server:{ver}:*:*:*:*:*:*:*")
            }
            "nginx" => {
                format!("cpe:2.3:a:nginx:nginx:{ver}:*:*:*:*:*:*:*")
            }
            "mysql" => {
                format!("cpe:2.3:a:oracle:mysql:{ver}:*:*:*:*:*:*:*")
            }
            "postgresql" | "postgres" => {
                format!("cpe:2.3:a:postgresql:postgresql:{ver}:*:*:*:*:*:*:*")
            }
            "ftp" | "vsftpd" => {
                format!("cpe:2.3:a:vsftpd_project:vsftpd:{ver}:*:*:*:*:*:*:*")
            }
            "smtp" | "postfix" => {
                format!("cpe:2.3:a:postfix:postfix:{ver}:*:*:*:*:*:*:*")
            }
            "rdp" | "remote desktop" => {
                format!("cpe:2.3:a:microsoft:remote_desktop_services:{ver}:*:*:*:*:*:*:*")
            }
            "smb" | "samba" => {
                format!("cpe:2.3:a:samba:samba:{ver}:*:*:*:*:*:*:*")
            }
            _ => return None,
        };
        Some(CpeString::new(cpe))
    }

    /// Derive a CPE from a `ServiceFingerprint`, if possible.
    pub fn from_fingerprint(fp: &ServiceFingerprint) -> Option<CpeString> {
        // Prefer explicit CPE in the fingerprint
        if let Some(cpe) = &fp.cpe {
            return Some(cpe.clone());
        }
        let name = fp.product.as_deref().unwrap_or(&fp.name);
        Self::map(name, fp.version.as_deref())
    }
}

// ── CVSS Scorer ───────────────────────────────────────────────────────────────

/// Converts raw CVSS scores to `CvssSeverity`.
pub struct CvssScorer;

impl CvssScorer {
    /// Classify a CVSS base score.
    pub fn score_to_severity(score: f32) -> CvssSeverity {
        CvssSeverity::from_score(score)
    }

    /// Returns true if the score is actionable (Medium or above).
    pub fn is_actionable(score: f32) -> bool {
        score >= 4.0
    }
}

// ── Local Vuln Correlator ─────────────────────────────────────────────────────

/// In-process vulnerability source (returns empty — NVD feed pending).
pub struct LocalVulnCorrelator;

#[async_trait]
impl VulnSource for LocalVulnCorrelator {
    fn name(&self) -> &'static str { "local-correlator" }
    fn priority(&self) -> u8 { 100 }

    async fn query(&self, cpe: &CpeString) -> Result<Vec<Vulnerability>, VulnError> {
        debug!(cpe = %cpe, "LocalVulnCorrelator stub — returning empty");
        Ok(vec![])
    }
}

// ── Vuln Engine ───────────────────────────────────────────────────────────────

/// Queries all registered vulnerability sources and aggregates results.
pub struct VulnEngine {
    sources: Vec<Arc<dyn VulnSource>>,
}

impl VulnEngine {
    /// Create with the given sources.
    pub fn new(sources: Vec<Arc<dyn VulnSource>>) -> Self {
        Self { sources }
    }

    /// Create with only the built-in local correlator.
    pub fn with_local_only() -> Self {
        Self::new(vec![Arc::new(LocalVulnCorrelator)])
    }

    /// Query all sources for the given CPE, merging and deduplicating results.
    pub async fn query_all(&self, cpe: &CpeString) -> Vec<Vulnerability> {
        let mut all = Vec::new();
        let mut sources: Vec<&Arc<dyn VulnSource>> = self.sources.iter().collect();
        sources.sort_by_key(|s| s.priority());

        for source in sources {
            match source.query(cpe).await {
                Ok(mut vulns) => all.append(&mut vulns),
                Err(e) => {
                    tracing::warn!(source = source.name(), error = %e, "Vuln source query failed");
                }
            }
        }

        // Deduplicate by CVE ID
        let mut seen = std::collections::HashSet::new();
        all.retain(|v| seen.insert(v.cve_id.clone()));
        all
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpe_mapper_known_services() {
        let cpe = CpeMapper::map("ssh", Some("9.3")).unwrap();
        assert!(cpe.0.contains("openssh"));
        assert!(cpe.0.contains("9.3"));
    }

    #[test]
    fn cpe_mapper_nginx() {
        let cpe = CpeMapper::map("nginx", Some("1.24.0")).unwrap();
        assert!(cpe.0.contains("nginx"));
    }

    #[test]
    fn cpe_mapper_unknown_returns_none() {
        assert!(CpeMapper::map("unknown-service-xyz", None).is_none());
    }

    #[test]
    fn cpe_mapper_default_version_wildcard() {
        let cpe = CpeMapper::map("mysql", None).unwrap();
        assert!(cpe.0.contains(":*:"));
    }

    #[test]
    fn cvss_scorer_boundaries() {
        assert_eq!(CvssScorer::score_to_severity(9.5), CvssSeverity::Critical);
        assert_eq!(CvssScorer::score_to_severity(7.0), CvssSeverity::High);
        assert_eq!(CvssScorer::score_to_severity(5.0), CvssSeverity::Medium);
        assert_eq!(CvssScorer::score_to_severity(2.0), CvssSeverity::Low);
        assert_eq!(CvssScorer::score_to_severity(0.0), CvssSeverity::None);
    }

    #[test]
    fn cvss_scorer_actionable() {
        assert!(CvssScorer::is_actionable(4.0));
        assert!(!CvssScorer::is_actionable(3.9));
    }

    #[tokio::test]
    async fn local_correlator_returns_empty() {
        let cpe = CpeString::new("cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*");
        let result = LocalVulnCorrelator.query(&cpe).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn vuln_engine_aggregates_empty() {
        let engine = VulnEngine::with_local_only();
        let cpe = CpeString::new("cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*");
        let results = engine.query_all(&cpe).await;
        assert!(results.is_empty());
    }
}

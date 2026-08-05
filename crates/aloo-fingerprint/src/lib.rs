//! `aloo-fingerprint` — Service and OS fingerprinting engine.
//!
//! Matches banner data against regex patterns to identify services.
//! Patterns are hard-coded for now; a real database will be added later.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use aloo_core::{BannerData, CpeString, OsFingerprint, ProbeResult, ServiceFingerprint};
use aloo_traits::Fingerprinter;
use regex::Regex;
use std::sync::OnceLock;

// ── Pattern database ──────────────────────────────────────────────────────────

struct ServicePattern {
    name:    &'static str,
    product: &'static str,
    pattern: &'static str,
    cpe:     &'static str,
}

static PATTERNS: &[ServicePattern] = &[
    ServicePattern {
        name: "ssh", product: "OpenSSH",
        pattern: r"SSH-(?P<proto>[\d.]+)-OpenSSH_(?P<ver>[\d.p]+\S*)",
        cpe: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
    },
    ServicePattern {
        name: "http", product: "Apache httpd",
        pattern: r"Apache/(?P<ver>[\d.]+)",
        cpe: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
    },
    ServicePattern {
        name: "http", product: "nginx",
        pattern: r"nginx/(?P<ver>[\d.]+)",
        cpe: "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
    },
    ServicePattern {
        name: "ftp", product: "vsftpd",
        pattern: r"220.*vsftpd\s+(?P<ver>[\d.]+)",
        cpe: "cpe:2.3:a:vsftpd_project:vsftpd:*:*:*:*:*:*:*:*",
    },
    ServicePattern {
        name: "smtp", product: "Postfix SMTP",
        pattern: r"220.*Postfix",
        cpe: "cpe:2.3:a:postfix:postfix:*:*:*:*:*:*:*:*",
    },
    ServicePattern {
        name: "mysql", product: "MySQL",
        pattern: r"(?i)mysql",
        cpe: "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*",
    },
    ServicePattern {
        name: "rdp", product: "Remote Desktop",
        pattern: r"\x03\x00",
        cpe: "cpe:2.3:a:microsoft:remote_desktop:*:*:*:*:*:*:*:*",
    },
];

/// Returns the compiled service patterns (lazily compiled on first call).
fn compiled_patterns() -> &'static Vec<(Regex, &'static ServicePattern)> {
    static COMPILED: OnceLock<Vec<(Regex, &'static ServicePattern)>> = OnceLock::new();
    COMPILED.get_or_init(|| {
        PATTERNS
            .iter()
            .filter_map(|p| Regex::new(p.pattern).ok().map(|r| (r, p)))
            .collect()
    })
}

// ── Service matcher ───────────────────────────────────────────────────────────

/// Matches service banners against a pattern database.
pub struct ServiceMatcher;

impl ServiceMatcher {
    /// Match a banner against all known patterns.
    ///
    /// Returns `Some((fingerprint, confidence))` for the best match.
    pub fn match_banner(banner: &BannerData) -> Option<(ServiceFingerprint, f32)> {
        let text = banner.text.as_deref().unwrap_or("");
        for (re, pat) in compiled_patterns() {
            if let Some(caps) = re.captures(text) {
                let version = caps.name("ver").map(|m| m.as_str().to_string());
                let fp = ServiceFingerprint {
                    name:       pat.name.to_string(),
                    version,
                    product:    Some(pat.product.to_string()),
                    extra_info: None,
                    confidence: 0.85,
                    cpe:        Some(CpeString::new(pat.cpe)),
                };
                return Some((fp, 0.85));
            }
        }
        None
    }
}

impl Fingerprinter for ServiceMatcher {
    fn name(&self) -> &'static str { "service-matcher" }

    fn fingerprint_service(&self, banner: &BannerData) -> Option<(ServiceFingerprint, f32)> {
        Self::match_banner(banner)
    }

    fn fingerprint_os(&self, _probe: &ProbeResult) -> Option<(OsFingerprint, f32)> {
        None // Delegate to OsFingerprintMatcher
    }
}

// ── OS fingerprinter ──────────────────────────────────────────────────────────

struct OsPattern {
    name:    &'static str,
    family:  &'static str,
    pattern: &'static str,
}

static OS_PATTERNS: &[OsPattern] = &[
    OsPattern { name: "Linux",   family: "unix",    pattern: r"(?i)ubuntu|debian|centos|redhat|fedora|arch" },
    OsPattern { name: "Windows", family: "windows", pattern: r"(?i)windows|microsoft-iis|win32" },
    OsPattern { name: "macOS",   family: "unix",    pattern: r"(?i)darwin|macos|mac os" },
    OsPattern { name: "FreeBSD", family: "unix",    pattern: r"(?i)freebsd" },
];

/// Matches OS fingerprints from probe banner data.
pub struct OsFingerprintMatcher;

impl OsFingerprintMatcher {
    /// Attempt OS identification from a text banner.
    pub fn match_text(text: &str) -> Option<(OsFingerprint, f32)> {
        static OS_COMPILED: OnceLock<Vec<(Regex, &'static OsPattern)>> = OnceLock::new();
        let compiled = OS_COMPILED.get_or_init(|| {
            OS_PATTERNS
                .iter()
                .filter_map(|p| Regex::new(p.pattern).ok().map(|r| (r, p)))
                .collect()
        });
        for (re, pat) in compiled {
            if re.is_match(text) {
                let fp = OsFingerprint {
                    name:       pat.name.to_string(),
                    family:     pat.family.to_string(),
                    generation: None,
                    accuracy:   0.6,
                    cpe:        None,
                };
                return Some((fp, 0.6));
            }
        }
        None
    }
}

impl Fingerprinter for OsFingerprintMatcher {
    fn name(&self) -> &'static str { "os-matcher" }

    fn fingerprint_service(&self, _banner: &BannerData) -> Option<(ServiceFingerprint, f32)> {
        None
    }

    fn fingerprint_os(&self, probe: &ProbeResult) -> Option<(OsFingerprint, f32)> {
        if let Some(banner) = &probe.banner {
            if let Some(text) = &banner.text {
                return Self::match_text(text);
            }
        }
        None
    }
}

// ── Fingerprint database facade ───────────────────────────────────────────────

/// Facade that runs all fingerprinters in order and returns the best match.
pub struct FingerprintDb {
    fingerprinters: Vec<Box<dyn Fingerprinter>>,
}

impl FingerprintDb {
    /// Create with the default set of fingerprinters.
    pub fn with_defaults() -> Self {
        Self {
            fingerprinters: vec![
                Box::new(ServiceMatcher),
                Box::new(OsFingerprintMatcher),
            ],
        }
    }

    /// Identify a service from banner data (returns highest confidence match).
    pub fn identify_service(&self, banner: &BannerData) -> Option<(ServiceFingerprint, f32)> {
        self.fingerprinters
            .iter()
            .filter_map(|fp| fp.fingerprint_service(banner))
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
    }

    /// Identify OS from a probe result.
    pub fn identify_os(&self, probe: &ProbeResult) -> Option<(OsFingerprint, f32)> {
        self.fingerprinters
            .iter()
            .filter_map(|fp| fp.fingerprint_os(probe))
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn banner(text: &str) -> BannerData {
        BannerData::from_bytes(text.as_bytes())
    }

    #[test]
    fn matches_openssh_banner() {
        let b = banner("SSH-2.0-OpenSSH_9.3\r\n");
        let (fp, conf) = ServiceMatcher::match_banner(&b).unwrap();
        assert_eq!(fp.name, "ssh");
        assert_eq!(fp.version.as_deref(), Some("9.3"));
        assert!(conf > 0.5);
    }

    #[test]
    fn matches_nginx_banner() {
        let b = banner("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n");
        let (fp, _) = ServiceMatcher::match_banner(&b).unwrap();
        assert_eq!(fp.name, "http");
        assert!(fp.product.as_deref().unwrap_or("").contains("nginx"));
    }

    #[test]
    fn no_match_returns_none() {
        let b = banner("\x00\x01\x02\x03");
        assert!(ServiceMatcher::match_banner(&b).is_none());
    }

    #[test]
    fn os_matcher_windows() {
        let result = OsFingerprintMatcher::match_text("Server: Microsoft-IIS/10.0");
        let (fp, _) = result.unwrap();
        assert_eq!(fp.family, "windows");
    }

    #[test]
    fn os_matcher_linux() {
        let result = OsFingerprintMatcher::match_text("Ubuntu 22.04 LTS");
        let (fp, _) = result.unwrap();
        assert_eq!(fp.name, "Linux");
    }

    #[test]
    fn fingerprint_db_identifies_ssh() {
        let db = FingerprintDb::with_defaults();
        let b = banner("SSH-2.0-OpenSSH_8.9\r\n");
        let (fp, _) = db.identify_service(&b).unwrap();
        assert_eq!(fp.name, "ssh");
    }
}

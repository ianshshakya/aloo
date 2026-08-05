//! All domain value types.

use std::net::IpAddr;
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::id::{HostId, PortId, SessionId};

// ── Enumerations ─────────────────────────────────────────────────────────────

/// Network transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Protocol {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
    /// Internet Control Message Protocol.
    Icmp,
    /// Stream Control Transmission Protocol.
    Sctp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp  => write!(f, "TCP"),
            Protocol::Udp  => write!(f, "UDP"),
            Protocol::Icmp => write!(f, "ICMP"),
            Protocol::Sctp => write!(f, "SCTP"),
        }
    }
}

/// Observed state of a scanned port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortState {
    /// Port is open and accepting connections.
    Open,
    /// Port actively refused connection (RST).
    Closed,
    /// No response; firewall may be dropping packets.
    Filtered,
    /// Cannot distinguish open from filtered without privilege.
    OpenFiltered,
    /// Cannot distinguish closed from filtered.
    ClosedFiltered,
    /// Completely unresponsive.
    Unresponsive,
}

/// Method used to discover a host as alive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryMethod {
    /// ICMP echo request.
    IcmpEcho,
    /// TCP connect to common ports.
    TcpPing,
    /// ARP sweep (LAN only).
    ArpSweep,
    /// Explicitly provided by the user; not probed.
    UserSpecified,
}

/// Overall status of a scan session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    /// Not yet started.
    Pending,
    /// Currently running.
    Running,
    /// Finished successfully.
    Completed,
    /// Encountered a fatal error.
    Failed,
    /// Cancelled by the user.
    Interrupted,
}

/// CVSS v3.1 severity classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CvssSeverity {
    /// Score 0.0 — no impact.
    None,
    /// Score 0.1–3.9.
    Low,
    /// Score 4.0–6.9.
    Medium,
    /// Score 7.0–8.9.
    High,
    /// Score 9.0–10.0.
    Critical,
}

impl CvssSeverity {
    /// Derive severity from a raw CVSS v3.1 base score.
    pub fn from_score(score: f32) -> Self {
        match score {
            s if s >= 9.0 => CvssSeverity::Critical,
            s if s >= 7.0 => CvssSeverity::High,
            s if s >= 4.0 => CvssSeverity::Medium,
            s if s > 0.0  => CvssSeverity::Low,
            _             => CvssSeverity::None,
        }
    }
}

/// TLS cipher suite strength classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CipherStrength {
    /// Deprecated algorithms (RC4, DES, export suites).
    Weak,
    /// Acceptable but not modern (3DES, non-AEAD CBC).
    Acceptable,
    /// Modern AEAD suites (AES-GCM, ChaCha20-Poly1305).
    Strong,
}

/// Preset scan profiles controlling depth and speed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ScanProfileKind {
    /// Top 1024 ports, fast timeouts.
    Quick,
    /// All 65535 ports, all probes enabled.
    #[default]
    Full,
    /// Slow rate, minimal footprint to avoid IDS.
    Stealth,
    /// UDP-only scan.
    UdpOnly,
    /// User-defined; read from config.
    Custom,
}

// ── Value types ───────────────────────────────────────────────────────────────

/// A CPE 2.3 formatted string (e.g. `cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CpeString(pub String);

impl CpeString {
    /// Wrap a string as a CPE.
    pub fn new(s: impl Into<String>) -> Self {
        CpeString(s.into())
    }
}

impl std::fmt::Display for CpeString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// A range of TCP/UDP port numbers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRange {
    /// Inclusive `(start, end)` pairs.
    pub ranges: Vec<(u16, u16)>,
}

impl PortRange {
    /// Ports 1–1024.
    pub fn top_1000() -> Self {
        Self { ranges: vec![(1, 1024)] }
    }

    /// All 65535 ports.
    pub fn all() -> Self {
        Self { ranges: vec![(1, 65535)] }
    }

    /// Single port.
    pub fn single(port: u16) -> Self {
        Self { ranges: vec![(port, port)] }
    }

    /// Returns true if the port falls in any range.
    pub fn contains(&self, port: u16) -> bool {
        self.ranges.iter().any(|(s, e)| port >= *s && port <= *e)
    }

    /// Lazy iterator over all port numbers.
    pub fn iter(&self) -> impl Iterator<Item = u16> + '_ {
        self.ranges.iter().flat_map(|(s, e)| *s..=*e)
    }

    /// Total port count.
    pub fn count(&self) -> usize {
        self.ranges.iter().map(|(s, e)| (*e as usize) - (*s as usize) + 1).sum()
    }
}

impl Default for PortRange {
    fn default() -> Self {
        Self::top_1000()
    }
}

// ── Fingerprint types ─────────────────────────────────────────────────────────

/// Identified service running on a port.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceFingerprint {
    /// Common service name (e.g. `ssh`, `http`, `mysql`).
    pub name: String,
    /// Detected version string.
    pub version: Option<String>,
    /// Product name (e.g. `OpenSSH`, `Apache httpd`).
    pub product: Option<String>,
    /// Extra info string.
    pub extra_info: Option<String>,
    /// Confidence score 0.0–1.0.
    pub confidence: f32,
    /// CPE 2.3 string if derivable.
    pub cpe: Option<CpeString>,
}

/// Operating system fingerprint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OsFingerprint {
    /// OS name (e.g. `Linux`, `Windows`).
    pub name: String,
    /// OS family (e.g. `unix`, `windows`).
    pub family: String,
    /// Generation / version string.
    pub generation: Option<String>,
    /// Detection accuracy 0.0–1.0.
    pub accuracy: f32,
    /// CPE string if known.
    pub cpe: Option<CpeString>,
}

// ── TLS types ─────────────────────────────────────────────────────────────────

/// Subset of X.509 certificate fields relevant for scanning.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Certificate {
    /// Subject common name.
    pub common_name: String,
    /// Subject Alternative Names.
    pub subject_alt_names: Vec<String>,
    /// Issuer distinguished name.
    pub issuer: String,
    /// Validity start.
    pub not_before: DateTime<Utc>,
    /// Validity end.
    pub not_after: DateTime<Utc>,
    /// True if the certificate is self-signed.
    pub self_signed: bool,
    /// Serial number as hex string.
    pub serial: String,
}

impl Certificate {
    /// Returns true if the certificate is currently expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.not_after
    }

    /// Days until expiry (negative if expired).
    pub fn days_until_expiry(&self) -> i64 {
        (self.not_after - Utc::now()).num_days()
    }
}

/// Results of a TLS handshake and certificate inspection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TlsReport {
    /// Negotiated TLS version (e.g. `TLSv1.3`).
    pub tls_version: String,
    /// Negotiated cipher suite.
    pub cipher_suite: String,
    /// Evaluated cipher strength.
    pub cipher_strength: CipherStrength,
    /// Server certificate chain leaf.
    pub certificate: Certificate,
}

// ── Vulnerability types ───────────────────────────────────────────────────────

/// A correlated vulnerability record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Vulnerability {
    /// CVE identifier.
    pub cve_id: String,
    /// Base CVSS v3.1 score.
    pub cvss_score: f32,
    /// Derived severity.
    pub severity: CvssSeverity,
    /// Short description.
    pub description: String,
    /// CPE that matched.
    pub cpe: CpeString,
    /// NVD publication date.
    pub published: DateTime<Utc>,
    /// NVD last-modified date.
    pub last_modified: DateTime<Utc>,
}

// ── Probe types ───────────────────────────────────────────────────────────────

/// A target for a probe operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeTarget {
    /// Target IP address.
    pub ip: IpAddr,
    /// Target port.
    pub port: u16,
    /// Protocol to use.
    pub protocol: Protocol,
}

impl ProbeTarget {
    /// TCP probe target.
    pub fn tcp(ip: IpAddr, port: u16) -> Self {
        Self { ip, port, protocol: Protocol::Tcp }
    }
    /// UDP probe target.
    pub fn udp(ip: IpAddr, port: u16) -> Self {
        Self { ip, port, protocol: Protocol::Udp }
    }
}

/// Raw banner data grabbed from a service.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BannerData {
    /// Raw bytes (hex-encoded in JSON).
    pub raw_hex: String,
    /// UTF-8 text interpretation.
    pub text: Option<String>,
    /// Heuristic protocol hint from the banner content.
    pub protocol_hint: Option<String>,
}

impl BannerData {
    /// Construct from raw bytes, attempting UTF-8 decoding.
    pub fn from_bytes(raw: &[u8]) -> Self {
        let raw_hex: String = raw.iter().map(|b| format!("{:02x}", b)).collect();
        let text = std::str::from_utf8(raw).ok().map(str::to_string);
        let protocol_hint = Self::infer_protocol(raw);
        Self { raw_hex, text, protocol_hint }
    }

    fn infer_protocol(data: &[u8]) -> Option<String> {
        if data.starts_with(b"SSH-")  { return Some("ssh".into()); }
        if data.starts_with(b"HTTP") || data.starts_with(b"HTTP/") {
            return Some("http".into());
        }
        if data.starts_with(b"220 ") { return Some("ftp-or-smtp".into()); }
        if data.starts_with(b"+OK")  { return Some("pop3".into()); }
        None
    }
}

/// Result of a single probe operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    /// The target that was probed.
    pub target: ProbeTarget,
    /// Grabbed banner data.
    pub banner: Option<BannerData>,
    /// Identified service.
    pub service: Option<ServiceFingerprint>,
    /// TLS analysis (when applicable).
    pub tls: Option<TlsReport>,
    /// Round-trip time in milliseconds.
    pub response_time_ms: u64,
}

// ── Host / Port / Session ─────────────────────────────────────────────────────

/// A discovered and scanned host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    /// Unique host identifier.
    pub id: HostId,
    /// Parent scan session.
    pub session_id: SessionId,
    /// IP address.
    pub ip: IpAddr,
    /// Resolved hostname.
    pub hostname: Option<String>,
    /// OS fingerprint.
    pub os_fingerprint: Option<OsFingerprint>,
    /// MAC address (LAN discovery only).
    pub mac_address: Option<String>,
    /// When this host was first discovered.
    pub discovered_at: DateTime<Utc>,
    /// Discovery method used.
    pub discovery_method: DiscoveryMethod,
    /// All scanned ports.
    pub ports: Vec<Port>,
}

/// A scanned port on a host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Port {
    /// Unique port identifier.
    pub id: PortId,
    /// Parent host.
    pub host_id: HostId,
    /// Port number.
    pub number: u16,
    /// Protocol.
    pub protocol: Protocol,
    /// Observed state.
    pub state: PortState,
    /// Identified service.
    pub service: Option<ServiceFingerprint>,
    /// Banner text.
    pub banner: Option<String>,
    /// TLS information.
    pub tls: Option<TlsReport>,
    /// Correlated vulnerabilities.
    pub vulnerabilities: Vec<Vulnerability>,
}

/// Metadata for a scan session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSession {
    /// Unique session identifier.
    pub id: SessionId,
    /// When the session started.
    pub started_at: DateTime<Utc>,
    /// When the session ended.
    pub completed_at: Option<DateTime<Utc>>,
    /// Current lifecycle status.
    pub status: ScanStatus,
    /// Raw target strings provided by the user.
    pub targets: Vec<String>,
}

impl ScanSession {
    /// Create a new pending session.
    pub fn new(targets: Vec<String>) -> Self {
        Self {
            id: SessionId::new(),
            started_at: Utc::now(),
            completed_at: None,
            status: ScanStatus::Pending,
            targets,
        }
    }

    /// Transition the session to running.
    pub fn start(&mut self) {
        self.status = ScanStatus::Running;
    }

    /// Mark the session as successfully completed.
    pub fn complete(&mut self) {
        self.completed_at = Some(Utc::now());
        self.status = ScanStatus::Completed;
    }

    /// Mark the session as interrupted.
    pub fn interrupt(&mut self) {
        self.completed_at = Some(Utc::now());
        self.status = ScanStatus::Interrupted;
    }
}

/// The full result of a completed scan session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Session metadata.
    pub session: ScanSession,
    /// All discovered hosts.
    pub hosts: Vec<Host>,
}

impl ScanResult {
    /// Total open ports across all hosts.
    pub fn total_open_ports(&self) -> usize {
        self.hosts
            .iter()
            .flat_map(|h| h.ports.iter())
            .filter(|p| p.state == PortState::Open)
            .count()
    }

    /// Total vulnerabilities across all hosts.
    pub fn total_vulnerabilities(&self) -> usize {
        self.hosts
            .iter()
            .flat_map(|h| h.ports.iter())
            .map(|p| p.vulnerabilities.len())
            .sum()
    }

    /// Hosts with at least one Critical vulnerability.
    pub fn critical_hosts(&self) -> Vec<&Host> {
        self.hosts
            .iter()
            .filter(|h| {
                h.ports
                    .iter()
                    .flat_map(|p| p.vulnerabilities.iter())
                    .any(|v| v.severity == CvssSeverity::Critical)
            })
            .collect()
    }
}

/// A parsed scan target (CIDR or single IP).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTarget {
    /// The network (single IPs are /32 or /128).
    pub network: IpNet,
}

impl ScanTarget {
    /// Parse a target string: CIDR notation or plain IP.
    pub fn parse(s: &str) -> Result<Self, String> {
        if let Ok(net) = s.parse::<IpNet>() {
            return Ok(Self { network: net });
        }
        if let Ok(addr) = s.parse::<IpAddr>() {
            let net = match addr {
                IpAddr::V4(v4) => {
                    IpNet::V4(ipnet::Ipv4Net::new(v4, 32).expect("32 is valid prefix"))
                }
                IpAddr::V6(v6) => {
                    IpNet::V6(ipnet::Ipv6Net::new(v6, 128).expect("128 is valid prefix"))
                }
            };
            return Ok(Self { network: net });
        }
        Err(format!("'{}' is not a valid IP address or CIDR notation", s))
    }

    /// Iterate all host addresses in this target.
    pub fn hosts(&self) -> Vec<IpAddr> {
        match &self.network {
            IpNet::V4(net) => net.hosts().map(IpAddr::V4).collect(),
            IpNet::V6(net) => net.hosts().map(IpAddr::V6).collect(),
        }
    }

    /// Number of host addresses in this target (2^(max_bits - prefix)).
    pub fn host_count(&self) -> u128 {
        let bits = match self.network {
            IpNet::V4(_) => 32u128,
            IpNet::V6(_) => 128u128,
        };
        1u128 << (bits - self.network.prefix_len() as u128)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn port_range_contains_and_count() {
        let r = PortRange { ranges: vec![(80, 80), (443, 443), (8000, 8002)] };
        assert!(r.contains(80));
        assert!(r.contains(443));
        assert!(r.contains(8002));
        assert!(!r.contains(81));
        assert_eq!(r.count(), 5);
    }

    #[test]
    fn port_range_iter_order() {
        let r = PortRange { ranges: vec![(1, 3), (10, 11)] };
        let v: Vec<u16> = r.iter().collect();
        assert_eq!(v, [1, 2, 3, 10, 11]);
    }

    #[test]
    fn cvss_severity_boundaries() {
        assert_eq!(CvssSeverity::from_score(10.0), CvssSeverity::Critical);
        assert_eq!(CvssSeverity::from_score(7.0),  CvssSeverity::High);
        assert_eq!(CvssSeverity::from_score(4.0),  CvssSeverity::Medium);
        assert_eq!(CvssSeverity::from_score(0.1),  CvssSeverity::Low);
        assert_eq!(CvssSeverity::from_score(0.0),  CvssSeverity::None);
    }

    #[test]
    fn scan_session_lifecycle() {
        let mut s = ScanSession::new(vec!["10.0.0.0/24".into()]);
        assert_eq!(s.status, ScanStatus::Pending);
        s.start();
        assert_eq!(s.status, ScanStatus::Running);
        s.complete();
        assert_eq!(s.status, ScanStatus::Completed);
        assert!(s.completed_at.is_some());
    }

    #[test]
    fn scan_result_counts_correctly() {
        let mut session = ScanSession::new(vec!["10.0.0.1".into()]);
        session.complete();
        let host = Host {
            id: HostId::new(),
            session_id: session.id,
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            hostname: None,
            os_fingerprint: None,
            mac_address: None,
            discovered_at: Utc::now(),
            discovery_method: DiscoveryMethod::TcpPing,
            ports: vec![Port {
                id: PortId::new(),
                host_id: HostId::new(),
                number: 443,
                protocol: Protocol::Tcp,
                state: PortState::Open,
                service: None,
                banner: None,
                tls: None,
                vulnerabilities: vec![],
            }],
        };
        let result = ScanResult { session, hosts: vec![host] };
        assert_eq!(result.total_open_ports(), 1);
        assert_eq!(result.total_vulnerabilities(), 0);
    }

    #[test]
    fn scan_target_parse_cidr() {
        let t = ScanTarget::parse("192.168.0.0/24").unwrap();
        assert_eq!(t.network.prefix_len(), 24);
        assert_eq!(t.host_count(), 256);
    }

    #[test]
    fn scan_target_parse_single_ip() {
        let t = ScanTarget::parse("10.0.0.1").unwrap();
        assert_eq!(t.host_count(), 1);
    }

    #[test]
    fn scan_target_parse_invalid() {
        assert!(ScanTarget::parse("not-an-ip").is_err());
    }

    #[test]
    fn banner_data_protocol_hint() {
        let b = BannerData::from_bytes(b"SSH-2.0-OpenSSH_9.3");
        assert_eq!(b.protocol_hint.as_deref(), Some("ssh"));
        assert!(b.text.is_some());
    }

    #[test]
    fn probe_target_constructors() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(ProbeTarget::tcp(ip, 80).protocol, Protocol::Tcp);
        assert_eq!(ProbeTarget::udp(ip, 53).protocol, Protocol::Udp);
    }
}

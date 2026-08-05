//! `aloo-dns` — DNS resolution subsystem.
//!
//! Provides forward and reverse DNS resolution with a TTL-aware cache.
//! Network I/O is stubbed — `hickory-resolver` will be wired in the
//! networking milestone.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use thiserror::Error;
use tracing::debug;

/// DNS resolution errors.
#[derive(Debug, Error)]
pub enum DnsError {
    /// Hostname could not be resolved.
    #[error("Failed to resolve '{hostname}': {reason}")]
    ResolutionFailed { hostname: String, reason: String },
    /// PTR record lookup failed.
    #[error("Reverse DNS failed for {ip}: {reason}")]
    ReverseFailed { ip: IpAddr, reason: String },
    /// Resolver not yet initialised.
    #[error("DNS resolver not initialised")]
    NotInitialised,
}

// ── Cache ─────────────────────────────────────────────────────────────────────

/// Cached DNS entry with expiry.
#[derive(Debug, Clone)]
struct CacheEntry {
    addrs: Vec<IpAddr>,
    expires_at: Instant,
}

/// TTL-aware DNS cache backed by `DashMap`.
pub struct DnsCache {
    inner: DashMap<String, CacheEntry>,
    ttl: Duration,
}

impl DnsCache {
    /// Create a cache with the given TTL.
    pub fn new(ttl: Duration) -> Self {
        Self { inner: DashMap::new(), ttl }
    }

    /// Default cache with 300-second TTL.
    pub fn default_ttl() -> Self {
        Self::new(Duration::from_secs(300))
    }

    /// Look up a hostname. Returns `None` if absent or expired.
    pub fn get(&self, hostname: &str) -> Option<Vec<IpAddr>> {
        self.inner.get(hostname).and_then(|entry| {
            if Instant::now() < entry.expires_at {
                Some(entry.addrs.clone())
            } else {
                None
            }
        })
    }

    /// Insert (or refresh) a hostname entry.
    pub fn insert(&self, hostname: impl Into<String>, addrs: Vec<IpAddr>) {
        let entry = CacheEntry { addrs, expires_at: Instant::now() + self.ttl };
        self.inner.insert(hostname.into(), entry);
    }

    /// Evict all expired entries.
    pub fn evict_expired(&self) {
        let now = Instant::now();
        self.inner.retain(|_, v| v.expires_at > now);
    }
}

// ── Forward resolver ──────────────────────────────────────────────────────────

/// Async DNS resolver (stub — returns empty until networking is wired).
pub struct DnsResolver {
    cache: Arc<DnsCache>,
}

impl DnsResolver {
    /// Create a new resolver with the given cache.
    pub fn new(cache: Arc<DnsCache>) -> Self {
        Self { cache }
    }

    /// Create a resolver with default cache settings.
    pub fn with_default_cache() -> Self {
        Self::new(Arc::new(DnsCache::default_ttl()))
    }

    /// Resolve a hostname to IP addresses.
    ///
    /// Returns cached results when available. Returns an empty `Vec` in stub mode.
    pub async fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>, DnsError> {
        if let Some(cached) = self.cache.get(hostname) {
            debug!(hostname, "DNS cache hit");
            return Ok(cached);
        }
        debug!(hostname, "DNS resolve stub — returning empty");
        // Stub: real implementation uses hickory-resolver
        Ok(vec![])
    }
}

// ── Reverse resolver ──────────────────────────────────────────────────────────

/// Reverse DNS (PTR) resolver (stub).
pub struct ReverseDnsResolver {
    cache: Arc<DnsCache>,
}

impl ReverseDnsResolver {
    /// Create with the given cache.
    pub fn new(cache: Arc<DnsCache>) -> Self {
        Self { cache }
    }

    /// Look up the PTR record for an IP address.
    ///
    /// Returns `None` in stub mode.
    pub async fn resolve_ptr(&self, ip: IpAddr) -> Result<Option<String>, DnsError> {
        debug!(%ip, "Reverse DNS stub — returning None");
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn cache_insert_and_get() {
        let cache = DnsCache::default_ttl();
        let addrs = vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))];
        cache.insert("cloudflare.com", addrs.clone());
        assert_eq!(cache.get("cloudflare.com"), Some(addrs));
    }

    #[test]
    fn cache_miss_returns_none() {
        let cache = DnsCache::default_ttl();
        assert!(cache.get("nonexistent.example").is_none());
    }

    #[test]
    fn cache_expired_returns_none() {
        let cache = DnsCache::new(Duration::from_millis(1));
        cache.insert("fast.expire", vec![]);
        std::thread::sleep(Duration::from_millis(10));
        assert!(cache.get("fast.expire").is_none());
    }

    #[tokio::test]
    async fn resolver_returns_empty_stub() {
        let r = DnsResolver::with_default_cache();
        let addrs = r.resolve("example.com").await.unwrap();
        assert!(addrs.is_empty());
    }

    #[tokio::test]
    async fn reverse_resolver_returns_none_stub() {
        let cache = Arc::new(DnsCache::default_ttl());
        let r = ReverseDnsResolver::new(cache);
        let result = r.resolve_ptr("8.8.8.8".parse().unwrap()).await.unwrap();
        assert!(result.is_none());
    }
}

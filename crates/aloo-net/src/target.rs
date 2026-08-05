//! Target specification parsing and host enumeration.

use std::net::IpAddr;

use aloo_core::{AlooError, ScanTarget};

/// A parsed and validated scan target.
#[derive(Debug, Clone)]
pub struct TargetSpec {
    /// Underlying scan target.
    pub inner: ScanTarget,
}

impl TargetSpec {
    /// Parse a string (CIDR notation or single IP).
    pub fn parse(s: &str) -> Result<Self, AlooError> {
        ScanTarget::parse(s)
            .map(|inner| Self { inner })
            .map_err(AlooError::Config)
    }

    /// Expand to all host addresses in this target.
    pub fn hosts(&self) -> Vec<IpAddr> {
        self.inner.hosts()
    }

    /// Total number of host addresses.
    pub fn host_count(&self) -> u128 {
        self.inner.host_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_ip_count() {
        let t = TargetSpec::parse("10.0.0.1").unwrap();
        assert_eq!(t.host_count(), 1);
    }

    #[test]
    fn slash_24_count() {
        let t = TargetSpec::parse("192.168.0.0/24").unwrap();
        assert_eq!(t.host_count(), 256);
    }

    #[test]
    fn invalid_target_errors() {
        assert!(TargetSpec::parse("not-valid").is_err());
    }
}

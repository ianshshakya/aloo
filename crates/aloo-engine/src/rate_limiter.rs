//! Global token-bucket rate limiter.
//!
//! Enforces a maximum packets-per-second rate across all concurrent workers
//! using a single shared bucket — no per-target buckets.

use std::time::Duration;

use aloo_traits::ScanError;
use tokio::time;

/// Global PPS-based rate limiter.
///
/// Uses a fixed inter-packet sleep to approximate the requested PPS limit.
/// A proper leaky-bucket implementation will replace this in the networking
/// milestone.
pub struct GlobalRateLimiter {
    /// Target packets per second (0 = unlimited).
    pps: u32,
    /// Pre-computed sleep duration between acquisitions.
    interval: Duration,
}

impl GlobalRateLimiter {
    /// Create a rate limiter targeting `pps` packets per second.
    ///
    /// If `pps` is 0, acquisition is always instant.
    pub fn new(pps: u32) -> Self {
        let interval = if pps == 0 {
            Duration::ZERO
        } else {
            Duration::from_micros(1_000_000 / pps as u64)
        };
        Self { pps, interval }
    }

    /// Unlimited rate limiter (always instant).
    pub fn unlimited() -> Self {
        Self::new(0)
    }

    /// Acquire one "token" — waits the inter-packet interval if needed.
    pub async fn acquire(&self) -> Result<(), ScanError> {
        if !self.interval.is_zero() {
            time::sleep(self.interval).await;
        }
        Ok(())
    }

    /// Target PPS configured for this limiter.
    pub fn pps(&self) -> u32 {
        self.pps
    }

    /// Whether this limiter enforces any limit.
    pub fn is_limited(&self) -> bool {
        self.pps > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn unlimited_has_zero_interval() {
        let l = GlobalRateLimiter::unlimited();
        assert!(!l.is_limited());
        assert_eq!(l.interval, Duration::ZERO);
    }

    #[test]
    fn pps_1000_gives_1ms_interval() {
        let l = GlobalRateLimiter::new(1_000);
        assert!(l.is_limited());
        assert_eq!(l.interval, Duration::from_micros(1_000));
    }

    #[test]
    fn pps_100_gives_10ms_interval() {
        let l = GlobalRateLimiter::new(100);
        assert_eq!(l.interval, Duration::from_micros(10_000));
    }

    #[tokio::test]
    async fn unlimited_acquire_is_instant() {
        let l = GlobalRateLimiter::unlimited();
        let t = Instant::now();
        l.acquire().await.unwrap();
        assert!(t.elapsed() < Duration::from_millis(5));
    }

    #[tokio::test]
    async fn limited_acquire_delays() {
        let l = GlobalRateLimiter::new(100); // 10 ms per packet
        let t = Instant::now();
        l.acquire().await.unwrap();
        // Should have slept ~10 ms
        assert!(t.elapsed() >= Duration::from_millis(5));
    }
}

//! `aloo-history` — Diff Engine and Asset Timeline tracking.
//!
//! Exposes APIs for comparing two scan sessions to detect delta changes
//! (new ports, closed ports, certificate changes) and tracking the lifecycle
//! of an asset over time.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::net::IpAddr;

use aloo_core::{HostId, SessionId, PortState, Protocol};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;

/// Errors from the diff engine.
#[derive(Debug, Error)]
pub enum HistoryError {
    /// The specified session could not be found for comparison.
    #[error("Session not found: {0}")]
    SessionNotFound(String),
}

/// A specific change detected on a port between two scans.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortChange {
    /// IP of the host.
    pub ip: IpAddr,
    /// The port number.
    pub port: u16,
    /// Protocol (TCP/UDP).
    pub protocol: Protocol,
    /// State in the older scan.
    pub previous_state: Option<PortState>,
    /// State in the newer scan.
    pub current_state: Option<PortState>,
}

/// The result of comparing two scan sessions.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanDiff {
    /// Hosts that were discovered in the current scan but were offline in the previous.
    pub new_hosts: Vec<IpAddr>,
    /// Hosts that were online in the previous scan but offline in the current.
    pub removed_hosts: Vec<IpAddr>,
    /// Delta of port states (e.g. Open -> Closed, Closed -> Open).
    pub port_changes: Vec<PortChange>,
    /// Textual summaries of service changes (e.g. "nginx 1.18" -> "nginx 1.20").
    pub service_changes: Vec<String>,
}

/// The diff engine correlates point-in-time observations.
pub struct DiffEngine;

impl DiffEngine {
    /// Create a new diff engine.
    pub fn new() -> Self {
        Self
    }

    /// Compare two sessions to detect delta changes. (Stub)
    ///
    /// In the final implementation, this will issue a SQL `LEFT JOIN` against
    /// the `observations` table for both Session IDs.
    pub async fn compare(
        &self,
        _previous: SessionId,
        _current: SessionId,
    ) -> Result<ScanDiff, HistoryError> {
        info!("DiffEngine::compare stub called");
        Ok(ScanDiff::default())
    }
}

impl Default for DiffEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents the history of a single asset over time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetTimeline {
    /// The canonical Host ID.
    pub host_id: HostId,
    /// The first time this asset was ever seen by Aloo.
    pub first_seen: DateTime<Utc>,
    /// The most recent time this asset was scanned.
    pub last_seen: DateTime<Utc>,
    /// Total number of scans this asset has participated in.
    pub scan_count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn diff_engine_returns_empty_stub() {
        let engine = DiffEngine::new();
        let diff = engine.compare(SessionId::new(), SessionId::new()).await.unwrap();
        assert!(diff.new_hosts.is_empty());
        assert!(diff.port_changes.is_empty());
    }
}

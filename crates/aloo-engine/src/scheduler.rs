//! Scan task scheduling — divides targets into work units.

use std::net::IpAddr;

use aloo_core::{PortRange, SessionId};

/// A single unit of work for the scanner.
#[derive(Debug, Clone)]
pub struct ScanTask {
    /// Target IP address.
    pub target: IpAddr,
    /// Port range to scan on this target.
    pub ports: PortRange,
    /// Session this task belongs to.
    pub session_id: SessionId,
}

impl ScanTask {
    /// Create a new task.
    pub fn new(target: IpAddr, ports: PortRange, session_id: SessionId) -> Self {
        Self { target, ports, session_id }
    }
}

/// Divides a list of target IPs into `ScanTask` work units.
pub struct ScanScheduler {
    default_ports: PortRange,
}

impl ScanScheduler {
    /// Create a scheduler with the given default port range.
    pub fn new(default_ports: PortRange) -> Self {
        Self { default_ports }
    }

    /// Create with top-1024 ports as the default.
    pub fn with_top_ports() -> Self {
        Self::new(PortRange::top_1000())
    }

    /// Schedule one `ScanTask` per target IP.
    pub fn schedule(&self, targets: Vec<IpAddr>, session_id: SessionId) -> Vec<ScanTask> {
        targets
            .into_iter()
            .map(|ip| ScanTask::new(ip, self.default_ports.clone(), session_id))
            .collect()
    }

    /// Schedule tasks with a per-target port override.
    pub fn schedule_with_ports(
        &self,
        targets: Vec<IpAddr>,
        ports: PortRange,
        session_id: SessionId,
    ) -> Vec<ScanTask> {
        targets
            .into_iter()
            .map(|ip| ScanTask::new(ip, ports.clone(), session_id))
            .collect()
    }
}

impl Default for ScanScheduler {
    fn default() -> Self {
        Self::with_top_ports()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_produces_one_task_per_ip() {
        let scheduler = ScanScheduler::default();
        let session = SessionId::new();
        let ips: Vec<IpAddr> = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let tasks = scheduler.schedule(ips.clone(), session);
        assert_eq!(tasks.len(), 3);
        assert_eq!(tasks[0].target, ips[0]);
    }

    #[test]
    fn schedule_empty_targets_returns_empty() {
        let scheduler = ScanScheduler::default();
        let tasks = scheduler.schedule(vec![], SessionId::new());
        assert!(tasks.is_empty());
    }

    #[test]
    fn schedule_with_ports_override() {
        let scheduler = ScanScheduler::default();
        let custom_ports = PortRange { ranges: vec![(8000, 8080)] };
        let session = SessionId::new();
        let ips = vec!["1.2.3.4".parse().unwrap()];
        let tasks = scheduler.schedule_with_ports(ips, custom_ports.clone(), session);
        assert_eq!(tasks[0].ports, custom_ports);
    }

    #[test]
    fn task_session_id_matches() {
        let scheduler = ScanScheduler::default();
        let session = SessionId::new();
        let tasks = scheduler.schedule(vec!["10.0.0.1".parse().unwrap()], session);
        assert_eq!(tasks[0].session_id, session);
    }
}

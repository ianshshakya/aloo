//! Typed event channels for the scan pipeline.
//!
//! Three channel kinds:
//! - `mpsc` (bounded) for `HostEvent`  — lossless storage writes
//! - `mpsc` (unbounded) for `PortEvent` / `VulnEvent` — high-throughput
//! - `watch` for `ControlEvent`         — latest-value control signals

use std::net::IpAddr;

use aloo_core::{Host, SessionId, Vulnerability};
use aloo_traits::PortObservation;
use tokio::sync::{mpsc, watch};

// ── Event payloads ────────────────────────────────────────────────────────────

/// Events relating to discovered hosts.
#[derive(Debug, Clone)]
pub enum HostEvent {
    /// A new host was found alive.
    Discovered(Box<Host>),
    /// A host did not respond to probes.
    Unreachable(IpAddr),
    /// Port scanning started on a host.
    ScanStarted { ip: IpAddr, session_id: SessionId },
    /// Port scanning finished on a host.
    ScanComplete { ip: IpAddr, session_id: SessionId },
}

/// Events for individual port scan results.
#[derive(Debug, Clone)]
pub enum PortEvent {
    /// An open port was observed.
    Open(PortObservation),
    /// A closed port was observed.
    Closed(PortObservation),
    /// A filtered port was observed.
    Filtered(PortObservation),
    /// A probe result was obtained for an open port.
    Probed { observation: PortObservation, response_time_ms: u64 },
}

/// Events for correlated vulnerabilities.
#[derive(Debug, Clone)]
pub enum VulnEvent {
    /// A vulnerability was correlated to a port.
    Found { vuln: Box<Vulnerability>, host_ip: IpAddr, port: u16 },
}

/// Control plane signals for the scan engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlEvent {
    /// Normal running state (initial value).
    Running,
    /// Pause scanning (drain in-flight; don't start new tasks).
    Pause,
    /// Orderly shutdown.
    Shutdown,
}

// ── EventBus ──────────────────────────────────────────────────────────────────

/// Channel configuration — capacity of the bounded host event channel.
const HOST_CHANNEL_CAPACITY: usize = 4_096;

/// Owns all typed event channels for one scan session.
pub struct EventBus {
    /// Send side for host lifecycle events (bounded — storage writer must keep up).
    pub host_tx: mpsc::Sender<HostEvent>,
    /// Receive side for host lifecycle events.
    pub host_rx: std::sync::Mutex<Option<mpsc::Receiver<HostEvent>>>,

    /// Send side for port observations (unbounded — scanner produces faster than storage).
    pub port_tx: mpsc::UnboundedSender<PortEvent>,
    /// Receive side for port observations.
    pub port_rx: std::sync::Mutex<Option<mpsc::UnboundedReceiver<PortEvent>>>,

    /// Send side for vulnerability events (unbounded).
    pub vuln_tx: mpsc::UnboundedSender<VulnEvent>,
    /// Receive side for vulnerability events.
    pub vuln_rx: std::sync::Mutex<Option<mpsc::UnboundedReceiver<VulnEvent>>>,

    /// Control signal sender (watch — consumers see latest value only).
    pub control_tx: watch::Sender<ControlEvent>,
    /// Control signal receiver (clone this per consumer).
    pub control_rx: watch::Receiver<ControlEvent>,
}

impl EventBus {
    /// Create a new event bus with all channels initialised.
    pub fn new() -> Self {
        let (host_tx, host_rx)   = mpsc::channel(HOST_CHANNEL_CAPACITY);
        let (port_tx, port_rx)   = mpsc::unbounded_channel();
        let (vuln_tx, vuln_rx)   = mpsc::unbounded_channel();
        let (control_tx, control_rx) = watch::channel(ControlEvent::Running);

        Self {
            host_tx,
            host_rx:    std::sync::Mutex::new(Some(host_rx)),
            port_tx,
            port_rx:    std::sync::Mutex::new(Some(port_rx)),
            vuln_tx,
            vuln_rx:    std::sync::Mutex::new(Some(vuln_rx)),
            control_tx,
            control_rx,
        }
    }

    /// Take ownership of the host receiver (may only be called once).
    pub fn take_host_rx(&self) -> Option<mpsc::Receiver<HostEvent>> {
        self.host_rx.lock().unwrap().take()
    }

    /// Take ownership of the port receiver (may only be called once).
    pub fn take_port_rx(&self) -> Option<mpsc::UnboundedReceiver<PortEvent>> {
        self.port_rx.lock().unwrap().take()
    }

    /// Take ownership of the vuln receiver (may only be called once).
    pub fn take_vuln_rx(&self) -> Option<mpsc::UnboundedReceiver<VulnEvent>> {
        self.vuln_rx.lock().unwrap().take()
    }

    /// Subscribe to the control signal (clones the receiver).
    pub fn subscribe_control(&self) -> watch::Receiver<ControlEvent> {
        self.control_rx.clone()
    }

    /// Send a shutdown signal to all consumers.
    pub fn shutdown(&self) {
        let _ = self.control_tx.send(ControlEvent::Shutdown);
    }

    /// Send a pause signal to all consumers.
    pub fn pause(&self) {
        let _ = self.control_tx.send(ControlEvent::Pause);
    }

    /// Resume after a pause.
    pub fn resume(&self) {
        let _ = self.control_tx.send(ControlEvent::Running);
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn host_event_send_receive() {
        let bus = EventBus::new();
        let mut rx = bus.take_host_rx().unwrap();
        bus.host_tx
            .send(HostEvent::Unreachable("10.0.0.1".parse().unwrap()))
            .await
            .unwrap();
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, HostEvent::Unreachable(_)));
    }

    #[test]
    fn port_event_send_receive() {
        let bus = EventBus::new();
        let mut rx = bus.take_port_rx().unwrap();
        let obs = PortObservation {
            ip: "10.0.0.1".parse().unwrap(),
            port: 443,
            protocol: aloo_core::Protocol::Tcp,
            state: aloo_core::PortState::Open,
            response_time_ms: 5,
        };
        bus.port_tx.send(PortEvent::Open(obs)).unwrap();
        let ev = rx.try_recv().unwrap();
        assert!(matches!(ev, PortEvent::Open(_)));
    }

    #[test]
    fn control_signal_watch() {
        let bus = EventBus::new();
        let mut ctrl = bus.subscribe_control();
        assert_eq!(*ctrl.borrow(), ControlEvent::Running);
        bus.pause();
        assert_eq!(*bus.control_rx.borrow(), ControlEvent::Pause);
        bus.shutdown();
        assert_eq!(*bus.control_rx.borrow(), ControlEvent::Shutdown);
    }
}

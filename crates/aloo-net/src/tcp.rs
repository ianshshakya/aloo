//! TCP Scanning implementations.

use std::net::SocketAddr;
use std::time::Duration;

use aloo_core::PortState;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Performs a standard full TCP connect scan against a target port.
/// 
/// Returns `PortState::Open` if the connection succeeds, `PortState::Closed` if refused,
/// or `PortState::Filtered` if it times out.
pub async fn tcp_connect_scan(addr: SocketAddr, timeout_duration: Duration) -> PortState {
    match timeout(timeout_duration, TcpStream::connect(&addr)).await {
        Ok(Ok(_stream)) => {
            // Connection successful, the OS completes the 3-way handshake.
            PortState::Open
        }
        Ok(Err(e)) => {
            // Connection refused or network unreachable.
            if e.kind() == std::io::ErrorKind::ConnectionRefused {
                PortState::Closed
            } else {
                PortState::Filtered
            }
        }
        Err(_) => {
            // Timeout reached without a response.
            PortState::Filtered
        }
    }
}

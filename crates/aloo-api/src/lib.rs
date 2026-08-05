//! `aloo-api` — Control Plane REST API.
//!
//! Provides a local API for the web dashboard, CLI querying, and third-party
//! integrations. Serves data from the SQLite storage layer.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::net::SocketAddr;

use thiserror::Error;
use tracing::info;

/// API server errors.
#[derive(Debug, Error)]
pub enum ApiError {
    /// The API server failed to bind to the requested port.
    #[error("Failed to bind API server to {0}: {1}")]
    BindError(SocketAddr, String),
}

/// The Aloo Control Plane API Server.
pub struct ApiServer {
    bind_addr: SocketAddr,
}

impl ApiServer {
    /// Create a new API server configured to bind to `addr`.
    pub fn new(bind_addr: SocketAddr) -> Self {
        Self { bind_addr }
    }

    /// Start the API server in the background (Stub).
    ///
    /// In the final version, this will spawn an `axum` or `tonic` server
    /// connected to the `aloo-storage` repositories.
    pub async fn serve(&self) -> Result<(), ApiError> {
        info!(addr = %self.bind_addr, "ApiServer::serve stub started");
        
        // Simulating a server block (which would normally block forever or until shutdown)
        // For the stub, we just return Ok.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn server_starts_stub() {
        let addr = "127.0.0.1:8080".parse().unwrap();
        let server = ApiServer::new(addr);
        server.serve().await.expect("stub server should not fail");
    }
}

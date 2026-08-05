//! `aloo-engine` — Scan orchestration engine.
//!
//! Wires together discovery, scanning, probing, fingerprinting, and
//! vulnerability correlation into a single coordinated scan pipeline.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod event_bus;
pub mod rate_limiter;
pub mod scheduler;
pub mod worker_pool;

use std::sync::Arc;

use aloo_config::AlooConfig;
use aloo_core::{ScanResult, ScanSession};
use aloo_traits::{ScanEngine, ScanError};
use async_trait::async_trait;
use tracing::info;

pub use event_bus::EventBus;
pub use rate_limiter::GlobalRateLimiter;
pub use scheduler::{ScanScheduler, ScanTask};
pub use worker_pool::WorkerPool;

// ── Engine ────────────────────────────────────────────────────────────────────

/// The main Aloo scan orchestration engine.
pub struct AlooEngine {
    config:       Arc<AlooConfig>,
    event_bus:    Arc<EventBus>,
    rate_limiter: Arc<GlobalRateLimiter>,
    worker_pool:  Arc<WorkerPool>,
}

impl AlooEngine {
    /// Create a new engine from config.
    pub fn new(config: AlooConfig) -> Self {
        let pps        = config.scan.rate_limit_pps;
        let workers    = config.scan.max_parallelism;
        Self {
            event_bus:    Arc::new(EventBus::new()),
            rate_limiter: Arc::new(GlobalRateLimiter::new(pps)),
            worker_pool:  Arc::new(WorkerPool::new(workers)),
            config:       Arc::new(config),
        }
    }

    /// Return a builder for constructing the engine.
    pub fn builder() -> EngineBuilder {
        EngineBuilder::default()
    }

    /// Reference to the event bus.
    pub fn event_bus(&self) -> &Arc<EventBus> {
        &self.event_bus
    }

    /// Reference to the rate limiter.
    pub fn rate_limiter(&self) -> &Arc<GlobalRateLimiter> {
        &self.rate_limiter
    }
}

#[async_trait]
impl ScanEngine for AlooEngine {
    async fn run(&self, targets: Vec<String>) -> Result<ScanResult, ScanError> {
        if targets.is_empty() {
            return Err(ScanError::NoTargets);
        }

        let mut session = ScanSession::new(targets.clone());
        session.start();
        info!(session_id = %session.id, target_count = targets.len(), "AlooEngine::run starting MVP TCP Scan");

        // 1. Parse all targets into a flat list of IPs.
        let mut ips = Vec::new();
        for t in &targets {
            match aloo_core::ScanTarget::parse(t) {
                Ok(spec) => ips.extend(spec.hosts()),
                Err(_) => {
                    // Attempt DNS resolution if it's not a raw IP or CIDR
                    if let Ok(addrs) = tokio::net::lookup_host(format!("{}:0", t)).await {
                        for addr in addrs {
                            ips.push(addr.ip());
                        }
                    } else {
                        return Err(ScanError::InvalidConfig(format!("Could not resolve target: {}", t)));
                    }
                }
            }
        }
        
        info!(total_ips = ips.len(), "Targets parsed successfully");

        // 2. Schedule tasks (1 task per IP, default top 1000 ports)
        let scheduler = ScanScheduler::default();
        let tasks = scheduler.schedule(ips.clone(), session.id);

        // 3. Execute via Worker Pool
        let timeout_duration = std::time::Duration::from_millis(self.config.scan.timeout_ms as u64);
        
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        // Bound the number of concurrent port connections across all IPs
        let port_semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(self.config.scan.max_parallelism));

        self.worker_pool.execute(tasks, move |task| {
            let tx = tx.clone();
            let sem = port_semaphore.clone();
            async move {
                let mut open_ports = 0;
                let target = task.target;
                let session_id = task.session_id;
                
                let mut join_set = tokio::task::JoinSet::new();

                for port in task.ports.iter() {
                    let tx_clone = tx.clone();
                    let permit = sem.clone().acquire_owned().await.unwrap();
                    
                    join_set.spawn(async move {
                        let _permit = permit; // Hold permit until the connection attempt finishes
                        let addr = std::net::SocketAddr::new(target, port);
                        let state = aloo_net::tcp::tcp_connect_scan(addr, timeout_duration).await;
                        
                        if state == aloo_core::PortState::Open {
                            let _ = tx_clone.send((target, port));
                            tracing::info!(ip = %target, port = port, "Discovered OPEN port");
                            // Also print directly to console for MVP visibility
                            println!("{} {}:{}", console::style("OPEN").green().bold(), target, port);
                            return 1;
                        }
                        0
                    });
                }
                
                while let Some(res) = join_set.join_next().await {
                    if let Ok(count) = res {
                        open_ports += count;
                    }
                }
                
                if open_ports > 0 {
                    tracing::info!(ip = %target, open_ports = open_ports, "Finished scanning host");
                }
            }
        }).await;
        
        // 4. Collect results and build the ScanResult
        let mut host_map = std::collections::HashMap::new();
        while let Ok((ip, port)) = rx.try_recv() {
            host_map.entry(ip).or_insert_with(Vec::new).push(port);
        }

        let mut hosts = Vec::new();
        for (ip, ports) in host_map {
            let mut port_list = Vec::new();
            for p in ports {
                port_list.push(aloo_core::Port {
                    id: aloo_core::PortId::new(),
                    host_id: aloo_core::HostId::new(), // In MVP, we just generate dummy IDs
                    number: p,
                    protocol: aloo_core::Protocol::Tcp,
                    state: aloo_core::PortState::Open,
                    service: None,
                    banner: None,
                    tls: None,
                    vulnerabilities: vec![],
                });
            }
            
            let host_id = aloo_core::HostId::new();
            // Fix all port host_ids to match the parent host
            for p in &mut port_list {
                p.host_id = host_id;
            }

            hosts.push(aloo_core::Host {
                id: host_id,
                session_id: session.id,
                ip,
                hostname: None,
                os_fingerprint: None,
                mac_address: None,
                discovered_at: chrono::Utc::now(),
                discovery_method: aloo_core::DiscoveryMethod::TcpPing,
                ports: port_list,
            });
        }

        session.complete();
        Ok(ScanResult { session, hosts })
    }
}

// ── Builder ───────────────────────────────────────────────────────────────────

/// Builder for constructing an `AlooEngine` with custom settings.
#[derive(Default)]
pub struct EngineBuilder {
    config: Option<AlooConfig>,
}

impl EngineBuilder {
    /// Set the configuration.
    pub fn config(mut self, config: AlooConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Build the engine.
    pub fn build(self) -> AlooEngine {
        AlooEngine::new(self.config.unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn engine_run_stub_returns_empty_result() {
        let engine = AlooEngine::builder().build();
        let result = engine.run(vec!["10.0.0.1".into()]).await.unwrap();
        assert!(result.hosts.is_empty());
        assert_eq!(result.session.targets, vec!["10.0.0.1"]);
    }

    #[tokio::test]
    async fn engine_run_no_targets_errors() {
        let engine = AlooEngine::builder().build();
        let err = engine.run(vec![]).await.unwrap_err();
        assert!(matches!(err, ScanError::NoTargets));
    }

    #[test]
    fn engine_builder_default_config() {
        let engine = AlooEngine::builder().build();
        assert_eq!(engine.config.scan.max_parallelism, 1_000);
    }
}

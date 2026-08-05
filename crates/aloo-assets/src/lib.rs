//! `aloo-assets` — Infrastructure Graph and Asset Inventory.
//!
//! Automatically infers relationships between discovered hosts based on
//! routing traces, TTLs, subnet allocations, and service fingerprints.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::HashMap;
use std::net::IpAddr;

use aloo_core::HostId;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;

/// Errors related to asset and graph building operations.
#[derive(Debug, Error)]
pub enum AssetError {
    /// Failed to build or traverse the infrastructure graph.
    #[error("Graph build error: {0}")]
    GraphBuild(String),
}

/// The type of relationship between two assets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationType {
    /// Asset A routes traffic to Asset B (e.g., Gateway -> Firewall).
    RoutesTo,
    /// Asset A balances traffic to Asset B.
    BalancesTo,
    /// Asset A is an API gateway serving endpoints on Asset B.
    ProxiesTo,
    /// Asset A shares a subnet with Asset B.
    PeersWith,
}

/// An edge connecting two nodes in the infrastructure graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    /// Source asset ID.
    pub source: HostId,
    /// Target asset ID.
    pub target: HostId,
    /// The nature of their relationship.
    pub relation: RelationType,
    /// Optional metadata explaining how this edge was inferred.
    pub confidence_score: f32,
}

/// A directed graph representing the physical and logical network infrastructure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfraGraph {
    /// Adjacency list mapping an asset ID to its outgoing edges.
    pub edges: HashMap<HostId, Vec<GraphEdge>>,
}

impl InfraGraph {
    /// Create a new empty infrastructure graph.
    pub fn new() -> Self {
        Self {
            edges: HashMap::new(),
        }
    }

    /// Add a relationship edge to the graph.
    pub fn add_edge(&mut self, edge: GraphEdge) {
        self.edges
            .entry(edge.source)
            .or_default()
            .push(edge);
    }
}

impl Default for InfraGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder responsible for digesting scan observations and inferring graph edges.
pub struct GraphBuilder;

impl GraphBuilder {
    /// Create a new `GraphBuilder`.
    pub fn new() -> Self {
        Self
    }

    /// Build an `InfraGraph` from a list of discovered IPs (Stub).
    ///
    /// In the future, this will consume traceroute outputs, TTL correlations,
    /// and HTTP `Via` / `X-Forwarded-For` headers to build a highly accurate graph.
    pub fn build_from_scan(&self, _ips: &[IpAddr]) -> Result<InfraGraph, AssetError> {
        info!("GraphBuilder::build_from_scan stub called");
        Ok(InfraGraph::new())
    }
}

impl Default for GraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_add_edge_to_graph() {
        let mut graph = InfraGraph::new();
        let src = HostId::new();
        let dst = HostId::new();

        graph.add_edge(GraphEdge {
            source: src,
            target: dst,
            relation: RelationType::RoutesTo,
            confidence_score: 0.95,
        });

        assert_eq!(graph.edges.len(), 1);
        assert_eq!(graph.edges.get(&src).unwrap().len(), 1);
    }
}

//! Agent relationship graph.
//!
//! Tracks interactions between agents using a directed graph. Nodes
//! represent agent identities, edges represent observed interactions
//! (HTTP relay, MCP tool calls, parent-child relationships).
//!
//! Edge detection uses temporal correlation: if agent A makes an
//! outbound call and agent B (in the same container) responds within
//! 5 seconds, an HttpRelay edge is inferred.
//!
//! Requires the `graph` feature flag.

#![cfg(feature = "graph")]

use crate::identity::IdentityId;
use petgraph::stable_graph::{NodeIndex, StableDiGraph};
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Temporal correlation window for relay detection (milliseconds).
const RELAY_WINDOW_MS: u64 = 5000;

/// Node in the agent relationship graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentNode {
    pub identity_id: IdentityId,
    pub label: String,
    pub first_seen: String,
    pub last_seen: String,
}

/// Edge type between agents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InteractionType {
    /// Agent A's outbound call is relayed through agent B.
    HttpRelay,
    /// Agent A invokes an MCP tool on agent B.
    McpToolCall,
    /// Agent A spawned agent B (parent-child).
    ParentChild,
}

/// Edge in the agent relationship graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractionEdge {
    pub interaction_type: InteractionType,
    pub count: u64,
    pub first_seen: String,
    pub last_seen: String,
}

/// Recent outbound event for temporal correlation.
struct RecentOutbound {
    identity_id: IdentityId,
    container_id_hash: u32,
    timestamp_ms: u64,
}

/// Agent relationship graph.
pub struct AgentGraph {
    graph: StableDiGraph<AgentNode, InteractionEdge>,
    /// Identity ID → node index mapping.
    node_map: HashMap<IdentityId, NodeIndex>,
    /// Recent outbound events for relay detection.
    recent_outbound: Vec<RecentOutbound>,
}

impl AgentGraph {
    /// Create a new empty graph.
    pub fn new() -> Self {
        Self {
            graph: StableDiGraph::new(),
            node_map: HashMap::new(),
            recent_outbound: Vec::new(),
        }
    }

    /// Ensure a node exists for the given identity, creating it if needed.
    pub fn ensure_node(
        &mut self,
        identity_id: IdentityId,
        label: &str,
        timestamp: &str,
    ) -> NodeIndex {
        if let Some(&idx) = self.node_map.get(&identity_id) {
            // Update last_seen
            if let Some(node) = self.graph.node_weight_mut(idx) {
                node.last_seen = timestamp.to_string();
            }
            idx
        } else {
            let node = AgentNode {
                identity_id,
                label: label.to_string(),
                first_seen: timestamp.to_string(),
                last_seen: timestamp.to_string(),
            };
            let idx = self.graph.add_node(node);
            self.node_map.insert(identity_id, idx);
            idx
        }
    }

    /// Record an outbound event (LLM API call or response) for relay detection.
    pub fn record_outbound(
        &mut self,
        identity_id: IdentityId,
        container_id_hash: u32,
        timestamp_ms: u64,
    ) {
        // Prune old entries beyond the relay window
        self.recent_outbound
            .retain(|r| timestamp_ms.saturating_sub(r.timestamp_ms) < RELAY_WINDOW_MS);

        self.recent_outbound.push(RecentOutbound {
            identity_id,
            container_id_hash,
            timestamp_ms,
        });
    }

    /// Check for temporal relay: if a different identity in the same container
    /// made an outbound call within the relay window, infer an HttpRelay edge.
    ///
    /// Returns the source identity ID if a relay was detected.
    pub fn check_relay(
        &mut self,
        identity_id: IdentityId,
        container_id_hash: u32,
        timestamp_ms: u64,
        timestamp_str: &str,
    ) -> Option<IdentityId> {
        if container_id_hash == 0 {
            return None; // No container context
        }

        let relay_source = self.recent_outbound.iter().find(|r| {
            r.identity_id != identity_id
                && r.container_id_hash == container_id_hash
                && timestamp_ms.saturating_sub(r.timestamp_ms) < RELAY_WINDOW_MS
        });

        if let Some(source) = relay_source {
            let source_id = source.identity_id;
            self.add_or_update_edge(
                source_id,
                identity_id,
                InteractionType::HttpRelay,
                timestamp_str,
            );
            Some(source_id)
        } else {
            None
        }
    }

    /// Record an MCP tool call from one agent to another.
    pub fn record_mcp_call(
        &mut self,
        caller_id: IdentityId,
        callee_id: IdentityId,
        timestamp: &str,
    ) {
        self.add_or_update_edge(
            caller_id,
            callee_id,
            InteractionType::McpToolCall,
            timestamp,
        );
    }

    /// Record a parent-child relationship.
    pub fn record_parent_child(
        &mut self,
        parent_id: IdentityId,
        child_id: IdentityId,
        timestamp: &str,
    ) {
        self.add_or_update_edge(parent_id, child_id, InteractionType::ParentChild, timestamp);
    }

    /// Add or update a directed edge between two identities.
    fn add_or_update_edge(
        &mut self,
        from: IdentityId,
        to: IdentityId,
        interaction_type: InteractionType,
        timestamp: &str,
    ) {
        let from_idx = match self.node_map.get(&from) {
            Some(&idx) => idx,
            None => return, // Node must exist
        };
        let to_idx = match self.node_map.get(&to) {
            Some(&idx) => idx,
            None => return, // Node must exist
        };

        // Check for existing edge of this type
        let existing = self
            .graph
            .edges_connecting(from_idx, to_idx)
            .find(|e| e.weight().interaction_type == interaction_type)
            .map(|e| e.id());

        if let Some(edge_id) = existing {
            if let Some(edge) = self.graph.edge_weight_mut(edge_id) {
                edge.count += 1;
                edge.last_seen = timestamp.to_string();
            }
        } else {
            self.graph.add_edge(
                from_idx,
                to_idx,
                InteractionEdge {
                    interaction_type,
                    count: 1,
                    first_seen: timestamp.to_string(),
                    last_seen: timestamp.to_string(),
                },
            );
        }
    }

    /// Remove a node and all its edges.
    pub fn remove_node(&mut self, identity_id: IdentityId) {
        if let Some(idx) = self.node_map.remove(&identity_id) {
            self.graph.remove_node(idx);
        }
        self.recent_outbound
            .retain(|r| r.identity_id != identity_id);
    }

    /// Number of nodes in the graph.
    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Number of edges in the graph.
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// Get all edges for a given identity (outgoing).
    pub fn outgoing_edges(&self, identity_id: IdentityId) -> Vec<&InteractionEdge> {
        let idx = match self.node_map.get(&identity_id) {
            Some(&idx) => idx,
            None => return Vec::new(),
        };

        self.graph.edges(idx).map(|e| e.weight()).collect()
    }

    /// Serialize the graph to bytes (for persistence).
    #[cfg(feature = "persist")]
    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(&self.graph).map_err(|e| e.to_string())
    }

    /// Deserialize the graph from bytes (for persistence).
    #[cfg(feature = "persist")]
    pub fn deserialize(bytes: &[u8]) -> Result<Self, String> {
        let graph: StableDiGraph<AgentNode, InteractionEdge> =
            bincode::deserialize(bytes).map_err(|e| e.to_string())?;

        let mut node_map = HashMap::new();
        for idx in graph.node_indices() {
            if let Some(node) = graph.node_weight(idx) {
                node_map.insert(node.identity_id, idx);
            }
        }

        Ok(Self {
            graph,
            node_map,
            recent_outbound: Vec::new(),
        })
    }
}

impl Default for AgentGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a "HH:MM:SS.mmm" timestamp to milliseconds since midnight.
/// Returns 0 on parse failure (used only for temporal comparison).
pub fn parse_timestamp_ms(ts: &str) -> u64 {
    let parts: Vec<&str> = ts.split(':').collect();
    if parts.len() != 3 {
        return 0;
    }

    let hours: u64 = parts[0].parse().unwrap_or(0);
    let minutes: u64 = parts[1].parse().unwrap_or(0);

    let sec_parts: Vec<&str> = parts[2].split('.').collect();
    let seconds: u64 = sec_parts[0].parse().unwrap_or(0);
    let millis: u64 = if sec_parts.len() > 1 {
        sec_parts[1].parse().unwrap_or(0)
    } else {
        0
    };

    hours * 3_600_000 + minutes * 60_000 + seconds * 1_000 + millis
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_graph() {
        let graph = AgentGraph::new();
        assert_eq!(graph.node_count(), 0);
        assert_eq!(graph.edge_count(), 0);
    }

    #[test]
    fn ensure_node_creates_and_updates() {
        let mut graph = AgentGraph::new();
        let idx1 = graph.ensure_node(1, "agent-a", "12:00:00.000");
        let idx2 = graph.ensure_node(1, "agent-a", "12:01:00.000");
        assert_eq!(idx1, idx2);
        assert_eq!(graph.node_count(), 1);

        let node = graph.graph.node_weight(idx1).unwrap();
        assert_eq!(node.last_seen, "12:01:00.000");
    }

    #[test]
    fn add_edge() {
        let mut graph = AgentGraph::new();
        graph.ensure_node(1, "agent-a", "12:00:00");
        graph.ensure_node(2, "agent-b", "12:00:00");

        graph.record_mcp_call(1, 2, "12:00:01");
        assert_eq!(graph.edge_count(), 1);

        let edges = graph.outgoing_edges(1);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].interaction_type, InteractionType::McpToolCall);
        assert_eq!(edges[0].count, 1);
    }

    #[test]
    fn edge_count_increments() {
        let mut graph = AgentGraph::new();
        graph.ensure_node(1, "a", "t0");
        graph.ensure_node(2, "b", "t0");

        graph.record_mcp_call(1, 2, "t1");
        graph.record_mcp_call(1, 2, "t2");
        graph.record_mcp_call(1, 2, "t3");

        let edges = graph.outgoing_edges(1);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].count, 3);
        assert_eq!(edges[0].last_seen, "t3");
    }

    #[test]
    fn different_edge_types_separate() {
        let mut graph = AgentGraph::new();
        graph.ensure_node(1, "a", "t0");
        graph.ensure_node(2, "b", "t0");

        graph.record_mcp_call(1, 2, "t1");
        graph.record_parent_child(1, 2, "t2");

        assert_eq!(graph.edge_count(), 2);
        let edges = graph.outgoing_edges(1);
        assert_eq!(edges.len(), 2);
    }

    #[test]
    fn temporal_relay_detection() {
        let mut graph = AgentGraph::new();
        graph.ensure_node(1, "agent-a", "12:00:00.000");
        graph.ensure_node(2, "agent-b", "12:00:00.000");

        // Agent A makes an outbound call
        graph.record_outbound(1, 0xABCD, 1000);

        // Agent B makes an outbound call in the same container within 5s
        let relay = graph.check_relay(2, 0xABCD, 3000, "12:00:03.000");
        assert_eq!(relay, Some(1));
        assert_eq!(graph.edge_count(), 1);
    }

    #[test]
    fn no_relay_different_container() {
        let mut graph = AgentGraph::new();
        graph.ensure_node(1, "a", "t");
        graph.ensure_node(2, "b", "t");

        graph.record_outbound(1, 0xABCD, 1000);
        let relay = graph.check_relay(2, 0x1234, 2000, "t");
        assert!(relay.is_none());
    }

    #[test]
    fn no_relay_outside_window() {
        let mut graph = AgentGraph::new();
        graph.ensure_node(1, "a", "t");
        graph.ensure_node(2, "b", "t");

        graph.record_outbound(1, 0xABCD, 1000);
        let relay = graph.check_relay(2, 0xABCD, 7000, "t"); // > 5s
        assert!(relay.is_none());
    }

    #[test]
    fn no_relay_same_identity() {
        let mut graph = AgentGraph::new();
        graph.ensure_node(1, "a", "t");

        graph.record_outbound(1, 0xABCD, 1000);
        let relay = graph.check_relay(1, 0xABCD, 2000, "t");
        assert!(relay.is_none());
    }

    #[test]
    fn no_relay_no_container() {
        let mut graph = AgentGraph::new();
        graph.ensure_node(1, "a", "t");
        graph.ensure_node(2, "b", "t");

        graph.record_outbound(1, 0, 1000);
        let relay = graph.check_relay(2, 0, 2000, "t");
        assert!(relay.is_none());
    }

    #[test]
    fn remove_node_cleans_up() {
        let mut graph = AgentGraph::new();
        graph.ensure_node(1, "a", "t");
        graph.ensure_node(2, "b", "t");
        graph.record_mcp_call(1, 2, "t");

        graph.remove_node(1);
        assert_eq!(graph.node_count(), 1);
        assert_eq!(graph.edge_count(), 0);
    }

    #[test]
    fn parse_timestamp_ms_valid() {
        assert_eq!(parse_timestamp_ms("12:30:45.123"), 45_045_123);
        assert_eq!(parse_timestamp_ms("00:00:00.000"), 0);
        assert_eq!(parse_timestamp_ms("23:59:59.999"), 86_399_999);
    }

    #[test]
    fn parse_timestamp_ms_no_millis() {
        assert_eq!(parse_timestamp_ms("12:00:00"), 43_200_000);
    }

    #[test]
    fn parse_timestamp_ms_invalid() {
        assert_eq!(parse_timestamp_ms("not-a-time"), 0);
        assert_eq!(parse_timestamp_ms(""), 0);
    }
}

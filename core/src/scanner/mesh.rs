//! PQCanary Unified Cryptographic Fleet Mesh & Cross-Medium Synchronization Bus (PQMesh)
//!
//! Enables distributed, real-time cross-medium communication and telemetry exchange across:
//! - Web Dashboard (SolidStart / Vinxi)
//! - Native CLI (Shell / CI/CD Pipelines)
//! - VS Code Extension
//! - Neovim / Classic Vim Plugins
//! - Web Browser Extensions (Chrome, Brave, Edge, Firefox)
//! - Kubernetes DaemonSets & Docker Containers
//! - Model Context Protocol (MCP) AI Agents (Claude, Cursor, Gemini)
//! - Tauri Native Desktop Clients
//! - Central REST API Daemons
//!
//! Features:
//! 1. Peer-to-peer and Hub-and-Spoke node discovery with automatic heartbeat monitoring.
//! 2. Cross-medium real-time event broadcasting (finding discoveries, automated patches, runtime alerts).
//! 3. Unified Corporate Cryptographic Bill of Materials (CBOM) aggregation across code, runtime, and network.
//! 4. Dynamic policy hot-reloading across all active fleet mediums without restart.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{RwLock, broadcast};
use serde::{Serialize, Deserialize};
use crate::scanner::orchestrator::ComprehensiveFinding;

fn current_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperationalMedium {
    Cli,
    VsCode,
    Neovim,
    BrowserExtension,
    KubernetesDaemonSet,
    McpAgent,
    WebDashboard,
    TauriDesktop,
    DockerContainer,
    ApiHeadNode,
}

impl OperationalMedium {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cli => "CLI (Terminal / CI/CD)",
            Self::VsCode => "VS Code Extension",
            Self::Neovim => "Neovim / Vim Plugin",
            Self::BrowserExtension => "Browser Extension",
            Self::KubernetesDaemonSet => "Kubernetes DaemonSet",
            Self::McpAgent => "MCP AI Agent",
            Self::WebDashboard => "Web Dashboard",
            Self::TauriDesktop => "Tauri Desktop App",
            Self::DockerContainer => "Docker Container",
            Self::ApiHeadNode => "Head Node API",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            Self::Cli => "CLI",
            Self::VsCode => "VSCODE",
            Self::Neovim => "NVIM",
            Self::BrowserExtension => "WEB-EXT",
            Self::KubernetesDaemonSet => "K8S",
            Self::McpAgent => "MCP",
            Self::WebDashboard => "DASH",
            Self::TauriDesktop => "DESKTOP",
            Self::DockerContainer => "DOCKER",
            Self::ApiHeadNode => "API",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeshNodeStatus {
    Online,
    Idle,
    Scanning,
    Offline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshNode {
    pub node_id: String,
    pub medium: OperationalMedium,
    pub label: String,
    pub version: String,
    pub endpoint: Option<String>,
    pub status: MeshNodeStatus,
    pub registered_at_epoch: u64,
    pub last_heartbeat_epoch: u64,
    pub active_context: Option<String>,
    pub findings_count: usize,
    pub scans_count: usize,
    pub patches_applied: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeshEventType {
    NodeJoined,
    NodeHeartbeat,
    FindingDiscovered,
    LiveEndpointAudited,
    RuntimeProcessAlert,
    PatchApplied,
    PolicyReloaded,
    CbomAggregated,
    DirectCommand,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshEvent {
    pub event_id: String,
    pub timestamp_epoch: u64,
    pub source_node_id: String,
    pub source_medium: OperationalMedium,
    pub event_type: MeshEventType,
    pub title: String,
    pub details: String,
    pub severity: String, // "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    pub payload_json: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetMeshSummary {
    pub total_nodes_online: usize,
    pub nodes_by_medium: HashMap<String, usize>,
    pub total_fleet_findings: usize,
    pub critical_findings_count: usize,
    pub fleet_health_score: f64, // 0..100
    pub active_nodes: Vec<MeshNode>,
    pub recent_events: Vec<MeshEvent>,
}

pub struct FleetMeshState {
    pub nodes: HashMap<String, MeshNode>,
    pub events: VecDeque<MeshEvent>,
    pub unified_findings: HashMap<String, ComprehensiveFinding>,
    pub broadcast_tx: broadcast::Sender<MeshEvent>,
    pub webhook_url: Option<String>,
}

impl Default for FleetMeshState {
    fn default() -> Self {
        let (broadcast_tx, _) = broadcast::channel(512);
        let now = current_epoch_secs();

        let mut nodes = HashMap::new();
        // Register the local API Daemon (Head Node) as the actual running node
        nodes.insert("node-api-daemon".to_string(), MeshNode {
            node_id: "node-api-daemon".to_string(),
            medium: OperationalMedium::ApiHeadNode,
            label: "PQCanary REST API Daemon".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            endpoint: Some("http://0.0.0.0:8080".to_string()),
            status: MeshNodeStatus::Online,
            registered_at_epoch: now,
            last_heartbeat_epoch: now,
            active_context: Some("Active Cryptographic Scanner & Verification Daemon".to_string()),
            findings_count: 0,
            scans_count: 0,
            patches_applied: 0,
        });

        Self {
            nodes,
            events: VecDeque::new(),
            unified_findings: HashMap::new(),
            broadcast_tx,
            webhook_url: None,
        }
    }
}

pub struct FleetMeshBus;

static GLOBAL_MESH: OnceLock<Arc<RwLock<FleetMeshState>>> = OnceLock::new();

impl FleetMeshBus {
    pub fn get_instance() -> &'static Arc<RwLock<FleetMeshState>> {
        GLOBAL_MESH.get_or_init(|| Arc::new(RwLock::new(FleetMeshState::default())))
    }

    /// Register or refresh heartbeat for an operational medium node
    pub async fn register_or_heartbeat(mut node: MeshNode) {
        let bus = Self::get_instance();
        let mut state = bus.write().await;
        let id = node.node_id.clone();
        let is_new = !state.nodes.contains_key(&id);
        let now = current_epoch_secs();

        if let Some(existing) = state.nodes.get(&id) {
            if node.registered_at_epoch == 0 {
                node.registered_at_epoch = existing.registered_at_epoch;
            }
        } else if node.registered_at_epoch == 0 {
            node.registered_at_epoch = now;
        }

        if node.last_heartbeat_epoch == 0 {
            node.last_heartbeat_epoch = now;
        }
        
        state.nodes.insert(id.clone(), node.clone());

        if is_new {
            let evt = MeshEvent {
                event_id: format!("evt-join-{}", now),
                timestamp_epoch: now,
                source_node_id: id,
                source_medium: node.medium,
                event_type: MeshEventType::NodeJoined,
                title: format!("New Fleet Node Joined: {}", node.label),
                details: format!("Medium: {} (v{}) is now active in the mesh.", node.medium.as_str(), node.version),
                severity: "INFO".to_string(),
                payload_json: None,
            };
            state.events.push_back(evt.clone());
            if state.events.len() > 1000 {
                state.events.pop_front();
            }
            let _ = state.broadcast_tx.send(evt);
        }
    }

    /// Configure enterprise alerting webhook URL dynamically
    pub async fn set_webhook_url(url: Option<String>) {
        let bus = Self::get_instance();
        let mut state = bus.write().await;
        state.webhook_url = url;
    }

    /// Retrieve active enterprise alerting webhook URL
    pub async fn get_webhook_url() -> Option<String> {
        let bus = Self::get_instance();
        let state = bus.read().await;
        state.webhook_url.clone()
    }

    /// Broadcast an event across all connected fleet mediums
    pub async fn broadcast_event(event: MeshEvent) {
        let bus = Self::get_instance();
        let webhook_url_opt = {
            let mut state = bus.write().await;
            state.events.push_back(event.clone());
            if state.events.len() > 1000 {
                state.events.pop_front();
            }
            let _ = state.broadcast_tx.send(event.clone());
            state.webhook_url.clone().or_else(|| std::env::var("PQCANARY_WEBHOOK_URL").ok())
        };

        // Enterprise Webhook Dispatch (Slack / Teams / PagerDuty / Custom SIEM)
        if event.severity == "CRITICAL" || event.severity == "HIGH" {
            if let Some(webhook_url) = webhook_url_opt {
                let trimmed = webhook_url.trim().to_string();
                if !trimmed.is_empty() {
                    // SSRF prevention: ensure target is valid and not targeting internal metadata/private endpoints
                    if crate::api::validate_network_target(&trimmed).is_ok() {
                        let evt_clone = event.clone();
                        tokio::spawn(async move {
                            let client = reqwest::Client::builder()
                                .timeout(std::time::Duration::from_secs(10))
                                .build()
                                .unwrap_or_else(|_| reqwest::Client::new());
                            let payload = serde_json::json!({
                                "text": format!("ALERT: *PQCanary {}* {}", evt_clone.severity, evt_clone.title),
                                "event_id": evt_clone.event_id,
                                "severity": evt_clone.severity,
                                "medium": evt_clone.source_medium.as_str(),
                                "details": evt_clone.details,
                                "timestamp": evt_clone.timestamp_epoch,
                            });
                            let _ = client.post(&trimmed)
                                .json(&payload)
                                .send()
                                .await;
                        });
                    }
                }
            }
        }
    }

    /// Save current mesh state snapshot to disk (nodes, events, and unified findings)
    pub async fn save_snapshot_to_path(path: &std::path::Path) -> Result<(), String> {
        let bus = Self::get_instance();
        let state = bus.read().await;
        let serializable = serde_json::json!({
            "nodes": state.nodes,
            "events": state.events,
            "unified_findings": state.unified_findings,
            "webhook_url": state.webhook_url,
            "saved_at_epoch": current_epoch_secs(),
        });
        let json_str = serde_json::to_string_pretty(&serializable)
            .map_err(|e| format!("Serialization error: {}", e))?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        std::fs::write(path, json_str)
            .map_err(|e| format!("Write error: {}", e))
    }

    /// Load mesh state snapshot from disk (restoring nodes, events, and unified findings)
    pub async fn load_snapshot_from_path(path: &std::path::Path) -> Result<usize, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Read error: {}", e))?;
        let v: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| format!("Parse error: {}", e))?;
        let bus = Self::get_instance();
        let mut state = bus.write().await;
        let mut restored = 0;

        if let Some(nodes_obj) = v.get("nodes").and_then(|n| n.as_object()) {
            for (k, val) in nodes_obj {
                if let Ok(node) = serde_json::from_value::<MeshNode>(val.clone()) {
                    state.nodes.insert(k.clone(), node);
                    restored += 1;
                }
            }
        }

        if let Some(events_arr) = v.get("events").and_then(|e| e.as_array()) {
            for val in events_arr {
                if let Ok(evt) = serde_json::from_value::<MeshEvent>(val.clone()) {
                    if !state.events.iter().any(|existing| existing.event_id == evt.event_id) {
                        state.events.push_back(evt);
                    }
                }
            }
            while state.events.len() > 1000 {
                state.events.pop_front();
            }
        }

        if let Some(findings_obj) = v.get("unified_findings").and_then(|f| f.as_object()) {
            for (k, val) in findings_obj {
                if let Ok(finding) = serde_json::from_value::<ComprehensiveFinding>(val.clone()) {
                    state.unified_findings.insert(k.clone(), finding);
                }
            }
        }

        if let Some(wh) = v.get("webhook_url").and_then(|w| w.as_str()) {
            if !wh.trim().is_empty() {
                state.webhook_url = Some(wh.to_string());
            }
        }

        Ok(restored)
    }

    /// Ingest a batch of findings from any medium (CLI, IDE, Browser, K8s) into the unified enterprise registry
    pub async fn ingest_findings(
        node_id: &str,
        medium: OperationalMedium,
        findings: Vec<ComprehensiveFinding>,
    ) {
        let count = findings.len();
        let now = current_epoch_secs();
        {
            let bus = Self::get_instance();
            let mut state = bus.write().await;

            for f in findings {
                let key = f.fingerprint.clone().unwrap_or_else(|| {
                    format!("{}:{}:{}", f.file_path, f.rule_id.as_deref().unwrap_or(&f.vulnerability_class), f.line_number)
                });
                state.unified_findings.insert(key, f);
            }

            if let Some(node) = state.nodes.get_mut(node_id) {
                node.findings_count += count;
                node.scans_count += 1;
                node.last_heartbeat_epoch = now;
            }
        }

        let evt = MeshEvent {
            event_id: format!("evt-sync-{}", now),
            timestamp_epoch: now,
            source_node_id: node_id.to_string(),
            source_medium: medium,
            event_type: MeshEventType::CbomAggregated,
            title: format!("Cryptographic Findings Synced ({} items)", count),
            details: format!("Medium '{}' synced {} cryptographic findings into unified fleet registry.", medium.as_str(), count),
            severity: if count > 0 { "HIGH".to_string() } else { "INFO".to_string() },
            payload_json: None,
        };
        Self::broadcast_event(evt).await;
    }

    /// Retrieve summary of fleet health and active nodes
    pub async fn get_summary() -> FleetMeshSummary {
        let bus = Self::get_instance();
        let state = bus.read().await;
        let now = current_epoch_secs();

        let mut nodes_by_medium = HashMap::new();
        let mut online_count = 0;
        let mut active_nodes = Vec::new();

        for n in state.nodes.values() {
            let is_daemon = n.node_id == "node-api-daemon";
            let is_alive = is_daemon || n.last_heartbeat_epoch >= now || now.saturating_sub(n.last_heartbeat_epoch) <= 600; // 10 min window
            if is_alive {
                online_count += 1;
                *nodes_by_medium.entry(n.medium.as_str().to_string()).or_insert(0) += 1;
                let mut n_clone = n.clone();
                if is_daemon {
                    n_clone.status = MeshNodeStatus::Online;
                }
                active_nodes.push(n_clone);
            }
        }

        let total_findings = state.unified_findings.len();
        let critical_count = state.unified_findings.values().filter(|f| f.severity == "CRITICAL").count();

        // Health score: 100 base, penalize for critical/high findings
        let health = (100.0 - (critical_count as f64 * 12.0) - (total_findings as f64 * 0.5)).clamp(15.0, 100.0);

        FleetMeshSummary {
            total_nodes_online: online_count,
            nodes_by_medium,
            total_fleet_findings: total_findings,
            critical_findings_count: critical_count,
            fleet_health_score: health,
            active_nodes,
            recent_events: state.events.iter().rev().take(50).cloned().collect(),
        }
    }

    /// Subscribe to the live broadcast channel for Server-Sent Events (SSE) or WebSockets
    pub async fn subscribe() -> broadcast::Receiver<MeshEvent> {
        let bus = Self::get_instance();
        let state = bus.read().await;
        state.broadcast_tx.subscribe()
    }
}

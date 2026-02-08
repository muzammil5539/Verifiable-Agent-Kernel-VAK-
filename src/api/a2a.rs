//! Agent-to-Agent API Endpoints (SWM-002)
//!
//! Exposes A2A functionality via HTTP API.

use crate::dashboard::server::HttpResponse;
use crate::swarm::a2a::DiscoveryService;
use std::sync::Arc;

/// Handle A2A API requests
pub async fn handle_request(
    discovery: &Arc<DiscoveryService>,
    path: &str,
    method: &str,
) -> Option<HttpResponse> {
    match (method, path) {
        ("GET", "/api/a2a/agents") => {
            let agents = discovery.list_agents().await;
            Some(HttpResponse {
                status: 200,
                content_type: "application/json".to_string(),
                body: serde_json::to_string(&agents).unwrap_or_else(|_| "[]".to_string()),
            })
        }
        ("GET", p) if p.starts_with("/api/a2a/agents/") => {
            let id = p.trim_start_matches("/api/a2a/agents/");
            if let Some(agent) = discovery.get_agent(id).await {
                Some(HttpResponse {
                    status: 200,
                    content_type: "application/json".to_string(),
                    body: serde_json::to_string(&agent).unwrap_or_else(|_| "{}".to_string()),
                })
            } else {
                Some(HttpResponse {
                    status: 404,
                    content_type: "application/json".to_string(),
                    body: r#"{"error": "Agent not found"}"#.to_string(),
                })
            }
        }
        _ => None,
    }
}

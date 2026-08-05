//! `aloo-ai` — AI-assisted scan summarisation.
//!
//! Builds prompts from scan results and forwards them to an LLM endpoint.
//! The HTTP client is **stubbed** — real API calls will be added once the
//! networking milestone is complete.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use aloo_core::ScanResult;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::debug;

// ── Error types ───────────────────────────────────────────────────────────────

/// Errors from the AI summarisation subsystem.
#[derive(Debug, Error)]
pub enum AiError {
    /// Client is not configured (no API key or endpoint).
    #[error("AI client not configured")]
    NotConfigured,
    /// HTTP request to the AI endpoint failed.
    #[error("AI request failed: {0}")]
    RequestFailed(String),
    /// The model returned an unexpected response format.
    #[error("Unexpected response from model: {0}")]
    BadResponse(String),
    /// Rate limit exceeded on the AI endpoint.
    #[error("AI endpoint rate limited")]
    RateLimited,
}

// ── Config ────────────────────────────────────────────────────────────────────

/// Configuration for an AI LLM endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    /// Base URL of the AI endpoint (e.g. `https://api.openai.com`).
    pub endpoint_url: String,
    /// API key / bearer token.
    pub api_key: String,
    /// Model identifier (e.g. `gpt-4o`, `gemini-1.5-pro`).
    pub model: String,
    /// Maximum tokens in the generated response.
    pub max_tokens: u32,
    /// Request timeout in seconds.
    pub timeout_secs: u64,
}

impl AiConfig {
    /// Create a minimal config.
    pub fn new(
        endpoint_url: impl Into<String>,
        api_key: impl Into<String>,
        model: impl Into<String>,
    ) -> Self {
        Self {
            endpoint_url: endpoint_url.into(),
            api_key: api_key.into(),
            model: model.into(),
            max_tokens: 2_048,
            timeout_secs: 30,
        }
    }

    /// Returns true if the config appears usable (non-empty key and URL).
    pub fn is_usable(&self) -> bool {
        !self.api_key.is_empty() && !self.endpoint_url.is_empty()
    }
}

// ── Prompt builder ────────────────────────────────────────────────────────────

/// Builds LLM prompts from scan results.
pub struct PromptBuilder;

impl PromptBuilder {
    /// Build a structured scan summary prompt.
    pub fn build_scan_summary_prompt(result: &ScanResult) -> String {
        let host_count    = result.hosts.len();
        let open_ports    = result.total_open_ports();
        let vuln_count    = result.total_vulnerabilities();
        let critical      = result.critical_hosts().len();
        let targets       = result.session.targets.join(", ");

        let services: Vec<String> = result
            .hosts
            .iter()
            .flat_map(|h| h.ports.iter())
            .filter_map(|p| p.service.as_ref().map(|s| s.name.clone()))
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        format!(
            "You are a senior network security analyst. Analyse the following Aloo scan results \
            and provide a concise executive summary with key findings, risk assessment, and \
            prioritised remediation recommendations.\n\n\
            ## Scan Details\n\
            - **Targets:** {targets}\n\
            - **Hosts Discovered:** {host_count}\n\
            - **Open Ports:** {open_ports}\n\
            - **Total Vulnerabilities:** {vuln_count}\n\
            - **Hosts with Critical Vulns:** {critical}\n\
            - **Detected Services:** {services}\n\n\
            Provide your analysis in the following format:\n\
            1. Executive Summary (2-3 sentences)\n\
            2. Key Findings (bullet points)\n\
            3. Risk Rating (Critical / High / Medium / Low)\n\
            4. Remediation Priorities (numbered list)\n",
            services = if services.is_empty() { "None identified".to_string() } else { services.join(", ") },
        )
    }

    /// Build a prompt for explaining a specific CVE in context.
    pub fn build_cve_explain_prompt(cve_id: &str, service: &str, host: &str) -> String {
        format!(
            "Explain {cve_id} as it applies to a {service} service on host {host}. \
            Include: (1) what the vulnerability is, (2) exploitation likelihood, \
            (3) business impact, (4) specific remediation steps.",
        )
    }
}

// ── AI client ─────────────────────────────────────────────────────────────────

/// Sends prompts to an LLM endpoint and returns generated text.
pub struct AiClient {
    config: AiConfig,
}

impl AiClient {
    /// Create an AI client with the given configuration.
    pub fn new(config: AiConfig) -> Self {
        Self { config }
    }

    /// Generate a scan summary using the configured LLM.
    ///
    /// **Stub** — returns a placeholder until the HTTP client is wired.
    pub async fn summarise(&self, result: &ScanResult) -> Result<String, AiError> {
        if !self.config.is_usable() {
            return Err(AiError::NotConfigured);
        }
        let prompt = PromptBuilder::build_scan_summary_prompt(result);
        debug!(
            model = %self.config.model,
            prompt_len = prompt.len(),
            "AiClient::summarise stub — returning placeholder"
        );
        // Stub: real implementation sends an HTTP POST to self.config.endpoint_url
        Ok(format!(
            "[AI stub] Would summarise scan with {} hosts using model '{}'.",
            result.hosts.len(),
            self.config.model
        ))
    }

    /// Explain a CVE in the context of a specific host and service.
    ///
    /// **Stub** — returns a placeholder.
    pub async fn explain_cve(
        &self,
        cve_id: &str,
        service: &str,
        host: &str,
    ) -> Result<String, AiError> {
        if !self.config.is_usable() {
            return Err(AiError::NotConfigured);
        }
        debug!(cve_id, service, host, "AiClient::explain_cve stub");
        Ok(format!("[AI stub] Would explain {cve_id} for {service} on {host}."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aloo_core::ScanSession;

    fn empty_result() -> ScanResult {
        let mut s = ScanSession::new(vec!["10.0.0.0/24".into()]);
        s.complete();
        ScanResult { session: s, hosts: vec![] }
    }

    #[test]
    fn prompt_builder_produces_non_empty_string() {
        let result = empty_result();
        let prompt = PromptBuilder::build_scan_summary_prompt(&result);
        assert!(!prompt.is_empty());
        assert!(prompt.contains("security analyst"));
    }

    #[test]
    fn prompt_builder_includes_target() {
        let result = empty_result();
        let prompt = PromptBuilder::build_scan_summary_prompt(&result);
        assert!(prompt.contains("10.0.0.0/24"));
    }

    #[test]
    fn cve_prompt_mentions_cve_id() {
        let p = PromptBuilder::build_cve_explain_prompt("CVE-2023-44487", "nginx", "10.0.0.1");
        assert!(p.contains("CVE-2023-44487"));
        assert!(p.contains("nginx"));
    }

    #[test]
    fn ai_config_usability_empty_key() {
        let c = AiConfig::new("https://api.example.com", "", "gpt-4o");
        assert!(!c.is_usable());
    }

    #[test]
    fn ai_config_usability_valid() {
        let c = AiConfig::new("https://api.example.com", "sk-test123", "gpt-4o");
        assert!(c.is_usable());
    }

    #[tokio::test]
    async fn ai_client_not_configured_error() {
        let config = AiConfig::new("", "", "gpt-4o");
        let client = AiClient::new(config);
        let result = empty_result();
        let err = client.summarise(&result).await.unwrap_err();
        assert!(matches!(err, AiError::NotConfigured));
    }

    #[tokio::test]
    async fn ai_client_stub_returns_placeholder() {
        let config = AiConfig::new("https://api.example.com", "sk-test", "gpt-4o");
        let client = AiClient::new(config);
        let result = empty_result();
        let s = client.summarise(&result).await.unwrap();
        assert!(s.contains("stub"));
    }
}

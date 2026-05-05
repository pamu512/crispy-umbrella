//! Proxy for local Ollama: HTTP to the Ollama daemon runs in the Tauri host so the WebView never
//! opens `http://127.0.0.1:11434` directly.

use std::time::Duration;

use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use tauri::State;

use crate::AppState;

/// Barney persona + live vault slice injected as the **first `system`** message (Ollama convention).
/// When `is_dino_mode`, [`crate::dino_persona::DINO_SYSTEM_PROMPT`] replaces the default Threat Hunter tone.
fn inject_barney_vault_context(mut messages: Vec<Value>, is_dino_mode: bool) -> Vec<Value> {
    let data = crate::fetch_recent_vault_context();
    let system_injection = if is_dino_mode {
        format!(
            "{}\n\nAnalyze the provided System Data Context to help your Best Friend. Stay in persona.\n\nSystem Data Context: {}",
            crate::dino_persona::DINO_SYSTEM_PROMPT,
            data
        )
    } else {
        format!(
            "You are Barney, the lead Cyber Threat Hunter for this CTI Command Center. Analyze the provided System Data Context to answer the user's queries proactively.\n\nSystem Data Context: {}",
            data
        )
    };
    if messages
        .first()
        .and_then(|m| m.get("role"))
        .and_then(|r| r.as_str())
        == Some("system")
    {
        let old = messages
            .get(0)
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .trim();
        let merged = if old.is_empty() {
            system_injection
        } else {
            format!(
                "{}\n\nAdditional instructions: {}",
                system_injection, old
            )
        };
        messages[0] = json!({ "role": "system", "content": merged });
    } else {
        messages.insert(
            0,
            json!({ "role": "system", "content": system_injection }),
        );
    }
    messages
}

const DEFAULT_MODEL: &str = "llama3.2";
const DEFAULT_OLLAMA_HOST: &str = "http://127.0.0.1:11434";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(600);

/// Payload from the frontend (`camelCase` keys). Either **`prompt`** (optional **`system`**) or
/// a full **`messages`** array (Ollama chat format) must be supplied.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvokeLocalLlmPayload {
    /// Single-turn user text. Ignored when `messages` is set.
    #[serde(default)]
    pub prompt: Option<String>,
    /// Full `messages` array for `/api/chat` (system, user, assistant, tool, …).
    #[serde(default)]
    pub messages: Option<Vec<Value>>,
    /// Optional tools definition (Ollama tool-calling). Omitted from the HTTP body when empty.
    #[serde(default)]
    pub tools: Option<Vec<Value>>,
    /// Prepended as a `system` message when using `prompt` mode.
    #[serde(default)]
    pub system: Option<String>,
    /// Ollama model name (default `llama3.2`).
    #[serde(default)]
    pub model: Option<String>,
    /// Base URL without trailing slash (default `http://127.0.0.1:11434`).
    #[serde(default)]
    pub ollama_host: Option<String>,
}

fn build_chat_url(host: &str) -> String {
    let h = host.trim().trim_end_matches('/');
    format!("{}/api/chat", h)
}

fn resolve_messages(payload: &InvokeLocalLlmPayload) -> Result<Vec<Value>, String> {
    if let Some(msgs) = &payload.messages {
        if msgs.is_empty() {
            return Err("messages must not be an empty array".into());
        }
        return Ok(msgs.clone());
    }
    let prompt = payload
        .prompt
        .as_ref()
        .ok_or_else(|| "Either prompt or messages is required".to_string())?;
    let trimmed = prompt.trim();
    if trimmed.is_empty() {
        return Err("prompt must not be empty".into());
    }
    let mut out: Vec<Value> = Vec::new();
    if let Some(sys) = &payload.system {
        let s = sys.trim();
        if !s.is_empty() {
            out.push(json!({ "role": "system", "content": s }));
        }
    }
    out.push(json!({ "role": "user", "content": trimmed }));
    Ok(out)
}

/// Forward a chat completion request to the local Ollama **`/api/chat`** endpoint using **reqwest**.
///
/// Default model is **`llama3.2`**. Returns the parsed JSON body from Ollama (same shape as a
/// direct `fetch` to `/api/chat` with `stream: false`).
#[tauri::command]
pub async fn invoke_local_llm(
    state: State<'_, AppState>,
    payload: InvokeLocalLlmPayload,
) -> Result<Value, String> {
    let messages = resolve_messages(&payload)?;
    let messages = inject_barney_vault_context(messages, state.dino_mode());

    let model = payload
        .model
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| DEFAULT_MODEL.to_string());

    let host = payload
        .ollama_host
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| DEFAULT_OLLAMA_HOST.to_string());

    let url = build_chat_url(&host);

    let mut body = Map::new();
    body.insert("model".into(), json!(model));
    body.insert("messages".into(), json!(messages));
    body.insert("stream".into(), json!(false));

    if let Some(ref tools) = payload.tools {
        if !tools.is_empty() {
            body.insert("tools".into(), json!(tools));
        }
    }

    let client = Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|e| format!("reqwest client build failed: {}", e))?;

    let response = client
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .json(&Value::Object(body))
        .send()
        .await
        .map_err(|e| format!("Ollama request failed (is Ollama running on {}?): {}", host, e))?;

    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|e| format!("reading Ollama response body failed: {}", e))?;

    if !status.is_success() {
        let body_preview = String::from_utf8_lossy(&bytes);
        return Err(format!(
            "Ollama returned HTTP {}: {}",
            status.as_u16(),
            body_preview.chars().take(2000).collect::<String>()
        ));
    }

    serde_json::from_slice(&bytes).map_err(|e| {
        format!(
            "invalid JSON from Ollama ({} bytes): {}",
            bytes.len(),
            e
        )
    })
}

//! External attack surface discovery without Docker, Postgres, or Celery.
//!
//! Uses **trust-dns-resolver** for `A` / `AAAA` / `MX`, passive subdomains from **crt.sh** (JSON
//! over HTTPS), a small DNS prefix probe list, **TCP** connect checks on common ports, and
//! **rustls** via **tokio-rustls** to scrape the presented TLS leaf certificate. Structured
//! results are upserted into **`asm_assets`** (`asset_target`, `asset_type`, `last_scan_at`,
//! `status`, `metadata`).

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hex::encode as hex_encode;
use regex::Regex;
use reqwest::header::USER_AGENT;
use rusqlite::params;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::error::ResolveErrorKind;
use trust_dns_resolver::proto::rr::Name;
use trust_dns_resolver::TokioAsyncResolver;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::FromDer;
use x509_parser::x509::X509Name;

use crate::config_manager::{get_api_key, KEYRING_EASM_PENTEST_TOOLS, KEYRING_EASM_SHODAN};
use crate::vault_db::{self, time_now_iso};

const SOURCE_TAG: &str = "easm_scanner";
/// Keyring label for Shodan (alias for [`crate::config_manager::KEYRING_EASM_SHODAN`]).
pub const API_KEY_SERVICE_SHODAN: &str = KEYRING_EASM_SHODAN;
/// Keyring label for Pentest-Tools (alias for [`crate::config_manager::KEYRING_EASM_PENTEST_TOOLS`]).
pub const API_KEY_SERVICE_PENTEST_TOOLS: &str = KEYRING_EASM_PENTEST_TOOLS;

const SHODAN_API_BASE: &str = "https://api.shodan.io";
const PENTEST_TOOLS_API_BASE: &str = "https://app.pentest-tools.com/api/v2";
/// Pentest-Tools tool id for Subdomain Finder (see their API examples).
const PENTEST_TOOL_SUBDOMAIN_FINDER: i64 = 20;
const HTTP_UA: &str =
    "Mozilla/5.0 (compatible; CTI-EASM/1.0; +https://example.invalid)";

const COMMON_PORTS: &[u16] = &[80, 443, 8080, 8443, 22, 25, 587, 993, 3389, 3306, 5432, 27017];

const SUBDOMAIN_PREFIXES: &[&str] = &[
    "www", "mail", "mx", "smtp", "webmail", "vpn", "remote", "api", "dev", "staging", "test",
    "portal", "cdn", "static", "ftp", "imap", "pop", "owa", "autodiscover", "m", "app", "gw",
    "firewall", "ns1", "ns2", "dns", "ldap", "admin", "intranet", "extranet", "citrix", "rdp",
];

// ---------------------------------------------------------------------------
// Shodan API — GET /dns/domain/{domain} (developer.shodan.io)
// ---------------------------------------------------------------------------

/// Top-level JSON returned by `GET https://api.shodan.io/dns/domain/{domain}?key=…`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ShodanDnsDomainResponse {
    pub domain: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub data: Vec<ShodanDnsDomainRecord>,
    #[serde(default)]
    pub subdomains: Vec<String>,
    #[serde(default)]
    pub more: bool,
}

/// One row in the Shodan DNS domain `data` array (`subdomain`, `type`, `value`, `last_seen`).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ShodanDnsDomainRecord {
    #[serde(default)]
    pub subdomain: String,
    #[serde(rename = "type")]
    pub record_type: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub last_seen: Option<String>,
}

// ---------------------------------------------------------------------------
// Pentest-Tools API v2 — scans + output (app.pentest-tools.com)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct PentestToolsEnvelope<T> {
    data: T,
}

#[derive(Debug, Deserialize)]
struct PentestScanCreateData {
    created_id: i64,
}

#[derive(Debug, Deserialize)]
struct PentestScanStatusData {
    status_name: String,
    /// Present in API responses; reserved for future logging / UI.
    #[serde(default)]
    #[allow(dead_code)]
    progress: Option<u8>,
}

static CRYPTO_INSTALLED: AtomicBool = AtomicBool::new(false);

fn ensure_rustls_crypto_provider() -> Result<(), EasmScanError> {
    if CRYPTO_INSTALLED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|e| {
            EasmScanError::Tls(format!(
                "rustls CryptoProvider install failed (already installed?): {:?}",
                e
            ))
        })
}

#[derive(Debug)]
pub enum EasmScanError {
    BadDomain(String),
    MissingVaultPath(String),
    Dns(String),
    Http(String),
    Json(String),
    Tls(String),
    Vault(String),
}

impl std::fmt::Display for EasmScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EasmScanError::BadDomain(s) => write!(f, "{}", s),
            EasmScanError::MissingVaultPath(s) => write!(f, "{}", s),
            EasmScanError::Dns(s) => write!(f, "dns: {}", s),
            EasmScanError::Http(s) => write!(f, "http: {}", s),
            EasmScanError::Json(s) => write!(f, "json: {}", s),
            EasmScanError::Tls(s) => write!(f, "tls: {}", s),
            EasmScanError::Vault(s) => write!(f, "vault: {}", s),
        }
    }
}

impl std::error::Error for EasmScanError {}

// ---------------------------------------------------------------------------
// DNS (trust-dns-resolver)
// ---------------------------------------------------------------------------

fn parse_name(fqdn: &str) -> Result<Name, EasmScanError> {
    let s = fqdn.trim().trim_end_matches('.');
    if s.is_empty() {
        return Err(EasmScanError::BadDomain("empty DNS name".into()));
    }
    Name::parse(s, None).map_err(|e| EasmScanError::Dns(format!("invalid name {:?}: {}", fqdn, e)))
}

async fn build_resolver() -> TokioAsyncResolver {
    match TokioAsyncResolver::tokio_from_system_conf() {
        Ok(r) => r,
        Err(e) => {
            log::warn!("system DNS resolver unavailable ({}); using defaults", e);
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
        }
    }
}

async fn lookup_ipv4_strings(resolver: &TokioAsyncResolver, name: &Name) -> Vec<String> {
    match resolver.lookup_ip(name.clone()).await {
        Ok(resp) => resp
            .iter()
            .filter(|ip| ip.is_ipv4())
            .map(|ip| ip.to_string())
            .collect(),
        Err(e) => {
            if matches!(e.kind(), ResolveErrorKind::NoRecordsFound { .. }) {
                Vec::new()
            } else {
                log::debug!("lookup_ip {:?}: {}", name, e);
                Vec::new()
            }
        }
    }
}

async fn lookup_ipv6_strings(resolver: &TokioAsyncResolver, name: &Name) -> Vec<String> {
    match resolver.lookup_ip(name.clone()).await {
        Ok(resp) => resp
            .iter()
            .filter(|ip| ip.is_ipv6())
            .map(|ip| ip.to_string())
            .collect(),
        Err(e) => {
            if matches!(e.kind(), ResolveErrorKind::NoRecordsFound { .. }) {
                Vec::new()
            } else {
                log::debug!("lookup_ip v6 {:?}: {}", name, e);
                Vec::new()
            }
        }
    }
}

async fn lookup_mx_hosts(resolver: &TokioAsyncResolver, apex: &Name) -> Vec<String> {
    match resolver.mx_lookup(apex.clone()).await {
        Ok(mx) => mx
            .iter()
            .map(|m| m.exchange().to_utf8().trim_end_matches('.').to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect(),
        Err(e) => {
            if matches!(e.kind(), ResolveErrorKind::NoRecordsFound { .. }) {
                Vec::new()
            } else {
                log::debug!("mx_lookup {:?}: {}", apex, e);
                Vec::new()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// crt.sh
// ---------------------------------------------------------------------------

async fn fetch_crt_sh_names(client: &reqwest::Client, apex: &str) -> Result<Vec<String>, EasmScanError> {
    let q = format!("%25.{}", apex.trim().trim_end_matches('.'));
    let url = format!(
        "https://crt.sh/?q={}&output=json",
        urlencoding_encode_query_value(&q)
    );
    let body = client
        .get(&url)
        .header(USER_AGENT, HTTP_UA)
        .timeout(Duration::from_secs(45))
        .send()
        .await
        .map_err(|e| EasmScanError::Http(e.to_string()))?
        .error_for_status()
        .map_err(|e| EasmScanError::Http(e.to_string()))?
        .text()
        .await
        .map_err(|e| EasmScanError::Http(e.to_string()))?;

    let rows: Vec<serde_json::Value> =
        serde_json::from_str(&body).map_err(|e| EasmScanError::Json(e.to_string()))?;
    let mut out = HashSet::new();
    for row in rows.into_iter().take(400) {
        let Some(nv) = row.get("name_value").and_then(|v| v.as_str()) else {
            continue;
        };
        for part in nv.split('\n') {
            let t = part.trim().trim_end_matches('.').to_ascii_lowercase();
            let t = t.strip_prefix("*.").unwrap_or(&t).to_string();
            if t.ends_with(apex) && t.contains('.') && !t.chars().any(|c| c == ' ' || c == '*') {
                out.insert(t);
            }
        }
    }
    let mut v: Vec<String> = out.into_iter().collect();
    v.sort();
    v.truncate(200);
    Ok(v)
}

/// Minimal query-value percent-encoding for `q=` (space → `+`, `%` → `%25`, etc.).
fn urlencoding_encode_query_value(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 8);
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => o.push(char::from(*b)),
            b' ' => o.push('+'),
            _ => o.push_str(&format!("%{:02X}", b)),
        }
    }
    o
}

// ---------------------------------------------------------------------------
// Shodan & Pentest-Tools (optional keyring-backed API keys)
// ---------------------------------------------------------------------------

fn fqdn_from_shodan_subdomain_label(subdomain: &str, apex: &str) -> String {
    let sub = subdomain.trim().trim_end_matches('.');
    let apex = apex.trim().trim_end_matches('.');
    if sub.is_empty() {
        apex.to_string()
    } else {
        format!("{}.{}", sub, apex)
    }
}

/// Collect discoverable hostnames from a Shodan [`ShodanDnsDomainResponse`] for `apex`.
fn hostnames_from_shodan(resp: &ShodanDnsDomainResponse, apex: &str) -> HashSet<String> {
    let apex_l = apex.trim().trim_end_matches('.').to_ascii_lowercase();
    let mut out = HashSet::new();
    for s in &resp.subdomains {
        let fq = fqdn_from_shodan_subdomain_label(s, &apex_l).to_ascii_lowercase();
        if looks_like_hostname(&fq) {
            out.insert(fq);
        }
    }
    for rec in &resp.data {
        let fq = fqdn_from_shodan_subdomain_label(&rec.subdomain, &apex_l).to_ascii_lowercase();
        if looks_like_hostname(&fq) {
            out.insert(fq);
        }
        let v = rec.value.trim().trim_end_matches('.').to_ascii_lowercase();
        if matches!(
            rec.record_type.to_ascii_uppercase().as_str(),
            "MX" | "NS" | "CNAME" | "SRV"
        ) && v.contains(&apex_l)
            && v.contains('.')
            && looks_like_hostname(&v)
        {
            out.insert(v);
        }
    }
    out
}

fn looks_like_hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() < 254
        && !s.chars().any(|c| c.is_whitespace())
}

/// Query Shodan DNS domain data for `apex_domain` using [`get_api_key`](`API_KEY_SERVICE_SHODAN`).
///
/// Returns `Ok(None)` when no API key is configured or the HTTP response is not usable.
pub async fn query_shodan_dns_domain(
    client: &reqwest::Client,
    apex_domain: &str,
) -> Result<Option<ShodanDnsDomainResponse>, EasmScanError> {
    let key = match get_api_key(KEYRING_EASM_SHODAN).filter(|s| !s.trim().is_empty()) {
        Some(k) => k,
        None => {
            log::debug!("Shodan: no API key for service {:?}", KEYRING_EASM_SHODAN);
            return Ok(None);
        }
    };
    let url = format!(
        "{}/dns/domain/{}?key={}",
        SHODAN_API_BASE,
        apex_domain.trim().trim_end_matches('.'),
        urlencoding_encode_query_value(key.trim())
    );
    let resp = client
        .get(&url)
        .header(USER_AGENT, HTTP_UA)
        .timeout(Duration::from_secs(55))
        .send()
        .await
        .map_err(|e| EasmScanError::Http(format!("shodan: {}", e)))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        log::warn!("Shodan DNS domain HTTP {}: {}", status, body.chars().take(200).collect::<String>());
        return Ok(None);
    }
    let body = resp
        .text()
        .await
        .map_err(|e| EasmScanError::Http(format!("shodan body: {}", e)))?;
    let parsed: ShodanDnsDomainResponse =
        serde_json::from_str(&body).map_err(|e| EasmScanError::Json(format!("shodan json: {}", e)))?;
    Ok(Some(parsed))
}

fn collect_hostname_strings(v: &Value, out: &mut HashSet<String>) {
    match v {
        Value::String(s) => {
            if let Some(h) = normalize_hostname_candidate(s) {
                out.insert(h);
            }
        }
        Value::Array(a) => {
            for el in a {
                collect_hostname_strings(el, out);
            }
        }
        Value::Object(map) => {
            for k in ["hostname", "host", "subdomain", "name", "target", "url"] {
                if let Some(inner) = map.get(k) {
                    collect_hostname_strings(inner, out);
                }
            }
        }
        _ => {}
    }
}

fn normalize_hostname_candidate(raw: &str) -> Option<String> {
    let mut t = raw.trim().to_ascii_lowercase();
    if t.is_empty() {
        return None;
    }
    if let Some(rest) = t.strip_prefix("https://").or_else(|| t.strip_prefix("http://")) {
        t = rest
            .split(|c| c == '/' || c == '?' || c == '#')
            .next()
            .unwrap_or("")
            .to_string();
    }
    t = t.trim_end_matches('.').to_string();
    if t.contains(':') {
        // drop :port
        t = t.split(':').next().unwrap_or("").to_string();
    }
    if looks_like_hostname(&t) {
        Some(t)
    } else {
        None
    }
}

/// Best-effort extraction of hostnames from Pentest-Tools `/scans/{id}/output` JSON.
fn hostnames_from_pentest_scan_output(root: &Value) -> HashSet<String> {
    let mut out = HashSet::new();
    let payload = root.get("data").unwrap_or(root);
    collect_hostname_strings(payload, &mut out);
    out
}

/// Start a Subdomain Finder scan (tool id 20), poll until finished, return JSON output `data`.
///
/// Uses [`get_api_key`](`API_KEY_SERVICE_PENTEST_TOOLS`) as `Authorization: Bearer …`.
pub async fn query_pentest_tools_subdomains(
    client: &reqwest::Client,
    apex_domain: &str,
) -> Result<Option<Value>, EasmScanError> {
    let token = match get_api_key(KEYRING_EASM_PENTEST_TOOLS).filter(|s| !s.trim().is_empty()) {
        Some(t) => t,
        None => {
            log::debug!(
                "Pentest-Tools: no API key for service {:?}",
                API_KEY_SERVICE_PENTEST_TOOLS
            );
            return Ok(None);
        }
    };
    let bearer = format!("Bearer {}", token.trim());
    let start_url = format!("{}/scans", PENTEST_TOOLS_API_BASE);
    let body = json!({
        "tool_id": PENTEST_TOOL_SUBDOMAIN_FINDER,
        "target_name": apex_domain.trim().trim_end_matches('.'),
    });
    let started = client
        .post(&start_url)
        .header("Authorization", &bearer)
        .header("Content-Type", "application/json")
        .json(&body)
        .timeout(Duration::from_secs(60))
        .send()
        .await
        .map_err(|e| EasmScanError::Http(format!("pentest-tools start: {}", e)))?;
    let http_status = started.status();
    let start_text = started
        .text()
        .await
        .map_err(|e| EasmScanError::Http(format!("pentest-tools start body: {}", e)))?;
    if !http_status.is_success() {
        log::warn!(
            "Pentest-Tools start scan HTTP {}: {}",
            http_status,
            start_text.chars().take(240).collect::<String>()
        );
        return Ok(None);
    }
    let created: PentestToolsEnvelope<PentestScanCreateData> = serde_json::from_str(&start_text)
        .map_err(|e| EasmScanError::Json(format!("pentest-tools start json: {}", e)))?;
    let scan_id = created.data.created_id;

    let status_url = format!("{}/scans/{}", PENTEST_TOOLS_API_BASE, scan_id);
    let output_url = format!("{}/scans/{}/output", PENTEST_TOOLS_API_BASE, scan_id);

    for attempt in 0..36 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
        let st_resp = client
            .get(&status_url)
            .header("Authorization", &bearer)
            .header(USER_AGENT, HTTP_UA)
            .timeout(Duration::from_secs(45))
            .send()
            .await
            .map_err(|e| EasmScanError::Http(format!("pentest-tools status: {}", e)))?;
        if !st_resp.status().is_success() {
            log::warn!("Pentest-Tools scan {} status HTTP {}", scan_id, st_resp.status());
            return Ok(None);
        }
        let st_text = st_resp
            .text()
            .await
            .map_err(|e| EasmScanError::Http(format!("pentest-tools status body: {}", e)))?;
        let status: PentestToolsEnvelope<PentestScanStatusData> = serde_json::from_str(&st_text)
            .map_err(|e| EasmScanError::Json(format!("pentest-tools status json: {}", e)))?;
        let name = status.data.status_name.as_str();
        match name {
            "finished" => {
                let out_resp = client
                    .get(&output_url)
                    .header("Authorization", &bearer)
                    .header(USER_AGENT, HTTP_UA)
                    .header(reqwest::header::ACCEPT, "application/json")
                    .timeout(Duration::from_secs(60))
                    .send()
                    .await
                    .map_err(|e| EasmScanError::Http(format!("pentest-tools output: {}", e)))?;
                if !out_resp.status().is_success() {
                    log::warn!(
                        "Pentest-Tools scan {} output HTTP {}",
                        scan_id,
                        out_resp.status()
                    );
                    return Ok(None);
                }
                let out_text = out_resp
                    .text()
                    .await
                    .map_err(|e| EasmScanError::Http(format!("pentest-tools output body: {}", e)))?;
                let v: Value =
                    serde_json::from_str(&out_text).map_err(|e| EasmScanError::Json(e.to_string()))?;
                return Ok(Some(v));
            }
            "stopped" | "failed to start" | "timed out" | "aborted" | "VPN connection error"
            | "auth failed" | "connection error" => {
                log::warn!("Pentest-Tools scan {} ended with status {:?}", scan_id, name);
                return Ok(None);
            }
            _ => continue,
        }
    }
    log::warn!(
        "Pentest-Tools scan {} did not finish within polling window",
        scan_id
    );
    Ok(None)
}

// ---------------------------------------------------------------------------
// TLS (rustls + tokio-rustls) + x509-parser
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
struct TlsCertSummary {
    subject: String,
    issuer: String,
    serial_hex: String,
    not_before: String,
    not_after: String,
    san_dns: Vec<String>,
    fingerprints_sha256: Vec<String>,
}

#[derive(Debug)]
struct AcceptAllCerts;

impl ServerCertVerifier for AcceptAllCerts {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
        ]
    }
}

fn tls_client_config_insecure() -> Result<ClientConfig, EasmScanError> {
    ensure_rustls_crypto_provider()?;
    let verifier = Arc::new(AcceptAllCerts);
    Ok(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| EasmScanError::Tls(e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth(),
    )
}

fn x509_name_to_string(name: &X509Name<'_>) -> String {
    name.iter()
        .flat_map(|rdn| rdn.iter())
        .map(|atav| {
            let oid = format!("{:?}", atav.attr_type());
            let v = String::from_utf8_lossy(atav.attr_value().as_bytes());
            format!("{}={}", oid, v)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn summarize_end_entity_cert(der: &[u8]) -> Result<TlsCertSummary, EasmScanError> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| EasmScanError::Tls(e.to_string()))?;
    let subject = x509_name_to_string(cert.subject());
    let issuer = x509_name_to_string(cert.issuer());
    let serial_hex = format!("{:X}", cert.serial);
    let nb = cert.validity().not_before.to_string();
    let na = cert.validity().not_after.to_string();
    let mut san_dns = Vec::new();
    if let Ok(Some(sans)) = cert.subject_alternative_name() {
        for gn in &sans.value.general_names {
            if let GeneralName::DNSName(d) = gn {
                san_dns.push(d.to_ascii_lowercase());
            }
        }
    }
    san_dns.sort();
    san_dns.dedup();
    let fp = hex_encode(Sha256::digest(der));
    Ok(TlsCertSummary {
        subject,
        issuer,
        serial_hex,
        not_before: nb,
        not_after: na,
        san_dns,
        fingerprints_sha256: vec![fp],
    })
}

async fn tls_probe_https(
    apex_sni: &str,
    connect_ip: &str,
    port: u16,
) -> Result<Option<TlsCertSummary>, EasmScanError> {
    if port != 443 && port != 8443 {
        return Ok(None);
    }
    let cfg = Arc::new(tls_client_config_insecure()?);
    let connector = TlsConnector::from(cfg);
    let sni = ServerName::try_from(apex_sni.to_string())
        .map_err(|e| EasmScanError::Tls(format!("SNI: {}", e)))?;
    let addr: SocketAddr = format!("{}:{}", connect_ip, port)
        .parse()
        .map_err(|e| EasmScanError::Tls(format!("socket addr: {}", e)))?;
    let tcp = tokio::time::timeout(Duration::from_secs(12), TcpStream::connect(addr))
        .await
        .map_err(|e| EasmScanError::Tls(format!("tcp connect timeout: {}", e)))?
        .map_err(|e| EasmScanError::Tls(e.to_string()))?;
    let mut tls = connector
        .connect(sni, tcp)
        .await
        .map_err(|e| EasmScanError::Tls(format!("handshake: {}", e)))?;

    let req = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: {}\r\n\r\n",
        apex_sni, HTTP_UA
    );
    let _ = tls.write_all(req.as_bytes()).await;
    let mut buf = [0u8; 2048];
    let _ = tls.read(&mut buf).await;

    let (_, conn) = tls.get_ref();
    let Some(certs) = conn.peer_certificates() else {
        return Ok(None);
    };
    let Some(first) = certs.first() else {
        return Ok(None);
    };
    summarize_end_entity_cert(first.as_ref()).map(Some)
}

async fn tcp_port_open(ip: &str, port: u16) -> bool {
    let Ok(addr) = format!("{}:{}", ip, port).parse::<SocketAddr>() else {
        return false;
    };
    match tokio::time::timeout(Duration::from_millis(2200), TcpStream::connect(addr)).await {
        Ok(Ok(_)) => true,
        _ => false,
    }
}

async fn scan_open_ports_for_ip(ip: &str) -> Vec<u16> {
    let mut open = Vec::new();
    for p in COMMON_PORTS {
        if tcp_port_open(ip, *p).await {
            open.push(*p);
        }
    }
    open.sort_unstable();
    open.dedup();
    open
}

// ---------------------------------------------------------------------------
// Domain + vault
// ---------------------------------------------------------------------------

fn normalize_apex(domain: &str) -> Result<String, EasmScanError> {
    let mut s = domain.trim().to_ascii_lowercase();
    if let Some(rest) = s.strip_prefix("https://") {
        s = rest
            .split(|c| c == '/' || c == '?' || c == '#')
            .next()
            .unwrap_or("")
            .to_string();
    } else if let Some(rest) = s.strip_prefix("http://") {
        s = rest
            .split(|c| c == '/' || c == '?' || c == '#')
            .next()
            .unwrap_or("")
            .to_string();
    }
    s = s.trim_end_matches('.').to_string();
    if s.is_empty() {
        return Err(EasmScanError::BadDomain("domain is empty".into()));
    }
    if !s.contains('.') {
        return Err(EasmScanError::BadDomain(
            "expected a DNS apex (e.g. example.com)".into(),
        ));
    }
    let re = Regex::new(r"^[a-z0-9.-]+$").map_err(|e| EasmScanError::BadDomain(e.to_string()))?;
    if !re.is_match(&s) {
        return Err(EasmScanError::BadDomain(format!("invalid characters in {:?}", s)));
    }
    Ok(s)
}

fn resolve_vault_db_path() -> Result<PathBuf, EasmScanError> {
    Ok(crate::vault_db::get_vault_path())
}

// ---------------------------------------------------------------------------
// Host model + persistence
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone, Serialize)]
struct HostRecord {
    ipv4: Vec<String>,
    ipv6: Vec<String>,
    from_mx: bool,
    from_crt: bool,
    from_prefix: bool,
    from_shodan: bool,
    from_pentest_tools: bool,
    open_ports: Vec<u16>,
    tls: Option<TlsCertSummary>,
}

fn upsert_asm_asset(
    conn: &rusqlite::Connection,
    asset_target: &str,
    asset_type: &str,
    metadata: &serde_json::Value,
) -> Result<(), EasmScanError> {
    let now = time_now_iso();
    let meta = metadata.to_string();
    conn.execute(
        "INSERT INTO asm_assets (asset_target, asset_type, last_scan_at, status, metadata)
         VALUES (?1, ?2, ?3, 'active', ?4)
         ON CONFLICT(asset_target) DO UPDATE SET
           asset_type = excluded.asset_type,
           last_scan_at = excluded.last_scan_at,
           status = excluded.status,
           metadata = COALESCE(excluded.metadata, asm_assets.metadata)",
        params![asset_target, asset_type, now, meta],
    )
    .map_err(|e| EasmScanError::Vault(e.to_string()))?;
    Ok(())
}

fn persist_scan_blocking(
    db_path: PathBuf,
    apex: &str,
    hosts: &HashMap<String, HostRecord>,
    apex_ips: &[String],
    apex_ipv6: &[String],
    apex_tls: &Option<TlsCertSummary>,
    apex_ports: &[u16],
    shodan_dns_domain: Option<&Value>,
    pentest_tools_scan: Option<&Value>,
) -> Result<usize, EasmScanError> {
    let conn = vault_db::open_vault(&db_path).map_err(|e| EasmScanError::Vault(e.to_string()))?;
    let mut n = 0usize;

    let apex_meta = json!({
        "easm": true,
        "source": SOURCE_TAG,
        "apex": apex,
        "ipv4": apex_ips,
        "ipv6": apex_ipv6,
        "open_ports": apex_ports,
        "tls": apex_tls,
        "shodan_dns_domain": shodan_dns_domain,
        "pentest_tools_subdomain_scan": pentest_tools_scan,
    });
    upsert_asm_asset(&conn, apex, "subdomain", &apex_meta)?;
    n = n.saturating_add(1);

    for (host, rec) in hosts {
        let meta = json!({
            "easm": true,
            "source": SOURCE_TAG,
            "apex": apex,
            "hostname": host,
            "ipv4": rec.ipv4,
            "ipv6": rec.ipv6,
            "mx_derived": rec.from_mx,
            "crt_sh": rec.from_crt,
            "prefix_probe": rec.from_prefix,
            "from_shodan": rec.from_shodan,
            "from_pentest_tools": rec.from_pentest_tools,
            "open_ports": rec.open_ports,
            "tls": rec.tls,
        });
        upsert_asm_asset(&conn, host, "subdomain", &meta)?;
        n = n.saturating_add(1);

        for ip in &rec.ipv4 {
            let key = format!("{}|{}", host, ip);
            let meta_ip = json!({
                "easm": true,
                "source": SOURCE_TAG,
                "apex": apex,
                "hostname": host,
                "ip": ip,
                "open_ports": rec.open_ports,
                "tls": rec.tls,
            });
            upsert_asm_asset(&conn, &key, "host_ip", &meta_ip)?;
            n = n.saturating_add(1);
        }
    }

    for ip in apex_ips {
        let meta = json!({
            "easm": true,
            "source": SOURCE_TAG,
            "apex": apex,
            "ip": ip,
            "open_ports": apex_ports,
            "tls": apex_tls,
        });
        upsert_asm_asset(&conn, ip, "host_ip", &meta)?;
        n = n.saturating_add(1);
    }

    Ok(n)
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

/// Passive + lightweight active discovery for `domain` (apex), persisted to **`asm_assets`**.
///
/// Requires **`CTI_DB_PATH`** pointing at `cti_vault.db`. Uses the system resolver when available.
pub async fn run_easm_scan(domain: &str) -> Result<usize, EasmScanError> {
    let apex = normalize_apex(domain)?;
    let db_path = resolve_vault_db_path()?;
    let resolver = build_resolver().await;
    let apex_name = parse_name(&apex)?;

    let apex_ipv4 = lookup_ipv4_strings(&resolver, &apex_name).await;
    let apex_ipv6 = lookup_ipv6_strings(&resolver, &apex_name).await;
    let mx_hosts = lookup_mx_hosts(&resolver, &apex_name).await;
    let mx_set: HashSet<String> = mx_hosts.iter().cloned().collect();

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .user_agent(HTTP_UA)
        .build()
        .map_err(|e| EasmScanError::Http(e.to_string()))?;

    let (shodan_res, pentest_res, crt_res) = tokio::join!(
        query_shodan_dns_domain(&http, &apex),
        query_pentest_tools_subdomains(&http, &apex),
        fetch_crt_sh_names(&http, &apex),
    );
    let shodan_parsed = shodan_res.unwrap_or_else(|e| {
        log::warn!("Shodan: {}", e);
        None
    });
    let pentest_json = pentest_res.unwrap_or_else(|e| {
        log::warn!("Pentest-Tools: {}", e);
        None
    });
    let crt_hosts = crt_res.unwrap_or_else(|e| {
        log::warn!("crt.sh fetch skipped: {}", e);
        Vec::new()
    });
    let shodan_hosts: HashSet<String> = shodan_parsed
        .as_ref()
        .map(|r| hostnames_from_shodan(r, &apex))
        .unwrap_or_default();
    let pentest_hosts: HashSet<String> = pentest_json
        .as_ref()
        .map(hostnames_from_pentest_scan_output)
        .unwrap_or_default();
    let shodan_snapshot: Option<Value> = shodan_parsed
        .as_ref()
        .and_then(|r| serde_json::to_value(r).ok());

    let crt_set: HashSet<String> = crt_hosts.iter().cloned().collect();

    let mut hostnames: HashSet<String> = HashSet::new();
    hostnames.insert(apex.clone());
    for h in &mx_hosts {
        hostnames.insert(h.clone());
    }
    for h in &crt_hosts {
        hostnames.insert(h.clone());
    }
    for h in &shodan_hosts {
        hostnames.insert(h.clone());
    }
    for h in &pentest_hosts {
        hostnames.insert(h.clone());
    }
    for pfx in SUBDOMAIN_PREFIXES {
        let fq = format!("{}.{}", pfx, apex);
        hostnames.insert(fq);
    }

    let mut hosts: HashMap<String, HostRecord> = HashMap::new();
    for h in hostnames {
        if h == apex {
            continue;
        }
        let host_dns = parse_name(&h).map_err(|e| EasmScanError::Dns(e.to_string()))?;
        let v4 = lookup_ipv4_strings(&resolver, &host_dns).await;
        let v6 = lookup_ipv6_strings(&resolver, &host_dns).await;
        let from_shodan = shodan_hosts.contains(&h);
        let from_pentest_tools = pentest_hosts.contains(&h);
        if v4.is_empty() && v6.is_empty() && !from_shodan && !from_pentest_tools {
            continue;
        }
        let from_mx = mx_set.contains(&h);
        let from_crt = crt_set.contains(&h);
        let from_prefix = SUBDOMAIN_PREFIXES
            .iter()
            .any(|p| h == format!("{}.{}", p, apex));
        let mut rec = HostRecord {
            ipv4: v4.clone(),
            ipv6: v6,
            from_mx,
            from_crt,
            from_prefix,
            from_shodan,
            from_pentest_tools,
            ..Default::default()
        };
        if let Some(ip) = v4.first() {
            rec.open_ports = scan_open_ports_for_ip(ip).await;
            if rec.open_ports.contains(&443) || rec.open_ports.contains(&8443) {
                let port = if rec.open_ports.contains(&443) {
                    443
                } else {
                    8443
                };
                rec.tls = tls_probe_https(&h, ip, port).await.ok().flatten();
            }
        }
        hosts.insert(h, rec);
        tokio::time::sleep(Duration::from_millis(120)).await;
    }

    let apex_ports = if let Some(ip) = apex_ipv4.first() {
        scan_open_ports_for_ip(ip.as_str()).await
    } else {
        Vec::new()
    };

    let mut apex_tls: Option<TlsCertSummary> = None;
    if let Some(ip) = apex_ipv4.first() {
        if apex_ports.contains(&443) {
            apex_tls = tls_probe_https(&apex, ip, 443).await.ok().flatten();
        } else if apex_ports.contains(&8443) {
            apex_tls = tls_probe_https(&apex, ip, 8443).await.ok().flatten();
        }
    }

    let apex_ports_vec = apex_ports;
    let apex_tls_cl = apex_tls.clone();
    let hosts_cl = hosts.clone();
    let apex_v4 = apex_ipv4.clone();
    let apex_v6 = apex_ipv6.clone();
    let apex_owned = apex.clone();
    let shodan_snap = shodan_snapshot.clone();
    let pentest_snap = pentest_json.clone();

    let n = tokio::task::spawn_blocking(move || {
        persist_scan_blocking(
            db_path,
            &apex_owned,
            &hosts_cl,
            &apex_v4,
            &apex_v6,
            &apex_tls_cl,
            &apex_ports_vec,
            shodan_snap.as_ref(),
            pentest_snap.as_ref(),
        )
    })
    .await
    .map_err(|e| EasmScanError::Vault(format!("join: {}", e)))??;

    Ok(n)
}

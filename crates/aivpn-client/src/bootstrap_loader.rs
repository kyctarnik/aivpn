//! Multi-channel Bootstrap Descriptor Loader
//!
//! Implements resilient bootstrap descriptor distribution across multiple channels
//! to prevent single-point-of-failure blocking by censors.

use rand::{prelude::SliceRandom, Rng};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use aivpn_common::error::{Error, Result};
pub use aivpn_common::mask::{BootstrapChannel, BootstrapConfig, BootstrapDescriptor};

use crate::bootstrap_cache::{load_descriptors, store_verified_descriptor};

/// Result from a single channel load attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelLoadResult {
    pub channel_name: String,
    pub channel_type: String,
    pub success: bool,
    pub descriptors_loaded: usize,
    pub error: Option<String>,
    pub latency_ms: u64,
}

/// Statistics from multi-channel loading
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiChannelLoadStats {
    pub total_channels: usize,
    pub successful_channels: usize,
    pub total_descriptors: usize,
    pub results: Vec<ChannelLoadResult>,
    pub elapsed_ms: u64,
}

/// Validate a bootstrap URL before fetching.
///
/// Rejects:
/// - Non-HTTPS schemes (prevents plaintext interception).
/// - Private/loopback/link-local hostnames (prevents SSRF against internal services).
pub(crate) fn validate_bootstrap_url(url: &str) -> Result<()> {
    // Must start with https:// — no HTTP, no custom schemes.
    if !url.starts_with("https://") {
        return Err(Error::Session(format!(
            "Bootstrap URL '{}' rejected: only HTTPS is allowed",
            url
        )));
    }

    // Reject any URL that contains userinfo credentials (user:pass@ or user@).
    // A crafted URL like https://user@169.254.169.254/path would otherwise bypass
    // the private-range checks below because host_and_port becomes "user@169.254.169.254".
    if url["https://".len()..].contains('@') {
        return Err(Error::Session(format!(
            "Bootstrap URL '{}' rejected: userinfo credentials are not allowed",
            url
        )));
    }

    // Extract the host portion (between "https://" and the next '/', ':', or '?').
    let after_scheme = &url["https://".len()..];
    let host_end = after_scheme
        .find(|c| c == '/' || c == '?' || c == '#')
        .unwrap_or(after_scheme.len());
    let host_and_port = &after_scheme[..host_end];
    // Strip optional port suffix (e.g., "host:8443" → "host").
    let host = match host_and_port.rfind(':') {
        Some(pos) => {
            // Only strip as port if the suffix is digits (avoids mangling IPv6 literals).
            let suffix = &host_and_port[pos + 1..];
            if suffix.chars().all(|c| c.is_ascii_digit()) {
                &host_and_port[..pos]
            } else {
                host_and_port
            }
        }
        None => host_and_port,
    };

    // Reject loopback and private-range hostnames.
    let blocked = matches!(
        host,
        "localhost" | "ip6-localhost" | "ip6-loopback" | "[::1]" | "::1"
    ) || host.starts_with("127.")
        || host.starts_with("10.")
        || host.starts_with("192.168.")
        || host.starts_with("169.254.")
        || {
            // 172.16.0.0/12 — second octet 16..=31
            if let Some(rest) = host.strip_prefix("172.") {
                rest.split('.')
                    .next()
                    .and_then(|octet| octet.parse::<u8>().ok())
                    .map_or(false, |n| (16..=31).contains(&n))
            } else {
                false
            }
        };

    if blocked {
        return Err(Error::Session(format!(
            "Bootstrap URL '{}' rejected: private/loopback addresses are not allowed",
            url
        )));
    }

    Ok(())
}

/// Hard cap on any bootstrap channel response body. Descriptor payloads are a
/// few KB; anything beyond this is either misconfiguration or an attempt to
/// exhaust memory via an attacker-influenced URL.
const MAX_RESPONSE_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Read a response body with a size cap — `response.text()` would buffer an
/// unbounded body in memory. Error strings are static so they can never leak
/// the request URL (which for Telegram embeds the bot token).
pub(crate) async fn read_body_capped(
    mut response: reqwest::Response,
) -> std::result::Result<String, &'static str> {
    if response
        .content_length()
        .is_some_and(|len| len > MAX_RESPONSE_BODY_BYTES as u64)
    {
        return Err("response body too large");
    }
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "failed to read response body")?
    {
        if body.len() + chunk.len() > MAX_RESPONSE_BODY_BYTES {
            return Err("response body too large");
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).map_err(|_| "response body is not valid UTF-8")
}

/// Load descriptors from a CDN channel
async fn load_from_cdn(url: &str) -> Result<Vec<BootstrapDescriptor>> {
    validate_bootstrap_url(url)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| Error::Session(format!("Failed to create HTTP client: {}", e)))?;

    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| Error::Session(format!("CDN request failed: {}", e)))?;

    if !response.status().is_success() {
        return Err(Error::Session(format!(
            "CDN returned status: {}",
            response.status()
        )));
    }

    let body = read_body_capped(response)
        .await
        .map_err(|e| Error::Session(format!("Failed to read CDN response: {}", e)))?;

    parse_descriptors_from_json(&body, None)
}

/// Describe a `reqwest::Error` without ever including its `Display` output,
/// which embeds the request URL — for Telegram Bot API calls, that URL
/// contains the bot token, and this text ends up in `ChannelLoadResult.error`,
/// which callers log.
fn describe_reqwest_error(e: &reqwest::Error) -> &'static str {
    if e.is_timeout() {
        "request timed out"
    } else if e.is_connect() {
        "connection failed"
    } else if e.is_decode() {
        "failed to decode response body"
    } else {
        "network error"
    }
}

/// Load descriptors from a Telegram bot channel via the authenticated Bot
/// API: getUpdates -> find a message/channel_post carrying a document ->
/// getFile -> download. Mirrors the Android/iOS implementations — the
/// server's actual publish path (`bootstrap_publish.rs`'s `sendDocument`)
/// can only be retrieved this way; an unauthenticated `t.me/...?format=json`
/// scrape cannot see bot-posted documents at all.
async fn load_from_telegram(
    bot_token: &str,
    chat_id: Option<&str>,
) -> Result<Vec<BootstrapDescriptor>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| Error::Session(format!("Failed to create HTTP client: {}", e)))?;

    let updates_url = format!(
        "https://api.telegram.org/bot{}/getUpdates?limit=50",
        bot_token
    );
    // Note: deliberately not formatting the reqwest::Error itself into these
    // messages — its Display output includes the request URL, which embeds
    // the bot token, and this error text flows into ChannelLoadResult.error
    // which gets logged.
    let response = client.get(&updates_url).send().await.map_err(|e| {
        Error::Session(format!(
            "Telegram getUpdates failed: {}",
            describe_reqwest_error(&e)
        ))
    })?;

    if !response.status().is_success() {
        return Err(Error::Session(format!(
            "Telegram getUpdates returned status: {}",
            response.status()
        )));
    }

    let body = read_body_capped(response).await.map_err(|e| {
        Error::Session(format!(
            "Failed to read Telegram getUpdates response: {}",
            e
        ))
    })?;

    let json: serde_json::Value = serde_json::from_str(&body).map_err(|e| {
        Error::Session(format!(
            "Failed to parse Telegram getUpdates response: {}",
            e
        ))
    })?;

    let updates = json
        .get("result")
        .and_then(|r| r.as_array())
        .ok_or_else(|| Error::Session("Telegram getUpdates response missing 'result'".into()))?;

    // Walk newest-first, same order the Android client scans in.
    for update in updates.iter().rev() {
        let message = update.get("message").or_else(|| update.get("channel_post"));
        let Some(message) = message else { continue };

        if let Some(want_chat) = chat_id {
            let chat = message.get("chat");
            let id_matches = chat
                .and_then(|c| c.get("id"))
                .map(|id| match id {
                    serde_json::Value::String(s) => s == want_chat,
                    other => other.to_string() == want_chat,
                })
                .unwrap_or(false);
            let username_matches = chat
                .and_then(|c| c.get("username"))
                .and_then(|u| u.as_str())
                .map(|u| format!("@{u}") == want_chat)
                .unwrap_or(false);
            if !id_matches && !username_matches {
                continue;
            }
        }

        let Some(file_id) = message
            .get("document")
            .and_then(|d| d.get("file_id"))
            .and_then(|f| f.as_str())
        else {
            continue;
        };

        let get_file_url = format!(
            "https://api.telegram.org/bot{}/getFile?file_id={}",
            bot_token, file_id
        );
        let Ok(meta_resp) = client.get(&get_file_url).send().await else {
            continue;
        };
        let Ok(meta_body) = read_body_capped(meta_resp).await else {
            continue;
        };
        let Ok(meta_json) = serde_json::from_str::<serde_json::Value>(&meta_body) else {
            continue;
        };
        let Some(file_path) = meta_json
            .get("result")
            .and_then(|r| r.get("file_path"))
            .and_then(|p| p.as_str())
        else {
            continue;
        };

        let download_url = format!(
            "https://api.telegram.org/file/bot{}/{}",
            bot_token, file_path
        );
        let Ok(file_resp) = client.get(&download_url).send().await else {
            continue;
        };
        let Ok(file_body) = read_body_capped(file_resp).await else {
            continue;
        };

        if let Ok(descriptors) = parse_descriptors_from_json(&file_body, None) {
            if !descriptors.is_empty() {
                return Ok(descriptors);
            }
        }
    }

    Err(Error::Session(
        "No verifiable bootstrap document found in recent Telegram updates \
         (getUpdates only sees messages since the bot's last poll)"
            .into(),
    ))
}

/// Load descriptors from a GitHub releases channel
async fn load_from_github(repo: &str, asset_name: &str) -> Result<Vec<BootstrapDescriptor>> {
    // The GitHub API URL is constructed from the repo slug, not user input, so
    // it is always a safe HTTPS URL. The asset download URL from the release JSON
    // is user-influenced via the connection key and must be validated.
    let url = format!("https://api.github.com/repos/{}/releases/latest", repo);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .default_headers({
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::USER_AGENT,
                reqwest::header::HeaderValue::from_static("aivpn-client"),
            );
            headers
        })
        .build()
        .map_err(|e| Error::Session(format!("Failed to create HTTP client: {}", e)))?;

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| Error::Session(format!("GitHub request failed: {}", e)))?;

    if !response.status().is_success() {
        return Err(Error::Session(format!(
            "GitHub returned status: {}",
            response.status()
        )));
    }

    let body = read_body_capped(response)
        .await
        .map_err(|e| Error::Session(format!("Failed to read GitHub response: {}", e)))?;

    // Parse release JSON to find asset URL
    let release: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| Error::Session(format!("Failed to parse GitHub release: {}", e)))?;

    if let Some(assets) = release.get("assets").and_then(|a| a.as_array()) {
        for asset in assets {
            if let Some(name) = asset.get("name").and_then(|n| n.as_str()) {
                if name.contains(asset_name) || asset_name.contains(name) {
                    if let Some(download_url) =
                        asset.get("browser_download_url").and_then(|u| u.as_str())
                    {
                        // Validate the asset URL before fetching — the download
                        // URL comes from GitHub's API response and must be HTTPS.
                        if let Err(e) = validate_bootstrap_url(download_url) {
                            return Err(Error::Session(format!(
                                "GitHub asset URL rejected: {}",
                                e
                            )));
                        }
                        // Download the asset
                        let asset_response =
                            client.get(download_url).send().await.map_err(|e| {
                                Error::Session(format!("Failed to download asset: {}", e))
                            })?;

                        let asset_body = read_body_capped(asset_response)
                            .await
                            .map_err(|e| Error::Session(format!("Failed to read asset: {}", e)))?;

                        return parse_descriptors_from_json(&asset_body, None);
                    }
                }
            }
        }
    }

    Err(Error::Session(format!(
        "Asset '{}' not found in GitHub release",
        asset_name
    )))
}

/// Load descriptors from an Email channel (simulated - actual implementation would use SMTP/IMAP)
async fn load_from_email(
    _address: &str,
    _subject_pattern: &str,
) -> Result<Vec<BootstrapDescriptor>> {
    // Email-based loading would require integration with mail servers
    // For now, this is a placeholder that returns an error
    Err(Error::Session("Email channel not yet implemented".into()))
}

/// Parse descriptors from JSON body
fn parse_descriptors_from_json(
    body: &str,
    signing_key: Option<&[u8; 32]>,
) -> Result<Vec<BootstrapDescriptor>> {
    // Try parsing as array first
    let descriptors: Vec<BootstrapDescriptor> = serde_json::from_str(body)
        .or_else(|_| {
            // Try parsing as single object
            let single: BootstrapDescriptor = serde_json::from_str(body)?;
            Ok(vec![single])
        })
        .map_err(|e: serde_json::Error| {
            Error::Session(format!("Failed to parse descriptors: {}", e))
        })?;

    // Verify each descriptor
    let mut valid_descriptors = Vec::new();
    for descriptor in descriptors {
        if store_verified_descriptor(descriptor.clone(), signing_key).is_ok() {
            valid_descriptors.push(descriptor);
        }
    }

    Ok(valid_descriptors)
}

/// Load descriptors from a single channel
async fn load_from_channel(channel: &BootstrapChannel) -> ChannelLoadResult {
    let start = std::time::Instant::now();

    let result = match channel {
        BootstrapChannel::CDN { url, provider: _ } => load_from_cdn(url).await,
        BootstrapChannel::Telegram { bot_token, chat_id } => {
            load_from_telegram(bot_token, chat_id.as_deref()).await
        }
        BootstrapChannel::GitHub { repo, asset_name } => load_from_github(repo, asset_name).await,
        BootstrapChannel::Email {
            address,
            subject_pattern,
        } => load_from_email(address, subject_pattern).await,
    };

    let latency_ms = start.elapsed().as_millis() as u64;

    match result {
        Ok(descriptors) => ChannelLoadResult {
            channel_name: channel.name().to_string(),
            channel_type: channel.channel_type().to_string(),
            success: true,
            descriptors_loaded: descriptors.len(),
            error: None,
            latency_ms,
        },
        Err(e) => ChannelLoadResult {
            channel_name: channel.name().to_string(),
            channel_type: channel.channel_type().to_string(),
            success: false,
            descriptors_loaded: 0,
            error: Some(e.to_string()),
            latency_ms,
        },
    }
}

/// Load descriptors from all channels with random order
pub async fn load_multi_channel(config: &BootstrapConfig) -> MultiChannelLoadStats {
    let start = std::time::Instant::now();

    // Randomize channel order to prevent pattern detection
    let mut channels: Vec<_> = config.channels.iter().collect();
    let mut rng = rand::thread_rng();
    channels.shuffle(&mut rng);

    // Race all channels concurrently — sequential probing with 10–15 s timeouts
    // per channel could block startup for up to N×15 s when most channels are
    // unreachable. Channels are cloned so each task owns its data ('static bound).
    let tasks: Vec<_> = channels
        .iter()
        .map(|ch| {
            let ch = (*ch).clone();
            tokio::spawn(async move { load_from_channel(&ch).await })
        })
        .collect();

    let mut results = Vec::with_capacity(tasks.len());
    for task in tasks {
        let r = task.await.unwrap_or_else(|e| ChannelLoadResult {
            channel_name: "unknown".into(),
            channel_type: "unknown".into(),
            success: false,
            descriptors_loaded: 0,
            error: Some(format!("task panicked: {e}")),
            latency_ms: 0,
        });
        results.push(r);
    }

    let mut total_descriptors = 0;
    for r in &results {
        total_descriptors += r.descriptors_loaded;
    }

    let successful_channels = results.iter().filter(|r| r.success).count();
    let elapsed_ms = start.elapsed().as_millis() as u64;

    MultiChannelLoadStats {
        total_channels: results.len(),
        successful_channels,
        total_descriptors,
        results,
        elapsed_ms,
    }
}

/// Check if we have valid descriptors in cache
pub fn has_valid_descriptors() -> bool {
    !load_descriptors().is_empty()
}

/// Get random delay for first refresh (1-60 seconds)
pub fn random_first_refresh_delay() -> Duration {
    let mut rng = rand::thread_rng();
    Duration::from_secs(rng.gen_range(1..=60))
}

/// Background descriptor refresher
pub struct BackgroundRefresher {
    config: BootstrapConfig,
}

impl BackgroundRefresher {
    pub fn new(config: BootstrapConfig) -> Self {
        Self { config }
    }

    /// Run the background refresher loop
    pub async fn run(&self) {
        // Random delay before first refresh
        if self.config.randomize_first_refresh {
            let delay = random_first_refresh_delay();
            tokio::time::sleep(delay).await;
        }

        let mut interval = tokio::time::interval(Duration::from_secs(self.config.refresh_interval));

        let mut last_refresh = std::time::Instant::now()
            .checked_sub(Duration::from_secs(self.config.refresh_interval))
            .unwrap_or_else(std::time::Instant::now);

        loop {
            interval.tick().await;

            // Always refresh when interval has elapsed, even if descriptors are valid.
            // This ensures descriptors are rotated before expiry (24h grace window
            // means has_valid_descriptors() stays true long after actual expiry).
            let elapsed = last_refresh.elapsed();
            if has_valid_descriptors()
                && elapsed < Duration::from_secs(self.config.refresh_interval)
            {
                continue;
            }

            last_refresh = std::time::Instant::now();

            // Load from multiple channels
            let stats = load_multi_channel(&self.config).await;

            tracing::info!(
                "Bootstrap refresh: {}/{} channels succeeded, {} descriptors loaded in {}ms",
                stats.successful_channels,
                stats.total_channels,
                stats.total_descriptors,
                stats.elapsed_ms
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bootstrap_channel_names() {
        let cdn = BootstrapChannel::CDN {
            url: "https://cdn.example.com/descriptors".to_string(),
            provider: "Cloudflare".to_string(),
        };
        assert_eq!(cdn.name(), "Cloudflare");
        assert_eq!(cdn.channel_type(), "CDN");

        let telegram = BootstrapChannel::Telegram {
            bot_token: "123456:ABC-DEF".to_string(),
            chat_id: Some("@aivpn_bot".to_string()),
        };
        assert_eq!(telegram.name(), "@aivpn_bot");
        assert_eq!(telegram.channel_type(), "Telegram");
    }

    #[test]
    fn test_bootstrap_config_builder() {
        let config = BootstrapConfig::default()
            .with_cdn("https://cdn.example.com", "Cloudflare")
            .with_telegram("123456:ABC-DEF", Some("@aivpn_bot".to_string()))
            .with_github("infosave2007/aivpn", "bootstrap-");

        assert_eq!(config.channels.len(), 3);
        assert_eq!(config.channels[0].channel_type(), "CDN");
        assert_eq!(config.channels[1].channel_type(), "Telegram");
        assert_eq!(config.channels[2].channel_type(), "GitHub");
    }

    #[test]
    fn test_validate_bootstrap_url_accepts_https() {
        assert!(validate_bootstrap_url("https://cdn.example.com/descriptors.json").is_ok());
        assert!(validate_bootstrap_url("https://cdn.example.com:8443/path").is_ok());
        assert!(validate_bootstrap_url("https://example.org").is_ok());
    }

    #[test]
    fn test_validate_bootstrap_url_rejects_http() {
        let err = validate_bootstrap_url("http://cdn.example.com/descriptors.json");
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("HTTPS"));
    }

    #[test]
    fn test_validate_bootstrap_url_rejects_custom_scheme() {
        assert!(validate_bootstrap_url("ftp://cdn.example.com/file").is_err());
        assert!(validate_bootstrap_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn test_validate_bootstrap_url_rejects_localhost() {
        assert!(validate_bootstrap_url("https://localhost/descriptors").is_err());
        assert!(validate_bootstrap_url("https://127.0.0.1/descriptors").is_err());
        assert!(validate_bootstrap_url("https://127.0.0.5:8080/path").is_err());
    }

    #[test]
    fn test_validate_bootstrap_url_rejects_private_ranges() {
        assert!(validate_bootstrap_url("https://10.0.0.1/descriptors").is_err());
        assert!(validate_bootstrap_url("https://192.168.1.100/descriptors").is_err());
        assert!(validate_bootstrap_url("https://172.16.0.1/descriptors").is_err());
        assert!(validate_bootstrap_url("https://172.31.255.255/descriptors").is_err());
        // 172.32.x.x is outside the /12 block — must be accepted
        assert!(validate_bootstrap_url("https://172.32.0.1/descriptors").is_ok());
    }

    #[test]
    fn test_validate_bootstrap_url_rejects_link_local() {
        assert!(validate_bootstrap_url("https://169.254.1.1/descriptors").is_err());
    }

    #[test]
    fn test_parse_descriptors_from_json_single_object() {
        // parse_descriptors_from_json accepts a single JSON object as well as an array.
        // A well-formed but unsigned descriptor with zero signature should round-trip through
        // the parser (store_verified_descriptor with None key accepts zero-sig descriptors).
        // HOME is process-wide and cargo test runs tests in parallel threads
        // within the same process — without this mutex, another test
        // mutating/reading HOME concurrently races with this one.
        let _guard = crate::TEST_HOME_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let temp = std::env::temp_dir().join("aivpn_parse_test");
        let _ = std::fs::create_dir_all(&temp);
        let old_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", &temp);

        let desc_json = r#"{
            "descriptor_id": "parse_single_test",
            "version": 1,
            "created_at": 0,
            "expires_at": 9999999999,
            "base_mask_ids": [],
            "embedded_masks": [],
            "candidate_count": 1,
            "kdf_salt": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "signature": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
        }"#;

        let result = parse_descriptors_from_json(desc_json, None);
        assert!(result.is_ok());
        let descs = result.unwrap();
        assert_eq!(descs.len(), 1);
        assert_eq!(descs[0].descriptor_id, "parse_single_test");

        if let Some(h) = old_home {
            std::env::set_var("HOME", h);
        } else {
            std::env::remove_var("HOME");
        }
        let _ = std::fs::remove_dir_all(temp);
    }

    #[test]
    fn test_parse_descriptors_from_json_invalid() {
        let result = parse_descriptors_from_json("not valid json at all !!!!", None);
        assert!(result.is_err());
    }
}

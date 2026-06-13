//! Discord webhook delivery for one-time login keys. Issues a single
//! POST with an embed describing the username, the 8-char key, and a
//! human-friendly expiry. Uses `reqwest` with rustls so we avoid
//! pulling in the system OpenSSL.

use anyhow::{anyhow, Result};
use serde_json::json;
use std::time::Duration;

const HTTP_TIMEOUT_SECS: u64 = 5;
const EMBED_COLOR:        u32 = 0x7c3aed;

/// Send a Discord embed to `webhook_url` announcing `key` for
/// `username`. Returns an error on transport failure, timeout, or any
/// non-2xx HTTP response.
pub async fn send_discord_key(webhook_url: &str, username: &str, key: &str) -> Result<()> {
    if webhook_url.trim().is_empty() {
        return Err(anyhow!("discord webhook is not configured"));
    }

    let body = json!({
        "embeds": [{
            "title":       "DefCrow login key",
            "description": "Use this one-time key to complete sign-in.",
            "color":       EMBED_COLOR,
            "fields": [
                { "name": "Username",   "value": format!("`{}`", username) },
                { "name": "Access key", "value": format!("`{}`", key) },
                { "name": "Expires",    "value": "in 5 minutes" }
            ]
        }]
    });

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .build()?;

    let resp = client.post(webhook_url).json(&body).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow!("discord webhook returned {}", resp.status()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_webhook_url_is_rejected() {
        let err = send_discord_key("", "alice", "ABCDEFGH").await.unwrap_err();
        assert!(err.to_string().contains("not configured"));
    }

    // Note: live Discord delivery is verified manually per the plan.
}

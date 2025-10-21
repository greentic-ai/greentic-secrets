#![cfg(feature = "imds")]

use std::time::Duration;

/// Perform a low-latency HTTP `HEAD` request to an instance metadata endpoint.
///
/// The helper intentionally swallows errors and returns `false` on any failure,
/// allowing callers to rely on it for best-effort probing without surfacing
/// network exceptions.
pub async fn head(url: &str, headers: &[(&str, &str)], timeout: Duration) -> bool {
    let client = match reqwest::Client::builder().timeout(timeout).build() {
        Ok(client) => client,
        Err(_) => return false,
    };

    let mut request = client.head(url);
    for (key, value) in headers {
        request = request.header(*key, *value);
    }

    match request.send().await {
        Ok(response) => response.status().is_success(),
        Err(_) => false,
    }
}

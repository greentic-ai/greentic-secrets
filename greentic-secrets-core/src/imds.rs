use std::time::Duration;
use url::{Host, Url};

/// Perform a low-latency HTTP `HEAD` request to an instance metadata endpoint.
///
/// The helper intentionally swallows errors and returns `false` on any failure,
/// allowing callers to rely on it for best-effort probing without surfacing
/// network exceptions.
pub async fn head(url: &str, headers: &[(&str, &str)], timeout: Duration) -> bool {
    let parsed = match Url::parse(url) {
        Ok(url) => url,
        Err(_) => return false,
    };

    let is_metadata_host = matches!(
        parsed.host(),
        Some(Host::Ipv4(ip)) if ip.octets() == [169, 254, 169, 254]
    );
    if parsed.scheme() != "http" || !is_metadata_host {
        return false;
    }

    let client = match reqwest::Client::builder().timeout(timeout).build() {
        Ok(client) => client,
        Err(_) => return false,
    };

    // codeql[non-https-url]: IMDS only supports HTTP on link-local 169.254.169.254 and is validated above.
    let mut request = client.head(parsed);
    for (key, value) in headers {
        request = request.header(*key, *value);
    }

    match request.send().await {
        Ok(response) => response.status().is_success(),
        Err(_) => false,
    }
}

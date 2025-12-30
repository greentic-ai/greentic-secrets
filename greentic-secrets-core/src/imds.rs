use std::time::Duration;
use url::{Host, Url};

const IMDS_HOST: [u8; 4] = [169, 254, 169, 254];

fn is_allowed_imds_url(url: &Url) -> bool {
    if url.scheme() != "http" {
        return false;
    }
    if !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    let is_metadata_host = matches!(url.host(), Some(Host::Ipv4(ip)) if ip.octets() == IMDS_HOST);
    if !is_metadata_host {
        return false;
    }
    if url.port_or_known_default() != Some(80) {
        return false;
    }
    url.query().is_none() && url.fragment().is_none()
}

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

    if !is_allowed_imds_url(&parsed) {
        return false;
    }

    let client = match reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(_) => return false,
    };

    let mut request = client.head(parsed);
    for (key, value) in headers {
        request = request.header(*key, *value);
    }

    match request.send().await {
        Ok(response) => response.status().is_success(),
        Err(_) => false,
    }
}

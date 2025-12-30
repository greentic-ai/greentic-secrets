use std::future::Future;
use std::time::Duration;

/// Parse a truthy env var in a tolerant way.
pub fn parse_bool_env(var: &str) -> bool {
    std::env::var(var)
        .ok()
        .map(|v| matches_ignore_ascii(&v, &["1", "true", "yes"]))
        .unwrap_or(false)
}

fn matches_ignore_ascii(value: &str, expected: &[&str]) -> bool {
    expected.iter().any(|pat| value.eq_ignore_ascii_case(pat))
}

/// Retry an async operation with fixed backoff.
pub async fn retry_async<F, Fut, T, E>(
    mut op: F,
    max_attempts: usize,
    base_delay: Duration,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let mut attempt = 0usize;
    loop {
        attempt += 1;
        match op().await {
            Ok(v) => return Ok(v),
            Err(err) if attempt >= max_attempts => return Err(err),
            Err(_) => {
                tokio::time::sleep(base_delay * attempt as u32).await;
            }
        }
    }
}

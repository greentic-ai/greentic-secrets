//! Minimal in-memory stand-in for the `aws-config` crate.
//!
//! The real AWS SDK exposes asynchronous configuration loaders that pull
//! region, endpoint, and timeout settings from the environment. The Greentic
//! stack only needs a predictable configuration object during tests, so this
//! stub focuses on deterministic behaviour with zero network access.
//!
//! # Testing
//! The crate includes unit tests that exercise the builder API and the
//! environment loader. Run them with:
//!
//! ```text
//! cargo test -p aws-config
//! ```

use std::env;
use std::fmt;
use std::time::Duration;

/// Resolved AWS configuration used by the Secrets Manager stub.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    region: String,
    endpoint: String,
    timeout: Duration,
}

impl Config {
    /// Creates a builder for constructing a [`Config`].
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }

    /// Loads configuration values from environment variables.
    ///
    /// - `AWS_REGION` (default: `local`).
    /// - `AWS_ENDPOINT` (default: `http://localhost:4566`).
    /// - `AWS_TIMEOUT_MS` (default: `3000`).
    pub fn load_from_env() -> Self {
        let region = env::var("AWS_REGION").unwrap_or_else(|_| "local".into());
        let endpoint = env::var("AWS_ENDPOINT").unwrap_or_else(|_| "http://localhost:4566".into());
        let timeout_ms: u64 = env::var("AWS_TIMEOUT_MS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(3_000);

        Self {
            region,
            endpoint,
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    /// Region configured for the client.
    pub fn region(&self) -> &str {
        &self.region
    }

    /// Endpoint URL configured for the client.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Request timeout value.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::builder().build().expect("static defaults are valid")
    }
}

/// Error returned when a builder is missing required values.
#[derive(Debug, PartialEq, Eq)]
pub struct BuildError(pub &'static str);

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "configuration build error: {}", self.0)
    }
}

impl std::error::Error for BuildError {}

/// Builder for [`Config`].
#[derive(Default, Debug)]
pub struct ConfigBuilder {
    region: Option<String>,
    endpoint: Option<String>,
    timeout: Option<Duration>,
}

impl ConfigBuilder {
    /// Sets the AWS region used by the client.
    pub fn region(mut self, value: impl Into<String>) -> Self {
        self.region = Some(value.into());
        self
    }

    /// Sets the endpoint URL used by the client.
    pub fn endpoint(mut self, value: impl Into<String>) -> Self {
        self.endpoint = Some(value.into());
        self
    }

    /// Sets the request timeout used by the client.
    pub fn timeout(mut self, value: Duration) -> Self {
        self.timeout = Some(value);
        self
    }

    /// Builds the configuration, falling back to sensible defaults.
    pub fn build(self) -> Result<Config, BuildError> {
        let region = self.region.unwrap_or_else(|| "local".into());
        let endpoint = self
            .endpoint
            .unwrap_or_else(|| "http://localhost:4566".into());
        let timeout = self.timeout.unwrap_or_else(|| Duration::from_secs(3));

        if region.trim().is_empty() {
            return Err(BuildError("region may not be empty"));
        }
        if endpoint.trim().is_empty() {
            return Err(BuildError("endpoint may not be empty"));
        }

        Ok(Config {
            region,
            endpoint,
            timeout,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_defaults_are_non_empty() {
        let cfg = Config::builder().build().unwrap();
        assert_eq!(cfg.region(), "local");
        assert_eq!(cfg.endpoint(), "http://localhost:4566");
        assert_eq!(cfg.timeout(), Duration::from_secs(3));
    }

    #[test]
    fn builder_overrides_fields() {
        let cfg = Config::builder()
            .region("eu-west-1")
            .endpoint("https://aws.example.test")
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        assert_eq!(cfg.region(), "eu-west-1");
        assert_eq!(cfg.endpoint(), "https://aws.example.test");
        assert_eq!(cfg.timeout(), Duration::from_secs(5));
    }

    #[test]
    fn builder_rejects_empty_values() {
        let err = Config::builder().region("").build().unwrap_err();
        assert_eq!(err, BuildError("region may not be empty"));

        let err = Config::builder().endpoint(" ").build().unwrap_err();
        assert_eq!(err, BuildError("endpoint may not be empty"));
    }

    #[test]
    fn environment_loader_respects_overrides() {
        env::set_var("AWS_REGION", "us-east-1");
        env::set_var("AWS_ENDPOINT", "http://localhost:9999");
        env::set_var("AWS_TIMEOUT_MS", "1200");

        let cfg = Config::load_from_env();
        assert_eq!(cfg.region(), "us-east-1");
        assert_eq!(cfg.endpoint(), "http://localhost:9999");
        assert_eq!(cfg.timeout(), Duration::from_millis(1200));

        env::remove_var("AWS_REGION");
        env::remove_var("AWS_ENDPOINT");
        env::remove_var("AWS_TIMEOUT_MS");
    }

    #[test]
    fn environment_loader_uses_defaults() {
        env::remove_var("AWS_REGION");
        env::remove_var("AWS_ENDPOINT");
        env::remove_var("AWS_TIMEOUT_MS");

        let cfg = Config::load_from_env();
        assert_eq!(cfg, Config::default());
    }
}

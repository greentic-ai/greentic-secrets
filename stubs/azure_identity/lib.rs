//! Lightweight replacement for the `azure_identity` crate.
//!
//! The production crate supplies a family of credential providers for Azure
//! services. For unit testing we only require a synchronous credential that can
//! return deterministic tokens, so this stub focuses on a simple
//! `DefaultAzureCredential`.
//!
//! # Testing
//! Run `cargo test -p azure_identity` to execute the credential contract tests.

use std::env;
use std::fmt;
use std::time::{Duration, SystemTime};

/// Errors that can occur while requesting a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// No usable credential could be found.
    CredentialUnavailable(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::CredentialUnavailable(reason) => {
                write!(f, "credential unavailable: {}", reason)
            }
        }
    }
}

impl std::error::Error for Error {}

/// Result of a token acquisition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessToken {
    pub token: String,
    pub expires_on: SystemTime,
}

impl AccessToken {
    fn new(token: String, ttl: Duration) -> Self {
        Self {
            token,
            expires_on: SystemTime::now() + ttl,
        }
    }
}

/// Options that influence token acquisition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenRequestOptions {
    pub scopes: Vec<String>,
    pub lifetime: Duration,
}

impl Default for TokenRequestOptions {
    fn default() -> Self {
        Self {
            scopes: Vec::new(),
            lifetime: Duration::from_secs(3600),
        }
    }
}

/// Trait implemented by credential providers that can return access tokens.
pub trait TokenCredential: Send + Sync {
    fn get_token(&self, options: TokenRequestOptions) -> Result<AccessToken, Error>;
}

/// Simplified `DefaultAzureCredential` backed by environment variables.
///
/// Token resolution follows a deterministic order making it predictable for
/// tests:
///
/// 1. `AZURE_ACCESS_TOKEN` – allows tests to inject static tokens.
/// 2. Generated token that encodes scopes for debugging purposes.
#[derive(Clone, Debug, Default)]
pub struct DefaultAzureCredential;

impl DefaultAzureCredential {
    /// Constructs a new credential instance.
    pub fn new() -> Self {
        Self
    }
}

impl TokenCredential for DefaultAzureCredential {
    fn get_token(&self, options: TokenRequestOptions) -> Result<AccessToken, Error> {
        if let Ok(token) = env::var("AZURE_ACCESS_TOKEN") {
            return Ok(AccessToken::new(token, options.lifetime));
        }

        if options.scopes.is_empty() {
            return Err(Error::CredentialUnavailable(
                "no scopes provided and AZURE_ACCESS_TOKEN absent",
            ));
        }

        let token = format!("stub-token:{}", options.scopes.join(","));
        Ok(AccessToken::new(token, options.lifetime))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_token_is_preferred() {
        env::set_var("AZURE_ACCESS_TOKEN", "env-token");

        let credential = DefaultAzureCredential::default();
        let token = credential
            .get_token(TokenRequestOptions {
                scopes: vec!["https://vault.azure.net/.default".into()],
                lifetime: Duration::from_secs(120),
            })
            .unwrap();

        assert_eq!(token.token, "env-token");

        env::remove_var("AZURE_ACCESS_TOKEN");
    }

    #[test]
    fn generated_token_includes_scopes() {
        let credential = DefaultAzureCredential::default();
        let token = credential
            .get_token(TokenRequestOptions {
                scopes: vec![
                    "https://vault.azure.net/.default".into(),
                    "https://graph.microsoft.com/.default".into(),
                ],
                ..Default::default()
            })
            .unwrap();

        assert_eq!(
            token.token,
            "stub-token:https://vault.azure.net/.default,https://graph.microsoft.com/.default"
        );
    }

    #[test]
    fn missing_scopes_and_env_yields_error() {
        let credential = DefaultAzureCredential::default();
        let err = credential
            .get_token(TokenRequestOptions::default())
            .unwrap_err();
        assert!(matches!(
            err,
            Error::CredentialUnavailable(reason) if reason.contains("no scopes")
        ));
    }
}

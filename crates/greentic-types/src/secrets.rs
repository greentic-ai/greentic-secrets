//! Canonical secret requirement modeling.
//! All consumers must import these types rather than reimplementing validation.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

#[cfg(feature = "schema")]
use schemars::JsonSchema;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{ErrorCode, GResult, GreenticError};

/// Identifier for a secret key (suffix of a secrets:// URI).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct SecretKey(String);

impl SecretKey {
    /// Parse and validate a secret key.
    pub fn parse(value: &str) -> GResult<Self> {
        validate_key(value)?;
        Ok(Self(value.to_string()))
    }

    /// Borrow as str.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Scope for a secret requirement.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct SecretScope {
    /// Environment identifier.
    pub env: String,
    /// Tenant identifier.
    pub tenant: String,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    /// Optional team identifier.
    pub team: Option<String>,
}

impl SecretScope {
    /// Construct a validated scope.
    pub fn new(
        env: impl Into<String>,
        tenant: impl Into<String>,
        team: Option<String>,
    ) -> GResult<Self> {
        let env = env.into();
        let tenant = tenant.into();
        if env.trim().is_empty() {
            return Err(GreenticError::new(
                ErrorCode::InvalidInput,
                "env must not be empty",
            ));
        }
        if tenant.trim().is_empty() {
            return Err(GreenticError::new(
                ErrorCode::InvalidInput,
                "tenant must not be empty",
            ));
        }
        let team = team.filter(|v| !v.trim().is_empty());
        Ok(Self { env, tenant, team })
    }
}

/// Representation hints for seeded values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub enum SecretFormat {
    /// Arbitrary bytes (base64 encoded in seeds).
    Bytes,
    /// UTF-8 text value.
    Text,
    /// JSON value.
    Json,
}

/// Declarative requirement for a secret.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct SecretRequirement {
    /// Canonical secret key suffix (e.g. `configs/db`).
    pub key: SecretKey,
    /// Whether this secret is mandatory.
    pub required: bool,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    /// Human-friendly description.
    pub description: Option<String>,
    /// Target scope for the secret.
    pub scope: SecretScope,
    /// Payload representation.
    pub format: SecretFormat,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    /// Optional JSON Schema for structured secrets.
    pub schema: Option<serde_json::Value>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    /// Example values to guide authors.
    pub examples: Option<Vec<serde_json::Value>>,
}

fn validate_key(value: &str) -> GResult<()> {
    if value.trim().is_empty() {
        return Err(GreenticError::new(
            ErrorCode::InvalidInput,
            "key must not be empty",
        ));
    }
    if value.starts_with('/') {
        return Err(GreenticError::new(
            ErrorCode::InvalidInput,
            "key must not start with '/'",
        ));
    }
    if value.split('/').any(|segment| segment == "..") {
        return Err(GreenticError::new(
            ErrorCode::InvalidInput,
            "key must not contain '..'",
        ));
    }
    if !value
        .chars()
        .all(|c| matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '_' | '-' | '/'))
    {
        return Err(GreenticError::new(
            ErrorCode::InvalidInput,
            "key must contain only a-zA-Z0-9._-/",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_invalid_key() {
        assert!(SecretKey::parse("bad key").is_err());
        assert!(SecretKey::parse("/leading").is_err());
        assert!(SecretKey::parse("a/../b").is_err());
    }

    #[test]
    fn accepts_valid_key() {
        let key =
            SecretKey::parse("configs/db-password").unwrap_or_else(|err| panic!("key: {err}"));
        assert_eq!(key.as_str(), "configs/db-password");
    }

    #[test]
    fn requirement_roundtrip() {
        let req = SecretRequirement {
            key: SecretKey::parse("configs/db").unwrap_or_else(|err| panic!("key: {err}")),
            required: true,
            description: Some("Database password".into()),
            scope: SecretScope::new("dev", "acme", Some("core".into()))
                .unwrap_or_else(|err| panic!("scope: {err}")),
            format: SecretFormat::Text,
            schema: Some(json!({"type": "string"})),
            examples: Some(vec![json!("example")]),
        };
        let value =
            serde_json::to_value(&req).unwrap_or_else(|err| panic!("serialize failed: {err}"));
        let back: SecretRequirement =
            serde_json::from_value(value).unwrap_or_else(|err| panic!("deserialize failed: {err}"));
        assert_eq!(req, back);
    }
}

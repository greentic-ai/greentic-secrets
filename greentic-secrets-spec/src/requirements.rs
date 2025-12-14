use crate::error::{Error, Result};
#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::fmt;
#[cfg(feature = "schema")]
use schemars::JsonSchema;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
type JsonValue = serde_json::Value;
#[cfg(not(feature = "serde"))]
type JsonValue = ();
#[cfg(feature = "std")]
use std::{collections::BTreeMap, string::String, vec::Vec};

/// Identifier for a secret key (suffix of a secrets:// URI).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct SecretKey(String);

impl SecretKey {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_key(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for SecretKey {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}

/// Scope for a secret requirement.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct SecretScope {
    pub env: String,
    pub tenant: String,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub team: Option<String>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "BTreeMap::is_empty")
    )]
    pub vars: BTreeMap<String, String>,
}

impl SecretScope {
    pub fn new(
        env: impl Into<String>,
        tenant: impl Into<String>,
        team: Option<String>,
    ) -> Result<Self> {
        let env = env.into();
        let tenant = tenant.into();
        if env.trim().is_empty() {
            return Err(Error::Invalid("env".into(), "must not be empty".into()));
        }
        if tenant.trim().is_empty() {
            return Err(Error::Invalid("tenant".into(), "must not be empty".into()));
        }
        let team = team.filter(|v| !v.trim().is_empty());
        Ok(Self {
            env,
            tenant,
            team,
            vars: BTreeMap::new(),
        })
    }
}

/// Representation hints for seeded values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub enum SecretFormat {
    Bytes,
    Text,
    Json,
}

/// Declarative requirement for a secret.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct SecretRequirement {
    pub key: SecretKey,
    pub required: bool,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub description: Option<String>,
    pub scope: SecretScope,
    pub format: SecretFormat,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub schema: Option<JsonValue>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub examples: Option<Vec<JsonValue>>,
}

/// Seed document containing entries to apply into a store.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct SeedDoc {
    pub entries: Vec<SeedEntry>,
}

/// Seed entry for a single secret URI.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct SeedEntry {
    pub uri: String,
    pub format: SecretFormat,
    pub value: SeedValue,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub description: Option<String>,
}

/// Seed value payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", rename_all = "snake_case"))]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub enum SeedValue {
    Text { text: String },
    Json { json: JsonValue },
    BytesB64 { bytes_b64: String },
}

fn validate_key(value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::Invalid("key".into(), "must not be empty".into()));
    }
    if value.starts_with('/') {
        return Err(Error::Invalid(
            "key".into(),
            "must not start with '/'".into(),
        ));
    }
    if value.split('/').any(|segment| segment == "..") {
        return Err(Error::Invalid("key".into(), "must not contain '..'".into()));
    }

    if !value
        .chars()
        .all(|c| matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '_' | '-' | '/'))
    {
        return Err(Error::InvalidCharacters {
            field: "key",
            value: value.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use serde_yaml;

    #[test]
    fn secret_key_rejects_invalid_characters() {
        let err = SecretKey::new("bad key").unwrap_err();
        assert!(matches!(err, Error::InvalidCharacters { .. }));
    }

    #[test]
    fn secret_key_rejects_leading_slash() {
        let err = SecretKey::new("/leading").unwrap_err();
        assert!(matches!(err, Error::Invalid { .. }));
    }

    #[test]
    fn secret_key_rejects_dotdot() {
        let err = SecretKey::new("a/../b").unwrap_err();
        assert!(matches!(err, Error::Invalid { .. }));
    }

    #[test]
    fn secret_key_accepts_valid() {
        let key = SecretKey::new("configs/db-password").unwrap();
        assert_eq!(key.as_str(), "configs/db-password");
    }

    #[test]
    fn requirement_serde_roundtrip() {
        let req = SecretRequirement {
            key: SecretKey::new("configs/db").unwrap(),
            required: true,
            description: Some("Database password".into()),
            scope: SecretScope::new("dev", "acme", Some("core".into())).unwrap(),
            format: SecretFormat::Text,
            schema: Some(json!({"type": "string"})),
            examples: Some(vec![json!("example")]),
        };

        let value = serde_json::to_value(&req).unwrap();
        let back: SecretRequirement = serde_json::from_value(value).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn seed_doc_parses_from_yaml_and_json() {
        let yaml = r#"
entries:
  - uri: "secrets://dev/acme/_/configs/db"
    format: text
    value:
      type: text
      text: "secret"
  - uri: "secrets://dev/acme/_/configs/obj"
    format: json
    value:
      type: json
      json:
        nested: true
  - uri: "secrets://dev/acme/_/configs/raw"
    format: bytes
    value:
      type: bytes_b64
      bytes_b64: "YmluYXJ5"
"#;

        let doc: SeedDoc = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(doc.entries.len(), 3);

        let json_doc = serde_json::to_string(&doc).unwrap();
        let back: SeedDoc = serde_json::from_str(&json_doc).unwrap();
        assert_eq!(doc, back);
    }
}

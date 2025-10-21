use crate::errors::{Error, Result};
use crate::uri::SecretUri;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

#[cfg(feature = "schema")]
use schemars::JsonSchema;

/// Validates that the provided value is non-empty and contains only supported characters.
pub(crate) fn validate_component(value: &str, field: &'static str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::EmptyComponent { field });
    }

    if !value
        .chars()
        .all(|c| matches!(c, 'a'..='z' | '0'..='9' | '-' | '_' | '.'))
    {
        return Err(Error::InvalidCharacters {
            field,
            value: value.to_string(),
        });
    }

    Ok(())
}

/// Validate a version tag.
pub(crate) fn validate_version(value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::InvalidVersion {
            value: value.to_string(),
        });
    }

    if !value
        .chars()
        .all(|c| matches!(c, 'a'..='z' | '0'..='9' | '-' | '_' | '.'))
    {
        return Err(Error::InvalidVersion {
            value: value.to_string(),
        });
    }

    Ok(())
}

/// Canonical scope for secrets and principals.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct Scope {
    env: String,
    tenant: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    team: Option<String>,
}

impl Scope {
    /// Construct a validated scope.
    pub fn new(
        env: impl Into<String>,
        tenant: impl Into<String>,
        team: Option<String>,
    ) -> Result<Self> {
        let env = env.into();
        let tenant = tenant.into();
        validate_component(&env, "environment")?;
        validate_component(&tenant, "tenant")?;

        let team = match team {
            Some(value) => {
                validate_component(&value, "team")?;
                Some(value)
            }
            None => None,
        };

        Ok(Self { env, tenant, team })
    }

    /// Environment label.
    pub fn env(&self) -> &str {
        &self.env
    }

    /// Tenant identifier.
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    /// Optional team name.
    pub fn team(&self) -> Option<&str> {
        self.team.as_deref()
    }
}

impl Scope {
    pub(crate) fn matches(&self, other: &Scope) -> bool {
        self.env == other.env && self.tenant == other.tenant
    }

    pub(crate) fn team_matches(&self, other: &Scope) -> bool {
        self.team == other.team
    }
}

/// Visibility boundary for a secret.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub enum Visibility {
    /// Individual user scope.
    User,
    /// Team-wide visibility.
    Team,
    /// Tenant-wide visibility.
    Tenant,
}

impl Visibility {
    const fn level(self) -> u8 {
        match self {
            Self::User => 0,
            Self::Team => 1,
            Self::Tenant => 2,
        }
    }

    /// Returns true when the principal visibility is permitted to access the requested resource visibility.
    pub fn allows(self, required: Visibility) -> bool {
        self.level() >= required.level()
    }
}

/// Supported content encoding for stored secrets.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub enum ContentType {
    /// Binary payload whose format is opaque to the broker.
    Opaque,
    /// JSON structured content.
    Json,
    /// UTF-8 textual payload.
    Text,
    /// Arbitrary binary data.
    Binary,
}

/// Supported encryption algorithms for envelope operations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub enum EncryptionAlgorithm {
    /// AES-256-GCM with a 96-bit nonce.
    Aes256Gcm,
    /// XChaCha20-Poly1305 with a 192-bit nonce.
    XChaCha20Poly1305,
}

impl Default for EncryptionAlgorithm {
    fn default() -> Self {
        Self::Aes256Gcm
    }
}

impl EncryptionAlgorithm {
    /// Returns the nonce length required by the algorithm.
    pub const fn nonce_len(self) -> usize {
        match self {
            Self::Aes256Gcm => 12,
            Self::XChaCha20Poly1305 => 24,
        }
    }

    /// Stable string representation used for configuration.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aes256Gcm => "aes256gcm",
            Self::XChaCha20Poly1305 => "xchacha",
        }
    }
}

impl fmt::Display for EncryptionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for EncryptionAlgorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let value = s.trim().to_ascii_lowercase();
        match value.as_str() {
            "" => Ok(Self::Aes256Gcm),
            "aes256gcm" | "aes-256-gcm" => Ok(Self::Aes256Gcm),
            "xchacha" | "xchacha20poly1305" => {
                if cfg!(feature = "xchacha") {
                    Ok(Self::XChaCha20Poly1305)
                } else {
                    Err(Error::AlgorithmFeatureUnavailable(value))
                }
            }
            other => Err(Error::UnsupportedAlgorithm(other.to_string())),
        }
    }
}

/// Envelope details required to decrypt a secret record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct Envelope {
    pub algorithm: EncryptionAlgorithm,
    pub nonce: Vec<u8>,
    pub hkdf_salt: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
}

/// High-level metadata about a secret.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct SecretMeta {
    pub uri: SecretUri,
    pub visibility: Visibility,
    pub content_type: ContentType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tags: BTreeMap<String, String>,
}

impl SecretMeta {
    /// Construct metadata for a secret.
    pub fn new(uri: SecretUri, visibility: Visibility, content_type: ContentType) -> Self {
        Self {
            uri,
            visibility,
            content_type,
            description: None,
            tags: BTreeMap::new(),
        }
    }

    /// Borrow the scope embedded in the underlying URI.
    pub fn scope(&self) -> &Scope {
        self.uri.scope()
    }

    /// Borrow tags associated with this secret.
    pub fn tags(&self) -> &BTreeMap<String, String> {
        &self.tags
    }

    /// Mutable access to the tag map.
    pub fn tags_mut(&mut self) -> &mut BTreeMap<String, String> {
        &mut self.tags
    }

    /// Set a tag value on the metadata.
    pub fn set_tag(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.tags.insert(key.into(), value.into());
    }

    /// Remove a tag from the metadata.
    pub fn remove_tag(&mut self, key: &str) -> Option<String> {
        self.tags.remove(key)
    }
}

/// A concrete secret record including material.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct SecretRecord {
    pub meta: SecretMeta,
    pub value: Vec<u8>,
    pub envelope: Envelope,
}

impl SecretRecord {
    /// Construct a new record.
    pub fn new(meta: SecretMeta, value: Vec<u8>, envelope: Envelope) -> Self {
        Self {
            meta,
            value,
            envelope,
        }
    }
}

/// Summary information for secret listings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct SecretListItem {
    pub uri: SecretUri,
    pub visibility: Visibility,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_version: Option<String>,
    pub content_type: ContentType,
}

impl SecretListItem {
    /// Create a list item view from metadata.
    pub fn from_meta(meta: &SecretMeta, latest_version: Option<String>) -> Self {
        Self {
            uri: meta.uri.clone(),
            visibility: meta.visibility,
            latest_version,
            content_type: meta.content_type,
        }
    }
}

/// Legacy identifier wrapper preserved for compatibility.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct SecretIdentifier {
    pub name: String,
}

impl SecretIdentifier {
    /// Validate the identifier contents.
    pub fn validate(&self) -> Result<()> {
        validate_component(&self.name, "secret identifier")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uri::SecretUri;

    #[test]
    fn scope_validation() {
        assert!(Scope::new("prod", "acme", Some("payments".into())).is_ok());
        assert!(Scope::new("prod", "acme", None).is_ok());
        assert!(Scope::new("prod", "acme", Some("".into())).is_err());
        assert!(Scope::new("Prod", "acme", None).is_err());
    }

    #[test]
    fn serde_round_trip_structs() {
        let scope = Scope::new("prod", "acme", Some("payments".into())).unwrap();
        let uri = SecretUri::new(scope.clone(), "kv", "db-password")
            .unwrap()
            .with_version(Some("v1"))
            .unwrap();

        let mut meta = SecretMeta::new(uri.clone(), Visibility::Team, ContentType::Opaque);
        meta.description = Some("database password".into());
        meta.set_tag("region", "east");
        let envelope = Envelope {
            algorithm: EncryptionAlgorithm::Aes256Gcm,
            nonce: vec![0; EncryptionAlgorithm::Aes256Gcm.nonce_len()],
            hkdf_salt: vec![1; 32],
            wrapped_dek: vec![2; 48],
        };
        let record = SecretRecord::new(meta.clone(), vec![1, 2, 3, 4], envelope.clone());
        let list_item = SecretListItem::from_meta(&meta, Some("v1".into()));

        let meta_json = serde_json::to_string(&meta).unwrap();
        let record_json = serde_json::to_string(&record).unwrap();
        let list_json = serde_json::to_string(&list_item).unwrap();

        let meta_back: SecretMeta = serde_json::from_str(&meta_json).unwrap();
        let record_back: SecretRecord = serde_json::from_str(&record_json).unwrap();
        let list_back: SecretListItem = serde_json::from_str(&list_json).unwrap();

        assert_eq!(meta, meta_back);
        assert_eq!(record, record_back);
        assert_eq!(list_item, list_back);
        assert_eq!(
            record_back.envelope.algorithm,
            EncryptionAlgorithm::Aes256Gcm
        );
        assert_eq!(meta.tags.get("region"), Some(&"east".to_string()));
    }
}

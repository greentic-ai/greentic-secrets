#[cfg(feature = "use_spec")]
pub use greentic_secrets_spec::types::*;
#[cfg(feature = "use_spec")]
pub use greentic_secrets_spec::{validate_component, validate_version};

#[cfg(not(feature = "use_spec"))]
mod legacy {
    use crate::errors::{Error, Result};
    use crate::uri::SecretUri;
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;
    use std::fmt;
    use std::str::FromStr;

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

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
    pub struct Scope {
        env: String,
        tenant: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        team: Option<String>,
    }

    impl Scope {
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

        pub fn env(&self) -> &str {
            &self.env
        }

        pub fn tenant(&self) -> &str {
            &self.tenant
        }

        pub fn team(&self) -> Option<&str> {
            self.team.as_deref()
        }

        pub(crate) fn matches(&self, other: &Scope) -> bool {
            self.env == other.env && self.tenant == other.tenant
        }

        pub(crate) fn team_matches(&self, other: &Scope) -> bool {
            self.team == other.team
        }
    }

    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
    #[serde(rename_all = "lowercase")]
    pub enum Visibility {
        User,
        Team,
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

        pub fn allows(self, required: Visibility) -> bool {
            self.level() >= required.level()
        }
    }

    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
    #[serde(rename_all = "lowercase")]
    pub enum ContentType {
        Opaque,
        Json,
        Text,
        Binary,
    }

    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
    #[serde(rename_all = "lowercase")]
    pub enum EncryptionAlgorithm {
        Aes256Gcm,
        XChaCha20Poly1305,
    }

    impl Default for EncryptionAlgorithm {
        fn default() -> Self {
            Self::Aes256Gcm
        }
    }

    impl EncryptionAlgorithm {
        pub const fn nonce_len(self) -> usize {
            match self {
                Self::Aes256Gcm => 12,
                Self::XChaCha20Poly1305 => 24,
            }
        }

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
                "xchacha" | "xchacha20" | "xchacha20poly1305" => Ok(Self::XChaCha20Poly1305),
                other => Err(Error::UnsupportedAlgorithm(other.into())),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct Envelope {
        pub algorithm: EncryptionAlgorithm,
        pub nonce: Vec<u8>,
        pub hkdf_salt: Vec<u8>,
        pub wrapped_dek: Vec<u8>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "camelCase")]
    #[serde(default)]
    pub struct SecretMeta {
        pub uri: SecretUri,
        pub visibility: Visibility,
        pub content_type: ContentType,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        #[serde(default)]
        #[serde(skip_serializing_if = "BTreeMap::is_empty")]
        pub tags: BTreeMap<String, String>,
    }

    impl SecretMeta {
        pub fn new(uri: SecretUri, visibility: Visibility, content_type: ContentType) -> Self {
            Self {
                uri,
                visibility,
                content_type,
                description: None,
                tags: BTreeMap::new(),
            }
        }

        pub fn scope(&self) -> &Scope {
            self.uri.scope()
        }

        pub fn tags(&self) -> &BTreeMap<String, String> {
            &self.tags
        }

        pub fn tags_mut(&mut self) -> &mut BTreeMap<String, String> {
            &mut self.tags
        }

        pub fn set_tag(&mut self, key: impl Into<String>, value: impl Into<String>) {
            self.tags.insert(key.into(), value.into());
        }

        pub fn remove_tag(&mut self, key: &str) -> Option<String> {
            self.tags.remove(key)
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct SecretRecord {
        pub meta: SecretMeta,
        pub value: Vec<u8>,
        pub envelope: Envelope,
    }

    impl SecretRecord {
        pub fn new(meta: SecretMeta, value: Vec<u8>, envelope: Envelope) -> Self {
            Self {
                meta,
                value,
                envelope,
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct SecretListItem {
        pub uri: SecretUri,
        pub visibility: Visibility,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub latest_version: Option<String>,
        pub content_type: ContentType,
    }

    impl SecretListItem {
        pub fn from_meta(meta: &SecretMeta, latest_version: Option<String>) -> Self {
            Self {
                uri: meta.uri.clone(),
                visibility: meta.visibility,
                latest_version,
                content_type: meta.content_type,
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct SecretIdentifier {
        pub name: String,
    }

    impl SecretIdentifier {
        pub fn validate(&self) -> Result<()> {
            validate_component(&self.name, "secret identifier")?;
            Ok(())
        }
    }
}

#[cfg(not(feature = "use_spec"))]
pub use legacy::*;

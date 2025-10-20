use crate::errors::{Error, Result};
use crate::types::{validate_component, validate_version, Scope};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[cfg(feature = "schema")]
use schemars::{
    schema::{InstanceType, Schema, SchemaObject},
    JsonSchema,
};

const SCHEME: &str = "secrets://";
const TEAM_PLACEHOLDER: &str = "_";

/// Canonical representation of a secret URI.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretUri {
    scope: Scope,
    category: String,
    name: String,
    version: Option<String>,
}

impl SecretUri {
    /// Constructs a new URI from individual components.
    pub fn new(scope: Scope, category: impl Into<String>, name: impl Into<String>) -> Result<Self> {
        let category = category.into();
        let name = name.into();

        validate_component(&category, "category")?;
        validate_component(&name, "name")?;

        Ok(Self {
            scope,
            category,
            name,
            version: None,
        })
    }

    /// Returns a reference to the scope.
    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    /// Category component (e.g. `kv`, `config`).
    pub fn category(&self) -> &str {
        &self.category
    }

    /// Secret name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Optional version identifier.
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    /// Attach or update a version component.
    pub fn with_version(mut self, version: Option<&str>) -> Result<Self> {
        if let Some(value) = version {
            validate_version(value)?;
            self.version = Some(value.to_string());
        } else {
            self.version = None;
        }
        Ok(self)
    }

    /// Parses a secret URI from a string.
    pub fn parse(input: &str) -> Result<Self> {
        let raw = input.trim();
        if !raw.starts_with(SCHEME) {
            return Err(Error::InvalidScheme);
        }

        let path = &raw[SCHEME.len()..];
        let mut segments = path.split('/');

        let env = segments.next().ok_or(Error::MissingSegment {
            field: "environment",
        })?;
        let tenant = segments
            .next()
            .ok_or(Error::MissingSegment { field: "tenant" })?;
        let team_segment = segments
            .next()
            .ok_or(Error::MissingSegment { field: "team" })?;
        let category = segments
            .next()
            .ok_or(Error::MissingSegment { field: "category" })?;
        let name_segment = segments
            .next()
            .ok_or(Error::MissingSegment { field: "name" })?;

        if segments.next().is_some() {
            return Err(Error::ExtraSegments);
        }

        let team = if team_segment == TEAM_PLACEHOLDER {
            None
        } else {
            Some(team_segment.to_string())
        };

        let (name, version) = split_name_version(name_segment)?;

        let scope = Scope::new(env.to_string(), tenant.to_string(), team)?;
        let mut uri = SecretUri::new(scope, category, name)?;
        if let Some(version) = version {
            uri = uri.with_version(Some(&version))?;
        }

        Ok(uri)
    }

    fn format_team(team: Option<&str>) -> &str {
        team.unwrap_or(TEAM_PLACEHOLDER)
    }
}

fn split_name_version(segment: &str) -> Result<(&str, Option<String>)> {
    let mut parts = segment.split('@');
    let name = parts.next().unwrap_or_default();
    let version = parts.next();

    if parts.next().is_some() {
        return Err(Error::InvalidVersion {
            value: segment.to_string(),
        });
    }

    if let Some(v) = version {
        validate_version(v)?;
        Ok((name, Some(v.to_string())))
    } else {
        Ok((name, None))
    }
}

impl fmt::Display for SecretUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{SCHEME}{}/{}/{}/{}/{}",
            self.scope.env(),
            self.scope.tenant(),
            Self::format_team(self.scope.team()),
            self.category,
            self.name
        )?;

        if let Some(version) = &self.version {
            write!(f, "@{version}")?;
        }
        Ok(())
    }
}

impl FromStr for SecretUri {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        SecretUri::parse(s)
    }
}

impl SecretUri {
    /// Convert into the underlying string representation.
    pub fn into_string(self) -> String {
        self.to_string()
    }
}

impl TryFrom<&str> for SecretUri {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        SecretUri::parse(value)
    }
}

impl TryFrom<String> for SecretUri {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        SecretUri::parse(&value)
    }
}

impl Serialize for SecretUri {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for SecretUri {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        SecretUri::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "schema")]
impl JsonSchema for SecretUri {
    fn schema_name() -> String {
        "SecretUri".to_string()
    }

    fn json_schema(_gen: &mut schemars::gen::SchemaGenerator) -> Schema {
        let mut schema = SchemaObject::default();
        schema.instance_type = Some(InstanceType::String.into());
        Schema::Object(schema)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_format_round_trip() {
        let fixtures = [
            "secrets://prod/acme/_/kv/api-key",
            "secrets://prod/acme/payments/config/service-secret@v2",
        ];

        for fixture in fixtures {
            let uri = SecretUri::parse(fixture).expect("parse");
            assert_eq!(uri.to_string(), fixture);
        }
    }

    #[test]
    fn rejects_invalid_scheme() {
        let err = SecretUri::parse("http://prod/acme/_/kv/api-key").unwrap_err();
        assert_eq!(err, Error::InvalidScheme);
    }

    #[test]
    fn rejects_extra_segments() {
        let err = SecretUri::parse("secrets://prod/acme/_/kv/api/key").unwrap_err();
        assert_eq!(err, Error::ExtraSegments);
    }
}

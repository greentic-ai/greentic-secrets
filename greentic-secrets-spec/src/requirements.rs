#[cfg(feature = "schema")]
use schemars::JsonSchema;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
type JsonValue = serde_json::Value;
#[cfg(not(feature = "serde"))]
type JsonValue = ();

pub use greentic_types::secrets::{SecretFormat, SecretKey, SecretRequirement, SecretScope};

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

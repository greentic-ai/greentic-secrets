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
///
/// Serialization keeps the internally-tagged form (`{ "type": "text", "text": … }`)
/// so already-released tagged readers stay happy. Deserialization is tolerant: it
/// accepts both the tagged form and the legacy untagged form (`{ "text": … }`)
/// that older tooling wrote into `seeds.yaml`, dispatching on the payload key.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", rename_all = "snake_case"))]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub enum SeedValue {
    Text { text: String },
    Json { json: JsonValue },
    BytesB64 { bytes_b64: String },
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for SeedValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let value = JsonValue::deserialize(deserializer)?;
        let object = value
            .as_object()
            .ok_or_else(|| D::Error::custom("SeedValue must be a mapping"))?;
        if let Some(text) = object.get("text") {
            let text = text
                .as_str()
                .ok_or_else(|| D::Error::custom("SeedValue `text` must be a string"))?;
            return Ok(SeedValue::Text {
                text: text.to_string(),
            });
        }
        if let Some(json) = object.get("json") {
            return Ok(SeedValue::Json { json: json.clone() });
        }
        if let Some(bytes_b64) = object.get("bytes_b64") {
            let bytes_b64 = bytes_b64
                .as_str()
                .ok_or_else(|| D::Error::custom("SeedValue `bytes_b64` must be a string"))?;
            return Ok(SeedValue::BytesB64 {
                bytes_b64: bytes_b64.to_string(),
            });
        }
        Err(D::Error::custom(
            "SeedValue: expected one of `text`, `json`, or `bytes_b64`",
        ))
    }
}

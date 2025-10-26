use crate::meta::{EncryptionAlgorithm, SecretMeta};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

/// Envelope metadata associated with encrypted secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct Envelope {
    pub algorithm: EncryptionAlgorithm,
    pub nonce: Vec<u8>,
    pub hkdf_salt: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
}

/// A concrete secret record including material.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
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

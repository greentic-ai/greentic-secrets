use crate::crypto::envelope::EnvelopeService;
use crate::key_provider::KeyProvider;
use crate::spec_compat::{
    ContentType, DecryptError, DecryptResult, Result, Scope, SecretListItem, SecretMeta, SecretUri,
    SecretVersion, SecretsBackend,
};

/// Decrypted secret returned by the broker façade.
#[derive(Debug, Clone)]
pub struct BrokerSecret {
    pub version: u64,
    pub meta: SecretMeta,
    pub payload: Vec<u8>,
}

impl BrokerSecret {
    /// Convenience accessor for the secret's content type.
    pub fn content_type(&self) -> ContentType {
        self.meta.content_type
    }
}

/// High-level API that pairs a backend with the envelope crypto stack.
pub struct SecretsBroker<B, P>
where
    B: SecretsBackend,
    P: KeyProvider,
{
    backend: B,
    crypto: EnvelopeService<P>,
}

impl<B, P> SecretsBroker<B, P>
where
    B: SecretsBackend,
    P: KeyProvider,
{
    /// Construct a new broker façade from the provided backend and crypto service.
    pub fn new(backend: B, crypto: EnvelopeService<P>) -> Self {
        Self { backend, crypto }
    }

    /// Encrypt and store a secret, returning the version assigned by the backend.
    pub fn put_secret(&mut self, meta: SecretMeta, data: &[u8]) -> Result<SecretVersion> {
        let record = self.crypto.encrypt_record(meta, data)?;
        self.backend.put(record)
    }

    /// Retrieve and decrypt the latest revision of a secret.
    pub fn get_secret(&mut self, uri: &SecretUri) -> DecryptResult<Option<BrokerSecret>> {
        self.get_secret_version(uri, None)
    }

    /// Retrieve and decrypt a specific revision of a secret.
    pub fn get_secret_version(
        &mut self,
        uri: &SecretUri,
        version: Option<u64>,
    ) -> DecryptResult<Option<BrokerSecret>> {
        let entry = self
            .backend
            .get(uri, version)
            .map_err(|err| DecryptError::Crypto(err.to_string()))?;

        let Some(entry) = entry else {
            return Ok(None);
        };

        if entry.deleted {
            return Ok(None);
        }

        let record = match entry.record {
            Some(record) => record,
            None => return Ok(None),
        };

        let payload = self.crypto.decrypt_record(&record)?;
        Ok(Some(BrokerSecret {
            version: entry.version,
            meta: record.meta.clone(),
            payload,
        }))
    }

    /// List available secrets for a scope with optional category/name prefixes.
    pub fn list_secrets(
        &self,
        scope: &Scope,
        category_prefix: Option<&str>,
        name_prefix: Option<&str>,
    ) -> Result<Vec<SecretListItem>> {
        self.backend.list(scope, category_prefix, name_prefix)
    }

    /// Soft-delete a secret (tombstone).
    pub fn delete_secret(&self, uri: &SecretUri) -> Result<SecretVersion> {
        self.backend.delete(uri)
    }

    /// Fetch all versions known for a secret.
    pub fn versions(&self, uri: &SecretUri) -> Result<Vec<SecretVersion>> {
        self.backend.versions(uri)
    }

    /// Determine whether the latest revision of the secret exists.
    pub fn exists(&self, uri: &SecretUri) -> Result<bool> {
        self.backend.exists(uri)
    }

    /// Borrow the underlying backend reference.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Borrow the envelope service for custom workflows.
    pub fn crypto(&self) -> &EnvelopeService<P> {
        &self.crypto
    }

    /// Mutable access to the envelope service (mainly for tests).
    pub fn crypto_mut(&mut self) -> &mut EnvelopeService<P> {
        &mut self.crypto
    }
}

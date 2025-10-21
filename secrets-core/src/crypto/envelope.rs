use crate::crypto::dek_cache::{CacheKey, DekCache, DekMaterial};
use crate::errors::{DecryptError, DecryptResult, Error, Result};
use crate::key_provider::KeyProvider;
use crate::types::{EncryptionAlgorithm, Envelope, Scope, SecretMeta, SecretRecord};
#[allow(deprecated)]
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use std::env;

#[cfg(feature = "xchacha")]
use chacha20poly1305::{Nonce as XNonce, XChaCha20Poly1305};

const DEFAULT_DEK_LEN: usize = 32;
const HKDF_SALT_LEN: usize = 32;
const ENC_ALGO_ENV: &str = "SECRETS_ENC_ALGO";

/// High-level service responsible for encrypting and decrypting secret records.
pub struct EnvelopeService<P>
where
    P: KeyProvider,
{
    provider: P,
    cache: DekCache,
    algorithm: EncryptionAlgorithm,
}

impl<P> EnvelopeService<P>
where
    P: KeyProvider,
{
    /// Constructs a new service with the supplied components.
    pub fn new(provider: P, cache: DekCache, algorithm: EncryptionAlgorithm) -> Self {
        Self {
            provider,
            cache,
            algorithm,
        }
    }

    /// Builds a service using environment configuration and default cache parameters.
    pub fn from_env(provider: P) -> Result<Self> {
        let algorithm = env::var(ENC_ALGO_ENV)
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(|value| value.parse())
            .transpose()?
            .unwrap_or_default();

        Ok(Self::new(provider, DekCache::from_env(), algorithm))
    }

    /// Currently configured algorithm.
    pub fn algorithm(&self) -> EncryptionAlgorithm {
        self.algorithm
    }

    /// Borrow the underlying DEK cache.
    pub fn cache(&self) -> &DekCache {
        &self.cache
    }

    /// Mutable access to the DEK cache.
    pub fn cache_mut(&mut self) -> &mut DekCache {
        &mut self.cache
    }

    /// Encrypts plaintext into a [`SecretRecord`] using envelope encryption.
    pub fn encrypt_record(&mut self, meta: SecretMeta, plaintext: &[u8]) -> Result<SecretRecord> {
        let cache_key = CacheKey::from_meta(&meta);
        let scope = meta.scope().clone();
        let info = meta.uri.to_string();

        let (dek, wrapped) = self.obtain_dek(&cache_key, &scope)?;

        let salt = random_bytes(HKDF_SALT_LEN);
        let key = derive_key(&dek, &salt, info.as_bytes())?;
        let nonce = random_bytes(self.algorithm.nonce_len());
        let ciphertext = encrypt_with_algorithm(self.algorithm, &key, &nonce, plaintext)?;

        let envelope = Envelope {
            algorithm: self.algorithm,
            nonce,
            hkdf_salt: salt,
            wrapped_dek: wrapped.clone(),
        };

        Ok(SecretRecord::new(meta, ciphertext, envelope))
    }

    fn obtain_dek(&mut self, cache_key: &CacheKey, scope: &Scope) -> Result<(Vec<u8>, Vec<u8>)> {
        if let Some(material) = self.cache.get(cache_key) {
            return Ok((material.dek, material.wrapped));
        }

        let dek = generate_dek();
        let wrapped = self.provider.wrap_dek(scope, &dek)?;
        self.cache
            .insert(cache_key.clone(), dek.clone(), wrapped.clone());
        Ok((dek, wrapped))
    }

    /// Decrypts the ciphertext of a [`SecretRecord`].
    pub fn decrypt_record(&mut self, record: &SecretRecord) -> DecryptResult<Vec<u8>> {
        let cache_key = CacheKey::from_meta(&record.meta);
        let scope = record.meta.scope();
        let algorithm = record.envelope.algorithm;
        let info = record.meta.uri.to_string();

        let material = match self.cache.get(&cache_key) {
            Some(material) => material,
            None => {
                let dek = self
                    .provider
                    .unwrap_dek(scope, &record.envelope.wrapped_dek)
                    .map_err(|err| DecryptError::Provider(err.to_string()))?;
                let material = DekMaterial {
                    dek: dek.clone(),
                    wrapped: record.envelope.wrapped_dek.clone(),
                };
                self.cache.insert(
                    cache_key.clone(),
                    material.dek.clone(),
                    material.wrapped.clone(),
                );
                material
            }
        };

        let key = derive_key(&material.dek, &record.envelope.hkdf_salt, info.as_bytes())
            .map_err(|err| DecryptError::Crypto(err.to_string()))?;
        let plaintext =
            decrypt_with_algorithm(algorithm, &key, &record.envelope.nonce, &record.value)?;

        Ok(plaintext)
    }
}

#[allow(deprecated)]
fn encrypt_with_algorithm(
    algorithm: EncryptionAlgorithm,
    key: &[u8; 32],
    nonce: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    match algorithm {
        EncryptionAlgorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|_| Error::Crypto("invalid AES key".into()))?;
            let nonce = GenericArray::clone_from_slice(nonce);
            cipher
                .encrypt(&nonce, plaintext)
                .map_err(|_| Error::Crypto("failed to encrypt payload".into()))
        }
        EncryptionAlgorithm::XChaCha20Poly1305 => {
            #[cfg(feature = "xchacha")]
            {
                let cipher = XChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| Error::Crypto("invalid XChaCha key".into()))?;
                let nonce = XNonce::from_slice(nonce);
                cipher
                    .encrypt(nonce, plaintext)
                    .map_err(|_| Error::Crypto("failed to encrypt payload".into()))
            }
            #[cfg(not(feature = "xchacha"))]
            {
                Err(Error::AlgorithmFeatureUnavailable(
                    algorithm.as_str().to_string(),
                ))
            }
        }
    }
}

#[allow(deprecated)]
fn decrypt_with_algorithm(
    algorithm: EncryptionAlgorithm,
    key: &[u8; 32],
    nonce: &[u8],
    ciphertext: &[u8],
) -> DecryptResult<Vec<u8>> {
    match algorithm {
        EncryptionAlgorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|_| DecryptError::Crypto("invalid AES key".into()))?;
            let nonce = GenericArray::clone_from_slice(nonce);
            cipher
                .decrypt(&nonce, ciphertext)
                .map_err(|_| DecryptError::MacMismatch)
        }
        EncryptionAlgorithm::XChaCha20Poly1305 => {
            #[cfg(feature = "xchacha")]
            {
                let cipher = XChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| DecryptError::Crypto("invalid XChaCha key".into()))?;
                let nonce = XNonce::from_slice(nonce);
                cipher
                    .decrypt(nonce, ciphertext)
                    .map_err(|_| DecryptError::MacMismatch)
            }
            #[cfg(not(feature = "xchacha"))]
            {
                Err(DecryptError::Crypto(format!(
                    "algorithm {algorithm} unavailable"
                )))
            }
        }
    }
}

fn derive_key(dek: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), dek);
    let mut okm = [0u8; 32];
    hkdf.expand(info, &mut okm)
        .map_err(|_| Error::Crypto("failed to derive key material".into()))?;
    Ok(okm)
}

fn generate_dek() -> Vec<u8> {
    random_bytes(DEFAULT_DEK_LEN)
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut buffer = vec![0u8; len];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut buffer);
    buffer
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::dek_cache::DekCache;
    use crate::key_provider::KeyProvider;
    use crate::types::{ContentType, Scope, SecretMeta, Visibility};
    use crate::uri::SecretUri;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[derive(Clone)]
    struct DummyProvider {
        wrap_calls: Arc<Mutex<usize>>,
        unwrap_calls: Arc<Mutex<usize>>,
    }

    impl DummyProvider {
        fn new() -> Self {
            Self {
                wrap_calls: Arc::new(Mutex::new(0)),
                unwrap_calls: Arc::new(Mutex::new(0)),
            }
        }

        fn calls(&self) -> (usize, usize) {
            (
                *self.wrap_calls.lock().unwrap(),
                *self.unwrap_calls.lock().unwrap(),
            )
        }
    }

    impl KeyProvider for DummyProvider {
        fn wrap_dek(&self, _scope: &Scope, dek: &[u8]) -> Result<Vec<u8>> {
            *self.wrap_calls.lock().unwrap() += 1;
            Ok(dek.iter().map(|b| b ^ 0xAA).collect())
        }

        fn unwrap_dek(&self, _scope: &Scope, wrapped: &[u8]) -> Result<Vec<u8>> {
            *self.unwrap_calls.lock().unwrap() += 1;
            Ok(wrapped.iter().map(|b| b ^ 0xAA).collect())
        }
    }

    fn sample_meta(team: Option<&str>) -> SecretMeta {
        let scope = Scope::new(
            "prod".to_string(),
            "acme".to_string(),
            team.map(|t| t.to_string()),
        )
        .unwrap();
        let uri = SecretUri::new(scope.clone(), "kv", "api")
            .unwrap()
            .with_version(Some("v1"))
            .unwrap();
        SecretMeta::new(uri, Visibility::Team, ContentType::Opaque)
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let provider = DummyProvider::new();
        let cache = DekCache::new(8, Duration::from_secs(300));
        let mut service = EnvelopeService::new(provider, cache, EncryptionAlgorithm::Aes256Gcm);

        let meta = sample_meta(Some("payments"));
        let plaintext = b"super-secret-data";
        let record = service
            .encrypt_record(meta.clone(), plaintext)
            .expect("encrypt");

        let recovered = service.decrypt_record(&record).expect("decrypt");
        assert_eq!(plaintext.to_vec(), recovered);
        assert_eq!(record.meta, meta);
    }

    #[test]
    fn tamper_detection() {
        let provider = DummyProvider::new();
        let cache = DekCache::new(8, Duration::from_secs(300));
        let mut service = EnvelopeService::new(provider, cache, EncryptionAlgorithm::Aes256Gcm);
        let meta = sample_meta(Some("payments"));

        let mut record = service.encrypt_record(meta, b"critical").expect("encrypt");
        record.value[0] ^= 0xFF;

        let err = service.decrypt_record(&record).unwrap_err();
        assert!(matches!(err, DecryptError::MacMismatch));
    }

    #[test]
    fn cache_hit_and_miss_behavior() {
        let provider = DummyProvider::new();
        let cache = DekCache::new(8, Duration::from_secs(300));
        let mut service =
            EnvelopeService::new(provider.clone(), cache, EncryptionAlgorithm::Aes256Gcm);
        let meta = sample_meta(Some("payments"));
        let plaintext = b"payload";

        service
            .encrypt_record(meta.clone(), plaintext)
            .expect("encrypt");
        let (wrap_calls, _) = provider.calls();
        assert_eq!(wrap_calls, 1);

        service
            .encrypt_record(meta.clone(), plaintext)
            .expect("encrypt again");
        let (wrap_calls, _) = provider.calls();
        assert_eq!(wrap_calls, 1, "expected cache hit to avoid wrapping");

        // Force TTL expiry by rebuilding cache with zero TTL.
        let (wrap_calls_before, _) = provider.calls();
        let mut service = EnvelopeService::new(
            provider.clone(),
            DekCache::new(8, Duration::from_secs(0)),
            EncryptionAlgorithm::Aes256Gcm,
        );
        service
            .encrypt_record(meta, plaintext)
            .expect("encrypt with fresh cache");
        let (wrap_calls, _) = provider.calls();
        assert!(
            wrap_calls > wrap_calls_before,
            "expected miss to invoke wrap again"
        );
    }
}

#[cfg(any(feature = "crypto-ring", feature = "crypto-none"))]
use base64::{engine::general_purpose::STANDARD, Engine};
#[cfg(any(feature = "crypto-ring", feature = "crypto-none"))]
use greentic_secrets_spec::{SecretsError, SecretsResult};
#[cfg(feature = "crypto-ring")]
use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};

// Simple envelope helpers; adapt to your exact formats if you already have them.

#[cfg(feature = "crypto-ring")]
const NONCE_LEN: usize = 12;
#[cfg(feature = "crypto-ring")]
const TAG_LEN: usize = 16;

#[cfg(feature = "crypto-ring")]
pub fn seal_aead(key_bytes: &[u8], plaintext: &[u8]) -> SecretsResult<String> {
    let rng = SystemRandom::new();
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut nonce)
        .map_err(|e| SecretsError::Backend(format!("rng: {e:?}")))?;

    let key = aead::UnboundKey::new(&aead::AES_256_GCM, key_bytes)
        .map_err(|_| SecretsError::Backend("invalid key".into()))?;
    let key = aead::LessSafeKey::new(key);

    let mut in_out = plaintext.to_vec();
    in_out.reserve(TAG_LEN);
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::empty(),
        &mut in_out,
    )
    .map_err(|_| SecretsError::Backend("seal failed".into()))?;

    let mut out = Vec::with_capacity(12 + in_out.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&in_out);
    Ok(STANDARD.encode(out))
}

#[cfg(feature = "crypto-ring")]
pub fn open_aead(key_bytes: &[u8], b64: &str) -> SecretsResult<Vec<u8>> {
    let data = STANDARD
        .decode(b64)
        .map_err(|_| SecretsError::Invalid("ciphertext".into(), "b64".into()))?;
    if data.len() < NONCE_LEN {
        return Err(SecretsError::Invalid(
            "ciphertext".into(),
            "too short".into(),
        ));
    }
    let (nonce, ct) = data.split_at(NONCE_LEN);

    let key = aead::UnboundKey::new(&aead::AES_256_GCM, key_bytes)
        .map_err(|_| SecretsError::Backend("invalid key".into()))?;
    let key = aead::LessSafeKey::new(key);

    let mut buffer = ct.to_vec();
    let plaintext = key
        .open_in_place(
            aead::Nonce::try_assume_unique_for_key(nonce)
                .map_err(|_| SecretsError::Invalid("nonce".into(), "invalid length".into()))?,
            aead::Aad::empty(),
            &mut buffer,
        )
        .map_err(|_| SecretsError::Backend("open failed".into()))?;

    Ok(plaintext.to_vec())
}

#[cfg(all(feature = "crypto-none", not(feature = "crypto-ring")))]
pub fn seal_aead(_key_bytes: &[u8], plaintext: &[u8]) -> SecretsResult<String> {
    Ok(STANDARD.encode(plaintext))
}

#[cfg(all(feature = "crypto-none", not(feature = "crypto-ring")))]
pub fn open_aead(_key_bytes: &[u8], b64: &str) -> SecretsResult<Vec<u8>> {
    STANDARD
        .decode(b64)
        .map_err(|_| SecretsError::Invalid("ciphertext".into(), "b64".into()))
}

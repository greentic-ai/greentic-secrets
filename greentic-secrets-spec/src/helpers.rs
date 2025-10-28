use crate::{
    ContentType, EncryptionAlgorithm, Envelope, Scope, SecretMeta, SecretRecord, SecretUri,
    Visibility,
};
use time::{Duration, OffsetDateTime};

const DEFAULT_ENV: &str = "local";
const DEFAULT_TENANT: &str = "default";
const DEFAULT_CATEGORY: &str = "support";
const DEFAULT_NAME: &str = "placeholder";

pub fn record_from_plain<S: Into<String>>(value: S) -> SecretRecord {
    record_from_bytes(value.into().into_bytes())
}

pub fn default_meta() -> SecretMeta {
    let uri = default_uri();
    let mut meta = SecretMeta::new(uri, Visibility::Team, ContentType::Opaque);
    stamp_created(&mut meta);
    meta
}

pub fn with_ttl(mut record: SecretRecord, seconds: i64) -> SecretRecord {
    let ttl = Duration::seconds(seconds);
    record
        .meta
        .set_tag("ttl_seconds", ttl.whole_seconds().to_string());
    stamp_updated(&mut record.meta);
    record
}

pub fn record_from_bytes(bytes: Vec<u8>) -> SecretRecord {
    SecretRecord::new(default_meta(), bytes, default_envelope())
}

pub fn default_uri() -> SecretUri {
    let scope = Scope::new(DEFAULT_ENV, DEFAULT_TENANT, None)
        .expect("default scope for greentic-secrets-spec helpers");
    SecretUri::new(scope, DEFAULT_CATEGORY, DEFAULT_NAME)
        .expect("default uri for greentic-secrets-spec helpers")
}

pub fn default_envelope() -> Envelope {
    Envelope {
        algorithm: EncryptionAlgorithm::default(),
        nonce: Vec::new(),
        hkdf_salt: Vec::new(),
        wrapped_dek: Vec::new(),
    }
}

pub fn stamp_created(meta: &mut SecretMeta) {
    let timestamp = OffsetDateTime::now_utc().unix_timestamp();
    meta.set_tag("created_at", timestamp.to_string());
    meta.set_tag("updated_at", timestamp.to_string());
}

pub fn stamp_updated(meta: &mut SecretMeta) {
    let timestamp = OffsetDateTime::now_utc().unix_timestamp();
    meta.set_tag("updated_at", timestamp.to_string());
}

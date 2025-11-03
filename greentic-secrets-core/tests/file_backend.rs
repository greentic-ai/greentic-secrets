#![cfg(feature = "file")]

use greentic_secrets_spec::{record_from_plain, with_ttl};
use secrets_core::SecretUri;
use secrets_core::SecretsBackend;
use secrets_core::backend::file::FileBackend;
use secrets_core::types::{ContentType, Envelope, SecretMeta, SecretRecord, Visibility};
use serde_json::json;
use tempfile::tempdir;

fn record(uri: &SecretUri) -> SecretRecord {
    let mut record = record_from_plain(json!({"status": "ok"}).to_string());
    let mut meta = SecretMeta::new(uri.clone(), Visibility::Team, ContentType::Json);
    meta.description = Some("file backend".into());
    record.meta = meta;
    record.envelope = Envelope {
        algorithm: secrets_core::types::EncryptionAlgorithm::Aes256Gcm,
        nonce: vec![1, 2, 3],
        hkdf_salt: vec![4, 5, 6],
        wrapped_dek: vec![7, 8, 9],
    };
    with_ttl(record, 600)
}

#[test]
fn file_backend_round_trip() {
    let dir = tempdir().unwrap();
    let backend = FileBackend::new(dir.path());
    let uri = SecretUri::try_from("secrets://dev/example/_/configs/app").unwrap();
    backend.put(record(&uri)).unwrap();

    let fetched = backend.get(&uri, None).unwrap().unwrap();
    assert_eq!(fetched.record.unwrap().meta.uri, uri);

    let scope = secrets_core::Scope::new("dev", "example", None).unwrap();
    let items = backend.list(&scope, Some("configs"), None).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].uri, uri);
}

use secrets_core::backend::env::EnvBackend;
use secrets_core::types::{ContentType, Envelope, SecretMeta, SecretRecord, Visibility};
use secrets_core::SecretUri;
use secrets_core::SecretsBackend;
use serde_json::json;

fn build_record(uri: &SecretUri) -> SecretRecord {
    let mut meta = SecretMeta::new(uri.clone(), Visibility::Team, ContentType::Json);
    meta.description = Some("env backend".into());
    let envelope = Envelope {
        algorithm: secrets_core::types::EncryptionAlgorithm::Aes256Gcm,
        nonce: vec![1, 2, 3],
        hkdf_salt: vec![4, 5, 6],
        wrapped_dek: vec![7, 8, 9],
    };
    SecretRecord::new(
        meta,
        json!({"value": "env"}).to_string().into_bytes(),
        envelope,
    )
}

fn var_name(uri: &SecretUri) -> String {
    format!(
        "GTSEC_{}_{}_{}_{}_{}",
        sanitize(uri.scope().env()),
        sanitize(uri.scope().tenant()),
        uri.scope()
            .team()
            .map(sanitize)
            .unwrap_or_else(|| "_".to_string()),
        sanitize(uri.category()),
        sanitize(uri.name())
    )
}

fn sanitize(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' => c.to_ascii_uppercase(),
            _ => '_',
        })
        .collect()
}

#[test]
fn env_backend_fetches_from_variable() {
    let backend = EnvBackend::new();
    let uri = SecretUri::try_from("secrets://dev/example/_/configs/app").unwrap();
    let record = build_record(&uri);
    let var = var_name(&uri);
    std::env::set_var(&var, serde_json::to_string(&record).unwrap());

    let fetched = backend.get(&uri, None).unwrap().unwrap();
    assert_eq!(fetched.record.unwrap().meta.uri, record.meta.uri);
}

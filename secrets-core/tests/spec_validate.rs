use secrets_core::embedded::SecretsCore;
use secrets_core::{SecretDescribable, SecretSpec};
use serde_json::json;
use std::time::Duration;

struct Demo;

impl SecretDescribable for Demo {
    fn secret_specs() -> &'static [SecretSpec] {
        &[
            SecretSpec {
                name: "alpha",
                description: None,
            },
            SecretSpec {
                name: "beta",
                description: None,
            },
        ]
    }
}

async fn build_core() -> SecretsCore {
    std::env::set_var("GREENTIC_SECRETS_DEV", "1");
    SecretsCore::builder()
        .tenant("example-tenant")
        .default_ttl(Duration::from_secs(10))
        .build()
        .await
        .unwrap()
}

#[tokio::test]
async fn validation_reports_missing_and_present() {
    let core = build_core().await;
    let base = "secrets://dev/example-tenant/_/";

    core.put_json(&format!("{base}configs/alpha"), &json!({"value": "alpha"}))
        .await
        .unwrap();

    let result = core
        .validate_specs_at_prefix(base, Demo::secret_specs())
        .await
        .unwrap();

    assert_eq!(result.present, vec!["alpha"]);
    assert_eq!(result.missing, vec!["beta"]);
}

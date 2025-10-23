use secrets_core::embedded::SecretsCore;
use serde_json::json;
use std::time::Duration;

#[tokio::test]
async fn put_and_get_json_helpers() {
    std::env::set_var("GREENTIC_SECRETS_DEV", "1");
    let core = SecretsCore::builder()
        .tenant("example-tenant")
        .default_ttl(Duration::from_secs(60))
        .build()
        .await
        .unwrap();

    let uri = "secrets://dev/example-tenant/_/configs/helpers";
    core.put_json(uri, &json!({"enabled": true})).await.unwrap();

    let value: serde_json::Value = core.get_json(uri).await.unwrap();
    assert_eq!(value["enabled"], true);
}

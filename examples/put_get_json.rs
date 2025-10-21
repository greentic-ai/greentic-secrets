use secrets_sdk::{helpers, HttpClient, Scope, Visibility};
use serde_json::json;
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let base_url = std::env::var("SECRETS_BROKER_HTTP")
        .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
    let token = std::env::var("SECRETS_BROKER_TOKEN").ok();

    let client = if let Some(token) = token {
        HttpClient::new(&base_url)?.with_token(token)
    } else {
        HttpClient::new(&base_url)?
    };

    let tenant = std::env::var("SECRETS_EXAMPLE_TENANT")
        .unwrap_or_else(|_| format!("examples-{}", Uuid::new_v4().simple()));
    let scope = Scope::new("dev".to_string(), tenant, None)?;

    let category = "configs";
    let name = "demo-json";

    let payload = json!({
        "feature": "put_get_json",
        "enabled": true,
        "limit": 42
    });

    let stored = helpers::put_json(
        &client,
        &scope,
        category,
        name,
        &payload,
        Visibility::Tenant,
        Some("SDK JSON example"),
    )
    .await?;

    println!("stored version {}", stored.version);

    let fetched: serde_json::Value = helpers::get_json(&client, &scope, category, name, None)
        .await?
        .expect("secret must exist after put");

    println!("fetched secret: {fetched}");
    Ok(())
}

use secrets_sdk::{helpers, HttpClient, NatsClient, Scope, Visibility};
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let http_base = std::env::var("SECRETS_BROKER_HTTP")
        .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
    let nats_url = std::env::var("SECRETS_BROKER_NATS")
        .unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());
    let token = std::env::var("SECRETS_BROKER_TOKEN").ok();

    let http_client = if let Some(token) = token.clone() {
        HttpClient::new(&http_base)?.with_token(token)
    } else {
        HttpClient::new(&http_base)?
    };

    let raw_client = async_nats::connect(&nats_url).await?;
    let nats_client = if let Some(token) = token.clone() {
        NatsClient::new(raw_client).with_token(token)
    } else {
        NatsClient::new(raw_client)
    };

    let tenant = std::env::var("SECRETS_EXAMPLE_TENANT").unwrap_or_else(|_| {
        let id = Uuid::new_v4().simple();
        format!("rotate-{id}")
    });
    let scope = Scope::new("dev".to_string(), tenant, Some("examples".into()))?;

    let stored = helpers::put_text(
        &http_client,
        &scope,
        "runtime",
        "rotate-demo",
        "initial",
        Visibility::Team,
        Some("rotation example"),
    )
    .await?;
    println!("stored version {}", stored.version);

    let summary = nats_client.rotate_category(&scope, "runtime", None).await?;
    println!(
        "rotation job {} rotated {} secrets",
        summary.job_id, summary.rotated
    );

    let latest = http_client
        .get_secret(&scope, "runtime", "rotate-demo", None)
        .await?
        .expect("secret must exist after rotation");
    println!("latest version {}", latest.version);

    Ok(())
}

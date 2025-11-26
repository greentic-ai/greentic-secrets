use greentic_types::{EnvId, TenantCtx, TenantId};
use secrets_core::{
    SecretsCore, events_provider_secret_uri, get_events_provider_secret,
    get_messaging_adapter_secret, messaging_adapter_secret_uri,
};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tenant = TenantCtx::new(EnvId::try_from("dev")?, TenantId::try_from("acme")?);

    // Build a core with the default in-memory backend (enabled via GREENTIC_SECRETS_DEV=1).
    let core = SecretsCore::builder().tenant("acme").build().await?;

    // Write provider and adapter secrets using the canonical URIs.
    let events_uri = events_provider_secret_uri(&tenant, "nats-core")?;
    core.put_json(&events_uri.to_string(), &json!({ "token": "abc123" }))
        .await?;

    let messaging_uri = messaging_adapter_secret_uri(&tenant, "teams-main")?;
    core.put_json(&messaging_uri.to_string(), &json!({ "api_key": "xyz" }))
        .await?;

    // Fetch them via the helpers (returns payload + metadata).
    let events_secret = get_events_provider_secret(&core, &tenant, "nats-core").await?;
    let messaging_secret = get_messaging_adapter_secret(&core, &tenant, "teams-main").await?;

    println!(
        "events payload: {}",
        String::from_utf8_lossy(&events_secret.payload)
    );
    println!(
        "messaging payload: {}",
        String::from_utf8_lossy(&messaging_secret.payload)
    );

    Ok(())
}

use secrets_core::SecretsCore;
use serde_json::json;
use std::process;
use std::time::Duration;

#[greentic_types::telemetry::main(service_name = "greentic-secrets-core-embedded")]
async fn main() {
    if let Err(err) = run_example().await {
        eprintln!("embedded example failed: {err:#}");
        process::exit(1);
    }
}

async fn run_example() -> anyhow::Result<()> {
    let core = SecretsCore::builder()
        .tenant("example-tenant")
        .default_ttl(Duration::from_secs(600))
        .build()
        .await?;

    if let Ok(password) = core
        .get_text("secrets://dev/example-tenant/_/configs/db_password")
        .await
    {
        // Avoid logging the secret value; report success with metadata only.
        println!("db_password retrieved (len={} chars)", password.len());
    } else {
        println!("db_password secret not found");
    }

    let cfg: serde_json::Value = core
        .get_json("secrets://dev/example-tenant/_/configs/app_cfg")
        .await
        .unwrap_or_else(|_| json!({ "status": "missing" }));
    println!("app_cfg: {cfg}");

    Ok(())
}

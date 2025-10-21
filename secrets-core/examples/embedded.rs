use secrets_core::SecretsCore;
use serde_json::json;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let core = SecretsCore::builder()
        .tenant("example-tenant")
        .default_ttl(Duration::from_secs(600))
        .build()
        .await?;

    if let Ok(password) = core
        .get_text("secrets://dev/example-tenant/_/configs/db_password")
        .await
    {
        println!("db_password: {password}");
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

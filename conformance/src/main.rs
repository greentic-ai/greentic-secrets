use anyhow::Result;
use greentic_types::telemetry;
use std::process;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    telemetry::install_telemetry("greentic-secrets-conformance")?;
    if let Err(err) = greentic_secrets_conformance::run().await {
        eprintln!("conformance suite failed: {err:#}");
        process::exit(1);
    }
    Ok(())
}

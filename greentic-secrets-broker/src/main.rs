use std::process;

#[greentic_types::telemetry::main(service_name = "greentic-secrets-broker")]
async fn main() {
    if let Err(err) = real_main().await {
        eprintln!("broker exited with error: {err:#}");
        process::exit(1);
    }
}

async fn real_main() -> anyhow::Result<()> {
    secrets_broker::run().await
}

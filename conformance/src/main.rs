use std::process;

#[greentic_types::telemetry::main(service_name = "greentic-secrets-conformance")]
async fn main() {
    if let Err(err) = greentic_secrets_conformance::run().await {
        eprintln!("conformance suite failed: {err:#}");
        process::exit(1);
    }
}

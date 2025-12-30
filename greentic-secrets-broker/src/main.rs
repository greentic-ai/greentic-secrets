use clap::Parser;
use greentic_config::{CliOverrides as ConfigOverrides, ConfigResolver};
use greentic_config_types::SecretsBackendRefConfig;
use greentic_types::EnvId;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process;

#[derive(Parser)]
struct BrokerArgs {
    /// Override config file path
    #[arg(long)]
    config: Option<PathBuf>,
    /// Override environment id
    #[arg(long)]
    env: Option<String>,
    /// Override bind address
    #[arg(long)]
    bind: Option<String>,
    /// Override NATS URL
    #[arg(long)]
    nats_url: Option<String>,
    /// Verbose output
    #[arg(long)]
    verbose: bool,
}

#[greentic_types::telemetry::main(service_name = "greentic-secrets-broker")]
async fn main() {
    if let Err(err) = real_main().await {
        eprintln!("broker exited with error: {err:#}");
        process::exit(1);
    }
}

async fn real_main() -> anyhow::Result<()> {
    let args = BrokerArgs::parse();
    let mut overrides = ConfigOverrides::new();
    if let Some(env) = args
        .env
        .as_deref()
        .and_then(|value| EnvId::try_from(value).ok())
    {
        overrides = overrides.with_env_id(env);
    }
    let mut resolver = ConfigResolver::new();
    if let Some(path) = args.config.clone() {
        resolver = resolver.with_config_path(path);
    }
    let resolved = resolver.with_cli_overrides_typed(overrides).load()?;
    if args.verbose {
        println!(
            "config loaded (root={}, state_dir={}, sources={:?})",
            resolved.config.paths.greentic_root.display(),
            resolved.config.paths.state_dir.display(),
            resolved.provenance
        );
        for warning in &resolved.warnings {
            eprintln!("warning: {warning}");
        }
    }

    let runtime_config = broker_runtime_config(&resolved, &args);
    secrets_broker::run(runtime_config).await
}

fn broker_runtime_config(
    resolved: &greentic_config::ResolvedConfig,
    args: &BrokerArgs,
) -> secrets_broker::BrokerRuntimeConfig {
    let bind = args
        .bind
        .clone()
        .or_else(|| std::env::var("BROKER__BIND_ADDRESS").ok())
        .unwrap_or_else(|| "0.0.0.0:8080".into());
    let nats_url = args
        .nats_url
        .clone()
        .or_else(|| std::env::var("BROKER__NATS_URL").ok());
    let secrets = SecretsBackendRefConfig {
        kind: std::env::var("SECRETS_BACKEND")
            .ok()
            .unwrap_or_else(|| resolved.config.secrets.kind.clone()),
        reference: resolved.config.secrets.reference.clone(),
    };
    let http_addr = bind
        .parse()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 8080)));

    secrets_broker::BrokerRuntimeConfig {
        http_addr,
        nats_url,
        network: resolved.config.network.clone(),
        telemetry: resolved.config.telemetry.clone(),
        paths: resolved.config.paths.clone(),
        secrets,
    }
}

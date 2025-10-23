pub mod auth;
pub mod config;
pub mod error;
pub mod http;
pub mod models;
pub mod nats;
pub mod path;
pub mod rotate;
pub mod state;
pub mod telemetry;
pub mod wit;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use auth::Authorizer;
use secrets_core::crypto::dek_cache::DekCache;
use secrets_core::crypto::envelope::EnvelopeService;
use secrets_core::types::EncryptionAlgorithm;
use secrets_core::SecretsBroker;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{info, warn};

pub use state::AppState;
pub use telemetry::CorrelationId;

pub async fn run() -> anyhow::Result<()> {
    telemetry::init()?;

    let config = BrokerConfig::from_env();
    let state = build_state().await?;

    let http_listener = TcpListener::bind(config.http_addr)
        .await
        .with_context(|| format!("failed to bind http listener on {}", config.http_addr))?;

    let http_addr = http_listener.local_addr()?;
    info!(%http_addr, "http server listening");

    let http_router = http::router(state.clone());
    let http_server = tokio::spawn(async move {
        axum::serve(http_listener, http_router)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .map_err(anyhow::Error::from)
    });

    let maybe_nats = if let Some(url) = &config.nats_url {
        info!(nats_url = %url, "connecting to nats");
        let client = async_nats::connect(url)
            .await
            .with_context(|| "failed to connect to nats")?;
        Some(tokio::spawn(nats::run(client, state.clone())))
    } else {
        warn!("nats disabled; BROKER__NATS_URL not set");
        None
    };

    if let Some(nats_task) = maybe_nats {
        let (http_result, nats_result) = tokio::try_join!(http_server, nats_task)?;
        http_result?;
        nats_result?;
    } else {
        http_server.await??;
    }

    Ok(())
}

#[derive(Clone)]
pub struct BrokerConfig {
    pub http_addr: SocketAddr,
    pub nats_url: Option<String>,
}

impl BrokerConfig {
    pub fn from_env() -> Self {
        let bind = std::env::var("BROKER__BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0:8080".into());
        let nats_url = std::env::var("BROKER__NATS_URL").ok();
        let http_addr = bind
            .parse()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 8080)));
        Self {
            http_addr,
            nats_url,
        }
    }
}

pub async fn build_state() -> anyhow::Result<AppState> {
    let authorizer = Authorizer::from_env().await?;
    let components = config::load_backend_components().await?;
    let crypto = EnvelopeService::new(
        components.key_provider,
        DekCache::from_env(),
        EncryptionAlgorithm::Aes256Gcm,
    );
    let broker = SecretsBroker::new(components.backend, crypto);
    Ok(AppState::new(
        Arc::new(Mutex::new(broker)),
        Arc::new(authorizer),
    ))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            warn!(?err, "failed to install ctrl-c handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(err) => warn!(?err, "failed to install sigterm handler"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

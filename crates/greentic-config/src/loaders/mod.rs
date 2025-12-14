use crate::GreenticConfigLayer;
use crate::paths::{project_config_path, user_config_path};
use anyhow::{Context, Result};
use greentic_types::{ConnectionKind, DeploymentCtx, EnvId};
use std::fs;
use std::path::{Path, PathBuf};

pub fn load_user_layer() -> Result<Option<GreenticConfigLayer>> {
    if let Some(path) = user_config_path() {
        if path.exists() {
            load_from_file(&path).map(Some)
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}

pub fn load_project_layer(
    root: &Path,
    override_path: Option<&PathBuf>,
) -> Result<Option<GreenticConfigLayer>> {
    if let Some(path) = override_path {
        return load_from_file(path).map(Some);
    }
    let path = project_config_path(root);
    if path.exists() {
        load_from_file(&path).map(Some)
    } else {
        Ok(None)
    }
}

pub fn load_from_file(path: &Path) -> Result<GreenticConfigLayer> {
    let data = fs::read_to_string(path)
        .with_context(|| format!("failed to read config {}", path.display()))?;
    parse_config(&data, path)
}

fn parse_config(data: &str, path: &Path) -> Result<GreenticConfigLayer> {
    if path.extension().map(|ext| ext == "json").unwrap_or(false) {
        let layer: GreenticConfigLayer = serde_json::from_str(data)
            .with_context(|| format!("invalid json config {}", path.display()))?;
        Ok(layer)
    } else {
        let layer: GreenticConfigLayer = toml::from_str(data)
            .with_context(|| format!("invalid toml config {}", path.display()))?;
        Ok(layer)
    }
}

pub fn env_layer() -> GreenticConfigLayer {
    let mut layer = GreenticConfigLayer::default();

    if let Ok(value) = std::env::var("GREENTIC_ENV") {
        if let Ok(parsed) = EnvId::try_from(value.as_str()) {
            layer
                .environment
                .get_or_insert_with(Default::default)
                .env_id = Some(parsed);
        }
    }
    if let Ok(value) = std::env::var("GREENTIC_DEPLOYMENT") {
        if let Ok(parsed) = serde_json::from_str::<DeploymentCtx>(&format!("\"{value}\"")) {
            layer
                .environment
                .get_or_insert_with(Default::default)
                .deployment = Some(parsed);
        }
    }
    if let Ok(value) = std::env::var("GREENTIC_CONNECTION") {
        if let Ok(parsed) = serde_json::from_str::<ConnectionKind>(&format!("\"{value}\"")) {
            layer
                .environment
                .get_or_insert_with(Default::default)
                .connection = Some(parsed);
        }
    }
    if let Ok(value) = std::env::var("GREENTIC_REGION") {
        layer
            .environment
            .get_or_insert_with(Default::default)
            .region = Some(value);
    }

    if let Ok(value) = std::env::var("GREENTIC_ROOT") {
        layer
            .paths
            .get_or_insert_with(Default::default)
            .greentic_root = Some(PathBuf::from(value));
    }
    if let Ok(value) = std::env::var("GREENTIC_STATE_DIR") {
        layer.paths.get_or_insert_with(Default::default).state_dir = Some(PathBuf::from(value));
    }
    if let Ok(value) = std::env::var("GREENTIC_CACHE_DIR") {
        layer.paths.get_or_insert_with(Default::default).cache_dir = Some(PathBuf::from(value));
    }
    if let Ok(value) = std::env::var("GREENTIC_LOGS_DIR") {
        layer.paths.get_or_insert_with(Default::default).logs_dir = Some(PathBuf::from(value));
    }

    if let Ok(value) = std::env::var("GREENTIC_MAX_CONCURRENCY") {
        if let Ok(parsed) = value.parse::<usize>() {
            layer
                .runtime
                .get_or_insert_with(Default::default)
                .max_concurrency = Some(parsed);
        }
    }
    if let Ok(value) = std::env::var("GREENTIC_REQUEST_TIMEOUT_MS") {
        if let Ok(parsed) = value.parse::<u64>() {
            layer
                .runtime
                .get_or_insert_with(Default::default)
                .request_timeout_ms = Some(parsed);
        }
    }
    if let Ok(value) = std::env::var("GREENTIC_IDLE_TIMEOUT_MS") {
        if let Ok(parsed) = value.parse::<u64>() {
            layer
                .runtime
                .get_or_insert_with(Default::default)
                .idle_timeout_ms = Some(parsed);
        }
    }

    if let Ok(value) = std::env::var("GREENTIC_TELEMETRY_ENABLED") {
        if let Ok(parsed) = value.parse::<bool>() {
            layer.telemetry.get_or_insert_with(Default::default).enabled = Some(parsed);
        }
    }
    if let Ok(value) = std::env::var("GREENTIC_TELEMETRY_EXPORTER") {
        layer
            .telemetry
            .get_or_insert_with(Default::default)
            .exporter = Some(value);
    }
    if let Ok(value) = std::env::var("GREENTIC_TELEMETRY_ENDPOINT") {
        layer
            .telemetry
            .get_or_insert_with(Default::default)
            .endpoint = Some(value);
    }
    if let Ok(value) = std::env::var("GREENTIC_TELEMETRY_SAMPLING") {
        if let Ok(parsed) = value.parse::<f64>() {
            layer
                .telemetry
                .get_or_insert_with(Default::default)
                .sampling = Some(parsed);
        }
    }

    if let Ok(value) = std::env::var("GREENTIC_PROXY") {
        layer.network.get_or_insert_with(Default::default).proxy = Some(value);
    }
    if let Ok(value) = std::env::var("GREENTIC_NO_PROXY") {
        layer.network.get_or_insert_with(Default::default).no_proxy = Some(value);
    }
    if let Ok(value) = std::env::var("GREENTIC_TLS_INSECURE") {
        if value == "1" || value.eq_ignore_ascii_case("true") {
            layer.network.get_or_insert_with(Default::default).tls_mode =
                Some("insecure_skip_verify".into());
        }
    }
    if let Ok(value) = std::env::var("GREENTIC_CONNECT_TIMEOUT_MS") {
        if let Ok(parsed) = value.parse::<u64>() {
            layer
                .network
                .get_or_insert_with(Default::default)
                .connect_timeout_ms = Some(parsed);
        }
    }
    if let Ok(value) = std::env::var("GREENTIC_NETWORK_TIMEOUT_MS") {
        if let Ok(parsed) = value.parse::<u64>() {
            layer
                .network
                .get_or_insert_with(Default::default)
                .request_timeout_ms = Some(parsed);
        }
    }
    if let Ok(value) = std::env::var("GREENTIC_OFFLINE") {
        if let Ok(parsed) = value.parse::<bool>() {
            layer.network.get_or_insert_with(Default::default).offline = Some(parsed);
        }
    }

    if let Ok(value) = std::env::var("GREENTIC_SECRETS_BACKEND") {
        layer.secrets.get_or_insert_with(Default::default).kind = Some(value);
    }
    if let Ok(value) = std::env::var("GREENTIC_SECRETS_PROFILE") {
        layer.secrets.get_or_insert_with(Default::default).profile = Some(value);
    }
    if let Ok(value) = std::env::var("GREENTIC_SECRETS_ENDPOINT") {
        layer.secrets.get_or_insert_with(Default::default).endpoint = Some(value);
    }

    if let Ok(value) = std::env::var("GREENTIC_DEV_ENV") {
        layer.dev.get_or_insert_with(Default::default).default_env = Some(value);
    }
    if let Ok(value) = std::env::var("GREENTIC_DEV_TENANT") {
        layer
            .dev
            .get_or_insert_with(Default::default)
            .default_tenant = Some(value);
    }
    if let Ok(value) = std::env::var("GREENTIC_DEV_TEAM") {
        layer.dev.get_or_insert_with(Default::default).default_team = Some(value);
    }

    layer
}

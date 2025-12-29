use greentic_config_types::{GreenticConfig, TelemetryExporter, TlsMode};
use std::env;

pub fn validate(cfg: &GreenticConfig) -> Vec<String> {
    let mut warnings = Vec::new();
    let env_id = cfg.environment.env_id.to_string();
    let is_dev = env_id == "dev";

    if cfg.network.offline && cfg.secrets.endpoint.is_some() {
        warnings.push("offline=true but secrets endpoint is configured; requests may fail".into());
    }
    if cfg.network.offline && cfg.secrets.kind != "dev" {
        warnings
            .push("offline=true with non-dev secrets backend; remote calls will be blocked".into());
    }
    if matches!(cfg.network.tls.mode, TlsMode::InsecureSkipVerify) && !is_dev {
        warnings.push("tls.insecure_skip_verify is enabled outside dev".into());
    }
    if cfg.network.offline {
        if matches!(cfg.telemetry.exporter, Some(TelemetryExporter::Otlp)) {
            warnings.push("telemetry exporter set to OTLP while offline=true".into());
        }
        if cfg.network.proxy.is_some() {
            warnings.push("proxy configured while offline=true (proxy unused)".into());
        }
    }
    if let Some(timeout) = cfg.runtime.request_timeout_ms
        && timeout > 0
        && timeout < 100
    {
        warnings.push(format!("request_timeout_ms={timeout}ms is very low"));
    }
    if let Some(timeout) = cfg.network.request_timeout_ms
        && timeout > 0
        && timeout < 100
    {
        warnings.push(format!(
            "network.request_timeout_ms={timeout}ms is very low"
        ));
    }

    let temp_dir = env::temp_dir();
    if !is_dev
        && (cfg.paths.state_dir.starts_with(&temp_dir)
            || cfg.paths.cache_dir.starts_with(&temp_dir))
    {
        warnings.push("state/cache directories resolved under temp dir outside dev".into());
    }

    warnings
}

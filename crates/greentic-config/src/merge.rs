use crate::{
    DevLayer, EnvironmentLayer, GreenticConfigLayer, NetworkLayer, PathsLayer, ProvenanceMap,
    RuntimeLayer, SecretsLayer, TelemetryLayer,
};
use anyhow::{Context, Result};
use greentic_config_types::{ConfigSource, GreenticConfig, TelemetryExporter, TlsMode};
use greentic_types::EnvId;

pub fn apply_layer(
    config: &mut GreenticConfig,
    layer: GreenticConfigLayer,
    source: ConfigSource,
    provenance: &mut ProvenanceMap,
) -> Result<()> {
    if let Some(version) = layer.schema_version {
        config.schema_version = version;
        provenance.insert("schema_version".into(), source.clone());
    }

    if let Some(env) = layer.environment {
        apply_environment(&mut config.environment, env, &source, provenance)?;
    }
    if let Some(paths) = layer.paths {
        apply_paths(&mut config.paths, paths, &source, provenance);
    }
    if let Some(runtime) = layer.runtime {
        apply_runtime(&mut config.runtime, runtime, &source, provenance);
    }
    if let Some(telemetry) = layer.telemetry {
        apply_telemetry(&mut config.telemetry, telemetry, &source, provenance)?;
    }
    if let Some(network) = layer.network {
        apply_network(&mut config.network, network, &source, provenance)?;
    }
    if let Some(secrets) = layer.secrets {
        apply_secrets(&mut config.secrets, secrets, &source, provenance);
    }
    if let Some(dev) = layer.dev {
        apply_dev(&mut config.dev, dev, &source, provenance)?;
    }

    Ok(())
}

fn apply_environment(
    target: &mut greentic_config_types::EnvironmentConfig,
    layer: EnvironmentLayer,
    source: &ConfigSource,
    provenance: &mut ProvenanceMap,
) -> Result<()> {
    if let Some(value) = layer.env_id {
        target.env_id = value;
        provenance.insert("environment.env_id".into(), source.clone());
    }
    if let Some(value) = layer.deployment {
        target.deployment = Some(value);
        provenance.insert("environment.deployment".into(), source.clone());
    }
    if let Some(value) = layer.connection {
        target.connection = Some(value);
        provenance.insert("environment.connection".into(), source.clone());
    }
    if let Some(value) = layer.region {
        target.region = Some(value);
        provenance.insert("environment.region".into(), source.clone());
    }
    Ok(())
}

fn apply_paths(
    target: &mut greentic_config_types::PathsConfig,
    layer: PathsLayer,
    source: &ConfigSource,
    provenance: &mut ProvenanceMap,
) {
    if let Some(value) = layer.greentic_root {
        target.greentic_root = value;
        provenance.insert("paths.greentic_root".into(), source.clone());
    }
    if let Some(value) = layer.state_dir {
        target.state_dir = value;
        provenance.insert("paths.state_dir".into(), source.clone());
    }
    if let Some(value) = layer.cache_dir {
        target.cache_dir = value;
        provenance.insert("paths.cache_dir".into(), source.clone());
    }
    if let Some(value) = layer.logs_dir {
        target.logs_dir = value;
        provenance.insert("paths.logs_dir".into(), source.clone());
    }
}

fn apply_runtime(
    target: &mut greentic_config_types::RuntimeConfig,
    layer: RuntimeLayer,
    source: &ConfigSource,
    provenance: &mut ProvenanceMap,
) {
    if let Some(value) = layer.max_concurrency {
        target.max_concurrency = Some(value);
        provenance.insert("runtime.max_concurrency".into(), source.clone());
    }
    if let Some(value) = layer.request_timeout_ms {
        target.request_timeout_ms = Some(value);
        provenance.insert("runtime.request_timeout_ms".into(), source.clone());
    }
    if let Some(value) = layer.idle_timeout_ms {
        target.idle_timeout_ms = Some(value);
        provenance.insert("runtime.idle_timeout_ms".into(), source.clone());
    }
}

fn apply_telemetry(
    target: &mut greentic_config_types::TelemetryConfig,
    layer: TelemetryLayer,
    source: &ConfigSource,
    provenance: &mut ProvenanceMap,
) -> Result<()> {
    if let Some(value) = layer.enabled {
        target.enabled = value;
        provenance.insert("telemetry.enabled".into(), source.clone());
    }
    if let Some(value) = layer.exporter {
        let exporter = match value.to_lowercase().as_str() {
            "otlp" => TelemetryExporter::Otlp,
            "stdout" => TelemetryExporter::Stdout,
            "stderr" => TelemetryExporter::Stderr,
            "none" => TelemetryExporter::None,
            other => {
                return Err(anyhow::anyhow!("unknown telemetry exporter `{other}`"));
            }
        };
        target.exporter = Some(exporter);
        provenance.insert("telemetry.exporter".into(), source.clone());
    }
    if let Some(value) = layer.endpoint {
        target.endpoint = Some(value);
        provenance.insert("telemetry.endpoint".into(), source.clone());
    }
    if let Some(value) = layer.sampling {
        target.sampling = Some(value);
        provenance.insert("telemetry.sampling".into(), source.clone());
    }
    Ok(())
}

fn apply_network(
    target: &mut greentic_config_types::NetworkConfig,
    layer: NetworkLayer,
    source: &ConfigSource,
    provenance: &mut ProvenanceMap,
) -> Result<()> {
    if let Some(value) = layer.proxy {
        target.proxy = Some(value);
        provenance.insert("network.proxy".into(), source.clone());
    }
    if let Some(value) = layer.no_proxy {
        target.no_proxy = Some(value);
        provenance.insert("network.no_proxy".into(), source.clone());
    }
    if let Some(value) = layer.tls_mode {
        let mode = match value.to_lowercase().as_str() {
            "system" => TlsMode::System,
            "rustls" => TlsMode::Rustls,
            "insecure_skip_verify" => TlsMode::InsecureSkipVerify,
            other => return Err(anyhow::anyhow!("unknown tls mode `{other}`")),
        };
        target.tls.mode = mode;
        provenance.insert("network.tls.mode".into(), source.clone());
    }
    if let Some(value) = layer.connect_timeout_ms {
        target.connect_timeout_ms = Some(value);
        provenance.insert("network.connect_timeout_ms".into(), source.clone());
    }
    if let Some(value) = layer.request_timeout_ms {
        target.request_timeout_ms = Some(value);
        provenance.insert("network.request_timeout_ms".into(), source.clone());
    }
    if let Some(value) = layer.offline {
        target.offline = value;
        provenance.insert("network.offline".into(), source.clone());
    }
    Ok(())
}

fn apply_secrets(
    target: &mut greentic_config_types::SecretsBackendRefConfig,
    layer: SecretsLayer,
    source: &ConfigSource,
    provenance: &mut ProvenanceMap,
) {
    if let Some(value) = layer.kind {
        target.kind = value;
        provenance.insert("secrets.kind".into(), source.clone());
    }
    if let Some(value) = layer.profile {
        target.profile = Some(value);
        provenance.insert("secrets.profile".into(), source.clone());
    }
    if let Some(value) = layer.endpoint {
        target.endpoint = Some(value);
        provenance.insert("secrets.endpoint".into(), source.clone());
    }
}

fn apply_dev(
    target: &mut Option<greentic_config_types::DevConfig>,
    layer: DevLayer,
    source: &ConfigSource,
    provenance: &mut ProvenanceMap,
) -> Result<()> {
    let mut dev_cfg = target.clone().unwrap_or_default();
    if let Some(value) = layer.default_env {
        dev_cfg.default_env =
            EnvId::try_from(value.as_str()).context("invalid dev.default_env provided")?;
        provenance.insert("dev.default_env".into(), source.clone());
    }
    if let Some(value) = layer.default_tenant {
        dev_cfg.default_tenant = value;
        provenance.insert("dev.default_tenant".into(), source.clone());
    }
    if let Some(value) = layer.default_team {
        dev_cfg.default_team = Some(value);
        provenance.insert("dev.default_team".into(), source.clone());
    }
    *target = Some(dev_cfg);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provenance() -> ProvenanceMap {
        ProvenanceMap::new()
    }

    #[test]
    fn apply_layer_sets_values_and_provenance() {
        let mut cfg = GreenticConfig::default();
        let mut prov = provenance();
        let layer = GreenticConfigLayer {
            schema_version: Some(greentic_config_types::ConfigVersion("2".into())),
            environment: Some(EnvironmentLayer {
                env_id: Some(EnvId::try_from("prod").unwrap()),
                deployment: Some(greentic_types::DeploymentCtx {
                    cloud: greentic_types::Cloud::Aws,
                    region: Some("us-west-2".into()),
                    platform: greentic_types::Platform::K8s,
                    runtime: None,
                }),
                connection: Some(greentic_types::ConnectionKind::Online),
                region: Some("us-west-2".into()),
            }),
            paths: Some(PathsLayer {
                greentic_root: Some("/tmp/gt".into()),
                state_dir: Some("/tmp/gt/state".into()),
                cache_dir: Some("/tmp/gt/cache".into()),
                logs_dir: Some("/tmp/gt/logs".into()),
            }),
            runtime: Some(RuntimeLayer {
                max_concurrency: Some(8),
                request_timeout_ms: Some(1000),
                idle_timeout_ms: Some(2000),
            }),
            telemetry: Some(TelemetryLayer {
                enabled: Some(false),
                exporter: Some("stdout".into()),
                endpoint: Some("http://otel".into()),
                sampling: Some(0.5),
            }),
            network: Some(NetworkLayer {
                proxy: Some("http://proxy".into()),
                no_proxy: Some("localhost".into()),
                tls_mode: Some("rustls".into()),
                connect_timeout_ms: Some(30),
                request_timeout_ms: Some(40),
                offline: Some(true),
            }),
            secrets: Some(SecretsLayer {
                kind: Some("aws".into()),
                profile: Some("p1".into()),
                endpoint: Some("http://endpoint".into()),
            }),
            dev: Some(DevLayer {
                default_env: Some("staging".into()),
                default_tenant: Some("tenant1".into()),
                default_team: Some("team-a".into()),
            }),
        };

        apply_layer(&mut cfg, layer, ConfigSource::Cli, &mut prov).expect("apply");

        assert_eq!(cfg.schema_version.0, "2");
        assert_eq!(cfg.environment.env_id, EnvId::try_from("prod").unwrap());
        assert_eq!(cfg.environment.region.as_deref(), Some("us-west-2"));
        assert_eq!(cfg.paths.greentic_root, std::path::PathBuf::from("/tmp/gt"));
        assert_eq!(cfg.runtime.max_concurrency, Some(8));
        assert_eq!(cfg.telemetry.enabled, false);
        assert_eq!(cfg.telemetry.exporter, Some(TelemetryExporter::Stdout));
        assert_eq!(cfg.network.tls.mode, TlsMode::Rustls);
        assert_eq!(cfg.secrets.kind, "aws");
        assert_eq!(
            cfg.dev.as_ref().unwrap().default_env,
            EnvId::try_from("staging").unwrap()
        );
        assert_eq!(
            cfg.dev.as_ref().unwrap().default_team.as_deref(),
            Some("team-a")
        );

        for path in [
            "schema_version",
            "environment.env_id",
            "paths.greentic_root",
            "runtime.max_concurrency",
            "telemetry.exporter",
            "network.tls.mode",
            "secrets.kind",
            "dev.default_env",
        ] {
            assert_eq!(
                prov.get(path),
                Some(&ConfigSource::Cli),
                "missing provenance for {path}"
            );
        }
    }

    #[test]
    fn telemetry_rejects_unknown_exporter() {
        let mut cfg = GreenticConfig::default();
        let mut prov = provenance();
        let layer = GreenticConfigLayer {
            telemetry: Some(TelemetryLayer {
                exporter: Some("bogus".into()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let err = apply_layer(&mut cfg, layer, ConfigSource::Env, &mut prov).unwrap_err();
        assert!(err.to_string().contains("unknown telemetry exporter"));
        assert!(cfg.telemetry.exporter.is_none());
        assert!(prov.is_empty());
    }

    #[test]
    fn network_rejects_unknown_tls_mode() {
        let mut cfg = GreenticConfig::default();
        let mut prov = provenance();
        let layer = GreenticConfigLayer {
            network: Some(NetworkLayer {
                tls_mode: Some("invalid".into()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let err = apply_layer(&mut cfg, layer, ConfigSource::Env, &mut prov).unwrap_err();
        assert!(err.to_string().contains("unknown tls mode"));
        assert_eq!(cfg.network.tls.mode, TlsMode::System);
        assert!(prov.is_empty());
    }

    #[test]
    fn dev_layer_rejects_invalid_env() {
        let mut cfg = GreenticConfig::default();
        let mut prov = provenance();
        let layer = GreenticConfigLayer {
            dev: Some(DevLayer {
                default_env: Some("not valid".into()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let err = apply_layer(&mut cfg, layer, ConfigSource::Env, &mut prov).unwrap_err();
        assert!(err.to_string().contains("invalid dev.default_env"));
        // ensure existing config untouched
        assert_eq!(
            cfg.dev.as_ref().unwrap().default_env,
            EnvId::try_from("dev").unwrap()
        );
        assert!(prov.is_empty());
    }
}

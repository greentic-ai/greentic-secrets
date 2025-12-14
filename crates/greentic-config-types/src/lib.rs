use greentic_types::{ConnectionKind, DeploymentCtx, EnvId};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub type ProvenancePath = String;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConfigSource {
    Default,
    UserConfig,
    ProjectConfig,
    OverrideConfig,
    Env,
    Cli,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigVersion(pub String);

impl Default for ConfigVersion {
    fn default() -> Self {
        Self("1".to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GreenticConfig {
    #[serde(default)]
    pub schema_version: ConfigVersion,
    pub environment: EnvironmentConfig,
    #[serde(default)]
    pub paths: PathsConfig,
    #[serde(default)]
    pub runtime: RuntimeConfig,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub secrets: SecretsBackendRefConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev: Option<DevConfig>,
}

impl Default for GreenticConfig {
    fn default() -> Self {
        Self {
            schema_version: ConfigVersion::default(),
            environment: EnvironmentConfig::default(),
            paths: PathsConfig::default(),
            runtime: RuntimeConfig::default(),
            telemetry: TelemetryConfig::default(),
            network: NetworkConfig::default(),
            secrets: SecretsBackendRefConfig::default(),
            dev: Some(DevConfig::default()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvironmentConfig {
    pub env_id: EnvId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment: Option<DeploymentCtx>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection: Option<ConnectionKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
}

impl Default for EnvironmentConfig {
    fn default() -> Self {
        Self {
            env_id: EnvId::try_from("dev").expect("valid default env id"),
            deployment: None,
            connection: None,
            region: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathsConfig {
    pub greentic_root: PathBuf,
    pub state_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub logs_dir: PathBuf,
}

impl Default for PathsConfig {
    fn default() -> Self {
        let root = PathBuf::from(".greentic");
        Self {
            greentic_root: root.clone(),
            state_dir: root.join("state"),
            cache_dir: root.join("cache"),
            logs_dir: root.join("logs"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RuntimeConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrency: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryExporter {
    Otlp,
    Stdout,
    Stderr,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TelemetryConfig {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exporter: Option<TelemetryExporter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sampling: Option<f64>,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            exporter: None,
            endpoint: None,
            sampling: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    #[default]
    System,
    Rustls,
    InsecureSkipVerify,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct TlsConfig {
    #[serde(default)]
    pub mode: TlsMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct NetworkConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_proxy: Option<String>,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_timeout_ms: Option<u64>,
    #[serde(default)]
    pub offline: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretsBackendRefConfig {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

impl Default for SecretsBackendRefConfig {
    fn default() -> Self {
        Self {
            kind: "dev".into(),
            profile: None,
            endpoint: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DevConfig {
    pub default_env: EnvId,
    pub default_tenant: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_team: Option<String>,
}

impl Default for DevConfig {
    fn default() -> Self {
        Self {
            default_env: EnvId::try_from("dev").expect("valid default env id"),
            default_tenant: "example".into(),
            default_team: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_round_trip_toml_and_json() {
        let cfg = GreenticConfig {
            environment: EnvironmentConfig {
                env_id: EnvId::try_from("dev").unwrap(),
                deployment: None,
                connection: None,
                region: Some("us-east-1".into()),
            },
            paths: PathsConfig::default(),
            runtime: RuntimeConfig {
                max_concurrency: Some(8),
                request_timeout_ms: Some(30_000),
                idle_timeout_ms: None,
            },
            telemetry: TelemetryConfig {
                enabled: true,
                exporter: Some(TelemetryExporter::Otlp),
                endpoint: Some("http://localhost:4317".into()),
                sampling: Some(0.5),
            },
            network: NetworkConfig {
                proxy: Some("http://proxy".into()),
                no_proxy: Some("localhost".into()),
                tls: TlsConfig {
                    mode: TlsMode::Rustls,
                },
                connect_timeout_ms: Some(1000),
                request_timeout_ms: Some(2000),
                offline: false,
            },
            secrets: SecretsBackendRefConfig {
                kind: "dev".into(),
                profile: None,
                endpoint: None,
            },
            dev: Some(DevConfig::default()),
            schema_version: ConfigVersion("1".into()),
        };

        let toml = toml::to_string(&cfg).expect("toml");
        let back: GreenticConfig = toml::from_str(&toml).expect("roundtrip toml");
        assert_eq!(cfg, back);

        let json = serde_json::to_string(&cfg).expect("json");
        let back_json: GreenticConfig = serde_json::from_str(&json).expect("roundtrip json");
        assert_eq!(cfg, back_json);
    }
}

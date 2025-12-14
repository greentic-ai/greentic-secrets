mod explain;
mod loaders;
mod merge;
mod paths;
mod validate;

use anyhow::{Context, Result};
use greentic_config_types::{ConfigSource, ConfigVersion, GreenticConfig, ProvenancePath};
use greentic_types::{ConnectionKind, DeploymentCtx, EnvId};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub use explain::ExplainReport;
pub use greentic_config_types::{
    GreenticConfig as Config, NetworkConfig as Network, PathsConfig as Paths,
    RuntimeConfig as Runtime, TelemetryConfig as Telemetry,
};

pub type ProvenanceMap = BTreeMap<ProvenancePath, ConfigSource>;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct GreenticConfigLayer {
    pub schema_version: Option<ConfigVersion>,
    pub environment: Option<EnvironmentLayer>,
    pub paths: Option<PathsLayer>,
    pub runtime: Option<RuntimeLayer>,
    pub telemetry: Option<TelemetryLayer>,
    pub network: Option<NetworkLayer>,
    pub secrets: Option<SecretsLayer>,
    pub dev: Option<DevLayer>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentLayer {
    pub env_id: Option<EnvId>,
    pub deployment: Option<DeploymentCtx>,
    pub connection: Option<ConnectionKind>,
    pub region: Option<String>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct PathsLayer {
    pub greentic_root: Option<PathBuf>,
    pub state_dir: Option<PathBuf>,
    pub cache_dir: Option<PathBuf>,
    pub logs_dir: Option<PathBuf>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeLayer {
    pub max_concurrency: Option<usize>,
    pub request_timeout_ms: Option<u64>,
    pub idle_timeout_ms: Option<u64>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryLayer {
    pub enabled: Option<bool>,
    pub exporter: Option<String>,
    pub endpoint: Option<String>,
    pub sampling: Option<f64>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct NetworkLayer {
    pub proxy: Option<String>,
    pub no_proxy: Option<String>,
    pub tls_mode: Option<String>,
    pub connect_timeout_ms: Option<u64>,
    pub request_timeout_ms: Option<u64>,
    pub offline: Option<bool>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct SecretsLayer {
    pub kind: Option<String>,
    pub profile: Option<String>,
    pub endpoint: Option<String>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct DevLayer {
    pub default_env: Option<String>,
    pub default_tenant: Option<String>,
    pub default_team: Option<String>,
}

#[derive(Default, Debug, Clone)]
pub struct CliOverrides {
    pub config_path: Option<PathBuf>,
    pub env: Option<String>,
    pub tenant: Option<String>,
    pub team: Option<String>,
    pub state_dir: Option<PathBuf>,
    pub greentic_root: Option<PathBuf>,
}

pub struct ConfigResolver {
    project_root: PathBuf,
    cli_overrides: CliOverrides,
}

impl ConfigResolver {
    pub fn new() -> Self {
        Self {
            project_root: paths::default_project_root(),
            cli_overrides: CliOverrides::default(),
        }
    }

    pub fn with_project_root(mut self, root: PathBuf) -> Self {
        self.project_root = root;
        self
    }

    pub fn with_cli_overrides(mut self, overrides: CliOverrides) -> Self {
        self.cli_overrides = overrides;
        self
    }

    pub fn load(&self) -> Result<ResolvedConfig> {
        let mut config = GreenticConfig::default();
        let mut provenance = default_provenance();
        let mut warnings = Vec::new();

        // Defaults already applied.

        if let Some(user_layer) = loaders::load_user_layer()? {
            merge::apply_layer(
                &mut config,
                user_layer,
                ConfigSource::UserConfig,
                &mut provenance,
            )?;
        }

        let override_path = self.cli_overrides.config_path.clone();
        if let Some(project_layer) =
            loaders::load_project_layer(&self.project_root, override_path.as_ref())?
        {
            merge::apply_layer(
                &mut config,
                project_layer,
                if override_path.is_some() {
                    ConfigSource::OverrideConfig
                } else {
                    ConfigSource::ProjectConfig
                },
                &mut provenance,
            )?;
        }

        let env_layer = loaders::env_layer();
        merge::apply_layer(&mut config, env_layer, ConfigSource::Env, &mut provenance)?;

        if let Some(cli_layer) = cli_layer(&self.cli_overrides)? {
            merge::apply_layer(&mut config, cli_layer, ConfigSource::Cli, &mut provenance)?;
        }

        absolutize_paths(&mut config, &self.project_root);
        warnings.extend(validate::validate(&config));

        Ok(ResolvedConfig {
            config,
            provenance,
            warnings,
        })
    }
}

impl Default for ConfigResolver {
    fn default() -> Self {
        Self::new()
    }
}

fn cli_layer(overrides: &CliOverrides) -> Result<Option<GreenticConfigLayer>> {
    let mut layer = GreenticConfigLayer::default();
    if let Some(env) = overrides.env.as_ref() {
        let parsed = EnvId::try_from(env.as_str())
            .with_context(|| format!("invalid env id provided via CLI: {env}"))?;
        layer
            .environment
            .get_or_insert_with(Default::default)
            .env_id = Some(parsed);
    }
    if let Some(tenant) = overrides.tenant.as_ref() {
        layer
            .dev
            .get_or_insert_with(Default::default)
            .default_tenant = Some(tenant.clone());
    }
    if let Some(team) = overrides.team.as_ref() {
        layer.dev.get_or_insert_with(Default::default).default_team = Some(team.clone());
    }
    if let Some(path) = overrides.state_dir.as_ref() {
        layer.paths.get_or_insert_with(Default::default).state_dir = Some(path.clone());
    }
    if let Some(root) = overrides.greentic_root.as_ref() {
        layer
            .paths
            .get_or_insert_with(Default::default)
            .greentic_root = Some(root.clone());
    }
    if layer.environment.is_some() || layer.dev.is_some() || layer.paths.is_some() {
        Ok(Some(layer))
    } else {
        Ok(None)
    }
}

fn absolutize_paths(config: &mut GreenticConfig, project_root: &Path) {
    let greentic_root = paths::absolutize(config.paths.greentic_root.clone(), project_root);
    config.paths.greentic_root = greentic_root.clone();
    config.paths.state_dir = paths::absolutize(config.paths.state_dir.clone(), &greentic_root);
    config.paths.cache_dir = paths::absolutize(config.paths.cache_dir.clone(), &greentic_root);
    config.paths.logs_dir = paths::absolutize(config.paths.logs_dir.clone(), &greentic_root);
}

fn default_provenance() -> ProvenanceMap {
    static DEFAULT_PATHS: Lazy<&'static [&'static str]> = Lazy::new(|| {
        &[
            "schema_version",
            "environment.env_id",
            "environment.deployment",
            "environment.connection",
            "environment.region",
            "paths.greentic_root",
            "paths.state_dir",
            "paths.cache_dir",
            "paths.logs_dir",
            "runtime.max_concurrency",
            "runtime.request_timeout_ms",
            "runtime.idle_timeout_ms",
            "telemetry.enabled",
            "telemetry.exporter",
            "telemetry.endpoint",
            "telemetry.sampling",
            "network.proxy",
            "network.no_proxy",
            "network.tls.mode",
            "network.connect_timeout_ms",
            "network.request_timeout_ms",
            "network.offline",
            "secrets.kind",
            "secrets.profile",
            "secrets.endpoint",
            "dev.default_env",
            "dev.default_tenant",
            "dev.default_team",
        ]
    });
    let mut map = ProvenanceMap::new();
    for path in DEFAULT_PATHS.iter() {
        map.insert(path.to_string(), ConfigSource::Default);
    }
    map
}

pub struct ResolvedConfig {
    pub config: GreenticConfig,
    pub provenance: ProvenanceMap,
    pub warnings: Vec<String>,
}

impl ResolvedConfig {
    pub fn explain(&self) -> ExplainReport {
        ExplainReport::new(
            self.config.clone(),
            self.provenance.clone(),
            self.warnings.clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn precedence_applies_cli_over_env() {
        unsafe {
            std::env::set_var("GREENTIC_ENV", "dev-env");
        }
        let resolver = ConfigResolver::new().with_cli_overrides(CliOverrides {
            env: Some("cli-env".into()),
            ..Default::default()
        });
        let resolved = resolver.load().expect("config");
        assert_eq!(
            resolved.config.environment.env_id,
            EnvId::try_from("cli-env").unwrap()
        );
        unsafe {
            std::env::remove_var("GREENTIC_ENV");
        }
    }

    #[test]
    fn paths_are_absolutized() {
        let dir = tempdir().unwrap();
        let resolver = ConfigResolver::new().with_project_root(dir.path().to_path_buf());
        let resolved = resolver.load().expect("config");
        assert!(resolved.config.paths.greentic_root.is_absolute());
        assert!(resolved.config.paths.state_dir.starts_with(dir.path()));
    }

    #[test]
    fn validation_warns_for_offline_remote() {
        let mut cfg = GreenticConfig::default();
        cfg.network.offline = true;
        cfg.secrets.kind = "aws".into();
        let warnings = validate::validate(&cfg);
        assert!(!warnings.is_empty());
    }
}

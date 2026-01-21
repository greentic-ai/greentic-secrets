use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use clap::{ArgAction, Args, Parser, Subcommand};
use greentic_config::{CliOverrides as ConfigOverrides, ConfigResolver, ResolvedConfig};
use greentic_config_types::{GreenticConfig, NetworkConfig, TlsMode};
use greentic_secrets_core::seed::{
    ApplyOptions, ApplyReport, DevContext, DevStore, HttpStore, SecretsStore, apply_seed,
    resolve_uri,
};
use greentic_secrets_spec::{SeedDoc, SeedEntry, SeedValue};
use greentic_types::EnvId;
use greentic_types::secrets::{SecretFormat, SecretRequirement};
use handlebars::Handlebars;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::TempDir;
use time::OffsetDateTime;
use wasmtime::{Config, Engine as WasmtimeEngine, Instance, Module, Store};
use zip::ZipArchive;

#[derive(Parser)]
#[command(name = "greentic-secrets", version, about = "Greentic secrets CLI")]
struct Cli {
    #[command(flatten)]
    config: GlobalConfigOpts,
    #[command(subcommand)]
    command: Command,
}

#[derive(Args, Default)]
struct GlobalConfigOpts {
    /// Override config file path (replaces project config)
    #[arg(long)]
    config: Option<PathBuf>,
    /// Override environment id
    #[arg(long)]
    env: Option<String>,
    /// Override tenant id
    #[arg(long)]
    tenant: Option<String>,
    /// Override team id
    #[arg(long)]
    team: Option<String>,
    /// Override greentic root directory
    #[arg(long)]
    greentic_root: Option<PathBuf>,
    /// Override state directory
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// Verbose output (prints config source)
    #[arg(long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Command {
    #[command(subcommand)]
    Dev(DevCmd),
    #[command(subcommand)]
    Ctx(CtxCmd),
    Scaffold(ScaffoldCmd),
    Wizard(WizardCmd),
    Apply(ApplyCmd),
    Init(InitCmd),
    Setup(SetupCmd),
    #[command(subcommand)]
    Config(ConfigCmd),
}

#[derive(Subcommand)]
enum ConfigCmd {
    Show,
    Explain,
}

#[derive(Subcommand)]
enum DevCmd {
    Up {
        #[arg(long)]
        store_path: Option<PathBuf>,
    },
    Down {
        #[arg(long)]
        destroy: bool,
        #[arg(long)]
        store_path: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum CtxCmd {
    Set(CtxSetArgs),
    Show,
}

#[derive(Args)]
struct CtxSetArgs {
    #[arg(long)]
    env: String,
    #[arg(long)]
    tenant: String,
    #[arg(long)]
    team: Option<String>,
}

#[derive(Args)]
struct ScaffoldCmd {
    #[arg(long)]
    pack: PathBuf,
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    env: Option<String>,
    #[arg(long)]
    tenant: Option<String>,
    #[arg(long)]
    team: Option<String>,
}

#[derive(Args)]
struct WizardCmd {
    #[arg(short = 'i', long)]
    input: PathBuf,
    #[arg(short = 'o', long)]
    output: PathBuf,
    #[arg(long = "from-dotenv")]
    from_dotenv: Option<PathBuf>,
    #[arg(long)]
    non_interactive: bool,
}

#[derive(Args)]
struct ApplyCmd {
    #[arg(short = 'f', long)]
    file: PathBuf,
    #[arg(long)]
    pack: Option<PathBuf>,
    #[arg(long)]
    store_path: Option<PathBuf>,
    #[arg(long)]
    broker_url: Option<String>,
    #[arg(long)]
    token: Option<String>,
}

#[derive(Args)]
struct InitCmd {
    #[arg(long)]
    pack: PathBuf,
    #[arg(long)]
    env: Option<String>,
    #[arg(long)]
    tenant: Option<String>,
    #[arg(long)]
    team: Option<String>,
    #[arg(long = "from-dotenv")]
    from_dotenv: Option<PathBuf>,
    #[arg(long)]
    non_interactive: bool,
    #[arg(long)]
    store_path: Option<PathBuf>,
    #[arg(long)]
    seed_out: Option<PathBuf>,
    #[arg(long)]
    broker_url: Option<String>,
    #[arg(long)]
    token: Option<String>,
}

#[derive(Args)]
struct SetupCmd {
    #[arg(long)]
    pack: String,
    #[arg(long, conflicts_with = "terraform")]
    tofu: bool,
    #[arg(long, conflicts_with = "tofu")]
    terraform: bool,
    #[arg(long)]
    out: Option<PathBuf>,
    #[arg(long)]
    write_secrets_tfvars: bool,
    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CtxFile {
    env: String,
    tenant: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    team: Option<String>,
}

#[derive(Default)]
struct CtxOverrides {
    env: Option<String>,
    tenant: Option<String>,
    team: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let resolved = resolve_config(&cli)?;
    if cli.config.verbose {
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

    match cli.command {
        Command::Dev(cmd) => handle_dev(cmd, &resolved.config),
        Command::Ctx(cmd) => handle_ctx(cmd, &resolved.config),
        Command::Scaffold(cmd) => handle_scaffold(cmd, &resolved),
        Command::Wizard(cmd) => handle_wizard(cmd, &resolved),
        Command::Apply(cmd) => handle_apply(cmd, &resolved),
        Command::Init(cmd) => handle_init(cmd, &resolved),
        Command::Setup(cmd) => handle_setup(cmd, &resolved),
        Command::Config(cmd) => handle_config_cmd(cmd, &resolved),
    }
}

fn resolve_config(cli: &Cli) -> Result<ResolvedConfig> {
    let mut overrides = ConfigOverrides::new();
    if let Some(env) = cli
        .config
        .env
        .as_deref()
        .and_then(|value| EnvId::try_from(value).ok())
    {
        overrides = overrides.with_env_id(env);
    }
    let mut resolver = ConfigResolver::new();
    if let Some(path) = cli.config.config.clone() {
        resolver = resolver.with_config_path(path);
    }
    resolver.with_cli_overrides_typed(overrides).load()
}

fn handle_config_cmd(cmd: ConfigCmd, resolved: &ResolvedConfig) -> Result<()> {
    match cmd {
        ConfigCmd::Show => {
            println!("{}", toml::to_string_pretty(&resolved.config)?);
        }
        ConfigCmd::Explain => {
            let report = resolved.explain();
            println!("{report:?}");
        }
    }
    Ok(())
}

fn handle_dev(cmd: DevCmd, cfg: &GreenticConfig) -> Result<()> {
    let store_path = dev_store_path(cfg);
    match cmd {
        DevCmd::Up {
            store_path: override_path,
        } => {
            let path = override_path.unwrap_or_else(|| store_path.clone());
            ensure_parent(&path)?;
            let _store = DevStore::with_path(&path).context("failed to prepare dev store")?;
            println!("Dev store ready at {}", path.display());
        }
        DevCmd::Down {
            destroy,
            store_path: override_path,
        } => {
            let path = override_path.unwrap_or(store_path);
            if destroy && path.exists() {
                fs::remove_file(&path).context("failed to remove dev store")?;
                println!("Removed dev store {}", path.display());
            } else {
                println!(
                    "Nothing to do (pass --destroy to remove {})",
                    path.display()
                );
            }
        }
    }
    Ok(())
}

fn handle_ctx(cmd: CtxCmd, cfg: &GreenticConfig) -> Result<()> {
    let path = ctx_path(cfg);
    match cmd {
        CtxCmd::Set(args) => {
            let ctx = CtxFile {
                env: args.env,
                tenant: args.tenant,
                team: args.team,
            };
            write_ctx(&ctx, &path)?;
            println!("Context saved to {}", path.display());
        }
        CtxCmd::Show => {
            let ctx = read_ctx(&path).context("ctx not set; run ctx set")?;
            println!("env={}", ctx.env);
            println!("tenant={}", ctx.tenant);
            println!("team={}", ctx.team.as_deref().unwrap_or("_"));
        }
    }
    Ok(())
}

fn handle_scaffold(cmd: ScaffoldCmd, resolved: &ResolvedConfig) -> Result<()> {
    let ctx_file = read_ctx(&ctx_path(&resolved.config)).ok();
    let ctx = resolve_ctx(
        &resolved.config,
        ctx_file.as_ref(),
        &CtxOverrides {
            env: cmd.env.clone(),
            tenant: cmd.tenant.clone(),
            team: cmd.team.clone(),
        },
    )?;
    let requirements = read_pack_requirements(&cmd.pack)?;
    let entries = requirements
        .iter()
        .map(|req| scaffold_entry(&ctx, req))
        .collect();
    let doc = SeedDoc { entries };
    write_seed(&doc, &cmd.out)?;
    println!("Wrote scaffold to {}", cmd.out.display());
    Ok(())
}

fn handle_wizard(cmd: WizardCmd, _resolved: &ResolvedConfig) -> Result<()> {
    let mut doc = read_seed(&cmd.input)?;
    let dotenv = if let Some(path) = cmd.from_dotenv.as_ref() {
        Some(read_dotenv(path)?)
    } else {
        None
    };

    for entry in &mut doc.entries {
        let key = env_key_for_entry(entry);
        if let Some(map) = &dotenv
            && let Some(value) = map.get(&key)
        {
            fill_entry_from_str(entry, value)?;
            continue;
        }

        if cmd.non_interactive {
            continue;
        }

        println!("Value for {} ({:?})", entry.uri, entry.format);
        print!("> ");
        io::stdout().flush().ok();
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let trimmed = input.trim().to_string();
        if trimmed.is_empty() {
            continue;
        }
        fill_entry_from_str(entry, &trimmed)?;
    }

    write_seed(&doc, &cmd.output)?;
    println!("Wrote {}", cmd.output.display());
    Ok(())
}

fn handle_apply(cmd: ApplyCmd, resolved: &ResolvedConfig) -> Result<()> {
    let seed = read_seed(&cmd.file)?;
    let requirements = match cmd.pack {
        Some(path) => Some(read_pack_requirements(&path)?),
        None => None,
    };
    let store: Box<dyn SecretsStore> = match cmd.broker_url {
        Some(url) => {
            ensure_online(&resolved.config.network, "broker apply")?;
            let client = build_http_client(&resolved.config.network)?;
            Box::new(HttpStore::with_client(client, url, cmd.token))
        }
        None => {
            let kind = resolved.config.secrets.kind.as_str();
            if kind != "dev" && kind != "none" {
                anyhow::bail!(
                    "secrets.kind={} requires --broker-url (or set secrets.kind=dev)",
                    resolved.config.secrets.kind
                );
            }
            if kind == "none" {
                eprintln!("warning: secrets.kind=none; using dev store for CLI apply");
            }
            Box::new(
                DevStore::with_path(
                    cmd.store_path
                        .unwrap_or_else(|| dev_store_path(&resolved.config)),
                )
                .context("failed to open dev store")?,
            )
        }
    };
    let options = ApplyOptions {
        requirements: requirements.as_deref(),
        ..ApplyOptions::default()
    };
    let report = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(async { apply_seed(store.as_ref(), &seed, options).await });
    print_report(&report);
    if report.failed.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("apply completed with failures"))
    }
}

fn handle_init(cmd: InitCmd, resolved: &ResolvedConfig) -> Result<()> {
    handle_dev(
        DevCmd::Up {
            store_path: cmd.store_path.clone(),
        },
        &resolved.config,
    )?;

    let ctx_file_path = ctx_path(&resolved.config);
    if read_ctx(&ctx_file_path).is_err() {
        let ctx = resolve_ctx(
            &resolved.config,
            None,
            &CtxOverrides {
                env: cmd.env.clone(),
                tenant: cmd.tenant.clone(),
                team: cmd.team.clone(),
            },
        )?;
        write_ctx(&ctx, &ctx_file_path)?;
        println!("Context written to {}", ctx_file_path.display());
    }

    let seed_out = cmd
        .seed_out
        .clone()
        .unwrap_or_else(|| PathBuf::from("seeds.yaml"));

    handle_scaffold(
        ScaffoldCmd {
            pack: cmd.pack.clone(),
            out: seed_out.clone(),
            env: cmd.env.clone(),
            tenant: cmd.tenant.clone(),
            team: cmd.team.clone(),
        },
        resolved,
    )?;

    if cmd.non_interactive {
        handle_wizard(
            WizardCmd {
                input: seed_out.clone(),
                output: seed_out.clone(),
                from_dotenv: cmd.from_dotenv.clone(),
                non_interactive: true,
            },
            resolved,
        )?;
    } else {
        handle_wizard(
            WizardCmd {
                input: seed_out.clone(),
                output: seed_out.clone(),
                from_dotenv: cmd.from_dotenv.clone(),
                non_interactive: false,
            },
            resolved,
        )?;
    }

    handle_apply(
        ApplyCmd {
            file: seed_out,
            pack: Some(cmd.pack),
            store_path: cmd.store_path,
            broker_url: cmd.broker_url,
            token: cmd.token,
        },
        resolved,
    )
}

fn handle_setup(cmd: SetupCmd, _resolved: &ResolvedConfig) -> Result<()> {
    if !cmd.dry_run {
        bail!("setup only supports --dry-run=true (no cloud calls are allowed)");
    }

    let flavor = if cmd.terraform {
        IacFlavor::Terraform
    } else {
        IacFlavor::Tofu
    };
    let pack = resolve_pack(&cmd.pack)?;
    let requirements = load_setup_requirements(&pack.root)?;
    let config_schema = find_config_schema(&pack.root)?;

    if !requirements.config_required.is_empty() {
        println!(
            "Required config keys: {}",
            requirements.config_required.join(", ")
        );
    }
    if !requirements.config_optional.is_empty() {
        println!(
            "Optional config keys: {}",
            requirements.config_optional.join(", ")
        );
    }
    if !requirements.secret_required.is_empty() {
        println!(
            "Required secret keys: {}",
            requirements.secret_required.join(", ")
        );
    }
    if !requirements.secret_optional.is_empty() {
        println!(
            "Optional secret keys: {}",
            requirements.secret_optional.join(", ")
        );
    }

    let config_values = collect_config_values(&requirements, config_schema.as_ref())?;
    let (secret_values, write_secrets_file) =
        collect_secret_values(&requirements, cmd.write_secrets_tfvars)?;
    let answers = json!({
        "config": config_values,
        "secrets": secret_values,
    });

    if let Some(raw_requirements) = requirements.raw.as_ref() {
        validate_answers(raw_requirements, &answers)?;
    }

    let plan = run_setup_apply(&pack.root, &answers)?;
    let output_dir = cmd.out.unwrap_or_else(|| default_setup_out(&pack.slug));
    fs::create_dir_all(&output_dir)
        .with_context(|| format!("create output dir {}", output_dir.display()))?;

    let template_root = pack.root.join("iac").join(flavor.template_dir());

    let plan_value = plan.get("plan").cloned().unwrap_or_else(|| plan.clone());
    let config_patch = plan_value
        .get("config_patch")
        .cloned()
        .unwrap_or(Value::Object(serde_json::Map::new()));

    let mut template_ctx = serde_json::Map::new();
    let install_id = format!("{}-install", pack.slug);
    template_ctx.insert(
        "provider_id".to_owned(),
        Value::String(pack.pack_id.clone()),
    );
    template_ctx.insert("install_id".to_owned(), Value::String(install_id.clone()));
    template_ctx.insert("config".to_owned(), config_patch.clone());
    template_ctx.insert("outputs".to_owned(), Value::Object(serde_json::Map::new()));

    if template_root.exists() {
        render_templates(&template_root, &output_dir, &Value::Object(template_ctx))?;
        write_tfvars(&output_dir, &config_patch)?;
        write_gitignore(&output_dir)?;
        if write_secrets_file && let Some(secrets) = answers.get("secrets") {
            write_secrets_tfvars(&output_dir, secrets)?;
        }
    } else {
        println!("no infra required");
    }

    write_readme(
        &output_dir,
        &pack,
        flavor,
        write_secrets_file,
        template_root.exists(),
    )?;
    write_provider_install(
        &output_dir,
        &pack,
        &plan_value,
        &requirements,
        write_secrets_file,
    )?;

    println!("Wrote setup scaffolding to {}", output_dir.display());
    Ok(())
}

fn scaffold_entry(ctx: &CtxFile, req: &SecretRequirement) -> SeedEntry {
    let uri = resolve_uri(
        &DevContext::new(&ctx.env, &ctx.tenant, ctx.team.clone()),
        req,
    );
    let placeholder = placeholder_value(req);
    let format = req.format.clone().unwrap_or(SecretFormat::Text);

    SeedEntry {
        uri,
        format,
        description: req.description.clone(),
        value: placeholder,
    }
}

fn placeholder_value(req: &SecretRequirement) -> SeedValue {
    let format = req.format.clone().unwrap_or(SecretFormat::Text);

    if let Some(first) = req.examples.first() {
        return match format {
            SecretFormat::Text => SeedValue::Text {
                text: first.clone(),
            },
            SecretFormat::Json => SeedValue::Json {
                json: serde_json::from_str(first)
                    .unwrap_or_else(|_| serde_json::Value::String(first.clone())),
            },
            SecretFormat::Bytes => SeedValue::BytesB64 {
                bytes_b64: STANDARD.encode(first.as_bytes()),
            },
        };
    }

    match format {
        SecretFormat::Text => SeedValue::Text {
            text: String::new(),
        },
        SecretFormat::Json => SeedValue::Json { json: json!({}) },
        SecretFormat::Bytes => SeedValue::BytesB64 {
            bytes_b64: String::new(),
        },
    }
}

fn read_pack_requirements(path: &Path) -> Result<Vec<SecretRequirement>> {
    let bytes =
        fs::read(path).with_context(|| format!("failed to read pack {}", path.display()))?;

    if looks_like_zip(&bytes) {
        return read_gtpack_zip(&bytes);
    }

    if let Ok(meta) = serde_json::from_slice::<PackMetadata>(&bytes) {
        return Ok(meta.secret_requirements);
    }
    let meta: PackMetadata =
        serde_yaml::from_slice(&bytes).context("pack is not valid JSON/YAML or .gtpack zip")?;
    Ok(meta.secret_requirements)
}

#[derive(Deserialize)]
struct PackMetadata {
    #[serde(default)]
    secret_requirements: Vec<SecretRequirement>,
}

fn read_seed(path: &Path) -> Result<SeedDoc> {
    let bytes =
        fs::read(path).with_context(|| format!("failed to read seed file {}", path.display()))?;
    serde_yaml::from_slice(&bytes)
        .or_else(|_| serde_json::from_slice(&bytes))
        .context("failed to parse seed file")
}

fn write_seed(doc: &SeedDoc, path: &Path) -> Result<()> {
    ensure_parent(path)?;
    let data = serde_yaml::to_string(doc)?;
    fs::write(path, data)?;
    Ok(())
}

fn read_ctx(path: &Path) -> Result<CtxFile> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let text = String::from_utf8(bytes)?;
    parse_ctx(&text).context("invalid ctx file")
}

fn write_ctx(ctx: &CtxFile, path: &Path) -> Result<()> {
    ensure_parent(path)?;
    let data = format!(
        "env = \"{}\"\ntenant = \"{}\"\nteam = {}\n",
        ctx.env,
        ctx.tenant,
        ctx.team
            .as_ref()
            .map(|t| format!("\"{t}\""))
            .unwrap_or_else(|| "null".into())
    );
    fs::write(path, data)?;
    Ok(())
}

fn parse_ctx(raw: &str) -> Option<CtxFile> {
    let mut map = HashMap::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().trim_matches('"').to_string());
        }
    }
    let env = map.get("env")?.to_string();
    let tenant = map.get("tenant")?.to_string();
    let team = map.get("team").and_then(|v| {
        if v == "null" {
            None
        } else {
            Some(v.to_string())
        }
    });
    Some(CtxFile { env, tenant, team })
}

fn resolve_ctx(
    cfg: &GreenticConfig,
    ctx_file: Option<&CtxFile>,
    overrides: &CtxOverrides,
) -> Result<CtxFile> {
    let env = overrides
        .env
        .clone()
        .or_else(|| ctx_file.map(|c| c.env.clone()))
        .or_else(|| cfg.dev.as_ref().map(|d| d.default_env.to_string()))
        .or_else(|| Some(cfg.environment.env_id.to_string()))
        .ok_or_else(|| anyhow::anyhow!("env must be provided"))?;

    let tenant = overrides
        .tenant
        .clone()
        .or_else(|| ctx_file.map(|c| c.tenant.clone()))
        .or_else(|| cfg.dev.as_ref().map(|d| d.default_tenant.clone()))
        .ok_or_else(|| anyhow::anyhow!("tenant must be provided"))?;

    let team = overrides
        .team
        .clone()
        .or_else(|| ctx_file.and_then(|c| c.team.clone()))
        .or_else(|| cfg.dev.as_ref().and_then(|d| d.default_team.clone()));

    Ok(CtxFile { env, tenant, team })
}

fn ctx_path(cfg: &GreenticConfig) -> PathBuf {
    cfg.paths.state_dir.join("secrets.toml")
}

fn dev_store_path(cfg: &GreenticConfig) -> PathBuf {
    cfg.paths.state_dir.join("dev/.dev.secrets.env")
}

fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn build_http_client(network: &NetworkConfig) -> Result<Client> {
    let mut builder = Client::builder();
    if let Some(proxy) = &network.proxy_url {
        builder = builder.proxy(reqwest::Proxy::all(proxy)?);
    }
    if let Some(connect_timeout) = network.connect_timeout_ms {
        builder = builder.connect_timeout(Duration::from_millis(connect_timeout));
    }
    if let Some(timeout) = network.read_timeout_ms {
        builder = builder.timeout(Duration::from_millis(timeout));
    }
    if matches!(network.tls_mode, TlsMode::Disabled) {
        bail!("tls_mode=disabled is not permitted");
    }
    builder.build().map_err(Into::into)
}

fn ensure_online(_: &NetworkConfig, _: &str) -> Result<()> {
    Ok(())
}

fn read_dotenv(path: &Path) -> Result<HashMap<String, String>> {
    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut map = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    Ok(map)
}

fn fill_entry_from_str(entry: &mut SeedEntry, value: &str) -> Result<()> {
    match entry.format {
        SecretFormat::Text => {
            entry.value = SeedValue::Text {
                text: value.to_string(),
            };
        }
        SecretFormat::Json => {
            let parsed: serde_json::Value =
                serde_json::from_str(value).context("value is not valid JSON")?;
            entry.value = SeedValue::Json { json: parsed };
        }
        SecretFormat::Bytes => {
            let _ = STANDARD
                .decode(value.as_bytes())
                .context("value must be base64")?;
            entry.value = SeedValue::BytesB64 {
                bytes_b64: value.to_string(),
            };
        }
    }
    Ok(())
}

fn env_key_for_entry(entry: &SeedEntry) -> String {
    entry
        .uri
        .split('/')
        .next_back()
        .map(|s| s.to_string())
        .unwrap_or_default()
}

fn print_report(report: &ApplyReport) {
    println!("Applied {} entries", report.ok);
    if report.failed.is_empty() {
        println!("All entries applied successfully");
    } else {
        println!("Failures:");
        for failure in &report.failed {
            println!("- {}: {}", failure.uri, failure.error);
        }
    }
}

fn looks_like_zip(bytes: &[u8]) -> bool {
    bytes.first() == Some(&b'P') && bytes.get(1) == Some(&b'K')
}

fn read_gtpack_zip(bytes: &[u8]) -> Result<Vec<SecretRequirement>> {
    let cursor = io::Cursor::new(bytes);
    let mut archive = ZipArchive::new(cursor).context("failed to open gtpack zip")?;
    let mut last_err: Option<anyhow::Error> = None;
    for name in &[
        "assets/secret-requirements.json",
        "assets/secret_requirements.json",
        "secret-requirements.json",
        "secret_requirements.json",
    ] {
        match read_requirements_from_zip(&mut archive, name) {
            Ok(Some(reqs)) => return Ok(reqs),
            Ok(None) => {}
            Err(err) => {
                last_err = Some(err);
            }
        }
    }
    for name in &[
        "metadata.json",
        "pack-metadata.json",
        "pack/metadata.json",
        "gtpack/metadata.json",
    ] {
        match archive.by_name(name) {
            Ok(mut file) => {
                let mut data = String::new();
                io::Read::read_to_string(&mut file, &mut data)
                    .context("failed to read metadata from gtpack")?;
                let meta: PackMetadata =
                    serde_json::from_str(&data).context("gtpack metadata is not valid JSON")?;
                return Ok(meta.secret_requirements);
            }
            Err(err) => {
                last_err = Some(err.into());
            }
        }
    }
    if archive.by_name("manifest.cbor").is_ok() {
        return Ok(Vec::new());
    }
    Err(anyhow::anyhow!(
        "gtpack missing metadata or secret requirements ({last_err:?})"
    ))
}

fn read_requirements_from_zip(
    archive: &mut ZipArchive<io::Cursor<&[u8]>>,
    name: &str,
) -> Result<Option<Vec<SecretRequirement>>> {
    let mut file = match archive.by_name(name) {
        Ok(file) => file,
        Err(_) => return Ok(None),
    };
    let mut data = Vec::new();
    io::Read::read_to_end(&mut file, &mut data)
        .context("failed to read secret requirements from gtpack")?;
    let reqs: Vec<SecretRequirement> =
        serde_json::from_slice(&data).context("gtpack secret requirements are not valid JSON")?;
    Ok(Some(reqs))
}

#[derive(Clone, Copy)]
enum IacFlavor {
    Tofu,
    Terraform,
}

impl IacFlavor {
    fn template_dir(self) -> &'static str {
        match self {
            IacFlavor::Tofu => "tofu",
            IacFlavor::Terraform => "terraform",
        }
    }

    fn cli_name(self) -> &'static str {
        match self {
            IacFlavor::Tofu => "tofu",
            IacFlavor::Terraform => "terraform",
        }
    }
}

struct ResolvedPack {
    root: PathBuf,
    pack_id: String,
    slug: String,
    _temp: Option<TempDir>,
}

struct SetupRequirements {
    raw: Option<Value>,
    config_required: Vec<String>,
    config_optional: Vec<String>,
    config_enums: HashMap<String, Vec<String>>,
    secret_required: Vec<String>,
    secret_optional: Vec<String>,
}

fn resolve_pack(input: &str) -> Result<ResolvedPack> {
    let path = PathBuf::from(input);
    if path.exists() {
        return resolve_pack_path(&path);
    }

    if let Some(found) = find_pack_by_id(input)? {
        return resolve_pack_path(&found);
    }

    bail!("pack not found: {input}");
}

fn resolve_pack_path(path: &Path) -> Result<ResolvedPack> {
    if path.is_file() {
        if path.extension().and_then(|ext| ext.to_str()) == Some("gtpack") {
            let temp = extract_gtpack(path)?;
            let root = temp.path().to_path_buf();
            let pack_id = read_pack_id(&root)?;
            let slug = slug_from_pack_id(&pack_id);
            return Ok(ResolvedPack {
                root,
                pack_id,
                slug,
                _temp: Some(temp),
            });
        }
        bail!("pack path must be a directory or .gtpack file");
    }

    let pack_id = read_pack_id(path)?;
    let slug = slug_from_pack_id(&pack_id);
    Ok(ResolvedPack {
        root: path.to_path_buf(),
        pack_id,
        slug,
        _temp: None,
    })
}

fn find_pack_by_id(pack_id: &str) -> Result<Option<PathBuf>> {
    let roots = [PathBuf::from("dist/packs"), PathBuf::from("packs")];
    for root in roots {
        if !root.exists() {
            continue;
        }
        for entry in
            fs::read_dir(&root).with_context(|| format!("read pack dir {}", root.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.is_file()
                && path.extension().and_then(|ext| ext.to_str()) == Some("gtpack")
                && let Some(id) = read_pack_id_from_gtpack(&path).ok().flatten()
                && (id == pack_id || slug_from_pack_id(&id) == pack_id)
            {
                return Ok(Some(path));
            }
            if path.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("gtpack") {
                if path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .map(|stem| stem.contains(pack_id))
                    .unwrap_or(false)
                {
                    return Ok(Some(path));
                }
            } else if path.is_dir() {
                if let Ok(id) = read_pack_id(&path)
                    && (id == pack_id || slug_from_pack_id(&id) == pack_id)
                {
                    return Ok(Some(path));
                }
                if path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| name.contains(pack_id))
                    .unwrap_or(false)
                {
                    return Ok(Some(path));
                }
            }
        }
    }
    Ok(None)
}

fn extract_gtpack(path: &Path) -> Result<TempDir> {
    let temp = TempDir::new().context("create temp dir")?;
    let file = fs::File::open(path).with_context(|| format!("open pack {}", path.display()))?;
    let mut archive = ZipArchive::new(file).context("read pack archive")?;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).context("read pack entry")?;
        let out_path = temp.path().join(entry.name());
        if entry.is_dir() {
            fs::create_dir_all(&out_path).context("create pack dir")?;
            continue;
        }
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent).context("create pack parent")?;
        }
        let mut out_file = fs::File::create(&out_path).context("write pack entry")?;
        std::io::copy(&mut entry, &mut out_file).context("copy pack entry")?;
    }
    Ok(temp)
}

fn read_pack_id(root: &Path) -> Result<String> {
    let candidates = [
        root.join("pack.json"),
        root.join("assets").join("pack.json"),
        root.join("metadata.json"),
        root.join("pack").join("metadata.json"),
        root.join("gtpack").join("metadata.json"),
    ];
    for path in candidates {
        if !path.exists() {
            continue;
        }
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("read pack metadata {}", path.display()))?;
        let value: Value = serde_json::from_str(&raw)
            .with_context(|| format!("parse pack metadata {}", path.display()))?;
        if let Some(id) = value.get("id").and_then(Value::as_str) {
            return Ok(id.to_owned());
        }
        if let Some(id) = value.get("pack_id").and_then(Value::as_str) {
            return Ok(id.to_owned());
        }
    }
    bail!("pack id not found under {}", root.display());
}

fn read_pack_id_from_gtpack(path: &Path) -> Result<Option<String>> {
    let file = fs::File::open(path).with_context(|| format!("open pack {}", path.display()))?;
    let mut archive = ZipArchive::new(file).context("open pack zip")?;
    for name in ["pack.json", "assets/pack.json"] {
        if let Ok(mut file) = archive.by_name(name) {
            let mut data = String::new();
            io::Read::read_to_string(&mut file, &mut data).context("read pack.json")?;
            let value: Value = serde_json::from_str(&data).context("parse pack.json in gtpack")?;
            if let Some(id) = value.get("id").and_then(Value::as_str) {
                return Ok(Some(id.to_owned()));
            }
        }
    }
    Ok(None)
}

fn slug_from_pack_id(pack_id: &str) -> String {
    pack_id.split('.').next_back().unwrap_or(pack_id).to_owned()
}

fn load_setup_requirements(root: &Path) -> Result<SetupRequirements> {
    let empty_answers = Value::Object(serde_json::Map::new());
    if let Some(value) = run_requirements_flow(root, &empty_answers)? {
        let raw = Some(value.clone());
        return Ok(parse_requirements(&value, raw));
    }

    let config_schema = find_config_schema(root)?;
    let (config_required, config_optional, config_enums) =
        config_requirements_from_schema(config_schema.as_ref());
    let (secret_required, secret_optional) = secret_requirements_from_assets(root)?;
    Ok(SetupRequirements {
        raw: None,
        config_required,
        config_optional,
        config_enums,
        secret_required,
        secret_optional,
    })
}

fn parse_requirements(value: &Value, raw: Option<Value>) -> SetupRequirements {
    let requirements = value.get("requirements").unwrap_or(value);
    let config_required = requirements
        .get("config")
        .and_then(|value| value.get("required"))
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let config_optional = requirements
        .get("config")
        .and_then(|value| value.get("optional"))
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let mut config_enums = HashMap::new();
    if let Some(map) = requirements
        .get("config")
        .and_then(|value| value.get("constraints"))
        .and_then(|value| value.get("enum"))
        .and_then(Value::as_object)
    {
        for (key, value) in map {
            if let Some(list) = value.as_array() {
                let options: Vec<String> = list
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect();
                if !options.is_empty() {
                    config_enums.insert(key.clone(), options);
                }
            }
        }
    }
    let (secret_required, secret_optional) = requirements
        .get("secrets")
        .and_then(Value::as_object)
        .map(|secrets| {
            let required = secrets
                .get("required")
                .and_then(Value::as_array)
                .map(|list| {
                    list.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            let optional = secrets
                .get("optional")
                .and_then(Value::as_array)
                .map(|list| {
                    list.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            (required, optional)
        })
        .unwrap_or_default();

    SetupRequirements {
        raw,
        config_required,
        config_optional,
        config_enums,
        secret_required,
        secret_optional,
    }
}

fn config_requirements_from_schema(
    schema: Option<&Value>,
) -> (Vec<String>, Vec<String>, HashMap<String, Vec<String>>) {
    let Some(schema) = schema else {
        return (Vec::new(), Vec::new(), HashMap::new());
    };
    let required = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let mut enums = HashMap::new();
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        for (key, value) in properties {
            if let Some(options) = value.get("enum").and_then(Value::as_array) {
                let values: Vec<String> = options
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect();
                if !values.is_empty() {
                    enums.insert(key.clone(), values);
                }
            }
        }
    }
    (required, Vec::new(), enums)
}

fn secret_requirements_from_assets(root: &Path) -> Result<(Vec<String>, Vec<String>)> {
    let candidates = [
        root.join("secret-requirements.json"),
        root.join("assets").join("secret-requirements.json"),
    ];
    for path in candidates {
        if !path.exists() {
            continue;
        }
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("read secret requirements {}", path.display()))?;
        let value: Value = serde_json::from_str(&raw)
            .with_context(|| format!("parse secret requirements {}", path.display()))?;
        let mut required = Vec::new();
        let mut optional = Vec::new();
        if let Value::Array(items) = value {
            for item in items {
                let key = item
                    .get("key")
                    .and_then(Value::as_str)
                    .or_else(|| item.get("id").and_then(Value::as_str))
                    .or_else(|| item.get("name").and_then(Value::as_str));
                let required_flag = item
                    .get("required")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if let Some(key) = key {
                    if required_flag {
                        required.push(key.to_owned());
                    } else {
                        optional.push(key.to_owned());
                    }
                }
            }
        }
        return Ok((required, optional));
    }
    Ok((Vec::new(), Vec::new()))
}

fn find_config_schema(root: &Path) -> Result<Option<Value>> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).with_context(|| format!("read dir {}", dir.display()))? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.file_name().and_then(|name| name.to_str()) == Some("config.schema.json") {
                let raw = fs::read_to_string(&path)
                    .with_context(|| format!("read {}", path.display()))?;
                let schema: Value = serde_json::from_str(&raw)
                    .with_context(|| format!("parse {}", path.display()))?;
                return Ok(Some(schema));
            }
        }
    }
    Ok(None)
}

fn collect_config_values(
    requirements: &SetupRequirements,
    schema: Option<&Value>,
) -> Result<Value> {
    let mut config = serde_json::Map::new();
    if let Some(schema) = schema {
        let required_keys = schema
            .get("required")
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_else(|| requirements.config_required.clone());
        let properties = schema.get("properties").and_then(Value::as_object);
        for key in required_keys {
            let prop = properties.and_then(|map| map.get(&key));
            if let Some(prop) = prop {
                let enum_override = requirements.config_enums.get(&key);
                if let Some(value) = prompt_schema_value(&key, prop, true, enum_override)? {
                    config.insert(key, value);
                }
            } else {
                let value = prompt_string_value(&key, true, None)?;
                config.insert(key, Value::String(value));
            }
        }
        return Ok(Value::Object(config));
    }

    for key in &requirements.config_required {
        let enum_override = requirements.config_enums.get(key);
        if let Some(options) = enum_override {
            if let Some(value) = prompt_enum_value(key, options, true)? {
                config.insert(key.clone(), Value::String(value));
            }
            continue;
        }
        let value = prompt_string_value(key, true, None)?;
        config.insert(key.clone(), Value::String(value));
    }
    Ok(Value::Object(config))
}

fn collect_secret_values(
    requirements: &SetupRequirements,
    write_secrets_tfvars: bool,
) -> Result<(Value, bool)> {
    if requirements.secret_required.is_empty() && requirements.secret_optional.is_empty() {
        return Ok((Value::Object(serde_json::Map::new()), false));
    }
    let want_values = write_secrets_tfvars;

    let mut secrets = serde_json::Map::new();
    for key in &requirements.secret_required {
        if want_values {
            let value = prompt_secret_value(key, true)?;
            secrets.insert(key.clone(), Value::String(value));
        } else {
            secrets.insert(key.clone(), Value::String(secret_placeholder()));
        }
    }
    if want_values {
        for key in &requirements.secret_optional {
            let value = prompt_secret_value(key, false)?;
            if !value.is_empty() {
                secrets.insert(key.clone(), Value::String(value));
            }
        }
    }

    Ok((Value::Object(secrets), write_secrets_tfvars))
}

fn prompt_schema_value(
    key: &str,
    schema: &Value,
    required: bool,
    enum_override: Option<&Vec<String>>,
) -> Result<Option<Value>> {
    if let Some(options) = enum_override {
        let value = prompt_enum_value(key, options, required)?;
        return Ok(value.map(Value::String));
    }
    if let Some(options) = schema.get("enum").and_then(Value::as_array) {
        let values: Vec<String> = options
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        let value = prompt_enum_value(key, &values, required)?;
        return Ok(value.map(Value::String));
    }
    let Some(value_type) = schema.get("type").and_then(Value::as_str) else {
        let value = prompt_string_value(key, required, None)?;
        return Ok(Some(Value::String(value)));
    };
    match value_type {
        "object" => {
            let value = prompt_object_value(key, schema)?;
            if value.is_empty() && !required {
                Ok(None)
            } else {
                Ok(Some(Value::Object(value)))
            }
        }
        "boolean" => {
            let default = schema.get("default").and_then(Value::as_bool);
            let value = prompt_bool_value(key, required, default)?;
            Ok(value.map(Value::Bool))
        }
        "integer" => {
            let default = schema.get("default").and_then(Value::as_i64);
            let value = prompt_int_value(key, required, default)?;
            Ok(value.map(|val| Value::Number(val.into())))
        }
        "number" => {
            let default = schema.get("default").and_then(Value::as_f64);
            let value = prompt_float_value(key, required, default)?;
            Ok(value.map(|val| {
                Value::Number(serde_json::Number::from_f64(val).unwrap_or_else(|| 0.into()))
            }))
        }
        "array" => {
            let default = schema.get("default").cloned();
            let value = prompt_array_value(key, required, default)?;
            Ok(value)
        }
        _ => {
            let default = schema.get("default").and_then(Value::as_str);
            let value = prompt_string_value(key, required, default)?;
            Ok(Some(Value::String(value)))
        }
    }
}

fn prompt_object_value(key: &str, schema: &Value) -> Result<serde_json::Map<String, Value>> {
    let mut map = serde_json::Map::new();
    let required_fields: Vec<String> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let properties = schema.get("properties").and_then(Value::as_object);
    for field in required_fields {
        let field_schema = properties.and_then(|props| props.get(&field));
        let field_key = format!("{key}.{field}");
        if let Some(field_schema) = field_schema {
            if let Some(value) = prompt_schema_value(&field_key, field_schema, true, None)? {
                map.insert(field, value);
            }
        } else {
            let value = prompt_string_value(&field_key, true, None)?;
            map.insert(field, Value::String(value));
        }
    }
    Ok(map)
}

fn prompt_line(prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn prompt_enum_value(key: &str, options: &[String], required: bool) -> Result<Option<String>> {
    println!("Select {key}:");
    for (idx, option) in options.iter().enumerate() {
        println!("  {}) {}", idx + 1, option);
    }
    loop {
        let input = prompt_line("> ")?;
        if input.is_empty() && !required {
            return Ok(None);
        }
        if input.is_empty() && required {
            continue;
        }
        if let Ok(index) = input.parse::<usize>()
            && index > 0
            && index <= options.len()
        {
            return Ok(Some(options[index - 1].clone()));
        }
        if options.iter().any(|opt| opt == &input) {
            return Ok(Some(input));
        }
        println!("Invalid choice, try again.");
    }
}

fn prompt_string_value(key: &str, required: bool, default: Option<&str>) -> Result<String> {
    loop {
        let label = if let Some(default) = default {
            format!("{key} [{default}]: ")
        } else {
            format!("{key}: ")
        };
        let input = prompt_line(&label)?;
        if input.is_empty() {
            if let Some(default) = default {
                return Ok(default.to_owned());
            }
            if !required {
                return Ok(String::new());
            }
            continue;
        }
        return Ok(input);
    }
}

fn prompt_secret_value(key: &str, required: bool) -> Result<String> {
    loop {
        let input = prompt_line(&format!("{key} (secret): "))?;
        if input.is_empty() && required {
            continue;
        }
        return Ok(input);
    }
}

fn prompt_bool_value(key: &str, required: bool, default: Option<bool>) -> Result<Option<bool>> {
    let label = match default {
        Some(true) => format!("{key} [Y/n]: "),
        Some(false) => format!("{key} [y/N]: "),
        None => format!("{key} [y/n]: "),
    };
    loop {
        let input = prompt_line(&label)?;
        if input.is_empty() {
            if let Some(default) = default {
                return Ok(Some(default));
            }
            if !required {
                return Ok(None);
            }
            continue;
        }
        let value = matches!(input.as_str(), "y" | "Y" | "yes" | "true" | "1");
        return Ok(Some(value));
    }
}

fn prompt_int_value(key: &str, required: bool, default: Option<i64>) -> Result<Option<i64>> {
    let label = if let Some(default) = default {
        format!("{key} [{default}]: ")
    } else {
        format!("{key}: ")
    };
    loop {
        let input = prompt_line(&label)?;
        if input.is_empty() {
            if let Some(default) = default {
                return Ok(Some(default));
            }
            if !required {
                return Ok(None);
            }
            continue;
        }
        if let Ok(value) = input.parse::<i64>() {
            return Ok(Some(value));
        }
        println!("Invalid number, try again.");
    }
}

fn prompt_float_value(key: &str, required: bool, default: Option<f64>) -> Result<Option<f64>> {
    let label = if let Some(default) = default {
        format!("{key} [{default}]: ")
    } else {
        format!("{key}: ")
    };
    loop {
        let input = prompt_line(&label)?;
        if input.is_empty() {
            if let Some(default) = default {
                return Ok(Some(default));
            }
            if !required {
                return Ok(None);
            }
            continue;
        }
        if let Ok(value) = input.parse::<f64>() {
            return Ok(Some(value));
        }
        println!("Invalid number, try again.");
    }
}

fn prompt_array_value(key: &str, required: bool, default: Option<Value>) -> Result<Option<Value>> {
    let label = if default.is_some() {
        format!("{key} (comma-separated, empty for default): ")
    } else {
        format!("{key} (comma-separated): ")
    };
    loop {
        let input = prompt_line(&label)?;
        if input.is_empty() {
            if let Some(default) = default.clone() {
                return Ok(Some(default));
            }
            if !required {
                return Ok(None);
            }
            continue;
        }
        let values: Vec<Value> = input
            .split(',')
            .map(|value| Value::String(value.trim().to_owned()))
            .collect();
        return Ok(Some(Value::Array(values)));
    }
}

fn secret_placeholder() -> String {
    "SET_AT_APPLY".to_owned()
}

fn run_requirements_flow(root: &Path, answers: &Value) -> Result<Option<Value>> {
    let Some(component_path) = find_wasm_for_step(root, "requirements") else {
        return Ok(None);
    };
    let output = execute_wasm_step(
        &component_path,
        "requirements",
        answers,
        Duration::from_secs(30),
    )?;
    let value = output
        .get("requirements")
        .cloned()
        .unwrap_or_else(|| output.clone());
    Ok(Some(value))
}

fn run_setup_apply(root: &Path, answers: &Value) -> Result<Value> {
    let Some(component_path) = find_wasm_for_step(root, "apply") else {
        bail!("setup apply step not found in pack");
    };
    execute_wasm_step(&component_path, "apply", answers, Duration::from_secs(30))
}

fn find_wasm_for_step(root: &Path, step: &str) -> Option<PathBuf> {
    let candidates = [format!("setup_default__{step}")];
    let roots = [
        root.join("wasm"),
        root.join("components"),
        root.to_path_buf(),
    ];
    for candidate in candidates {
        for base in &roots {
            let wasm = base.join(format!("{candidate}.wasm"));
            if wasm.exists() {
                return Some(wasm);
            }
            let wat = base.join(format!("{candidate}.wat"));
            if wat.exists() {
                return Some(wat);
            }
        }
    }
    None
}

fn execute_wasm_step(
    path: &Path,
    step_name: &str,
    answers: &Value,
    timeout: Duration,
) -> Result<Value> {
    let wasm_bytes = load_component_bytes(path)?;
    let mut config = Config::new();
    config.epoch_interruption(true);
    let engine = WasmtimeEngine::new(&config)?;
    let mut store = Store::new(&engine, ());

    let engine_clone = engine.clone();
    let timeout_ms = timeout.as_millis().min(u64::MAX as u128) as u64;
    let epoch_handle = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(timeout_ms));
        engine_clone.increment_epoch();
    });
    store.set_epoch_deadline(1);

    let module = Module::new(&engine, wasm_bytes)?;
    let instance = Instance::new(&mut store, &module, &[])?;
    let memory = instance
        .get_memory(&mut store, "memory")
        .ok_or_else(|| anyhow::anyhow!("missing exported memory"))?;

    let input = json!({
        "step": step_name,
        "inputs": { "answers": answers },
        "state": { "answers": answers, "previous": [] }
    });
    let input_bytes = serde_json::to_vec(&input)?;
    write_wasm_input(&memory, &mut store, &input_bytes)?;

    let func = instance
        .get_func(&mut store, "run")
        .ok_or_else(|| anyhow::anyhow!("missing run export"))?;
    let func = func.typed::<(i32, i32), (i32, i32)>(&store)?;

    let (output_ptr, output_len) = func
        .call(&mut store, (4096i32, input_bytes.len() as i32))
        .map_err(|err| anyhow::anyhow!("wasm trap: {err}"))?;
    let output = read_wasm_output(&memory, &mut store, output_ptr, output_len)?;

    let _ = epoch_handle.join();
    Ok(output)
}

fn load_component_bytes(path: &Path) -> Result<Vec<u8>> {
    let bytes =
        fs::read(path).with_context(|| format!("failed to read component {}", path.display()))?;
    if path.extension().and_then(|ext| ext.to_str()) == Some("wat") {
        let wasm = wat::parse_bytes(&bytes)
            .map_err(|err| anyhow::anyhow!("failed to parse wat: {err}"))?;
        Ok(wasm.into())
    } else {
        Ok(bytes)
    }
}

fn write_wasm_input(
    memory: &wasmtime::Memory,
    store: &mut Store<()>,
    input_bytes: &[u8],
) -> Result<()> {
    let memory_size = memory.data_size(&store);
    let input_ptr = 4096usize;
    if input_ptr + input_bytes.len() > memory_size {
        bail!("wasm input too large");
    }
    memory
        .write(store, input_ptr, input_bytes)
        .map_err(|err| anyhow::anyhow!("memory write failed: {err}"))?;
    Ok(())
}

fn read_wasm_output(
    memory: &wasmtime::Memory,
    store: &mut Store<()>,
    output_ptr: i32,
    output_len: i32,
) -> Result<Value> {
    let output_len = output_len as usize;
    let mut buffer = vec![0u8; output_len];
    memory
        .read(store, output_ptr as usize, &mut buffer)
        .map_err(|err| anyhow::anyhow!("memory read failed: {err}"))?;
    let value = serde_json::from_slice(&buffer)?;
    Ok(value)
}

fn render_templates(src: &Path, dst: &Path, ctx: &Value) -> Result<()> {
    let mut handlebars = Handlebars::new();
    handlebars.register_escape_fn(handlebars::no_escape);
    render_templates_inner(src, dst, ctx, &handlebars)
}

fn render_templates_inner(
    src: &Path,
    dst: &Path,
    ctx: &Value,
    handlebars: &Handlebars<'_>,
) -> Result<()> {
    for entry in fs::read_dir(src).with_context(|| format!("read {}", src.display()))? {
        let entry = entry?;
        let path = entry.path();
        let out_path = dst.join(entry.file_name());
        if path.is_dir() {
            fs::create_dir_all(&out_path)
                .with_context(|| format!("create {}", out_path.display()))?;
            render_templates_inner(&path, &out_path, ctx, handlebars)?;
            continue;
        }
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("read template {}", path.display()))?;
        let rendered = handlebars
            .render_template(&raw, ctx)
            .with_context(|| format!("render template {}", path.display()))?;
        fs::write(&out_path, rendered).with_context(|| format!("write {}", out_path.display()))?;
    }
    Ok(())
}

fn write_tfvars(out_dir: &Path, config: &Value) -> Result<()> {
    let path = out_dir.join("terraform.tfvars.json");
    let value = if config.is_object() {
        config.clone()
    } else {
        Value::Object(serde_json::Map::new())
    };
    let content = serde_json::to_string_pretty(&value)?;
    fs::write(&path, content).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn write_secrets_tfvars(out_dir: &Path, secrets: &Value) -> Result<()> {
    let path = out_dir.join("secrets.auto.tfvars.json");
    let value = if secrets.is_object() {
        secrets.clone()
    } else {
        Value::Object(serde_json::Map::new())
    };
    let content = serde_json::to_string_pretty(&value)?;
    fs::write(&path, content).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn write_gitignore(out_dir: &Path) -> Result<()> {
    let path = out_dir.join(".gitignore");
    let content = "secrets.auto.tfvars.json\n*.auto.tfvars*\n*.tfstate*\n";
    fs::write(&path, content).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn write_provider_install(
    out_dir: &Path,
    pack: &ResolvedPack,
    plan: &Value,
    requirements: &SetupRequirements,
    write_secrets_tfvars: bool,
) -> Result<()> {
    let sanitized_plan = sanitize_plan(plan);
    let config_patch = plan
        .get("config_patch")
        .cloned()
        .unwrap_or(Value::Object(serde_json::Map::new()));
    let install_id = format!("{}-install", pack.slug);
    let now = OffsetDateTime::now_utc();
    let stamp = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        now.year(),
        now.month() as u8,
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );
    let install = json!({
        "provider_id": pack.pack_id,
        "install_id": install_id,
        "generated_at": stamp,
        "config_patch": config_patch,
        "plan": sanitized_plan,
        "secrets": {
            "required": requirements.secret_required.clone(),
            "optional": requirements.secret_optional.clone(),
            "written_to_disk": write_secrets_tfvars,
        }
    });
    let path = out_dir.join("provider-install.json");
    fs::write(&path, serde_json::to_string_pretty(&install)?)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn write_readme(
    out_dir: &Path,
    pack: &ResolvedPack,
    flavor: IacFlavor,
    write_secrets_tfvars: bool,
    has_templates: bool,
) -> Result<()> {
    let mut readme = String::new();
    readme.push_str("# Greentic Secrets Setup\n\n");
    readme.push_str(&format!("Provider: `{}`\n\n", pack.pack_id));
    if has_templates {
        readme.push_str("## Next steps\n\n");
        readme.push_str(&format!(
            "1. `{0} init`\n2. `{0} plan`\n3. `{0} apply`\n\n",
            flavor.cli_name()
        ));
    } else {
        readme.push_str("## Infrastructure\n\n");
        readme.push_str("No infrastructure required for this provider.\n\n");
    }
    readme.push_str("## Secrets handling\n\n");
    if write_secrets_tfvars {
        readme.push_str(
            "`secrets.auto.tfvars.json` was generated (auto-loaded by Terraform/OpenTofu); keep it out of version control.\n",
        );
    } else {
        readme.push_str(
            "No secret values were written. Provide secrets via `TF_VAR_<secret_key>` or your external injection system.\n",
        );
    }
    let path = out_dir.join("README.generated.md");
    fs::write(&path, readme).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn sanitize_plan(plan: &Value) -> Value {
    let mut sanitized = plan.clone();
    if let Some(secrets_patch) = sanitized.get_mut("secrets_patch")
        && let Some(set) = secrets_patch.get_mut("set").and_then(Value::as_object_mut)
    {
        for value in set.values_mut() {
            let mut replacement = serde_json::Map::new();
            replacement.insert("redacted".to_owned(), Value::Bool(true));
            replacement.insert("value".to_owned(), Value::Null);
            *value = Value::Object(replacement);
        }
    }
    sanitized
}

fn default_setup_out(slug: &str) -> PathBuf {
    let now = OffsetDateTime::now_utc();
    let stamp = format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        now.year(),
        now.month() as u8,
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );
    PathBuf::from(format!("out/secrets-setup/{slug}/{stamp}"))
}

fn validate_answers(requirements: &Value, answers: &Value) -> Result<()> {
    let config_required = requirements
        .get("config")
        .and_then(|value| value.get("required"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let secret_required = requirements
        .get("secrets")
        .and_then(|value| value.get("required"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let enum_constraints = requirements
        .get("config")
        .and_then(|value| value.get("constraints"))
        .and_then(|value| value.get("enum"))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    let config_values = answers
        .get("config")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let secret_values = answers
        .get("secrets")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    for key in config_required {
        let key = key.as_str().unwrap_or_default();
        if key.is_empty() {
            continue;
        }
        let Some(value) = config_values.get(key) else {
            bail!("missing required config field {key}");
        };
        if matches!(value, Value::String(text) if text.is_empty()) {
            bail!("missing required config field {key}");
        }
    }

    for key in secret_required {
        let key = key.as_str().unwrap_or_default();
        if key.is_empty() {
            continue;
        }
        let Some(value) = secret_values.get(key) else {
            bail!("missing required secret field {key}");
        };
        if matches!(value, Value::String(text) if text.is_empty()) {
            bail!("missing required secret field {key}");
        }
    }

    for (key, values) in enum_constraints {
        let Some(values) = values.as_array() else {
            continue;
        };
        let Some(current) = config_values.get(&key) else {
            continue;
        };
        let current = current.as_str().unwrap_or_default();
        if !values.iter().any(|value| value.as_str() == Some(current)) {
            bail!("config field {key} must be one of {:?}", values);
        }
    }
    Ok(())
}

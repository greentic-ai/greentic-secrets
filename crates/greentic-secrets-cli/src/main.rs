use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::{Args, Parser, Subcommand};
use greentic_secrets_core::seed::{
    ApplyOptions, ApplyReport, DevContext, DevStore, HttpStore, SecretsStore, apply_seed,
    resolve_uri,
};
use greentic_secrets_spec::{SecretFormat, SecretRequirement, SeedDoc, SeedEntry, SeedValue};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use zip::ZipArchive;

#[derive(Parser)]
#[command(name = "greentic-secrets", version, about = "Greentic secrets CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CtxFile {
    env: String,
    tenant: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    team: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Dev(cmd) => handle_dev(cmd),
        Command::Ctx(cmd) => handle_ctx(cmd),
        Command::Scaffold(cmd) => handle_scaffold(cmd),
        Command::Wizard(cmd) => handle_wizard(cmd),
        Command::Apply(cmd) => handle_apply(cmd),
        Command::Init(cmd) => handle_init(cmd),
    }
}

fn handle_dev(cmd: DevCmd) -> Result<()> {
    match cmd {
        DevCmd::Up { store_path } => {
            let path = store_path.unwrap_or_else(default_store_path);
            ensure_parent(&path)?;
            let _store = DevStore::with_path(&path).context("failed to prepare dev store")?;
            println!("Dev store ready at {}", path.display());
        }
        DevCmd::Down {
            destroy,
            store_path,
        } => {
            let path = store_path.unwrap_or_else(default_store_path);
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

fn handle_ctx(cmd: CtxCmd) -> Result<()> {
    match cmd {
        CtxCmd::Set(args) => {
            let ctx = CtxFile {
                env: args.env,
                tenant: args.tenant,
                team: args.team,
            };
            write_ctx(&ctx)?;
            println!("Context saved to {}", ctx_path().display());
        }
        CtxCmd::Show => {
            let ctx = read_ctx().context("ctx not set; run ctx set")?;
            println!("env={}", ctx.env);
            println!("tenant={}", ctx.tenant);
            println!("team={}", ctx.team.as_deref().unwrap_or("_"));
        }
    }
    Ok(())
}

fn handle_scaffold(cmd: ScaffoldCmd) -> Result<()> {
    let ctx = resolve_ctx(cmd.env, cmd.tenant, cmd.team)?;
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

fn handle_wizard(cmd: WizardCmd) -> Result<()> {
    let mut doc = read_seed(&cmd.input)?;
    let dotenv = if let Some(path) = cmd.from_dotenv.as_ref() {
        Some(read_dotenv(path)?)
    } else {
        None
    };

    for entry in &mut doc.entries {
        let key = env_key_for_entry(entry);
        if let Some(map) = &dotenv {
            if let Some(value) = map.get(&key) {
                fill_entry_from_str(entry, value)?;
                continue;
            }
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

fn handle_apply(cmd: ApplyCmd) -> Result<()> {
    let seed = read_seed(&cmd.file)?;
    let requirements = match cmd.pack {
        Some(path) => Some(read_pack_requirements(&path)?),
        None => None,
    };
    let store: Box<dyn SecretsStore> = if let Some(url) = cmd.broker_url {
        Box::new(HttpStore::new(url, cmd.token))
    } else {
        Box::new(
            DevStore::with_path(cmd.store_path.unwrap_or_else(default_store_path))
                .context("failed to open dev store")?,
        )
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

fn handle_init(cmd: InitCmd) -> Result<()> {
    handle_dev(DevCmd::Up {
        store_path: cmd.store_path.clone(),
    })?;

    if read_ctx().is_err() {
        let env = match cmd.env.clone() {
            Some(value) => value,
            None => prompt("env")?,
        };
        let tenant = match cmd.tenant.clone() {
            Some(value) => value,
            None => prompt("tenant")?,
        };
        let team = cmd.team.clone();
        write_ctx(&CtxFile { env, tenant, team })?;
        println!("Context written to {}", ctx_path().display());
    }

    let seed_out = cmd
        .seed_out
        .clone()
        .unwrap_or_else(|| PathBuf::from("seeds.yaml"));

    handle_scaffold(ScaffoldCmd {
        pack: cmd.pack.clone(),
        out: seed_out.clone(),
        env: cmd.env.clone(),
        tenant: cmd.tenant.clone(),
        team: cmd.team.clone(),
    })?;

    if cmd.non_interactive {
        handle_wizard(WizardCmd {
            input: seed_out.clone(),
            output: seed_out.clone(),
            from_dotenv: cmd.from_dotenv.clone(),
            non_interactive: true,
        })?;
    } else {
        handle_wizard(WizardCmd {
            input: seed_out.clone(),
            output: seed_out.clone(),
            from_dotenv: cmd.from_dotenv.clone(),
            non_interactive: false,
        })?;
    }

    handle_apply(ApplyCmd {
        file: seed_out,
        pack: Some(cmd.pack),
        store_path: cmd.store_path,
        broker_url: cmd.broker_url,
        token: cmd.token,
    })
}

fn scaffold_entry(ctx: &CtxFile, req: &SecretRequirement) -> SeedEntry {
    let uri = resolve_uri(
        &DevContext::new(&ctx.env, &ctx.tenant, ctx.team.clone()),
        req,
    );
    let placeholder = placeholder_value(req);

    SeedEntry {
        uri,
        format: req.format,
        description: req.description.clone(),
        value: placeholder,
    }
}

fn placeholder_value(req: &SecretRequirement) -> SeedValue {
    if let Some(examples) = &req.examples {
        if let Some(first) = examples.first() {
            return match req.format {
                SecretFormat::Text => SeedValue::Text {
                    text: first.as_str().unwrap_or_default().to_string(),
                },
                SecretFormat::Json => SeedValue::Json {
                    json: first.clone(),
                },
                SecretFormat::Bytes => SeedValue::BytesB64 {
                    bytes_b64: STANDARD.encode(first.to_string()),
                },
            };
        }
    }

    match req.format {
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
        if let Ok(reqs) = read_gtpack_zip(&bytes) {
            return Ok(reqs);
        }
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

fn read_ctx() -> Result<CtxFile> {
    let path = ctx_path();
    let bytes = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let text = String::from_utf8(bytes)?;
    parse_ctx(&text).context("invalid ctx file")
}

fn write_ctx(ctx: &CtxFile) -> Result<()> {
    let path = ctx_path();
    ensure_parent(&path)?;
    let data = format!(
        "env = \"{}\"\ntenant = \"{}\"\nteam = {}\n",
        ctx.env,
        ctx.tenant,
        ctx.team
            .as_ref()
            .map(|t| format!("\"{t}\""))
            .unwrap_or_else(|| "null".into())
    );
    fs::write(&path, data)?;
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
    env: Option<String>,
    tenant: Option<String>,
    team: Option<String>,
) -> Result<CtxFile> {
    if env.is_some() || tenant.is_some() || team.is_some() {
        let ctx = CtxFile {
            env: env.unwrap_or_default(),
            tenant: tenant.unwrap_or_default(),
            team,
        };
        if ctx.env.is_empty() || ctx.tenant.is_empty() {
            anyhow::bail!("env and tenant must be provided");
        }
        return Ok(ctx);
    }
    read_ctx().context("ctx missing; pass --env/--tenant or run ctx set")
}

fn ctx_path() -> PathBuf {
    greentic_dir().join("secrets.toml")
}

fn greentic_dir() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".greentic")
}

fn default_store_path() -> PathBuf {
    greentic_dir().join("dev/.dev.secrets.env")
}

fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
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

fn prompt(label: &str) -> Result<String> {
    print!("{label}: ");
    io::stdout().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn looks_like_zip(bytes: &[u8]) -> bool {
    bytes.first() == Some(&b'P') && bytes.get(1) == Some(&b'K')
}

fn read_gtpack_zip(bytes: &[u8]) -> Result<Vec<SecretRequirement>> {
    let cursor = io::Cursor::new(bytes);
    let mut archive = ZipArchive::new(cursor).context("failed to open gtpack zip")?;
    let mut last_err = None;
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
                last_err = Some(err);
            }
        }
    }
    Err(anyhow::anyhow!(
        "gtpack missing metadata.json ({last_err:?})"
    ))
}

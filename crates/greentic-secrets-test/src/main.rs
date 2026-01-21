use anyhow::Result;
use clap::{ArgAction, Parser, Subcommand};
use greentic_secrets_test::{E2eOptions, run_e2e};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "greentic-secrets-test",
    about = "Greentic secrets conformance CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run end-to-end conformance checks against secrets packs.
    E2e {
        /// Directory containing secrets-*.gtpack files
        #[arg(long, value_name = "DIR", required = true)]
        packs: PathBuf,
        /// Optional provider filter (pack id or filename substring)
        #[arg(long)]
        provider: Option<String>,
        /// Optional JSON report output path
        #[arg(long, value_name = "FILE")]
        report: Option<PathBuf>,
        /// Dry-run mode (default true)
        #[arg(
            long,
            default_value_t = true,
            action = ArgAction::Set,
            num_args = 0..=1,
            default_missing_value = "true"
        )]
        dry_run: bool,
        /// Enable live network calls (requires env gating)
        #[arg(long)]
        live: bool,
        /// Enable trace logging (reserved)
        #[arg(long)]
        trace: bool,
        /// Fixtures root directory (defaults to ./packs)
        #[arg(long, default_value = "packs")]
        fixtures_root: PathBuf,
        /// Timeout per pack in seconds
        #[arg(long, default_value_t = 60)]
        timeout_secs: u64,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::E2e {
            packs,
            provider,
            report,
            dry_run,
            live,
            trace,
            fixtures_root,
            timeout_secs,
        } => {
            let options = E2eOptions {
                packs_dir: packs,
                provider_filter: provider,
                report_path: report,
                dry_run,
                live,
                trace,
                fixtures_root,
                timeout: Duration::from_secs(timeout_secs),
            };
            let report = run_e2e(options)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
    }
    Ok(())
}

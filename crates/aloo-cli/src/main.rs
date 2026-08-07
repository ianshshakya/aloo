//! `aloo` — The Aloo network intelligence CLI.
//!
//! ```text
//! aloo [OPTIONS] <COMMAND>
//!
//! Commands:
//!   scan     Scan one or more network targets
//!   report   Generate a report from a previous scan session
//!   plugin   Manage Aloo plugins
//!   history  List past scan sessions
//!   version  Print version information and exit
//! ```

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use tracing::info;

// ── CLI definition ────────────────────────────────────────────────────────────

/// Aloo — The next-generation network intelligence platform.
#[derive(Debug, Parser)]
#[command(
    name    = "aloo",
    version = env!("CARGO_PKG_VERSION"),
    author  = "Aloo Contributors",
    about   = "Authorised network discovery, service fingerprinting, and vulnerability correlation.",
    long_about = None,
)]
struct Cli {
    /// Path to a configuration file (default: aloo.toml in the current directory).
    #[arg(short, long, global = true, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Log verbosity. May be specified multiple times (-v, -vv, -vvv).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Emit structured JSON logs (useful for log aggregation).
    #[arg(long, global = true, env = "ALOO_JSON_LOGS")]
    json_logs: bool,

    #[command(subcommand)]
    command: Commands,
}

/// Available subcommands.
#[derive(Debug, Subcommand)]
enum Commands {
    /// Scan one or more targets for open ports and services.
    Scan(ScanArgs),

    /// Generate a report from a previous scan session.
    Report(ReportArgs),

    /// Manage Aloo plugins.
    Plugin(PluginArgs),

    /// List past scan sessions stored in the history database.
    History(HistoryArgs),

    /// Print version information and exit.
    Version,
}

// ── Scan ──────────────────────────────────────────────────────────────────────

/// Arguments for the `scan` subcommand.
#[derive(Debug, Parser)]
struct ScanArgs {
    /// One or more target specifications (IP addresses or CIDR ranges).
    ///
    /// Examples: `192.168.1.0/24`, `10.0.0.1`, `10.0.0.1-254`
    #[arg(required = true, value_name = "TARGET")]
    targets: Vec<String>,

    /// Scan profile preset.
    #[arg(short = 'p', long, value_enum, default_value = "full")]
    profile: ProfileArg,

    /// Comma-separated port list or ranges (e.g. `80,443,8000-8080`).
    /// Overrides the profile default when specified.
    #[arg(long, value_name = "PORTS")]
    ports: Option<String>,

    /// Maximum concurrent workers.
    #[arg(short = 'j', long, value_name = "N", env = "ALOO_PARALLELISM")]
    parallelism: Option<usize>,

    /// Connection timeout in milliseconds.
    #[arg(short = 't', long, value_name = "MS", default_value = "3000")]
    timeout: u64,

    /// Rate limit in packets per second (0 = unlimited).
    #[arg(short = 'r', long, value_name = "PPS", default_value = "1000")]
    rate: u32,

    /// Write JSON output to a file.
    #[arg(long, value_name = "FILE")]
    json_out: Option<PathBuf>,

    /// Write an HTML report to a file.
    #[arg(long, value_name = "FILE")]
    html_out: Option<PathBuf>,

    /// Write a Markdown report to a file.
    #[arg(long, value_name = "FILE")]
    md_out: Option<PathBuf>,

    /// Skip host discovery (treat all targets as alive).
    #[arg(long)]
    skip_discovery: bool,

    /// Skip service banner grabbing.
    #[arg(long)]
    no_banner: bool,

    /// Disable TLS analysis.
    #[arg(long)]
    no_tls: bool,

    /// Disable vulnerability correlation.
    #[arg(long)]
    no_vuln: bool,
}

/// Scan profile options for the CLI.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProfileArg {
    /// Top 1024 ports, fast timeouts.
    Quick,
    /// All 65535 ports, all probes.
    Full,
    /// Slow rate, minimal footprint.
    Stealth,
    /// UDP scan only.
    Udp,
}

// ── Report ────────────────────────────────────────────────────────────────────

/// Arguments for the `report` subcommand.
#[derive(Debug, Parser)]
struct ReportArgs {
    /// Session ID to generate a report for (omit to use the most recent session).
    #[arg(value_name = "SESSION_ID")]
    session_id: Option<String>,

    /// Output format.
    #[arg(short = 'f', long, value_enum, default_value = "json")]
    format: ReportFormatArg,

    /// Output file (default: stdout).
    #[arg(short = 'o', long, value_name = "FILE")]
    output: Option<PathBuf>,
}

/// Report format options.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum ReportFormatArg {
    Json,
    Html,
    Markdown,
}

// ── Plugin ────────────────────────────────────────────────────────────────────

/// Arguments for the `plugin` subcommand.
#[derive(Debug, Parser)]
struct PluginArgs {
    #[command(subcommand)]
    action: PluginAction,
}

#[derive(Debug, Subcommand)]
enum PluginAction {
    /// List all installed plugins.
    List,
    /// Install a plugin from a manifest file.
    Install {
        /// Path to the plugin manifest (.toml).
        #[arg(value_name = "MANIFEST")]
        manifest: PathBuf,
    },
    /// Remove an installed plugin by ID.
    Remove {
        /// Plugin ID to remove.
        #[arg(value_name = "PLUGIN_ID")]
        id: String,
    },
}

// ── History ───────────────────────────────────────────────────────────────────

/// Arguments for the `history` subcommand.
#[derive(Debug, Parser)]
struct HistoryArgs {
    /// Maximum number of sessions to display.
    #[arg(short = 'n', long, default_value = "20")]
    limit: usize,

    /// Show only sessions with a specific status.
    #[arg(long, value_name = "STATUS")]
    status: Option<String>,
}

// ── Command handlers ──────────────────────────────────────────────────────────

async fn run_scan(args: ScanArgs, cfg: aloo_config::AlooConfig) -> Result<()> {
    let targets_display = args.targets.join(", ");
    
    // A stunning, modern ASCII banner for Aloo
    let banner = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n",
        style("    ___    __               ").cyan().bold(),
        style("   /   |  / /___  ____      ").cyan().bold(),
        style("  / /| | / / __ \\/ __ \\ ").cyan().bold(),
        style(" / ___ |/ / /_/ / /_/ /     ").cyan().bold(),
        style("/_/  |_/_/\\____/\\____/  ").cyan().bold(),
        style("                            ").cyan().bold()
    );

    println!("{}", banner);
    println!("{} {}", style("Aloo Network Intelligence").bold(), style(env!("CARGO_PKG_VERSION")).dim());
    println!("{}", style("==================================================").dim());
    println!(
        "{:<15} {}",
        style("Target(s):").cyan().bold(),
        style(&targets_display).yellow()
    );
    println!(
        "{:<15} {}",
        style("Profile:").cyan().bold(),
        style(format!("{:?}", args.profile)).green()
    );
    println!(
        "{:<15} {}",
        style("Rate Limit:").cyan().bold(),
        style(format!("{} pps", cfg.scan.rate_limit_pps)).magenta()
    );
    println!("{}", style("==================================================\n").dim());

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template("{spinner:.cyan} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    pb.set_message("Initializing Aloo Engine...");
    pb.enable_steady_tick(std::time::Duration::from_millis(80));

    let engine = aloo_engine::AlooEngine::builder()
        .config(cfg)
        .build();

    pb.set_message(format!("Scanning {} target(s) [Engine Active]...", args.targets.len()));

    let result = aloo_traits::ScanEngine::run(&engine, args.targets).await?;

    pb.finish_and_clear();

    println!("\n{}", style("==================================================").dim());
    println!(
        "{} {}",
        style("✔ Scan Completed").green().bold(),
        style(format!("in {} ms", result.session.completed_at.unwrap_or(chrono::Utc::now()).timestamp_millis() - result.session.started_at.timestamp_millis())).dim()
    );
    println!("{}", style("==================================================").dim());
    println!(
        "{:<20} {}",
        style("Hosts Discovered:").cyan(),
        style(result.hosts.len().to_string()).white().bold()
    );
    println!(
        "{:<20} {}",
        style("Open Ports:").cyan(),
        style(result.total_open_ports().to_string()).yellow().bold()
    );
    println!(
        "{:<20} {}",
        style("Vulnerabilities:").cyan(),
        style(result.total_vulnerabilities().to_string()).red().bold()
    );
    println!("{}\n", style("==================================================").dim());

    // Write JSON output if requested
    if let Some(path) = &args.json_out {
        let reporter = aloo_report::JsonReporter::pretty();
        let json = aloo_traits::Reporter::render_to_string(&reporter, &result).await?;
        std::fs::write(path, &json)?;
        println!("{} JSON report written to {}", style("→").dim(), path.display());
    }

    // Write HTML output if requested
    if let Some(path) = &args.html_out {
        let reporter = aloo_report::HtmlReporter;
        let html = aloo_traits::Reporter::render_to_string(&reporter, &result).await?;
        std::fs::write(path, &html)?;
        println!("{} HTML report written to {}", style("→").dim(), path.display());
    }

    // Write Markdown output if requested
    if let Some(path) = &args.md_out {
        let reporter = aloo_report::MarkdownReporter;
        let md = aloo_traits::Reporter::render_to_string(&reporter, &result).await?;
        std::fs::write(path, &md)?;
        println!("{} Markdown report written to {}", style("→").dim(), path.display());
    }

    Ok(())
}

async fn run_report(args: ReportArgs) -> Result<()> {
    let session_id = args.session_id.as_deref().unwrap_or("<latest>");
    println!(
        "{} Generating {} report for session {}",
        style("▶").cyan().bold(),
        style(format!("{:?}", args.format)).yellow(),
        style(session_id).dim(),
    );
    println!("{} Report command stub — storage not yet connected.\n", style("ℹ").blue());
    Ok(())
}

async fn run_plugin(args: PluginArgs) -> Result<()> {
    match args.action {
        PluginAction::List => {
            println!("{} Plugin registry stub — no plugins installed.\n", style("ℹ").blue());
        }
        PluginAction::Install { manifest } => {
            println!(
                "{} Installing plugin from {} (stub)\n",
                style("▶").cyan().bold(),
                manifest.display()
            );
        }
        PluginAction::Remove { id } => {
            println!("{} Removing plugin '{}' (stub)\n", style("▶").cyan().bold(), id);
        }
    }
    Ok(())
}

async fn run_history(args: HistoryArgs) -> Result<()> {
    println!(
        "{} Listing last {} session(s) (stub — no history yet)\n",
        style("ℹ").blue(),
        args.limit,
    );
    Ok(())
}

fn print_version() {
    println!(
        "\n  {} {}\n  {}\n  {}\n",
        style("aloo").cyan().bold(),
        style(env!("CARGO_PKG_VERSION")).yellow(),
        style("The next-generation network intelligence platform.").dim(),
        style("https://github.com/ianshshakya/aloo").dim(),
    );
}

// ── Tracing initialisation ────────────────────────────────────────────────────

fn init_tracing(verbose: u8, json: bool) {
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    let level = match verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    // Respect RUST_LOG if set, otherwise fall back to verbosity level
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("aloo={level},aloo_engine={level}")));

    if json {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().with_target(verbose > 1))
            .init();
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    init_tracing(cli.verbose, cli.json_logs);

    // Load configuration
    let mut cfg = match &cli.config {
        Some(path) => aloo_config::ConfigLoader::from_file(path)
            .map_err(|e| anyhow::anyhow!("Config error: {e}"))?,
        None => aloo_config::ConfigLoader::load_default(),
    };
    cfg = aloo_config::ConfigLoader::apply_env(cfg);

    info!(version = env!("CARGO_PKG_VERSION"), "Aloo starting");

    match cli.command {
        Commands::Scan(args)    => run_scan(args, cfg).await?,
        Commands::Report(args)  => run_report(args).await?,
        Commands::Plugin(args)  => run_plugin(args).await?,
        Commands::History(args) => run_history(args).await?,
        Commands::Version       => print_version(),
    }

    Ok(())
}

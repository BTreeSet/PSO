use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use pso::api::ProtonApiClient;
use pso::control_plane::{ControlPlane, ControlPlaneConfig};
use pso::deploy::{DeployPlan, deploy_with_sighup, validate_singbox_config};
use pso::health::HealthMonitor;
use pso::model::{PhysicalServer, ProtonLogicalResponse};
use pso::process::find_process_pid;
use pso::provisioning::LocalKeyProvisioner;
use pso::session::{SessionStore, UserSession};
use pso::template::hydrate_template;
use serde_json::Value;
use tracing::info;

#[derive(Debug, Parser)]
#[command(name = "pso", about = "Proton-Singbox Orchestrator")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Render(RenderArgs),
    Baseline,
    Probe(ProbeArgs),
    ControlPlane(ControlPlaneArgs),
    FetchLogicals(FetchLogicalsArgs),
}

#[derive(Debug, Args)]
struct RenderArgs {
    #[arg(long, default_value = "config.template.json")]
    template: PathBuf,
    #[arg(long, default_value = "proton-logicals.json")]
    topology: PathBuf,
    #[arg(long, default_value = "rendered.config.json.tmp")]
    output: PathBuf,
    #[arg(long)]
    active_config: Option<PathBuf>,
    #[arg(long)]
    singbox_pid: Option<i32>,
    #[arg(long, default_value = "sing-box")]
    singbox_bin: PathBuf,
    #[arg(long = "session", value_parser = parse_session, required = true)]
    sessions: Vec<(String, String)>,
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Args)]
struct ProbeArgs {
    #[arg(long)]
    raw_ip: Option<String>,
    #[arg(long)]
    proxy_url: Option<String>,
    #[arg(long, default_value = "60")]
    interval_secs: u64,
    #[arg(long)]
    loop_forever: bool,
    #[arg(long, default_value = "manual-probe")]
    outbound_tag: String,
}

#[derive(Debug, Args)]
struct ControlPlaneArgs {
    #[arg(long, env = "PSO_PROTON_ACCESS_TOKEN")]
    access_token: String,
    #[arg(long, default_value = "https://api.protonvpn.ch")]
    api_base_url: String,
    #[arg(long)]
    active_config: PathBuf,
    #[arg(long)]
    singbox_pid: Option<i32>,
    #[arg(long, default_value = "proton-wg")]
    outbound_tag: String,
    #[arg(long)]
    endpoint: String,
    #[arg(long)]
    peer_public_key: Option<String>,
}

#[derive(Debug, Args)]
struct FetchLogicalsArgs {
    #[arg(long, env = "PSO_PROTON_ACCESS_TOKEN")]
    access_token: String,
    #[arg(long, default_value = "https://api.protonvpn.ch")]
    api_base_url: String,
    #[arg(long, default_value = "proton-logicals.json")]
    output: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Render(args) => render(args).await,
        Command::Baseline => {
            let ip = HealthMonitor::acquire_baseline().await?;
            println!("{ip}");
            Ok(())
        }
        Command::Probe(args) => probe(args).await,
        Command::ControlPlane(args) => control_plane(args).await,
        Command::FetchLogicals(args) => fetch_logicals(args).await,
    }
}

async fn render(args: RenderArgs) -> Result<()> {
    let template: Value = read_json(&args.template)?;
    let topology_response: ProtonLogicalResponse = read_json(&args.topology)?;
    let sessions = SessionStore::new();
    for (username, tier) in args.sessions {
        sessions.insert(UserSession::new(username, tier));
    }

    let provisioner = LocalKeyProvisioner::default();
    let rendered = hydrate_template(
        &template,
        &sessions,
        &topology_response.into_servers(),
        &provisioner,
    )?;
    let rendered_text = serde_json::to_string_pretty(&rendered)?;
    fs::write(&args.output, rendered_text)
        .with_context(|| format!("failed to write {}", args.output.display()))?;
    info!(path = %args.output.display(), "rendered hydrated sing-box config");

    if args.dry_run {
        return Ok(());
    }

    validate_singbox_config(&args.singbox_bin, &args.output).await?;
    if let (Some(active_config), Some(singbox_pid)) = (args.active_config, args.singbox_pid) {
        deploy_with_sighup(&DeployPlan {
            singbox_bin: args.singbox_bin,
            rendered_tmp: args.output,
            active_config,
            singbox_pid,
        })
        .await?;
    }

    Ok(())
}

async fn probe(args: ProbeArgs) -> Result<()> {
    let raw_ip = match args.raw_ip {
        Some(ip) => ip,
        None => HealthMonitor::acquire_baseline().await?,
    };
    let monitor = HealthMonitor::new(raw_ip, Duration::from_secs(args.interval_secs))?;

    if args.loop_forever {
        monitor.run_loop(args.outbound_tag, args.proxy_url).await
    } else {
        let result = monitor.probe_once(args.proxy_url.as_deref()).await;
        println!("{result:?}");
        Ok(())
    }
}

async fn control_plane(args: ControlPlaneArgs) -> Result<()> {
    let singbox_pid = match args.singbox_pid {
        Some(pid) => pid,
        None => find_process_pid("sing-box").context("sing-box process was not found")?,
    };
    let api = ProtonApiClient::new(args.api_base_url)?;
    let control_plane = ControlPlane::new(api);
    control_plane
        .run_refresh_loop(ControlPlaneConfig {
            access_token: args.access_token,
            active_config: args.active_config,
            singbox_pid,
            outbound_tag: args.outbound_tag,
            selected_server: PhysicalServer {
                id: String::new(),
                name: String::new(),
                entry_ip: Some(args.endpoint),
                entry_ipv6: None,
                exit_ip: None,
                domain: None,
                label: None,
                status: 1,
                load: None,
                public_key: args.peer_public_key,
                generation: None,
                services_down: Some(0),
                services_down_reason: None,
            },
        })
        .await
}

async fn fetch_logicals(args: FetchLogicalsArgs) -> Result<()> {
    let api = ProtonApiClient::new(args.api_base_url)?;
    let logicals = api.get_logicals(&args.access_token).await?;
    let value = serde_json::json!({ "LogicalServers": logicals });
    fs::write(&args.output, serde_json::to_string_pretty(&value)?)
        .with_context(|| format!("failed to write {}", args.output.display()))?;
    Ok(())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &PathBuf) -> Result<T> {
    let text =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("failed to parse {}", path.display()))
}

fn parse_session(value: &str) -> Result<(String, String), String> {
    let (username, tier) = value
        .split_once(':')
        .ok_or_else(|| "session must use username:tier format".to_string())?;
    Ok((username.to_string(), tier.to_string()))
}

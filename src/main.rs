use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use pso::api::{AuthTokens, ProtonApiClient};
use pso::auth::{calculate_srp_proof, resolve_two_factor_code};
use pso::control_plane::{ControlPlane, ControlPlaneConfig};
use pso::deploy::{DeployPlan, deploy_with_sighup, validate_singbox_config};
use pso::health::{HealthMonitor, HealthStatus};
use pso::model::{PhysicalServer, ProtonLogicalResponse};
use pso::process::{find_process_pid, find_process_pid_by_exe};
use pso::provisioning::LocalKeyProvisioner;
use pso::session::{SessionStore, UserSession};
use pso::template::hydrate_template;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::time::sleep;
use tracing::info;

#[derive(Debug, Parser)]
#[command(name = "pso", about = "Proton-Singbox Orchestrator")]
struct Cli {
    #[arg(long, default_value = "pso.config.json")]
    config: PathBuf,
    #[arg(long, env = "PSO_STATE_DIR")]
    state_dir: Option<PathBuf>,
    #[arg(long, env = "PSO_API_BASE_URL")]
    api_base_url: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Run(RunArgs),
    Render(RenderArgs),
    Health(HealthArgs),
    ControlPlane(ControlPlaneArgs),
    Auth(AuthArgs),
    Topology(TopologyArgs),
}

#[derive(Debug, Args)]
struct AuthArgs {
    #[command(subcommand)]
    command: AuthCommand,
}

#[derive(Debug, Subcommand)]
enum AuthCommand {
    Login(LoginArgs),
    Refresh(RefreshVpnTokenArgs),
}

#[derive(Debug, Args)]
struct TopologyArgs {
    #[command(subcommand)]
    command: TopologyCommand,
}

#[derive(Debug, Subcommand)]
enum TopologyCommand {
    Fetch(FetchLogicalsArgs),
}

#[derive(Debug, Args)]
struct HealthArgs {
    #[command(subcommand)]
    command: HealthCommand,
}

#[derive(Debug, Subcommand)]
enum HealthCommand {
    Baseline,
    Probe(ProbeArgs),
}

#[derive(Debug, Args)]
struct RenderArgs {
    #[arg(long)]
    template: Option<PathBuf>,
    #[arg(long)]
    topology: Option<PathBuf>,
    #[arg(long)]
    output: Option<PathBuf>,
    #[arg(long)]
    active_config: Option<PathBuf>,
    #[arg(long)]
    singbox_pid: Option<i32>,
    #[arg(long)]
    singbox_bin: Option<PathBuf>,
    #[arg(long = "session", value_parser = parse_session)]
    sessions: Vec<(String, String)>,
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Args)]
struct RunArgs {
    #[arg(long, env = "PSO_PROTON_ACCESS_TOKEN")]
    access_token: Option<String>,
    #[arg(long)]
    raw_ip: Option<String>,
    #[arg(long)]
    proxy_url: Option<String>,
    #[arg(long)]
    once: bool,
    #[arg(long)]
    interval_secs: Option<u64>,
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
    #[arg(long)]
    active_config: Option<PathBuf>,
    #[arg(long)]
    singbox_pid: Option<i32>,
    #[arg(long)]
    singbox_bin: Option<PathBuf>,
    #[arg(long)]
    outbound_tag: Option<String>,
    #[arg(long)]
    endpoint: Option<String>,
    #[arg(long)]
    peer_public_key: Option<String>,
}

#[derive(Debug, Args)]
struct FetchLogicalsArgs {
    #[arg(long, env = "PSO_PROTON_ACCESS_TOKEN")]
    access_token: String,
    #[arg(long, default_value = "proton-logicals.json")]
    output: PathBuf,
    #[arg(long)]
    fallback_topology: Option<PathBuf>,
    #[arg(long)]
    require_live: bool,
}

#[derive(Debug, Args)]
struct LoginArgs {
    #[arg(long)]
    username: Option<String>,
    #[arg(long, env = "PSO_PROTON_PASSWORD")]
    password: Option<String>,
    #[arg(long, env = "PSO_PROTON_PASSWORD_FILE")]
    password_file: Option<PathBuf>,
    #[arg(long)]
    no_prompt: bool,
    #[arg(
        long,
        env = "PSO_PROTON_TOTP",
        help = "Six-digit 2FA code, base32 TOTP secret, or otpauth:// URI"
    )]
    totp: Option<String>,
    #[arg(long)]
    human_verification_token: Option<String>,
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct RefreshVpnTokenArgs {
    #[arg(long)]
    username: Option<String>,
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Clone, Debug)]
struct RuntimeContext {
    api_base_url: String,
    state_dir: PathBuf,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct AppConfig {
    api_base_url: Option<String>,
    state_dir: Option<PathBuf>,
    auth: AuthConfig,
    topology: TopologyConfig,
    render: RenderConfig,
    control_plane: ControlPlaneDefaults,
    run: RunConfig,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct AuthConfig {
    username: Option<String>,
    password: Option<String>,
    password_file: Option<PathBuf>,
    totp: Option<String>,
    no_prompt: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct TopologyConfig {
    fallback_topology: Option<PathBuf>,
    require_live: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct RenderConfig {
    template: Option<PathBuf>,
    topology: Option<PathBuf>,
    output: Option<PathBuf>,
    active_config: Option<PathBuf>,
    singbox_pid: Option<i32>,
    singbox_bin: Option<PathBuf>,
    sessions: Vec<SessionEntry>,
    dry_run: Option<bool>,
}

#[derive(Clone, Debug, Deserialize)]
struct SessionEntry {
    username: String,
    tier: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct ControlPlaneDefaults {
    active_config: Option<PathBuf>,
    singbox_pid: Option<i32>,
    singbox_bin: Option<PathBuf>,
    outbound_tag: Option<String>,
    endpoint: Option<String>,
    peer_public_key: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct RunConfig {
    proxy_url: Option<String>,
    interval_secs: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct VpnSessionState {
    uid: String,
    refresh_token: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let config = read_optional_config(&cli.config)?;
    let context = RuntimeContext {
        api_base_url: cli
            .api_base_url
            .or(config.api_base_url.clone())
            .unwrap_or_else(|| "https://api.protonvpn.ch".to_string()),
        state_dir: cli
            .state_dir
            .or(config.state_dir.clone())
            .unwrap_or_else(|| PathBuf::from("pso-state")),
    };

    match cli.command {
        Command::Run(args) => run(&context, &config, args).await,
        Command::Render(args) => render(&config.render, args).await,
        Command::Health(args) => match args.command {
            HealthCommand::Baseline => {
                let ip = HealthMonitor::acquire_baseline().await?;
                println!("{ip}");
                Ok(())
            }
            HealthCommand::Probe(args) => probe(args).await,
        },
        Command::ControlPlane(args) => control_plane(&context, &config.control_plane, args).await,
        Command::Auth(args) => match args.command {
            AuthCommand::Login(args) => login(&context, &config.auth, args).await,
            AuthCommand::Refresh(args) => refresh_vpn_token(&context, &config.auth, args).await,
        },
        Command::Topology(args) => match args.command {
            TopologyCommand::Fetch(args) => fetch_logicals(&context, &config.topology, args).await,
        },
    }
}

async fn run(context: &RuntimeContext, config: &AppConfig, args: RunArgs) -> Result<()> {
    let interval = Duration::from_secs(
        args.interval_secs
            .or(config.run.interval_secs)
            .unwrap_or(300),
    );
    let proxy_url = args.proxy_url.or(config.run.proxy_url.clone());
    let raw_ip = match args.raw_ip {
        Some(ip) => ip,
        None => HealthMonitor::acquire_baseline().await?,
    };
    let monitor = HealthMonitor::new(raw_ip, interval)?;

    loop {
        let access_token = resolve_run_access_token(context, args.access_token.as_deref()).await?;
        let topology_output = config
            .render
            .topology
            .clone()
            .unwrap_or_else(|| PathBuf::from("proton-logicals.json"));
        fetch_logicals(
            context,
            &config.topology,
            FetchLogicalsArgs {
                access_token,
                output: topology_output,
                fallback_topology: None,
                require_live: false,
            },
        )
        .await?;

        render(
            &config.render,
            RenderArgs {
                template: None,
                topology: None,
                output: None,
                active_config: None,
                singbox_pid: None,
                singbox_bin: None,
                sessions: Vec::new(),
                dry_run: false,
            },
        )
        .await?;

        let probe = monitor.probe_once(proxy_url.as_deref()).await;
        if probe.status != HealthStatus::Healthy {
            eprintln!(
                "warning: health probe reported {:?}; next cycle will refresh state and render again",
                probe.status
            );
        }

        if args.once {
            return Ok(());
        }
        sleep(interval).await;
    }
}

async fn resolve_run_access_token(
    context: &RuntimeContext,
    access_token: Option<&str>,
) -> Result<String> {
    if let Some(access_token) = access_token {
        return Ok(access_token.to_string());
    }

    let session_state = context.state_dir.join("vpn-session.json");
    let state = load_vpn_session_state(&session_state)?;
    let api = ProtonApiClient::new(&context.api_base_url)?;
    let refreshed: AuthTokens = api
        .refresh_session(&state.uid, &state.refresh_token)
        .await
        .context("failed to refresh VPN token from state")?;
    let uid = refreshed.uid.as_deref().unwrap_or(&state.uid);
    store_vpn_session_state(uid, &refreshed.refresh_token, &session_state)?;
    Ok(refreshed.access_token)
}

async fn render(config: &RenderConfig, args: RenderArgs) -> Result<()> {
    let template_path = args
        .template
        .or(config.template.clone())
        .unwrap_or_else(|| PathBuf::from("config.template.json"));
    let topology_path = args
        .topology
        .or(config.topology.clone())
        .unwrap_or_else(|| PathBuf::from("proton-logicals.json"));
    let output_path = args
        .output
        .or(config.output.clone())
        .unwrap_or_else(|| PathBuf::from("rendered.config.json.tmp"));
    let active_config = args.active_config.or(config.active_config.clone());
    let singbox_pid = args.singbox_pid.or(config.singbox_pid);
    let singbox_bin = args
        .singbox_bin
        .or(config.singbox_bin.clone())
        .unwrap_or_else(|| PathBuf::from("sing-box"));
    let resolved_sessions = resolve_sessions(args.sessions, &config.sessions)?;
    let dry_run = args.dry_run || config.dry_run.unwrap_or(false);

    let template: Value = read_json(&template_path)?;
    let topology_response: ProtonLogicalResponse = read_json(&topology_path)?;
    let sessions = SessionStore::new();
    for (username, tier) in resolved_sessions {
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
    fs::write(&output_path, rendered_text)
        .with_context(|| format!("failed to write {}", output_path.display()))?;
    info!(path = %output_path.display(), "rendered hydrated sing-box config");

    if dry_run {
        return Ok(());
    }

    validate_singbox_config(&singbox_bin, &output_path).await?;
    if let (Some(active_config), Some(singbox_pid)) = (active_config, singbox_pid) {
        deploy_with_sighup(&DeployPlan {
            singbox_bin,
            rendered_tmp: output_path,
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

async fn control_plane(
    context: &RuntimeContext,
    config: &ControlPlaneDefaults,
    args: ControlPlaneArgs,
) -> Result<()> {
    let singbox_bin = args
        .singbox_bin
        .or(config.singbox_bin.clone())
        .unwrap_or_else(|| PathBuf::from("sing-box"));
    let singbox_pid = match args.singbox_pid.or(config.singbox_pid) {
        Some(pid) => pid,
        None => resolve_singbox_pid(&singbox_bin)?,
    };
    let active_config = args
        .active_config
        .or(config.active_config.clone())
        .context("active config path is required; pass --active-config or set control_plane.active_config")?;
    let endpoint = args
        .endpoint
        .or(config.endpoint.clone())
        .context("endpoint is required; pass --endpoint or set control_plane.endpoint")?;
    let api = ProtonApiClient::new(&context.api_base_url)?;
    let control_plane = ControlPlane::new(api);
    control_plane
        .run_refresh_loop(ControlPlaneConfig {
            access_token: args.access_token,
            active_config,
            singbox_pid,
            outbound_tag: args
                .outbound_tag
                .or(config.outbound_tag.clone())
                .unwrap_or_else(|| "proton-wg".to_string()),
            selected_server: PhysicalServer {
                id: String::new(),
                name: String::new(),
                entry_ip: Some(endpoint),
                entry_ipv6: None,
                exit_ip: None,
                domain: None,
                label: None,
                status: 1,
                load: None,
                public_key: args.peer_public_key.or(config.peer_public_key.clone()),
                generation: None,
                services_down: Some(0),
                services_down_reason: None,
            },
        })
        .await
}

async fn fetch_logicals(
    context: &RuntimeContext,
    config: &TopologyConfig,
    args: FetchLogicalsArgs,
) -> Result<()> {
    let api = ProtonApiClient::new(&context.api_base_url)?;
    let state_logicals = context.state_dir.join("logicals.json");
    let fallback_topology = args
        .fallback_topology
        .as_ref()
        .or(config.fallback_topology.as_ref());
    let require_live = args.require_live || config.require_live.unwrap_or(false);
    match api.get_logicals(&args.access_token).await {
        Ok(logicals) => {
            let value = serde_json::json!({ "LogicalServers": logicals });
            let text = serde_json::to_string_pretty(&value)?;
            fs::write(&args.output, &text)
                .with_context(|| format!("failed to write {}", args.output.display()))?;
            write_state_file(&state_logicals, &text)?;
        }
        Err(error) if require_live => return Err(error),
        Err(error) => write_logicals_from_available_state(
            &args.output,
            &state_logicals,
            fallback_topology,
            error,
        )?,
    }
    Ok(())
}

fn write_logicals_from_available_state(
    output: &PathBuf,
    state_logicals: &PathBuf,
    fallback_topology: Option<&PathBuf>,
    error: anyhow::Error,
) -> Result<()> {
    let source = match fallback_topology {
        Some(path) if path.exists() => {
            eprintln!(
                "warning: /vpn/logicals fetch failed, using fallback topology from {}: {error:#}",
                path.display()
            );
            path
        }
        _ if state_logicals.exists() => {
            eprintln!(
                "warning: /vpn/logicals fetch failed, using topology state from {}: {error:#}",
                state_logicals.display()
            );
            state_logicals
        }
        Some(path) => anyhow::bail!(
            "/vpn/logicals fetch failed and fallback topology {} does not exist: {error:#}",
            path.display()
        ),
        None => return Err(error),
    };

    let logicals: ProtonLogicalResponse = read_json(source)?;
    let value = serde_json::json!({ "LogicalServers": logicals.into_servers() });
    fs::write(output, serde_json::to_string_pretty(&value)?)
        .with_context(|| format!("failed to write {}", output.display()))
}

async fn login(context: &RuntimeContext, config: &AuthConfig, args: LoginArgs) -> Result<()> {
    let username = args
        .username
        .or(config.username.clone())
        .context("username is required; pass --username or set auth.username in config")?;
    let password = match args.password.or(config.password.clone()) {
        Some(password) => password,
        None => match args.password_file.or(config.password_file.clone()) {
            Some(path) => fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?
                .trim_end_matches(['\r', '\n'])
                .to_string(),
            None if !(args.no_prompt || config.no_prompt.unwrap_or(false)) => {
                rpassword::prompt_password("Proton password: ")?
            }
            None => anyhow::bail!(
                "password is required; pass --password, PSO_PROTON_PASSWORD, --password-file, or PSO_PROTON_PASSWORD_FILE"
            ),
        },
    };

    let api = ProtonApiClient::new(&context.api_base_url)?;
    let info = api
        .auth_info(&username, args.human_verification_token.as_deref())
        .await?;
    if info.version != 4 {
        anyhow::bail!("unsupported Proton SRP auth version {}", info.version);
    }

    let totp_arg = args.totp.or(config.totp.clone());
    let no_prompt = args.no_prompt || config.no_prompt.unwrap_or(false);
    let two_factor_input = if info.two_factor.unwrap_or(0) > 0 && totp_arg.is_none() && !no_prompt {
        Some(rpassword::prompt_password("Proton TOTP: ")?)
    } else if info.two_factor.unwrap_or(0) > 0 && totp_arg.is_none() {
        anyhow::bail!("TOTP is required for this account; pass --totp or PSO_PROTON_TOTP")
    } else {
        totp_arg
    };
    let totp = two_factor_input
        .as_deref()
        .map(resolve_two_factor_code)
        .transpose()?;

    let proof = calculate_srp_proof(
        &username,
        &password,
        &info.salt,
        &info.modulus,
        &info.server_ephemeral,
    )?;
    let primary = api
        .authenticate(
            &username,
            &proof,
            &info.modulus,
            totp.as_deref(),
            args.human_verification_token.as_deref(),
        )
        .await?;
    let vpn = api.fork_vpn_session(&primary.access_token, None).await?;

    let uid = vpn
        .uid
        .clone()
        .or(primary.uid.clone())
        .context("Proton login response did not include UID for session state")?;
    store_vpn_session_state(
        &uid,
        &vpn.refresh_token,
        &context.state_dir.join("vpn-session.json"),
    )?;

    if let Some(output) = args.output {
        fs::write(&output, serde_json::to_string_pretty(&vpn)?)
            .with_context(|| format!("failed to write {}", output.display()))?;
    } else {
        println!("{}", serde_json::to_string_pretty(&vpn)?);
    }

    Ok(())
}

async fn refresh_vpn_token(
    context: &RuntimeContext,
    config: &AuthConfig,
    args: RefreshVpnTokenArgs,
) -> Result<()> {
    let _username = args
        .username
        .or(config.username.clone())
        .context("username is required; pass --username or set auth.username in config")?;
    let session_state = context.state_dir.join("vpn-session.json");
    let state = load_vpn_session_state(&session_state)?;
    let api = ProtonApiClient::new(&context.api_base_url)?;
    let refreshed = api
        .refresh_session(&state.uid, &state.refresh_token)
        .await?;
    let uid = refreshed.uid.as_deref().unwrap_or(&state.uid);
    store_vpn_session_state(uid, &refreshed.refresh_token, &session_state)?;

    if let Some(output) = args.output {
        fs::write(&output, serde_json::to_string_pretty(&refreshed)?)
            .with_context(|| format!("failed to write {}", output.display()))?;
    } else {
        println!("{}", serde_json::to_string_pretty(&refreshed)?);
    }

    Ok(())
}

fn store_vpn_session_state(uid: &str, refresh_token: &str, state_file: &PathBuf) -> Result<()> {
    let state = VpnSessionState {
        uid: uid.to_string(),
        refresh_token: refresh_token.to_string(),
    };
    let text = serde_json::to_string(&state)?;
    write_state_file(state_file, &text)
}

fn load_vpn_session_state(state_file: &PathBuf) -> Result<VpnSessionState> {
    let state = fs::read_to_string(state_file)
        .with_context(|| format!("failed to read {}", state_file.display()))?;
    serde_json::from_str(&state).context("failed to decode VPN session state")
}

fn read_optional_config(path: &PathBuf) -> Result<AppConfig> {
    if !path.exists() {
        return Ok(AppConfig::default());
    }
    read_json(path)
}

fn write_state_file(path: &PathBuf, text: &str) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(path, text).with_context(|| format!("failed to write {}", path.display()))
}

fn resolve_sessions(
    cli_sessions: Vec<(String, String)>,
    config_sessions: &[SessionEntry],
) -> Result<Vec<(String, String)>> {
    if !cli_sessions.is_empty() {
        return Ok(cli_sessions);
    }
    let sessions: Vec<_> = config_sessions
        .iter()
        .map(|session| (session.username.clone(), session.tier.clone()))
        .collect();
    if sessions.is_empty() {
        anyhow::bail!(
            "at least one render session is required; pass --session username:tier or set render.sessions in config"
        )
    }
    Ok(sessions)
}

fn resolve_singbox_pid(singbox_bin: &Path) -> Result<i32> {
    match find_process_pid_by_exe(singbox_bin) {
        Ok(Some(pid)) => Ok(pid),
        Ok(None) => find_process_pid("sing-box").with_context(|| {
            format!(
                "sing-box process was not found for executable {}; pass --singbox-pid to target an explicit process",
                singbox_bin.display()
            )
        }),
        Err(error) => find_process_pid("sing-box").with_context(|| {
            format!(
                "failed to match sing-box executable path ({error:#}); pass --singbox-pid to target an explicit process"
            )
        }),
    }
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

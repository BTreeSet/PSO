use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "pso", about = "Proton-Singbox Orchestrator")]
pub struct Cli {
    #[arg(long, default_value = "pso.config.json")]
    pub config: PathBuf,
    #[arg(long, env = "PSO_STATE_DIR")]
    pub state_dir: Option<PathBuf>,
    #[arg(long, env = "PSO_API_BASE_URL")]
    pub api_base_url: Option<String>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Run(RunArgs),
    Render(RenderArgs),
    Health(HealthArgs),
    ControlPlane(ControlPlaneArgs),
    Auth(AuthArgs),
    Topology(TopologyArgs),
    Providers(ProvidersArgs),
    State(StateArgs),
    Debug(DebugArgs),
}

#[derive(Debug, Args)]
pub struct DebugArgs {
    #[command(subcommand)]
    pub command: DebugCommand,
}

#[derive(Debug, Subcommand)]
pub enum DebugCommand {
    Auth(DebugAuthArgs),
}

#[derive(Debug, Args)]
pub struct DebugAuthArgs {
    #[command(subcommand)]
    pub command: DebugAuthCommand,
}

#[derive(Debug, Subcommand)]
pub enum DebugAuthCommand {
    Login(LoginArgs),
}

#[derive(Debug, Args)]
pub struct AuthArgs {
    #[command(subcommand)]
    pub command: AuthCommand,
}

#[derive(Debug, Subcommand)]
pub enum AuthCommand {
    Login(LoginArgs),
    Refresh(RefreshVpnTokenArgs),
}

#[derive(Debug, Args)]
pub struct TopologyArgs {
    #[command(subcommand)]
    pub command: TopologyCommand,
}

#[derive(Debug, Subcommand)]
pub enum TopologyCommand {
    Fetch(FetchLogicalsArgs),
}

#[derive(Debug, Args)]
pub struct StateArgs {
    #[command(subcommand)]
    pub command: StateCommand,
}

#[derive(Debug, Subcommand)]
pub enum StateCommand {
    Users,
    Certs(StateListArgs),
    Wireguard(StateListArgs),
    Events(StateListArgs),
    Health(StateListArgs),
    Cookies(CookieArgs),
}

#[derive(Debug, Args)]
pub struct CookieArgs {
    #[command(subcommand)]
    pub command: CookieCommand,
}

#[derive(Debug, Subcommand)]
pub enum CookieCommand {
    Clear(CookieClearArgs),
}

#[derive(Debug, Args)]
pub struct CookieClearArgs {
    #[arg(long)]
    pub username: Option<String>,
    #[arg(long)]
    pub all: bool,
}

#[derive(Debug, Args)]
pub struct ProvidersArgs {
    #[command(subcommand)]
    pub command: ProvidersCommand,
}

#[derive(Debug, Subcommand)]
pub enum ProvidersCommand {
    List(ProviderListArgs),
}

#[derive(Debug, Args)]
pub struct ProviderListArgs {
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct StateListArgs {
    #[arg(long, default_value = "50")]
    pub limit: usize,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct HealthArgs {
    #[command(subcommand)]
    pub command: HealthCommand,
}

#[derive(Debug, Subcommand)]
pub enum HealthCommand {
    Baseline,
    Probe(ProbeArgs),
}

#[derive(Debug, Args)]
pub struct RenderArgs {
    #[arg(long)]
    pub template: Option<PathBuf>,
    #[arg(long)]
    pub topology: Option<PathBuf>,
    #[arg(long)]
    pub output: Option<PathBuf>,
    #[arg(long)]
    pub active_config: Option<PathBuf>,
    #[arg(long)]
    pub singbox_pid: Option<i32>,
    #[arg(long)]
    pub singbox_bin: Option<PathBuf>,
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    #[arg(long, env = "PSO_PROTON_ACCESS_TOKEN")]
    pub access_token: Option<String>,
    #[arg(long)]
    pub raw_ip: Option<String>,
    #[arg(long)]
    pub proxy_url: Option<String>,
    #[arg(long)]
    pub once: bool,
    #[arg(long)]
    pub interval_secs: Option<u64>,
}

#[derive(Debug, Args)]
pub struct ProbeArgs {
    #[arg(long)]
    pub raw_ip: Option<String>,
    #[arg(long)]
    pub proxy_url: Option<String>,
    #[arg(long, default_value = "60")]
    pub interval_secs: u64,
    #[arg(long)]
    pub loop_forever: bool,
    #[arg(long, default_value = "manual-probe")]
    pub outbound_tag: String,
}

#[derive(Debug, Args)]
pub struct ControlPlaneArgs {
    #[arg(long, env = "PSO_PROTON_ACCESS_TOKEN")]
    pub access_token: Option<String>,
    #[arg(long)]
    pub username: Option<String>,
    #[arg(long)]
    pub active_config: Option<PathBuf>,
    #[arg(long)]
    pub singbox_pid: Option<i32>,
    #[arg(long)]
    pub singbox_bin: Option<PathBuf>,
    #[arg(long)]
    pub outbound_tag: Option<String>,
    #[arg(long)]
    pub endpoint: Option<String>,
    #[arg(long)]
    pub peer_public_key: Option<String>,
}

#[derive(Debug, Args)]
pub struct FetchLogicalsArgs {
    #[arg(long, env = "PSO_PROTON_ACCESS_TOKEN")]
    pub access_token: Option<String>,
    #[arg(long)]
    pub username: Option<String>,
    #[arg(long, default_value = "proton-logicals.json")]
    pub output: PathBuf,
    #[arg(long)]
    pub fallback_topology: Option<PathBuf>,
    #[arg(long)]
    pub require_live: bool,
}

#[derive(Debug, Args)]
pub struct LoginArgs {
    #[arg(long)]
    pub username: Option<String>,
    #[arg(long, env = "PSO_PROTON_PASSWORD")]
    pub password: Option<String>,
    #[arg(long, env = "PSO_PROTON_PASSWORD_FILE")]
    pub password_file: Option<PathBuf>,
    #[arg(long)]
    pub no_prompt: bool,
    #[arg(
        long,
        env = "PSO_PROTON_TOTP",
        help = "Six-digit 2FA code, base32 TOTP secret, or otpauth:// URI"
    )]
    pub totp: Option<String>,
    #[arg(
        long,
        visible_alias = "captcha-token",
        env = "PSO_PROTON_HUMAN_VERIFICATION_TOKEN",
        help = "Resolved verification token returned after completing Proton CAPTCHA"
    )]
    pub human_verification_token: Option<String>,
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct RefreshVpnTokenArgs {
    #[arg(long)]
    pub username: Option<String>,
    #[arg(long)]
    pub output: Option<PathBuf>,
}

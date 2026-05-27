use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use pso::api::{AuthTokens, ProtonAccessToken, ProtonApiClient};
use pso::cli::{
    AuthCommand, Cli, Command, ControlPlaneArgs, DebugAuthCommand, DebugCommand, FetchLogicalsArgs,
    HealthCommand, LoginArgs, ProbeArgs, ProviderListArgs, ProvidersArgs, ProvidersCommand,
    RefreshVpnTokenArgs, RenderArgs, RunArgs, TopologyCommand,
};
use pso::config::{
    AppConfig, AuthConfig, ControlPlaneDefaults, DEFAULT_API_BASE_URL, DEFAULT_STATE_DIR,
    ProtonClientProfile, RuntimeContext, TopologyConfig, read_json, read_optional_config,
};
use pso::control_plane::{ControlPlane, ControlPlaneConfig};
use pso::health::HealthMonitor;
use pso::model::{PhysicalServer, ProtonLogicalResponse};
use pso::process::{find_process_pid, find_process_pid_by_exe};
use pso::proton::{
    CachedAccessToken, ConfiguredLoginOptions, login_configured_user, login_with_prompts,
    persist_proton_session,
};
use pso::provider::known_wireguard_providers;
use pso::state::{StateStore, topology_state_file, write_state_file};
use pso::supervisor::{SupervisorOptions, run_supervisor};
use pso::users::{ProtonUserRegistry, require_single_user_access_token};

mod state_cli;

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
            .unwrap_or_else(|| DEFAULT_API_BASE_URL.to_string()),
        state_dir: cli
            .state_dir
            .or(config.state_dir.clone())
            .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR)),
        proton_client: ProtonClientProfile::from_auth_config(&config.auth.proton),
    };

    match cli.command {
        Command::Run(args) => run(&context, &config, args).await,
        Command::Render(args) => render(&context, &config, args).await,
        Command::Health(args) => match args.command {
            HealthCommand::Baseline => {
                let ip = HealthMonitor::acquire_baseline().await?;
                println!("{ip}");
                Ok(())
            }
            HealthCommand::Probe(args) => probe(args).await,
        },
        Command::ControlPlane(args) => {
            control_plane(&context, &config.auth, &config.control_plane, args).await
        }
        Command::Auth(args) => match args.command {
            AuthCommand::Login(args) => login(&context, &config.auth, args, false).await,
            AuthCommand::Refresh(args) => refresh_vpn_token(&context, &config.auth, args).await,
        },
        Command::Topology(args) => match args.command {
            TopologyCommand::Fetch(args) => {
                fetch_logicals(&context, &config.auth, &config.topology, args).await
            }
        },
        Command::Providers(args) => providers(args),
        Command::State(args) => state_cli::run_state(&context, args),
        Command::Debug(args) => match args.command {
            DebugCommand::Auth(args) => match args.command {
                DebugAuthCommand::Login(args) => login(&context, &config.auth, args, true).await,
            },
        },
    }
}

fn providers(args: ProvidersArgs) -> Result<()> {
    match args.command {
        ProvidersCommand::List(args) => list_providers(args),
    }
}

fn list_providers(args: ProviderListArgs) -> Result<()> {
    let providers = known_wireguard_providers();
    if args.json {
        println!("{}", serde_json::to_string_pretty(providers)?);
        return Ok(());
    }

    println!("provider\tmode\tnotes");
    for provider in providers {
        println!("{}\t{}\t{}", provider.name, provider.mode, provider.notes);
    }
    Ok(())
}

async fn run(context: &RuntimeContext, config: &AppConfig, args: RunArgs) -> Result<()> {
    let interval = Duration::from_secs(
        args.interval_secs
            .or(config.run.interval_secs)
            .unwrap_or(300),
    );
    run_supervisor(
        context,
        config,
        SupervisorOptions {
            access_token: args.access_token,
            raw_ip: args.raw_ip,
            proxy_url: args.proxy_url.or(config.run.proxy_url.clone()),
            once: args.once,
            interval,
            session_keepalive_interval: None,
        },
    )
    .await
}

async fn render(context: &RuntimeContext, config: &AppConfig, args: RenderArgs) -> Result<()> {
    let mut render_config = config.clone();
    if let Some(template) = args.template {
        render_config.render.template = Some(template);
    }
    if let Some(topology) = args.topology {
        render_config.render.topology = Some(topology);
    }
    if let Some(output) = args.output {
        render_config.render.output = Some(output);
    }
    if let Some(active_config) = args.active_config {
        render_config.render.active_config = Some(active_config);
    }
    if let Some(singbox_pid) = args.singbox_pid {
        render_config.render.singbox_pid = Some(singbox_pid);
    }
    if let Some(singbox_bin) = args.singbox_bin {
        render_config.render.singbox_bin = Some(singbox_bin);
    }
    if args.dry_run {
        render_config.render.dry_run = Some(true);
    }

    let interval = Duration::from_secs(render_config.run.interval_secs.unwrap_or(300));
    run_supervisor(
        context,
        &render_config,
        SupervisorOptions {
            access_token: None,
            raw_ip: None,
            proxy_url: render_config.run.proxy_url.clone(),
            once: true,
            interval,
            session_keepalive_interval: None,
        },
    )
    .await
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
    auth: &AuthConfig,
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
    let username = args.username.or(config.username.clone());
    let access_token =
        resolve_manual_access_token(context, auth, args.access_token, username.as_deref()).await?;
    let api = ProtonApiClient::from_context(context)?;
    let control_plane = ControlPlane::new(api);
    control_plane
        .run_refresh_loop(ControlPlaneConfig {
            access_token,
            active_config,
            singbox_pid,
            outbound_tag: args
                .outbound_tag
                .or(config.outbound_tag.clone())
                .unwrap_or_else(|| "proton-wg".to_string()),
            device_name: context.proton_client.device_name.clone(),
            selected_server: PhysicalServer {
                id: String::new(),
                name: String::new(),
                entry_ip: Some(endpoint),
                entry_ipv6: None,
                entry_per_protocol: Default::default(),
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
    auth: &AuthConfig,
    config: &TopologyConfig,
    args: FetchLogicalsArgs,
) -> Result<()> {
    let api = ProtonApiClient::from_context(context)?;
    let state_logicals = topology_state_file(context);
    let username = args.username.or(config.username.clone());
    let access_token =
        resolve_manual_access_token(context, auth, args.access_token, username.as_deref()).await?;
    let fallback_topology = args
        .fallback_topology
        .as_ref()
        .or(config.fallback_topology.as_ref());
    let require_live = args.require_live || config.require_live.unwrap_or(false);
    match api
        .get_logicals(
            &access_token,
            config.country.as_deref(),
            config.netzone.as_deref(),
        )
        .await
    {
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
                "warning: /vpn/v2/logicals fetch failed, using fallback topology from {}: {error:#}",
                path.display()
            );
            path
        }
        _ if state_logicals.exists() => {
            eprintln!(
                "warning: /vpn/v2/logicals fetch failed, using topology state from {}: {error:#}",
                state_logicals.display()
            );
            state_logicals
        }
        Some(path) => anyhow::bail!(
            "/vpn/v2/logicals fetch failed and fallback topology {} does not exist: {error:#}",
            path.display()
        ),
        None => return Err(error),
    };

    let logicals: ProtonLogicalResponse = read_json(source)?;
    let value = serde_json::json!({ "LogicalServers": logicals.into_servers() });
    fs::write(output, serde_json::to_string_pretty(&value)?)
        .with_context(|| format!("failed to write {}", output.display()))
}

async fn login(
    context: &RuntimeContext,
    config: &AuthConfig,
    args: LoginArgs,
    debug_http: bool,
) -> Result<()> {
    let registry = ProtonUserRegistry::from_auth(config)?;
    let LoginArgs {
        username,
        password,
        password_file,
        no_prompt,
        totp,
        human_verification_token,
        output,
    } = args;
    let password_supplied = password.is_some() || password_file.is_some();
    let configured_login_options =
        |human_verification_token: Option<String>| ConfiguredLoginOptions {
            password_override: password.clone(),
            password_file_override: password_file.clone(),
            totp_override: totp.clone(),
            no_prompt_override: no_prompt,
            human_verification_token,
            debug_http,
        };
    let session = if let Some(username) = username {
        if !password_supplied {
            if let Some(session) =
                refresh_stored_login_session(context, &username, debug_http).await?
            {
                session
            } else if let Some(user) = registry.get_by_username(&username) {
                let session = login_configured_user(
                    context,
                    user,
                    configured_login_options(human_verification_token.clone()),
                )
                .await?;
                persist_proton_session(context, &user.username, None, &session)?;
                session
            } else {
                let password =
                    resolve_cli_password(password.clone(), password_file.clone(), no_prompt)?;
                let session = login_with_prompts(
                    context,
                    &username,
                    password,
                    totp,
                    no_prompt,
                    human_verification_token,
                    debug_http,
                )
                .await?;
                persist_proton_session(context, &username, None, &session)?;
                session
            }
        } else if let Some(user) = registry.get_by_username(&username) {
            let session = login_configured_user(
                context,
                user,
                configured_login_options(human_verification_token.clone()),
            )
            .await?;
            persist_proton_session(context, &user.username, None, &session)?;
            session
        } else {
            let password = resolve_cli_password(password, password_file, no_prompt)?;
            let session = login_with_prompts(
                context,
                &username,
                password,
                totp,
                no_prompt,
                human_verification_token,
                debug_http,
            )
            .await?;
            persist_proton_session(context, &username, None, &session)?;
            session
        }
    } else if registry.len() == 1 {
        let user = registry
            .iter()
            .next()
            .context("missing configured Proton username")?;
        if !password_supplied {
            if let Some(session) =
                refresh_stored_login_session(context, &user.username, debug_http).await?
            {
                session
            } else {
                let session = login_configured_user(
                    context,
                    user,
                    configured_login_options(human_verification_token.clone()),
                )
                .await?;
                persist_proton_session(context, &user.username, None, &session)?;
                session
            }
        } else {
            let session = login_configured_user(
                context,
                user,
                configured_login_options(human_verification_token),
            )
            .await?;
            persist_proton_session(context, &user.username, None, &session)?;
            session
        }
    } else {
        anyhow::bail!("a Proton username is required; pass --username")
    };

    if let Some(output) = output {
        write_json_output(&output, &session)?;
    } else {
        println!("{}", serde_json::to_string_pretty(&session)?);
    }

    Ok(())
}

async fn refresh_vpn_token(
    context: &RuntimeContext,
    config: &AuthConfig,
    args: RefreshVpnTokenArgs,
) -> Result<()> {
    let registry = ProtonUserRegistry::from_auth(config)?;
    let username = if let Some(username) = args.username {
        username
    } else if registry.len() == 1 {
        registry
            .iter()
            .next()
            .context("missing configured Proton username")?
            .username
            .clone()
    } else {
        anyhow::bail!("a Proton username is required; pass --username")
    };
    let relogin_hint = format!("pso auth login --username {username}");
    let refreshed = pso::proton::refresh_stored_proton_session_tokens(context, &username, false)
        .await
        .with_context(|| {
            format!(
                "failed to refresh stored Proton session for {username}; if the stored session is expired or revoked, re-authenticate with '{relogin_hint}'"
            )
        })?
        .context("Proton session state was not found")?;

    if let Some(output) = args.output {
        write_json_output(&output, &refreshed.tokens)?;
    } else {
        println!("{}", serde_json::to_string_pretty(&refreshed.tokens)?);
    }

    Ok(())
}

async fn refresh_stored_login_session(
    context: &RuntimeContext,
    username: &str,
    debug_http: bool,
) -> Result<Option<AuthTokens>> {
    match pso::proton::refresh_stored_proton_session_tokens(context, username, debug_http).await {
        Ok(Some(session)) => Ok(Some(session.tokens)),
        Ok(None) => Ok(None),
        Err(error) => {
            if debug_http {
                eprintln!(
                    "[pso-debug] stored Proton session for {username} could not be refreshed; falling back to password login: {error:#}"
                );
            }
            Ok(None)
        }
    }
}

fn resolve_cli_password(
    password: Option<String>,
    password_file: Option<PathBuf>,
    no_prompt: bool,
) -> Result<String> {
    match password {
        Some(password) => Ok(password),
        None => match password_file {
            Some(path) => Ok(fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?
                .trim_end_matches(['\r', '\n'])
                .to_string()),
            None if !no_prompt => Ok(rpassword::prompt_password("Proton password: ")?),
            None => anyhow::bail!(
                "password is required; pass --password, PSO_PROTON_PASSWORD, --password-file, or PSO_PROTON_PASSWORD_FILE"
            ),
        },
    }
}

async fn resolve_manual_access_token(
    context: &RuntimeContext,
    auth: &AuthConfig,
    access_token: Option<String>,
    username: Option<&str>,
) -> Result<ProtonAccessToken> {
    let registry = ProtonUserRegistry::from_auth(auth)?;
    if let Some(access_token) = access_token {
        require_single_user_access_token(&registry, username)?;
        return Ok(ProtonAccessToken::new(
            access_token,
            load_selected_username_uid(context, &registry, username),
        ));
    }

    if registry.is_empty() {
        anyhow::bail!(
            "a Proton access token is required; pass --access-token or configure auth.proton.users"
        );
    }

    let user = registry.resolve_username(username)?;
    let mut cache = CachedAccessToken::default();
    pso::ensure_user_access_token(context, user, &mut cache).await
}

fn load_selected_username_uid(
    context: &RuntimeContext,
    registry: &ProtonUserRegistry,
    username: Option<&str>,
) -> Option<String> {
    let username = if let Some(username) = username {
        username
    } else if registry.len() == 1 {
        registry.first_username()?
    } else {
        return None;
    };
    StateStore::open(context)
        .ok()?
        .load_proton_session(username)
        .ok()
        .map(|state| state.uid)
}

fn write_json_output(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    fs::write(path, serde_json::to_string_pretty(value)?)
        .with_context(|| format!("failed to write {}", path.display()))
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

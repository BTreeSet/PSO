use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use pso::cli::{
    AuthCommand, Cli, Command, DebugAuthCommand, DebugCommand, HealthCommand, TopologyCommand,
};
use pso::config::{
    DEFAULT_API_BASE_URL, DEFAULT_STATE_DIR, ProtonClientProfile, RuntimeContext,
    read_optional_config,
};
use pso::health::HealthMonitor;

mod debug_cli;
mod main_support;
mod state_cli;

#[cfg(test)]
mod main_tests;

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
        Command::Run(args) => main_support::run(&context, &config, args).await,
        Command::Render(args) => main_support::render(&context, &config, args).await,
        Command::Health(args) => match args.command {
            HealthCommand::Baseline => {
                let ip = HealthMonitor::acquire_baseline().await?;
                println!("{ip}");
                Ok(())
            }
            HealthCommand::Probe(args) => main_support::probe(args).await,
        },
        Command::ControlPlane(args) => {
            main_support::control_plane(&context, &config.auth, &config.control_plane, args).await
        }
        Command::Auth(args) => match args.command {
            AuthCommand::Login(args) => {
                main_support::login(&context, &config.auth, args, false).await
            }
            AuthCommand::Refresh(args) => {
                main_support::refresh_vpn_token(&context, &config.auth, args).await
            }
        },
        Command::Topology(args) => match args.command {
            TopologyCommand::Fetch(args) => {
                main_support::fetch_logicals(&context, &config.auth, &config.topology, args).await
            }
        },
        Command::Providers(args) => main_support::providers(args),
        Command::State(args) => state_cli::run_state(&context, args),
        Command::Debug(args) => match args.command {
            DebugCommand::Auth(args) => match args.command {
                DebugAuthCommand::Login(args) => {
                    main_support::login(&context, &config.auth, args, true).await
                }
            },
            DebugCommand::Db(args) => debug_cli::run_debug_db(&context, args),
        },
    }
}

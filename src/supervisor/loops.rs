use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{error, warn};

use super::{EndpointSpec, SupervisorRuntime, proton, topology, util};
use crate::health::{HealthMonitor, ProbeResult};
use crate::state::{HealthRecord, StateStore};
use crate::supervisor_render::{render_and_deploy, rendered_output_path};

const DEFAULT_COALESCE_DELAY: Duration = Duration::from_secs(5);

pub(crate) async fn run_continuous(runtime: SupervisorRuntime) -> Result<()> {
    let (deploy_tx, deploy_rx) = mpsc::channel(64);
    let deploy_runtime = runtime.clone();
    tokio::spawn(async move { deployment_loop(deploy_runtime, deploy_rx).await });

    if let Some(username) = util::topology_username(&runtime.topology, &runtime.specs) {
        let topology_runtime = runtime.clone();
        let topology_tx = deploy_tx.clone();
        tokio::spawn(async move { topology_loop(topology_runtime, username, topology_tx).await });
    }

    for spec in runtime.specs.iter().cloned() {
        let outbound_runtime = runtime.clone();
        let outbound_tx = deploy_tx.clone();
        tokio::spawn(async move { outbound_loop(outbound_runtime, spec, outbound_tx).await });
    }
    for username in runtime.sessions.keys().cloned() {
        let refresh_runtime = runtime.clone();
        tokio::spawn(async move { session_refresh_loop(refresh_runtime, username).await });
    }
    if runtime.options.session_keepalive_interval.is_some() {
        for username in runtime.sessions.keys().cloned() {
            let keepalive_runtime = runtime.clone();
            tokio::spawn(async move {
                session_keepalive_loop(keepalive_runtime, username).await;
            });
        }
    }
    drop(deploy_tx);

    std::future::pending::<()>().await;
    Ok(())
}

pub(crate) async fn supervise_once(runtime: &SupervisorRuntime) -> Result<()> {
    let mut changed = false;
    for spec in runtime.specs.iter() {
        changed |= process_endpoint(runtime, spec, false).await?;
    }
    if changed || !rendered_output_path(&runtime.context, &runtime.render).exists() {
        render_and_deploy(runtime).await?;
    }
    Ok(())
}

async fn topology_loop(runtime: SupervisorRuntime, username: String, deploy_tx: mpsc::Sender<()>) {
    loop {
        sleep(runtime.options.interval).await;
        match topology::refresh_topology(&runtime, &username).await {
            Ok(()) => {
                let _ = deploy_tx.send(()).await;
            }
            Err(error) => {
                warn!(%error, "topology refresh failed");
                util::record_runtime_error(
                    &runtime.context,
                    None,
                    None,
                    "topology_refresh_failed",
                    &error,
                );
            }
        }
    }
}

async fn deployment_loop(runtime: SupervisorRuntime, mut deploy_rx: mpsc::Receiver<()>) {
    while deploy_rx.recv().await.is_some() {
        sleep(DEFAULT_COALESCE_DELAY).await;
        while deploy_rx.try_recv().is_ok() {}
        if let Err(error) = render_and_deploy(&runtime).await {
            error!(%error, "coalesced sing-box deployment failed");
            util::record_runtime_error(
                &runtime.context,
                None,
                None,
                "coalesced_deployment_failed",
                &error,
            );
        }
    }
}

async fn process_endpoint(
    runtime: &SupervisorRuntime,
    spec: &EndpointSpec,
    force_refresh: bool,
) -> Result<bool> {
    match spec {
        EndpointSpec::Proton(spec) => {
            proton::process_proton_endpoint(runtime, spec, force_refresh).await
        }
        EndpointSpec::StaticWireGuard(spec) => {
            super::wireguard::process_static_wireguard_endpoint(runtime, spec, force_refresh).await
        }
    }
}

pub(crate) async fn probe_endpoint_once(
    context: &crate::config::RuntimeContext,
    options: &super::SupervisorOptions,
    username: Option<&str>,
    outbound_tag: &str,
    health_proxy_url: Option<&str>,
) -> Result<ProbeResult> {
    let raw_ip = options
        .raw_ip
        .as_deref()
        .context("raw IP baseline was not initialized")?;
    let monitor = HealthMonitor::new(raw_ip.to_owned(), options.interval)?;
    let proxy_url = health_proxy_url.or(options.proxy_url.as_deref());
    let probe = monitor.probe_once(proxy_url).await;
    StateStore::open(context)?.record_health(HealthRecord {
        username,
        outbound_tag: Some(outbound_tag),
        status: &format!("{:?}", probe.status),
        raw_ip,
        returned_ip: probe.returned_ip.as_deref(),
        reason: &probe.reason,
    })?;
    Ok(probe)
}

async fn session_refresh_loop(runtime: SupervisorRuntime, username: String) {
    let Some(token_state) = runtime.token_states.get(&username).cloned() else {
        return;
    };

    let user = match runtime.proton_users.get_required(&username) {
        Ok(user) => user.clone(),
        Err(error) => {
            warn!(%error, username = %username, "missing Proton user for refresh loop");
            util::record_runtime_error(
                &runtime.context,
                Some(&username),
                None,
                "proton_session_refresh_loop_missing_user",
                &error,
            );
            return;
        }
    };

    let mut refresh_failures = 0u32;
    loop {
        let delay = {
            let cache = token_state.lock().await;
            cache
                .next_refresh_delay(refresh_failures)
                .unwrap_or(Duration::ZERO)
        };

        if !delay.is_zero() {
            sleep(delay).await;
        }

        let mut recovery_sleep = None;
        {
            let mut cache = token_state.lock().await;
            match crate::proton::refresh_stored_proton_session_tokens(
                &runtime.context,
                &username,
                false,
            )
            .await
            {
                Ok(Some(session)) => {
                    cache.store(&session.tokens, Some(&session.uid));
                    refresh_failures = 0;
                }
                Ok(None) => {
                    if let Err(error) =
                        proton::bootstrap_proton_session(&runtime, &user, &mut cache).await
                    {
                        warn!(username = %username, %error, "Proton session bootstrap failed");
                        util::record_runtime_error(
                            &runtime.context,
                            Some(&username),
                            None,
                            "proton_session_bootstrap_failed",
                            &error,
                        );
                        recovery_sleep = Some(Duration::from_secs(30));
                    } else {
                        refresh_failures = 0;
                    }
                }
                Err(error) => {
                    refresh_failures = refresh_failures.saturating_add(1);
                    warn!(username = %username, refresh_failures, %error, "Proton session refresh failed");
                    util::record_runtime_error(
                        &runtime.context,
                        Some(&username),
                        None,
                        "proton_session_refresh_failed",
                        &error,
                    );

                    let expired = cache
                        .refresh_window()
                        .map(|window| crate::current_time_ms() >= window.expires_at_ms)
                        .unwrap_or(false);

                    if expired {
                        if let Err(login_error) =
                            proton::bootstrap_proton_session(&runtime, &user, &mut cache).await
                        {
                            warn!(username = %username, %login_error, "Proton session headless recovery failed");
                            util::record_runtime_error(
                                &runtime.context,
                                Some(&username),
                                None,
                                "proton_session_recovery_failed",
                                &login_error,
                            );
                            recovery_sleep = Some(Duration::from_secs(30));
                        } else {
                            refresh_failures = 0;
                        }
                    } else if cache.refresh_window().is_none() {
                        recovery_sleep = Some(Duration::from_secs(30));
                    }
                }
            }
        }

        if let Some(delay) = recovery_sleep {
            sleep(delay).await;
        }
    }
}

async fn session_keepalive_loop(runtime: SupervisorRuntime, username: String) {
    let Some(interval) = runtime.options.session_keepalive_interval else {
        return;
    };

    loop {
        sleep(interval).await;
        if let Err(error) = proton::keepalive_proton_session(&runtime, &username).await {
            warn!(username = %username, %error, "Proton session keepalive failed");
            let username = runtime
                .proton_users
                .get_by_username(&username)
                .map(|user| user.username.as_str())
                .or(Some(username.as_str()));
            util::record_runtime_error(
                &runtime.context,
                username,
                None,
                "proton_session_keepalive_failed",
                &error,
            );
        }
    }
}

async fn outbound_loop(
    runtime: SupervisorRuntime,
    spec: EndpointSpec,
    deploy_tx: mpsc::Sender<()>,
) {
    loop {
        match process_endpoint(&runtime, &spec, false).await {
            Ok(true) => {
                let _ = deploy_tx.send(()).await;
            }
            Ok(false) => {}
            Err(error) => {
                error!(tag = %spec.tag(), %error, "outbound supervisor cycle failed");
                let username = util::endpoint_username(&spec);
                util::record_runtime_error(
                    &runtime.context,
                    username,
                    Some(spec.tag()),
                    "outbound_cycle_failed",
                    &error,
                );
            }
        }
        sleep(runtime.options.interval).await;
    }
}

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use serde_json::Value;
use tokio::sync::Mutex;

use crate::config::{AppConfig, RenderConfig, RuntimeContext, TopologyConfig, read_json};
use crate::filter::ServerFilter;
use crate::health::HealthMonitor;
use crate::proton::CachedAccessToken;
use crate::provider::{ProvidersConfig, WireGuardServerFilter};
use crate::session::UserSession;
use crate::supervisor_render::{
    endpoint_specs, proton_user_sessions, template_path, validate_proton_user_bindings,
};
use crate::users::ProtonUserRegistry;

mod loops;
mod proton;
mod topology;
mod util;
mod wireguard;

#[derive(Clone, Debug)]
pub struct SupervisorOptions {
    pub access_token: Option<String>,
    pub raw_ip: Option<String>,
    pub proxy_url: Option<String>,
    pub once: bool,
    pub interval: Duration,
    pub session_keepalive_interval: Option<Duration>,
}

#[derive(Clone, Debug)]
pub(crate) struct ProtonEndpointSpec {
    pub(crate) tag: String,
    pub(crate) username: String,
    pub(crate) filter: ServerFilter,
    pub(crate) health_proxy_url: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct StaticWireGuardEndpointSpec {
    pub(crate) tag: String,
    pub(crate) provider: String,
    pub(crate) filter: WireGuardServerFilter,
    pub(crate) local_address: Vec<String>,
    pub(crate) allowed_ips: Vec<String>,
    pub(crate) pre_shared_key: Option<String>,
    pub(crate) persistent_keepalive_interval: Option<u16>,
    pub(crate) reserved: Option<Vec<u8>>,
    pub(crate) health_proxy_url: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) enum EndpointSpec {
    Proton(ProtonEndpointSpec),
    StaticWireGuard(StaticWireGuardEndpointSpec),
}

impl EndpointSpec {
    pub(crate) fn tag(&self) -> &str {
        match self {
            Self::Proton(spec) => &spec.tag,
            Self::StaticWireGuard(spec) => &spec.tag,
        }
    }
}

#[derive(Clone)]
pub(crate) struct SupervisorRuntime {
    pub(crate) context: Arc<RuntimeContext>,
    pub(crate) render: Arc<RenderConfig>,
    pub(crate) topology: Arc<TopologyConfig>,
    pub(crate) providers: Arc<ProvidersConfig>,
    pub(crate) proton_users: Arc<ProtonUserRegistry>,
    pub(crate) template: Arc<Value>,
    pub(crate) specs: Arc<Vec<EndpointSpec>>,
    pub(crate) sessions: Arc<BTreeMap<String, UserSession>>,
    pub(crate) options: Arc<SupervisorOptions>,
    pub(crate) token_states: Arc<BTreeMap<String, Arc<Mutex<CachedAccessToken>>>>,
}

pub async fn run_supervisor(
    context: &RuntimeContext,
    config: &AppConfig,
    mut options: SupervisorOptions,
) -> Result<()> {
    config.providers.validate()?;
    config.auth.validate()?;
    let template_path = template_path(&config.render);
    let template: Value = read_json(&template_path)?;
    let specs = endpoint_specs(&template)?;
    if specs.is_empty() {
        anyhow::bail!("run requires at least one provider endpoint in the template");
    }
    let proton_in_use = specs
        .iter()
        .any(|spec| matches!(spec, EndpointSpec::Proton(_)));
    let proton_users = if proton_in_use {
        ProtonUserRegistry::from_auth(&config.auth)?
    } else {
        ProtonUserRegistry::default()
    };
    if proton_in_use {
        validate_proton_user_bindings(&specs, &proton_users)?;
    }
    let sessions = if proton_in_use {
        proton_user_sessions(&proton_users)?
    } else {
        BTreeMap::new()
    };
    let token_states = sessions
        .keys()
        .map(|username| {
            (
                username.clone(),
                Arc::new(Mutex::new(CachedAccessToken::default())),
            )
        })
        .collect();

    let raw_ip = match options.raw_ip.take() {
        Some(ip) => ip,
        None => HealthMonitor::acquire_baseline().await?,
    };
    let options = SupervisorOptions {
        raw_ip: Some(raw_ip),
        session_keepalive_interval: (config.run.session_keepalive_interval_secs > 0)
            .then(|| Duration::from_secs(config.run.session_keepalive_interval_secs)),
        ..options
    };
    let runtime = SupervisorRuntime {
        context: Arc::new(context.clone()),
        render: Arc::new(config.render.clone()),
        topology: Arc::new(config.topology.clone()),
        providers: Arc::new(config.providers.clone()),
        proton_users: Arc::new(proton_users),
        template: Arc::new(template),
        specs: Arc::new(specs),
        sessions: Arc::new(sessions),
        options: Arc::new(options),
        token_states: Arc::new(token_states),
    };

    if let Some(username) = util::topology_username(&runtime.topology, &runtime.specs) {
        topology::refresh_topology(&runtime, &username).await?;
    }
    loops::supervise_once(&runtime).await?;
    if runtime.options.once {
        return Ok(());
    }

    loops::run_continuous(runtime).await
}

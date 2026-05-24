use anyhow::Result;
use pso::cli::{StateArgs, StateCommand, StateListArgs};
use pso::config::RuntimeContext;
use pso::state::{
    AccountRow, CertificateRow, HealthCheckRow, RuntimeEventRow, StateStore, WireGuardEndpointRow,
};

pub fn run_state(context: &RuntimeContext, args: StateArgs) -> Result<()> {
    let store = StateStore::open(context)?;
    match args.command {
        StateCommand::Accounts => print_accounts(&store.list_accounts()?),
        StateCommand::Certs(args) => print_certs(&store.list_certificates(args.limit)?, &args),
        StateCommand::Wireguard(args) => {
            print_wireguard(&store.list_wireguard_endpoints(args.limit)?, &args)
        }
        StateCommand::Events(args) => print_events(&store.list_events(args.limit)?, &args),
        StateCommand::Health(args) => print_health(&store.list_health_checks(args.limit)?, &args),
    }
}

fn print_accounts(rows: &[AccountRow]) -> Result<()> {
    println!("updated_at\taccount_key\thas_proton_session\tusername");
    for row in rows {
        println!(
            "{}\t{}\t{}\t{}",
            row.updated_at,
            shorten(&row.account_key),
            row.has_proton_session,
            row.username
        );
    }
    Ok(())
}

fn print_events(rows: &[RuntimeEventRow], args: &StateListArgs) -> Result<()> {
    if args.json {
        println!("{}", serde_json::to_string_pretty(rows)?);
        return Ok(());
    }

    println!("occurred_at\tid\tusername\toutbound\tevent\tdetails");
    for row in rows {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            row.occurred_at,
            row.id,
            row.username.as_deref().unwrap_or("-"),
            row.outbound_tag.as_deref().unwrap_or("-"),
            row.event_type,
            row.details_json.as_deref().unwrap_or("-")
        );
    }
    Ok(())
}

fn print_certs(rows: &[CertificateRow], args: &StateListArgs) -> Result<()> {
    if args.json {
        println!("{}", serde_json::to_string_pretty(rows)?);
        return Ok(());
    }

    println!(
        "updated_at\toutbound\tusername\tserver\tendpoint\tassigned_ip\trefresh_at_ms\texpires_at_ms\tfailures\tlast_error"
    );
    for row in rows {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            row.updated_at,
            row.outbound_tag,
            row.username,
            row.server_name,
            row.endpoint,
            row.assigned_ip.as_deref().unwrap_or("-"),
            row.refresh_at_ms
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".into()),
            row.expires_at_ms
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".into()),
            row.consecutive_failures,
            row.last_error.as_deref().unwrap_or("-")
        );
    }
    Ok(())
}

fn print_wireguard(rows: &[WireGuardEndpointRow], args: &StateListArgs) -> Result<()> {
    if args.json {
        println!("{}", serde_json::to_string_pretty(rows)?);
        return Ok(());
    }

    println!(
        "updated_at\toutbound\tprovider\tidentity\tserver\tendpoint\tassigned_ips\tallowed_ips\tkeepalive\treserved\trefresh_at_ms\texpires_at_ms"
    );
    for row in rows {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            row.updated_at,
            row.outbound_tag,
            row.provider,
            row.identity.as_deref().unwrap_or("-"),
            row.server_name,
            row.endpoint,
            row.assigned_ips.join(","),
            row.allowed_ips.join(","),
            row.persistent_keepalive_interval
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".into()),
            row.reserved
                .as_ref()
                .map(|bytes| {
                    bytes
                        .iter()
                        .map(u8::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_else(|| "-".into()),
            row.refresh_at_ms
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".into()),
            row.expires_at_ms
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".into())
        );
    }
    Ok(())
}

fn print_health(rows: &[HealthCheckRow], args: &StateListArgs) -> Result<()> {
    if args.json {
        println!("{}", serde_json::to_string_pretty(rows)?);
        return Ok(());
    }

    println!("occurred_at\tid\tusername\toutbound\tstatus\traw_ip\treturned_ip\treason");
    for row in rows {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            row.occurred_at,
            row.id,
            row.username.as_deref().unwrap_or("-"),
            row.outbound_tag.as_deref().unwrap_or("-"),
            row.status,
            row.raw_ip,
            row.returned_ip.as_deref().unwrap_or("-"),
            row.reason
        );
    }
    Ok(())
}

fn shorten(value: &str) -> &str {
    value.get(..12).unwrap_or(value)
}

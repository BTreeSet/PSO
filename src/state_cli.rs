use anyhow::Result;
use pso::cli::{StateArgs, StateCommand, StateListArgs};
use pso::config::RuntimeContext;
use pso::state::{AccountRow, HealthCheckRow, RuntimeEventRow, StateStore};

pub fn run_state(context: &RuntimeContext, args: StateArgs) -> Result<()> {
    let store = StateStore::open(context)?;
    match args.command {
        StateCommand::Accounts => print_accounts(&store.list_accounts()?),
        StateCommand::Events(args) => print_events(&store.list_events(args.limit)?, &args),
        StateCommand::Health(args) => print_health(&store.list_health_checks(args.limit)?, &args),
    }
}

fn print_accounts(rows: &[AccountRow]) -> Result<()> {
    println!("updated_at\taccount_key\thas_vpn_session\tusername");
    for row in rows {
        println!(
            "{}\t{}\t{}\t{}",
            row.updated_at,
            shorten(&row.account_key),
            row.has_vpn_session,
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

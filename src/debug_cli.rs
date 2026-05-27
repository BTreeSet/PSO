use std::fs;

use anyhow::Result;
use pso::cli::{DebugDbArgs, DebugDbCommand, DebugDbDumpArgs, StateListArgs};
use pso::config::RuntimeContext;
use pso::state::{
    ConfigDeploymentRow, PersistenceIntegrityReport, ProtonCookieRow, ProtonSessionRow, StateStore,
    state_db_file,
};

use crate::state_cli;

pub fn run_debug_db(context: &RuntimeContext, args: DebugDbArgs) -> Result<()> {
    let store = StateStore::open(context)?;
    match args.command {
        DebugDbCommand::Summary => print_summary(context, &store),
        DebugDbCommand::Check => print_integrity(&store),
        DebugDbCommand::Dump(args) => print_dump(context, &store, args),
    }
}

fn print_summary(context: &RuntimeContext, store: &StateStore) -> Result<()> {
    let database_path = state_db_file(context);
    println!("database\t{}", database_path.display());
    match fs::metadata(&database_path) {
        Ok(metadata) => println!("database_size_bytes\t{}", metadata.len()),
        Err(_) => println!("database_size_bytes\t-"),
    }

    let summary = store.persistence_summary()?;
    println!("foreign_keys_enabled\t{}", summary.foreign_keys_enabled);
    println!("table\trows\tlatest_at");
    for table in summary.tables {
        println!(
            "{}\t{}\t{}",
            table.table,
            table.row_count,
            format_optional_i64(table.latest_at)
        );
    }

    Ok(())
}

fn print_integrity(store: &StateStore) -> Result<()> {
    let report = store.integrity_report()?;
    print_integrity_report(&report);
    Ok(())
}

fn print_dump(context: &RuntimeContext, store: &StateStore, args: DebugDbDumpArgs) -> Result<()> {
    print_summary(context, store)?;
    println!();

    print_section("users");
    state_cli::print_users(&store.list_users()?)?;
    println!();

    print_section("sessions");
    print_proton_sessions(&store.list_proton_sessions(args.limit)?)?;
    println!();

    print_section("cookies");
    print_proton_cookies(&store.list_proton_cookies(args.limit)?)?;
    println!();

    print_section("certificates");
    let list_args = StateListArgs {
        limit: args.limit,
        json: false,
    };
    state_cli::print_certs(&store.list_certificates(args.limit)?, &list_args)?;
    println!();

    print_section("wireguard");
    state_cli::print_wireguard(&store.list_wireguard_endpoints(args.limit)?, &list_args)?;
    println!();

    print_section("events");
    state_cli::print_events(&store.list_events(args.limit)?, &list_args)?;
    println!();

    print_section("health");
    state_cli::print_health(&store.list_health_checks(args.limit)?, &list_args)?;
    println!();

    print_section("deployments");
    print_config_deployments(&store.list_config_deployments(args.limit)?)?;
    println!();

    print_section("integrity");
    let report = store.integrity_report()?;
    print_integrity_report(&report);

    Ok(())
}

fn print_integrity_report(report: &PersistenceIntegrityReport) {
    if report.integrity_check.is_empty() {
        println!("integrity_check\t-");
    } else {
        println!("integrity_check");
        for row in &report.integrity_check {
            println!("\t{row}");
        }
    }

    if report.foreign_key_violations.is_empty() {
        println!("foreign_key_check\tok");
        return;
    }

    println!("foreign_key_check");
    println!("table\trowid\tparent\tfkid");
    for row in &report.foreign_key_violations {
        println!(
            "{}\t{}\t{}\t{}",
            row.table,
            format_optional_i64(row.rowid),
            row.parent,
            row.fkid,
        );
    }
}

fn print_proton_sessions(rows: &[ProtonSessionRow]) -> Result<()> {
    println!("updated_at\tusername_key\tusername\tuid\trefresh_token");
    for row in rows {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            row.updated_at, row.username_key, row.username, row.uid, row.refresh_token
        );
    }
    Ok(())
}

fn print_proton_cookies(rows: &[ProtonCookieRow]) -> Result<()> {
    println!(
        "updated_at\tusername_key\tusername\tcookie_name\tcookie_domain\tcookie_path\tcookie_value\thost_only\tsecure\thttp_only\tsame_site\texpires_at_ms\tcreated_at"
    );
    for row in rows {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            row.updated_at,
            row.username_key,
            row.username,
            row.cookie_name,
            row.cookie_domain,
            row.cookie_path,
            row.cookie_value,
            row.host_only,
            row.secure,
            row.http_only,
            row.same_site.as_deref().unwrap_or("-"),
            format_optional_i64(row.expires_at_ms),
            row.created_at,
        );
    }
    Ok(())
}

fn print_config_deployments(rows: &[ConfigDeploymentRow]) -> Result<()> {
    println!("deployed_at\tid\tconfig_hash\toutbound_tags_json\tactive_config\tsuccess\terror");
    for row in rows {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            row.deployed_at,
            row.id,
            row.config_hash,
            row.outbound_tags_json,
            row.active_config,
            row.success,
            row.error.as_deref().unwrap_or("-"),
        );
    }
    Ok(())
}

fn print_section(name: &str) {
    println!("== {name} ==");
}

fn format_optional_i64(value: Option<i64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_string())
}

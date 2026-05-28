use std::fs;

use pso::api::AuthTokens;
use pso::config::{
    AuthConfig, DEFAULT_API_BASE_URL, ProtonAuthConfig, ProtonClientProfile, ProtonUserConfig,
    RuntimeContext,
};
use pso::proton::persist_proton_session;
use pso::users::ProtonUserRegistry;
use tempfile::tempdir;

use crate::main_support::{
    load_selected_username_uid, resolve_cli_password, resolve_manual_access_token,
    write_json_output,
};

fn runtime_context(state_dir: &std::path::Path) -> RuntimeContext {
    RuntimeContext {
        api_base_url: DEFAULT_API_BASE_URL.to_string(),
        state_dir: state_dir.to_path_buf(),
        proton_client: ProtonClientProfile::default(),
    }
}

fn auth_config(users: Vec<ProtonUserConfig>) -> AuthConfig {
    AuthConfig {
        proton: ProtonAuthConfig {
            users,
            ..Default::default()
        },
    }
}

#[test]
fn resolve_cli_password_prefers_inline_password() {
    let password = resolve_cli_password(Some("inline".into()), None, false).unwrap();

    assert_eq!(password, "inline");
}

#[test]
fn resolve_cli_password_reads_password_file() {
    let temp = tempdir().unwrap();
    let password_file = temp.path().join("password.txt");
    fs::write(&password_file, "from-file\n").unwrap();

    let password = resolve_cli_password(None, Some(password_file), true).unwrap();

    assert_eq!(password, "from-file");
}

#[test]
fn resolve_cli_password_errors_when_prompt_disabled() {
    let error = resolve_cli_password(None, None, true).unwrap_err();

    assert!(error.to_string().contains("password is required"));
}

#[test]
fn load_selected_username_uid_uses_persisted_session_for_single_user() {
    let temp = tempdir().unwrap();
    let context = runtime_context(temp.path());
    let auth = auth_config(vec![ProtonUserConfig {
        username: "alice@example.com".into(),
        tier: "plus".into(),
        password: None,
        password_file: None,
        totp: None,
        no_prompt: None,
    }]);
    let registry = ProtonUserRegistry::from_auth(&auth).unwrap();
    let tokens = AuthTokens {
        access_token: "access".into(),
        refresh_token: "refresh".into(),
        uid: Some("uid-one".into()),
        token_type: None,
        expires_in: Some(120),
    };
    persist_proton_session(&context, "alice@example.com", None, &tokens).unwrap();

    assert_eq!(
        load_selected_username_uid(&context, &registry, None),
        Some("uid-one".into())
    );
}

#[test]
fn load_selected_username_uid_returns_none_for_multiple_users_without_explicit_username() {
    let temp = tempdir().unwrap();
    let context = runtime_context(temp.path());
    let auth = auth_config(vec![
        ProtonUserConfig {
            username: "alice@example.com".into(),
            tier: "plus".into(),
            password: None,
            password_file: None,
            totp: None,
            no_prompt: None,
        },
        ProtonUserConfig {
            username: "bob@example.com".into(),
            tier: "plus".into(),
            password: None,
            password_file: None,
            totp: None,
            no_prompt: None,
        },
    ]);
    let registry = ProtonUserRegistry::from_auth(&auth).unwrap();

    assert_eq!(load_selected_username_uid(&context, &registry, None), None);
}

#[tokio::test]
async fn resolve_manual_access_token_uses_cached_uid_for_explicit_token() {
    let temp = tempdir().unwrap();
    let context = runtime_context(temp.path());
    let auth = auth_config(vec![ProtonUserConfig {
        username: "alice@example.com".into(),
        tier: "plus".into(),
        password: None,
        password_file: None,
        totp: None,
        no_prompt: None,
    }]);
    let tokens = AuthTokens {
        access_token: "access".into(),
        refresh_token: "refresh".into(),
        uid: Some("uid-one".into()),
        token_type: None,
        expires_in: Some(120),
    };
    persist_proton_session(&context, "alice@example.com", None, &tokens).unwrap();

    let token = resolve_manual_access_token(
        &context,
        &auth,
        Some("explicit-token".into()),
        Some("alice@example.com"),
    )
    .await
    .unwrap();

    assert_eq!(token.access_token, "explicit-token");
    assert_eq!(token.uid.as_deref(), Some("uid-one"));
}

#[test]
fn write_json_output_serializes_pretty_json() {
    let temp = tempdir().unwrap();
    let path = temp.path().join("output.json");

    write_json_output(&path, &serde_json::json!({"answer": 42})).unwrap();

    let written = fs::read_to_string(path).unwrap();
    assert!(written.contains("\n  \"answer\": 42\n"));
}

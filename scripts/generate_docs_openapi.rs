use std::fs;
use std::path::PathBuf;

use better_auth::plugins::{
    AccountManagementPlugin, AdminPlugin, ApiKeyPlugin, DeviceAuthorizationPlugin,
    EmailPasswordPlugin, EmailVerificationPlugin, OAuthPlugin, OrganizationPlugin, PasskeyPlugin,
    PasswordManagementPlugin, SessionManagementPlugin, TwoFactorPlugin, UserManagementPlugin,
};
use better_auth::{AuthBuilder, AuthConfig, BetterAuth};
use better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
use better_auth_seaorm::store::__private_test_support::migrator::run_migrations;
use better_auth_seaorm::{Database, SeaOrmStore};
use clap::Parser;
use serde_json::Value;

type DynError = Box<dyn std::error::Error + Send + Sync + 'static>;

const DOCS_TITLE: &str = "Better Auth RS";
const DOCS_DESCRIPTION: &str = "OpenAPI schema for the better-auth-rs v1 docs surface.";

const DEFAULT_TAG: &str = "Default";
const USERNAME_TAG: &str = "Username";
const DEVICE_AUTHORIZATION_TAG: &str = "Device-authorization";
const API_KEY_TAG: &str = "Api-key";
const ORGANIZATION_TAG: &str = "Organization";
const PASSKEY_TAG: &str = "Passkey";
const ADMIN_TAG: &str = "Admin";
const TWO_FACTOR_TAG: &str = "Two-factor";

const V1_DOCS_PATHS: &[(&str, &str)] = &[
    ("/ok", DEFAULT_TAG),
    ("/error", DEFAULT_TAG),
    ("/update-user", DEFAULT_TAG),
    ("/delete-user", DEFAULT_TAG),
    ("/delete-user/callback", DEFAULT_TAG),
    ("/change-email", DEFAULT_TAG),
    ("/sign-up/email", DEFAULT_TAG),
    ("/sign-in/email", DEFAULT_TAG),
    ("/sign-in/social", DEFAULT_TAG),
    ("/callback/{provider}", DEFAULT_TAG),
    ("/list-accounts", DEFAULT_TAG),
    ("/link-social", DEFAULT_TAG),
    ("/unlink-account", DEFAULT_TAG),
    ("/get-access-token", DEFAULT_TAG),
    ("/refresh-token", DEFAULT_TAG),
    ("/account-info", DEFAULT_TAG),
    ("/get-session", DEFAULT_TAG),
    ("/sign-out", DEFAULT_TAG),
    ("/list-sessions", DEFAULT_TAG),
    ("/revoke-session", DEFAULT_TAG),
    ("/revoke-sessions", DEFAULT_TAG),
    ("/revoke-other-sessions", DEFAULT_TAG),
    ("/request-password-reset", DEFAULT_TAG),
    ("/reset-password/{token}", DEFAULT_TAG),
    ("/reset-password", DEFAULT_TAG),
    ("/change-password", DEFAULT_TAG),
    ("/verify-password", DEFAULT_TAG),
    ("/send-verification-email", DEFAULT_TAG),
    ("/verify-email", DEFAULT_TAG),
    ("/sign-in/username", USERNAME_TAG),
    ("/is-username-available", USERNAME_TAG),
    ("/device/code", DEVICE_AUTHORIZATION_TAG),
    ("/device/token", DEVICE_AUTHORIZATION_TAG),
    ("/device", DEVICE_AUTHORIZATION_TAG),
    ("/device/approve", DEVICE_AUTHORIZATION_TAG),
    ("/device/deny", DEVICE_AUTHORIZATION_TAG),
    ("/api-key/create", API_KEY_TAG),
    ("/api-key/get", API_KEY_TAG),
    ("/api-key/list", API_KEY_TAG),
    ("/api-key/update", API_KEY_TAG),
    ("/api-key/delete", API_KEY_TAG),
    ("/organization/create", ORGANIZATION_TAG),
    ("/organization/check-slug", ORGANIZATION_TAG),
    ("/organization/update", ORGANIZATION_TAG),
    ("/organization/delete", ORGANIZATION_TAG),
    ("/organization/get-full-organization", ORGANIZATION_TAG),
    ("/organization/set-active", ORGANIZATION_TAG),
    ("/organization/list", ORGANIZATION_TAG),
    ("/organization/list-members", ORGANIZATION_TAG),
    ("/organization/get-active-member", ORGANIZATION_TAG),
    ("/organization/get-active-member-role", ORGANIZATION_TAG),
    ("/organization/update-member-role", ORGANIZATION_TAG),
    ("/organization/remove-member", ORGANIZATION_TAG),
    ("/organization/leave", ORGANIZATION_TAG),
    ("/organization/invite-member", ORGANIZATION_TAG),
    ("/organization/accept-invitation", ORGANIZATION_TAG),
    ("/organization/reject-invitation", ORGANIZATION_TAG),
    ("/organization/cancel-invitation", ORGANIZATION_TAG),
    ("/organization/get-invitation", ORGANIZATION_TAG),
    ("/organization/list-invitations", ORGANIZATION_TAG),
    ("/organization/list-user-invitations", ORGANIZATION_TAG),
    ("/organization/has-permission", ORGANIZATION_TAG),
    ("/passkey/generate-register-options", PASSKEY_TAG),
    ("/passkey/generate-authenticate-options", PASSKEY_TAG),
    ("/passkey/verify-registration", PASSKEY_TAG),
    ("/passkey/verify-authentication", PASSKEY_TAG),
    ("/passkey/list-user-passkeys", PASSKEY_TAG),
    ("/passkey/delete-passkey", PASSKEY_TAG),
    ("/passkey/update-passkey", PASSKEY_TAG),
    ("/admin/list-users", ADMIN_TAG),
    ("/admin/get-user", ADMIN_TAG),
    ("/admin/create-user", ADMIN_TAG),
    ("/admin/update-user", ADMIN_TAG),
    ("/admin/remove-user", ADMIN_TAG),
    ("/admin/set-user-password", ADMIN_TAG),
    ("/admin/set-role", ADMIN_TAG),
    ("/admin/has-permission", ADMIN_TAG),
    ("/admin/ban-user", ADMIN_TAG),
    ("/admin/unban-user", ADMIN_TAG),
    ("/admin/impersonate-user", ADMIN_TAG),
    ("/admin/stop-impersonating", ADMIN_TAG),
    ("/admin/list-user-sessions", ADMIN_TAG),
    ("/admin/revoke-user-session", ADMIN_TAG),
    ("/admin/revoke-user-sessions", ADMIN_TAG),
    ("/two-factor/enable", TWO_FACTOR_TAG),
    ("/two-factor/disable", TWO_FACTOR_TAG),
    ("/two-factor/get-totp-uri", TWO_FACTOR_TAG),
    ("/two-factor/verify-totp", TWO_FACTOR_TAG),
    ("/two-factor/send-otp", TWO_FACTOR_TAG),
    ("/two-factor/verify-otp", TWO_FACTOR_TAG),
    ("/two-factor/generate-backup-codes", TWO_FACTOR_TAG),
    ("/two-factor/verify-backup-code", TWO_FACTOR_TAG),
];

#[derive(Debug, Parser)]
#[command(
    name = "generate_docs_openapi",
    about = "Generate the v1 docs OpenAPI schema from the better-auth-rs runtime"
)]
struct Cli {
    #[arg(long, default_value = "docs/better-auth.json")]
    output: PathBuf,

    #[arg(long)]
    check: bool,
}

#[tokio::main]
async fn main() -> Result<(), DynError> {
    let cli = Cli::parse();
    let spec = generate_docs_openapi().await?;
    let json = serde_json::to_string_pretty(&spec)?;

    if cli.check {
        let existing = fs::read_to_string(&cli.output)?;
        if normalize_newlines(&existing) != normalize_newlines(&json) {
            return Err(format!(
                "generated docs OpenAPI differs from {}. Re-run `cargo run --bin generate_docs_openapi --features seaorm2`.",
                cli.output.display()
            )
            .into());
        }
        eprintln!("[ok] docs OpenAPI is up to date: {}", cli.output.display());
        return Ok(());
    }

    if let Some(parent) = cli.output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&cli.output, json)?;
    eprintln!("[ok] wrote docs OpenAPI: {}", cli.output.display());
    Ok(())
}

async fn generate_docs_openapi() -> Result<Value, DynError> {
    let auth = build_docs_auth().await?;
    let mut spec = auth.openapi_spec().to_value()?;
    rewrite_for_docs(&mut spec)?;
    Ok(spec)
}

async fn build_docs_auth() -> Result<BetterAuth<BundledSchema>, DynError> {
    let config = AuthConfig::new("docs-openapi-generation-secret-key-32c")
        .base_url("http://localhost:3000")
        .password_min_length(8);

    let database = Database::connect("sqlite::memory:").await?;
    run_migrations(&database).await?;
    let store = SeaOrmStore::<BundledSchema>::new(config.clone(), database);

    let auth = AuthBuilder::<BundledSchema>::new(config)
        .store(store)
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(SessionManagementPlugin::new())
        .plugin(PasswordManagementPlugin::new())
        .plugin(AccountManagementPlugin::new())
        .plugin(EmailVerificationPlugin::new())
        .plugin(
            UserManagementPlugin::new()
                .change_email_enabled(true)
                .delete_user_enabled(true)
                .require_delete_verification(false),
        )
        .plugin(OAuthPlugin::new())
        .plugin(DeviceAuthorizationPlugin::new())
        .plugin(ApiKeyPlugin::builder().build())
        .plugin(TwoFactorPlugin::new())
        .plugin(OrganizationPlugin::new())
        .plugin(
            PasskeyPlugin::new()
                .rp_id("localhost")
                .rp_name("Better Auth RS")
                .origin("http://localhost:3000"),
        )
        .plugin(AdminPlugin::new())
        .build()
        .await?;

    Ok(auth)
}

fn rewrite_for_docs(spec: &mut Value) -> Result<(), DynError> {
    let root = spec
        .as_object_mut()
        .ok_or_else(|| "OpenAPI spec must be a JSON object".to_string())?;

    let info = root
        .get_mut("info")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "OpenAPI spec must contain an info object".to_string())?;
    _ = info.insert("title".to_string(), Value::String(DOCS_TITLE.to_string()));
    _ = info.insert(
        "description".to_string(),
        Value::String(DOCS_DESCRIPTION.to_string()),
    );

    let paths = root
        .get_mut("paths")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "OpenAPI spec must contain a paths object".to_string())?;

    let mut filtered_paths = serde_json::Map::new();
    let mut missing_paths = Vec::new();

    for (path, tag) in V1_DOCS_PATHS {
        let Some(path_item) = paths.get(*path) else {
            missing_paths.push(*path);
            continue;
        };

        let mut path_item = path_item.clone();
        retag_path_item(&mut path_item, tag)?;
        _ = filtered_paths.insert((*path).to_string(), path_item);
    }

    if !missing_paths.is_empty() {
        return Err(format!(
            "Rust docs OpenAPI profile is missing v1 routes: {}",
            missing_paths.join(", ")
        )
        .into());
    }

    _ = root.insert("paths".to_string(), Value::Object(filtered_paths));
    Ok(())
}

fn retag_path_item(path_item: &mut Value, tag: &str) -> Result<(), DynError> {
    let operations = path_item
        .as_object_mut()
        .ok_or_else(|| "path item must be an object".to_string())?;

    for operation in operations.values_mut() {
        let operation = operation
            .as_object_mut()
            .ok_or_else(|| "operation must be an object".to_string())?;
        _ = operation.insert(
            "tags".to_string(),
            Value::Array(vec![Value::String(tag.to_string())]),
        );
    }

    Ok(())
}

fn normalize_newlines(input: &str) -> String {
    input.replace("\r\n", "\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_route_groups_use_supported_doc_tags() {
        for (_, tag) in V1_DOCS_PATHS {
            assert!(matches!(
                *tag,
                DEFAULT_TAG
                    | USERNAME_TAG
                    | DEVICE_AUTHORIZATION_TAG
                    | API_KEY_TAG
                    | ORGANIZATION_TAG
                    | PASSKEY_TAG
                    | ADMIN_TAG
                    | TWO_FACTOR_TAG
            ));
        }
    }

    #[test]
    fn v1_route_groups_include_callback_and_username_surface() {
        assert!(V1_DOCS_PATHS.contains(&("/callback/{provider}", DEFAULT_TAG)));
        assert!(V1_DOCS_PATHS.contains(&("/sign-in/username", USERNAME_TAG)));
        assert!(V1_DOCS_PATHS.contains(&("/is-username-available", USERNAME_TAG)));
    }

    #[test]
    fn v1_route_groups_exclude_server_only_backup_code_route() {
        assert!(
            !V1_DOCS_PATHS
                .iter()
                .any(|(path, _)| *path == "/two-factor/view-backup-codes")
        );
    }
}

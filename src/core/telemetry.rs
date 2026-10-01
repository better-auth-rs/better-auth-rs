mod fields;

use better_auth_core::config::{CookieCacheStrategy, SameSite};
use better_auth_core::middleware::{RateLimitConfig, RateLimitStorageKind};
use better_auth_core::observability::database::{DatabaseHook, DatabaseHookMetadata};
use better_auth_core::observability::telemetry::{PluginTelemetry, Telemetry};
use better_auth_core::{AuthConfig, AuthPlugin, AuthResult, AuthSchema};
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub(super) struct InitOptions<'a> {
    pub database: bool,
    pub adapter: &'static str,
    pub before: bool,
    pub after: bool,
    pub secondary: bool,
    pub on_error: bool,
    pub rate_limit: Option<&'a RateLimitConfig>,
    pub rate_limit_model: Option<better_auth_core::schema::ModelDeclaration>,
    pub database_hooks: Vec<DatabaseHookMetadata>,
}

fn option(
    value: &mut Map<String, Value>,
    key: &str,
    configured: Option<impl Serialize>,
) -> AuthResult<()> {
    if let Some(configured) = configured {
        let _ = value.insert(key.to_owned(), serde_json::to_value(configured)?);
    }
    Ok(())
}

fn duration_seconds(age: chrono::Duration) -> Value {
    if age.subsec_nanos() == 0 {
        json!(age.num_seconds())
    } else {
        json!(age.num_seconds() as f64 + f64::from(age.subsec_nanos()) / 1e9)
    }
}

pub(super) fn init_payload<S: AuthSchema>(
    config: &AuthConfig,
    plugins: &[Box<dyn AuthPlugin<S>>],
    options: InitOptions<'_>,
) -> AuthResult<Value> {
    let mut plugin_options = PluginTelemetry::default();
    for plugin in plugins {
        plugin.telemetry(&mut plugin_options);
    }
    let mut change_email = Map::from_iter([(
        "sendChangeEmailConfirmation".into(),
        json!(plugin_options.send_change_email_confirmation),
    )]);
    option(
        &mut change_email,
        "enabled",
        plugin_options.change_email_enabled,
    )?;
    let mut user = Map::from_iter([("changeEmail".into(), json!(change_email))]);
    option(
        &mut user,
        "additionalFields",
        config
            .user
            .additional_fields
            .as_ref()
            .map(fields::configuration)
            .transpose()?,
    )?;
    let mut logger = Map::from_iter([("log".into(), json!(config.logger.log.is_some()))]);
    option(&mut logger, "disabled", config.logger.disabled)?;
    option(
        &mut logger,
        "level",
        config.logger.level.map(|level| level.as_str()),
    )?;

    let mut cache = Map::new();
    if let Some(config) = &config.session.cookie_cache {
        option(&mut cache, "enabled", config.enabled)?;
        option(&mut cache, "maxAge", config.max_age.map(duration_seconds))?;
        option(
            &mut cache,
            "strategy",
            config.strategy.map(|strategy| match strategy {
                CookieCacheStrategy::Compact => "compact",
                CookieCacheStrategy::Jwt => "jwt",
                CookieCacheStrategy::Jwe => "jwe",
            }),
        )?;
    }
    let mut session = Map::from_iter([("cookieCache".into(), json!(cache))]);
    option(
        &mut session,
        "additionalFields",
        config
            .session
            .additional_fields
            .as_ref()
            .map(fields::configuration)
            .transpose()?,
    )?;
    option(
        &mut session,
        "expiresIn",
        config.session.expires_in.map(duration_seconds),
    )?;
    option(
        &mut session,
        "updateAge",
        config.session.update_age.map(duration_seconds),
    )?;
    option(
        &mut session,
        "disableSessionRefresh",
        config.session.disable_session_refresh,
    )?;
    option(
        &mut session,
        "storeSessionInDatabase",
        config.session.store_session_in_database,
    )?;
    option(
        &mut session,
        "preserveSessionInDatabase",
        config.session.preserve_session_in_database,
    )?;
    option(
        &mut session,
        "freshAge",
        config.session.fresh_age.map(duration_seconds),
    )?;

    let advanced = &config.advanced;
    let attributes = &advanced.default_cookie_attributes;
    let mut cookies = Map::from_iter([(
        "domain".into(),
        json!(
            attributes
                .domain
                .as_ref()
                .is_some_and(|value| !value.is_empty())
        ),
    )]);
    option(&mut cookies, "secure", attributes.secure)?;
    option(&mut cookies, "httpOnly", attributes.http_only)?;
    option(&mut cookies, "path", attributes.path.as_ref())?;
    option(
        &mut cookies,
        "sameSite",
        attributes
            .same_site
            .as_ref()
            .map(|same_site| match same_site {
                SameSite::Strict => "strict",
                SameSite::Lax => "lax",
                SameSite::None => "none",
            }),
    )?;
    let mut database = Map::new();
    option(
        &mut database,
        "defaultFindManyLimit",
        advanced.database.default_find_many_limit,
    )?;
    option(
        &mut database,
        "generateId",
        advanced
            .database
            .generate_id
            .as_ref()
            .and_then(|policy| match policy {
                better_auth_core::id::IdGeneration::Database => Some(json!(false)),
                better_auth_core::id::IdGeneration::Serial => Some(json!("serial")),
                better_auth_core::id::IdGeneration::Uuid => Some(json!("uuid")),
                better_auth_core::id::IdGeneration::Random
                | better_auth_core::id::IdGeneration::Custom(_) => None,
            }),
    )?;
    let mut ip_address = Map::new();
    option(
        &mut ip_address,
        "disableIpTracking",
        advanced.ip_address.disable_ip_tracking,
    )?;
    option(
        &mut ip_address,
        "ipAddressHeaders",
        advanced.ip_address.headers.as_ref(),
    )?;
    let cross_sub_domain = advanced.cross_sub_domain_cookies.as_ref();
    let mut cross_sub_domain_options = Map::from_iter([(
        "domain".into(),
        json!(
            cross_sub_domain
                .and_then(|config| config.domain.as_ref())
                .is_some_and(|value| !value.is_empty())
        ),
    )]);
    option(
        &mut cross_sub_domain_options,
        "enabled",
        cross_sub_domain.and_then(|config| config.enabled),
    )?;
    option(
        &mut cross_sub_domain_options,
        "additionalCookies",
        cross_sub_domain.and_then(|config| config.additional_cookies.as_ref()),
    )?;
    let mut advanced_options = Map::from_iter([
        ("ipAddress".into(), json!(ip_address)),
        ("cookies".into(), json!(advanced.cookies.is_some())),
        (
            "cookiePrefix".into(),
            json!(
                advanced
                    .cookie_prefix
                    .as_ref()
                    .is_some_and(|value| !value.is_empty())
            ),
        ),
        ("database".into(), json!(database)),
        ("cookieAttributes".into(), json!(cookies)),
        (
            "crossSubDomainCookies".into(),
            json!(cross_sub_domain_options),
        ),
    ]);
    option(
        &mut advanced_options,
        "useSecureCookies",
        advanced.use_secure_cookies,
    )?;
    option(
        &mut advanced_options,
        "disableCSRFCheck",
        advanced.disable_csrf_check,
    )?;

    let mut rate_limit = Map::from_iter([(
        "customStorage".into(),
        json!(
            options
                .rate_limit
                .is_some_and(|config| config.custom_storage.is_some())
        ),
    )]);
    option(
        &mut rate_limit,
        "modelName",
        options.rate_limit_model.and_then(|model| model.model_name),
    )?;
    option(
        &mut rate_limit,
        "window",
        options.rate_limit.and_then(|config| config.window),
    )?;
    option(
        &mut rate_limit,
        "max",
        options.rate_limit.and_then(|config| config.max_requests),
    )?;
    option(
        &mut rate_limit,
        "enabled",
        options.rate_limit.and_then(|config| config.enabled),
    )?;
    option(
        &mut rate_limit,
        "storage",
        options
            .rate_limit
            .and_then(|config| config.storage)
            .map(|storage| match storage {
                RateLimitStorageKind::Memory => "memory",
                RateLimitStorageKind::Database => "database",
                RateLimitStorageKind::Secondary => "secondary-storage",
            }),
    )?;
    let mut api_error = Map::from_iter([("onError".into(), json!(options.on_error))]);
    option(&mut api_error, "throw", config.api_error.throw_errors)?;
    option(
        &mut api_error,
        "errorURL",
        config.api_error.error_url.as_ref(),
    )?;

    let linking = &config.account.account_linking;
    let mut account_linking = Map::new();
    option(&mut account_linking, "enabled", linking.enabled)?;
    option(
        &mut account_linking,
        "allowUnlinkingAll",
        linking.allow_unlinking_all,
    )?;
    option(
        &mut account_linking,
        "updateUserInfoOnLink",
        linking.update_user_info_on_link,
    )?;
    option(
        &mut account_linking,
        "trustedProviders",
        config
            .account
            .account_linking
            .trusted_providers
            .as_ref()
            .and_then(better_auth_core::TrustedValues::as_static),
    )?;
    let mut account = Map::from_iter([("accountLinking".into(), json!(account_linking))]);
    option(
        &mut account,
        "encryptOAuthTokens",
        config.account.encrypt_oauth_tokens,
    )?;
    option(
        &mut account,
        "updateAccountOnSignIn",
        config.account.update_account_on_sign_in,
    )?;
    let mut verification = Map::new();
    option(
        &mut verification,
        "disableCleanup",
        config.verification.disable_cleanup,
    )?;

    for declaration in S::model_declarations() {
        use better_auth_core::schema::EntityRole;
        let model = match declaration.role {
            EntityRole::User => &mut user,
            EntityRole::Session => &mut session,
            EntityRole::Account => &mut account,
            EntityRole::Verification => &mut verification,
            _ => continue,
        };
        option(model, "modelName", declaration.model_name)?;
        option(
            model,
            "fields",
            declaration
                .fields
                .map(|fields| fields.iter().copied().collect::<BTreeMap<_, _>>()),
        )?;
    }

    let mut config_options = Map::from_iter([
        (
            "database".into(),
            json!(if options.database {
                "adapter"
            } else {
                "unknown"
            }),
        ),
        ("adapter".into(), json!(options.adapter)),
        (
            "socialProviders".into(),
            json!(plugin_options.social_providers),
        ),
        (
            "emailVerification".into(),
            json!(plugin_options.email_verification),
        ),
        (
            "emailAndPassword".into(),
            json!(plugin_options.email_and_password),
        ),
        ("user".into(), json!(user)),
        (
            "plugins".into(),
            json!(
                plugins
                    .iter()
                    .filter_map(|plugin| plugin.telemetry_plugin_id())
                    .collect::<Vec<_>>()
            ),
        ),
        (
            "hooks".into(),
            json!({"before":options.before,"after":options.after}),
        ),
        ("secondaryStorage".into(), json!(options.secondary)),
        ("logger".into(), json!(logger)),
        ("session".into(), json!(session)),
        ("account".into(), json!(account)),
        ("verification".into(), json!(verification)),
        ("advanced".into(), json!(advanced_options)),
        ("rateLimit".into(), json!(rate_limit)),
        ("onAPIError".into(), json!(api_error)),
        (
            "databaseHooks".into(),
            json!(database_hooks(&options.database_hooks)),
        ),
    ]);
    option(
        &mut config_options,
        "trustedOrigins",
        config.trusted_origins.as_ref().map(|values| match values {
            better_auth_core::TrustedValues::Static(values) => values.len(),
            better_auth_core::TrustedValues::Dynamic(_)
            | better_auth_core::TrustedValues::Merged(_) => 1,
        }),
    )?;
    let mut payload = Telemetry::initialization_metadata();
    let _ = payload.insert("config".into(), Value::Object(config_options));
    Ok(Value::Object(payload))
}

fn database_hooks(hooks: &[DatabaseHookMetadata]) -> Map<String, Value> {
    use DatabaseHook::*;
    let declared = |method| {
        hooks
            .iter()
            .any(|hook| hook.source == "user" && hook.methods.contains(&method))
    };
    [
        (
            "user",
            [
                BeforeCreateUser,
                AfterCreateUser,
                BeforeUpdateUser,
                AfterUpdateUser,
            ],
        ),
        (
            "session",
            [
                BeforeCreateSession,
                AfterCreateSession,
                BeforeUpdateSession,
                AfterUpdateSession,
            ],
        ),
        (
            "account",
            [
                BeforeCreateAccount,
                AfterCreateAccount,
                BeforeUpdateAccount,
                AfterUpdateAccount,
            ],
        ),
        (
            "verification",
            [
                BeforeCreateVerification,
                AfterCreateVerification,
                BeforeUpdateVerification,
                AfterUpdateVerification,
            ],
        ),
    ]
    .into_iter()
    .map(
        |(model, [before_create, after_create, before_update, after_update])| {
            (
                model.into(),
                json!({
                    "create":{"before":declared(before_create),"after":declared(after_create)},
                    "update":{"before":declared(before_update),"after":declared(after_update)},
                }),
            )
        },
    )
    .collect()
}

/// Start the init report before plugin initialization without awaiting a pending transport.
pub(super) async fn start_init(
    telemetry: better_auth_core::observability::telemetry::Telemetry,
    payload: Value,
) -> better_auth_core::AuthResult<()> {
    use std::{future::poll_fn, task::Poll};
    let mut task = Box::pin(async move { telemetry.publish("init", payload).await });
    match poll_fn(|cx| Poll::Ready(task.as_mut().poll(cx))).await {
        Poll::Ready(result) => result,
        Poll::Pending => {
            drop(tokio::spawn(async move {
                if let Err(error) = task.await {
                    better_auth_core::observability::logger::current().error(
                        "Telemetry serialization failed",
                        &[better_auth_core::observability::LogArgument::Error(&error)],
                    );
                }
            }));
            Ok(())
        }
    }
}

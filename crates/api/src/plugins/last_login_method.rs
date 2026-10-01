//! Track the last login method in a readable cookie and, optionally, the user record.

use std::sync::Arc;

use async_trait::async_trait;
use better_auth_core::entity::AuthSession;
use better_auth_core::plugin_runtime::PluginRuntime;
use better_auth_core::store::database_hooks::{
    DatabaseHookContext, DatabaseHookControl, DatabaseHooks,
};
use better_auth_core::user_fields::{UserConfig, UserFieldConfig};
use better_auth_core::utils::cookie_utils::{
    encode_cookie_value, render_cookie, session_cookie_template,
};
use better_auth_core::{
    AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
    AuthRoute, AuthSchema, CreateUser, UpdateUser,
};

use super::endpoint_context::EndpointContext;

/// Override the detected method. `None` uses the default resolver; an empty string suppresses tracking.
pub trait LastLoginMethodResolver<S: AuthSchema>: Send + Sync {
    /// Resolve the method from the active endpoint, runtime, and transaction.
    fn resolve(&self, context: &EndpointContext<'_, S>) -> AuthResult<Option<String>>;
}

/// Decide whether the readable method cookie should be written.
#[async_trait]
pub trait BeforeStoreLastLoginCookie<S: AuthSchema>: Send + Sync {
    /// A false result or error suppresses this cookie without failing authentication.
    async fn before_store_cookie(
        &self,
        context: &EndpointContext<'_, S>,
        method: &str,
    ) -> AuthResult<bool>;
}

/// Last-login persistence and cookie options.
#[derive(Clone)]
pub struct LastLoginMethodConfig {
    /// Literal cookie name. This name is not passed through the global cookie prefix resolver.
    pub cookie_name: String,
    /// Cookie lifetime in seconds. Zero expires the cookie; a negative value omits Max-Age.
    pub max_age: f64,
    /// Persist `lastLoginMethod` on user creation and after session creation commits.
    pub store_in_database: bool,
    /// Storage field used by the application's user model.
    pub field_name: Option<String>,
}

impl Default for LastLoginMethodConfig {
    fn default() -> Self {
        Self {
            cookie_name: "better-auth.last_used_login_method".into(),
            max_age: 2_592_000.0,
            store_in_database: false,
            field_name: None,
        }
    }
}

/// Last-login plugin with typed endpoint callbacks.
pub struct LastLoginMethodPlugin<S: AuthSchema> {
    config: LastLoginMethodConfig,
    resolver: Option<Arc<dyn LastLoginMethodResolver<S>>>,
    before_store_cookie: Option<Arc<dyn BeforeStoreLastLoginCookie<S>>>,
}

impl<S: AuthSchema> Clone for LastLoginMethodPlugin<S> {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            resolver: self.resolver.clone(),
            before_store_cookie: self.before_store_cookie.clone(),
        }
    }
}

impl<S: AuthSchema> Default for LastLoginMethodPlugin<S> {
    fn default() -> Self {
        Self::new(LastLoginMethodConfig::default())
    }
}

impl<S: AuthSchema> LastLoginMethodPlugin<S> {
    /// Construct the plugin with explicit persistence and cookie options.
    pub fn new(config: LastLoginMethodConfig) -> Self {
        Self {
            config,
            resolver: None,
            before_store_cookie: None,
        }
    }

    /// Configure a synchronous method resolver.
    pub fn custom_resolve_method(mut self, resolver: Arc<dyn LastLoginMethodResolver<S>>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Configure the asynchronous cookie permission callback.
    pub fn before_store_cookie(mut self, callback: Arc<dyn BeforeStoreLastLoginCookie<S>>) -> Self {
        self.before_store_cookie = Some(callback);
        self
    }

    fn resolve(&self, context: &EndpointContext<'_, S>) -> AuthResult<Option<String>> {
        if let Some(resolver) = &self.resolver
            && let Some(method) = resolver.resolve(context)?
        {
            return Ok(Some(method));
        }
        let path = context.path.unwrap_or("");
        let method = if path.starts_with("/callback/") {
            context
                .params
                .get("id")
                .filter(|value| !value.is_empty())
                .map(String::as_str)
                .or_else(|| path.rsplit('/').next())
        } else if matches!(path, "/sign-in/email" | "/sign-up/email") {
            Some("email")
        } else if path.contains("siwe") {
            Some("siwe")
        } else if path.contains("/passkey/verify-authentication") {
            Some("passkey")
        } else if path.starts_with("/magic-link/verify") {
            Some("magic-link")
        } else if path == "/sign-in/email-otp" {
            Some("email-otp")
        } else {
            None
        };
        Ok(method.map(str::to_owned))
    }
}

struct LoginDatabaseHooks<S: AuthSchema> {
    plugin: LastLoginMethodPlugin<S>,
    runtime: PluginRuntime<S>,
}

fn database_endpoint<'a, S: AuthSchema>(
    context: &'a DatabaseHookContext<'_, S>,
    auth: &'a AuthContext<S>,
) -> Option<EndpointContext<'a, S>> {
    let request = context.request.as_ref()?;
    let mut endpoint = EndpointContext::new(
        Some(&request.request),
        request.body.clone().unwrap_or(serde_json::Value::Null),
        auth,
    );
    endpoint.path = Some(&request.path);
    endpoint.params.clone_from(&request.params);
    endpoint.transaction = context.transaction;
    Some(endpoint)
}

#[better_auth_core::database_hooks("plugin:last-login-method")]
impl<S: AuthSchema> DatabaseHooks<S> for LoginDatabaseHooks<S> {
    async fn before_create_user(
        &self,
        user: &mut CreateUser,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        if context.request.is_none() {
            return Ok(DatabaseHookControl::Continue);
        }
        let auth = self.runtime.context()?;
        if let Some(endpoint) = database_endpoint(context, &auth)
            && let Some(method) = self
                .plugin
                .resolve(&endpoint)?
                .filter(|value| !value.is_empty())
        {
            let _ = user
                .additional_fields
                .insert("lastLoginMethod".into(), method.into());
        }
        Ok(DatabaseHookControl::Continue)
    }

    async fn after_create_session(
        &self,
        session: &S::Session,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        if context.request.is_none() {
            return Ok(());
        }
        let auth = self.runtime.context()?;
        let Some(endpoint) = database_endpoint(context, &auth) else {
            return Ok(());
        };
        // Resolver errors precede the upstream update catch and must fail the operation.
        let Some(method) = self
            .plugin
            .resolve(&endpoint)?
            .filter(|value| !value.is_empty())
        else {
            return Ok(());
        };
        let user_id = session.user_id();
        if user_id.is_empty() {
            return Ok(());
        }
        let update = UpdateUser {
            additional_fields: serde_json::Map::from_iter([(
                "lastLoginMethod".into(),
                method.into(),
            )]),
            ..Default::default()
        };
        if let Err(error) = auth.database.update_user(&user_id, update).await {
            // Upstream treats this post-commit metadata update as best effort.
            better_auth_core::observability::logger::current().error(
                "Failed to update lastLoginMethod",
                &[better_auth_core::observability::LogArgument::Error(&error)],
            );
        }
        Ok(())
    }
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for LastLoginMethodPlugin<S> {
    fn name(&self) -> &'static str {
        "last-login-method"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    fn openapi(&self) -> AuthResult<better_auth_core::openapi::OpenApiPluginMetadata> {
        let metadata = better_auth_core::openapi::OpenApiPluginMetadata::from_routes(
            <Self as better_auth_core::AuthPlugin<S>>::name(self),
            <Self as better_auth_core::AuthPlugin<S>>::routes(self),
        )?;
        Ok(if self.config.store_in_database {
            metadata
        } else {
            metadata.remove_model("user")
        })
    }

    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        if self.config.store_in_database {
            context.register_user_fields(UserConfig {
                additional_fields: [(
                    "lastLoginMethod".into(),
                    UserFieldConfig {
                        required: Some(false),
                        input: false,
                        field_name: self.config.field_name.clone(),
                        ..Default::default()
                    },
                )]
                .into(),
            });
            context.register_database_hook(Arc::new(LoginDatabaseHooks {
                plugin: self.clone(),
                runtime: context.runtime(),
            }));
        }
        Ok(())
    }

    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }

    async fn after_request(
        &self,
        request: &AuthRequest,
        response: &mut AuthResponse,
        auth: &AuthContext<S>,
    ) -> AuthResult<()> {
        better_auth_core::observability::instrumentation::with_endpoint_hook(
        &auth.config, request, "after", "plugin:last-login-method", async {
        let hook_context = better_auth_core::hooks::current_request_hook_context();
        let body = match &hook_context {
            Some(context) => context.body.clone().unwrap_or(serde_json::Value::Null),
            None if request.body.is_some() => request.body_as_json()?,
            None => serde_json::Value::Null,
        };
        let mut endpoint = EndpointContext::new(Some(request), body, auth);
        endpoint.path = Some(
            hook_context
                .as_ref()
                .map_or(request.path(), |context| context.path.as_str()),
        );
        endpoint.response = Some(response);
        let Some(method) = self.resolve(&endpoint)?.filter(|value| !value.is_empty()) else {
            return Ok(());
        };
        let template = session_cookie_template(&auth.config);
        if !response
            .headers
            .get_all("set-cookie")
            .any(|cookie| cookie.contains(template.name()))
        {
            return Ok(());
        }
        if let Some(callback) = &self.before_store_cookie {
            match callback.before_store_cookie(&endpoint, &method).await {
                Ok(true) => {}
                Ok(false) => return Ok(()),
                Err(error) => {
                    better_auth_core::observability::logger::current().error("[LastLoginMethod] Error in beforeStoreCookie hook", &[better_auth_core::observability::LogArgument::Error(&error)]);
                    return Ok(());
                }
            }
        }
        if self.config.max_age > 34_560_000.0 {
            return Err(AuthError::internal(
                "Cookies Max-Age SHOULD NOT be greater than 400 days (34560000 seconds) in duration.",
            ));
        }
        let mut cookie = template;
        cookie.set_name(self.config.cookie_name.clone());
        cookie.set_value(encode_cookie_value(&method));
        cookie.set_http_only(false);
        if self.config.cookie_name.starts_with("__Secure-")
            || self.config.cookie_name.starts_with("__Host-")
        {
            cookie.set_secure(true);
        }
        if self.config.cookie_name.starts_with("__Host-") {
            cookie.set_path("/");
            cookie.unset_domain();
        }
        if self.config.max_age >= 0.0 {
            cookie.set_max_age(cookie::time::Duration::seconds(
                self.config.max_age.floor() as i64
            ));
        }
        response.headers.append(
            "Set-Cookie",
            render_cookie(
                cookie,
                &auth.config.auth_cookie("session_token", Default::default()),
            ),
        );
        Ok(())
     }
    ).await
    }
}

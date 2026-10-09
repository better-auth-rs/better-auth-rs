use std::{future::Future, pin::Pin, sync::Arc};

use better_auth_core::wire::{SessionView, UserView};
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema, AuthSession,
    AuthUser, CreateUser, RequestMeta,
};
use rand::distributions::{Alphanumeric, DistString};
use validator::ValidateEmail;

use crate::plugins::helpers::{SessionIssueError, issue_selected_user_session_optional};

mod callbacks;
#[cfg(test)]
mod native_session_tests;
pub use callbacks::{AnonymousCallbackFuture, AnonymousCallbacks};

type FutureResult<T> = Pin<Box<dyn Future<Output = AuthResult<T>> + Send>>;
type Generator = dyn Fn() -> FutureResult<String> + Send + Sync;
type NameGenerator = dyn Fn(AuthRequest) -> FutureResult<String> + Send + Sync;
type LinkCallback = dyn Fn(AnonymousLink) -> FutureResult<()> + Send + Sync;

/// The authenticated identities involved when an anonymous session is upgraded.
#[derive(Debug, Clone)]
pub struct AnonymousLink {
    /// Anonymous identity that existed before authentication.
    pub anonymous_user: UserView,
    /// Active session for the anonymous identity.
    pub anonymous_session: SessionView,
    /// User value supplied by the completed endpoint.
    pub new_user: better_auth_core::FieldValue,
    /// Session issued by the completed endpoint.
    pub new_session: SessionView,
    /// Request that completed authentication.
    pub request: AuthRequest,
}

/// Anonymous sign-in with persisted identities and post-sign-in account linking.
#[derive(Clone, Default)]
pub struct AnonymousPlugin {
    email_domain_name: Option<String>,
    generate_random_email: Option<Arc<Generator>>,
    generate_name: Option<Arc<NameGenerator>>,
    on_link_account: Option<Arc<LinkCallback>>,
    disable_delete_anonymous_user: bool,
}

impl AnonymousPlugin {
    /// Use upstream defaults for anonymous sign-in and account cleanup.
    pub fn new() -> Self {
        Self::default()
    }
    /// Use this domain for generated placeholder emails.
    pub fn email_domain_name(mut self, domain: impl Into<String>) -> Self {
        self.email_domain_name = Some(domain.into());
        self
    }
    /// Disable explicit deletion and post-link anonymous identity cleanup.
    pub fn disable_delete_anonymous_user(mut self, disable: bool) -> Self {
        self.disable_delete_anonymous_user = disable;
        self
    }
    /// Supply an email generator; an empty result uses the default generator.
    pub fn generate_random_email<F, Fut>(mut self, callback: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = AuthResult<String>> + Send + 'static,
    {
        self.generate_random_email = Some(Arc::new(move || Box::pin(callback())));
        self
    }
    /// Generate a name from the sign-in request; an empty result uses `Anonymous`.
    pub fn generate_name<F, Fut>(mut self, callback: F) -> Self
    where
        F: Fn(AuthRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = AuthResult<String>> + Send + 'static,
    {
        self.generate_name = Some(Arc::new(move |request| Box::pin(callback(request))));
        self
    }
    /// Transfer application data before the anonymous identity is deleted.
    pub fn on_link_account<F, Fut>(mut self, callback: F) -> Self
    where
        F: Fn(AnonymousLink) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = AuthResult<()>> + Send + 'static,
    {
        self.on_link_account = Some(Arc::new(move |link| Box::pin(callback(link))));
        self
    }
    async fn sign_in<S: AuthSchema>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        let mut session_request = req.clone();
        let mut query = session_request
            .query
            .take()
            .and_then(|query| query.as_object().cloned())
            .unwrap_or_default();
        let _ = query.insert("disableRefresh".into(), serde_json::Value::Bool(true));
        session_request.query = Some(query.into());
        let previous = ctx
            .session_manager()
            .resolve_native(
                &session_request,
                better_auth_core::session::SessionRead::Cached,
            )
            .await?
            .data;
        if previous
            .as_ref()
            .is_some_and(|data| data.user_field("isAnonymous").is_truthy())
        {
            return Err(error(
                400,
                "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY",
                "Anonymous users cannot sign in again anonymously",
            ));
        }
        let custom_email = match &self.generate_random_email {
            Some(generate) => generate().await?,
            None => String::new(),
        };
        let email = if custom_email.is_empty() {
            let id = Alphanumeric.sample_string(&mut rand::thread_rng(), 32);
            match &self.email_domain_name {
                Some(domain) => format!("temp-{id}@{domain}"),
                None => format!("{id}@anonymous.placeholder.invalid"),
            }
        } else {
            if !custom_email.validate_email() {
                return Err(error(
                    400,
                    "INVALID_EMAIL_FORMAT",
                    "Email was not generated in a valid format",
                ));
            }
            custom_email
        };
        let body = req
            .body
            .as_deref()
            .filter(|body| !body.is_empty())
            .map(super::json_body::decode)
            .transpose()
            .map_err(AuthError::from)?
            .unwrap_or(serde_json::Value::Null);
        let mut endpoint = super::endpoint_context::EndpointContext::new(
            Some(req),
            better_auth_core::FieldValue::from_json(body)?,
            ctx,
        );
        endpoint.session = previous;
        let name = if let Some(generate) = ctx
            .extensions
            .get::<Arc<AnonymousCallbacks<S>>>()
            .and_then(|callbacks| callbacks.name.as_ref())
        {
            generate(&endpoint).await?
        } else if let Some(generate) = &self.generate_name {
            generate(req.clone()).await?
        } else {
            String::new()
        };
        let mut create = CreateUser::new()
            .with_email(email)
            .with_name(if name.is_empty() {
                "Anonymous".into()
            } else {
                name
            });
        create.is_anonymous = Some(true);
        create.email_verified = Some(false);

        let user = super::user_admission::create_user_optional(create, "anonymous", &endpoint)
            .await?
            .ok_or(AuthError::Upstream {
                status: 500,
                code: "FAILED_TO_CREATE_USER",
                message: "Failed to create user",
            })?;
        let meta = RequestMeta::from_request_with_config(req, &ctx.config.advanced.ip_address);
        let issued = issue_selected_user_session_optional(
            ctx,
            better_auth_core::FieldMap::from(ctx.internal_user_view(&user).await?).into(),
            &meta,
            ctx.config.session.expires_in(),
        )
        .await
        .map_err(SessionIssueError::into_auth_error)?
        .ok_or(AuthError::Upstream {
            status: 400,
            code: "COULD_NOT_CREATE_SESSION",
            message: "Could not create session",
        })?;
        let manager = ctx.session_manager();
        manager
            .set_native_session_cookie(req, issued.clone(), None)
            .await?;
        Ok(AuthResponse::native(
            None,
            better_auth_core::FieldMap::from([
                ("token".into(), issued.session.token().field_value()),
                (
                    "user".into(),
                    better_auth_core::FieldMap::from(ctx.user_view(&user).await?).into(),
                ),
            ])
            .into(),
        ))
    }
    async fn delete(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _) = ctx
            .require_authoritative_native_session(req)
            .await
            .map_err(|cause| {
                if matches!(cause, AuthError::Unauthenticated) {
                    error(401, "UNAUTHORIZED", "Unauthorized")
                } else {
                    cause
                }
            })?
            .into_views()?;
        if self.disable_delete_anonymous_user {
            return Err(error(
                400,
                "DELETE_ANONYMOUS_USER_DISABLED",
                "Deleting anonymous users is disabled",
            ));
        }
        if !user.is_anonymous.is_truthy()? {
            return Err(error(403, "USER_IS_NOT_ANONYMOUS", "User is not anonymous"));
        }
        ctx.database
            .delete_user_sessions_by_user_value(&user.id.field_value())
            .await
            .map_err(|cause| {
                better_auth_core::observability::logger::current().error(
                    "Failed to delete anonymous user sessions",
                    &[better_auth_core::observability::LogArgument::Error(&cause)],
                );
                error(
                    500,
                    "FAILED_TO_DELETE_ANONYMOUS_USER_SESSIONS",
                    "Failed to delete anonymous user sessions",
                )
            })?;
        ctx.database
            .delete_user_value(&user.id.field_value())
            .await
            .map_err(|cause| {
                better_auth_core::observability::logger::current().error(
                    "Failed to delete anonymous user",
                    &[better_auth_core::observability::LogArgument::Error(&cause)],
                );
                error(
                    500,
                    "FAILED_TO_DELETE_ANONYMOUS_USER",
                    "Failed to delete anonymous user",
                )
            })?;
        ctx.session_manager().clear_cookies(req)?;
        AuthResponse::json(None, &serde_json::json!({"success":true}))
    }
    async fn link<S: AuthSchema>(
        &self,
        req: &AuthRequest,
        response: &AuthResponse,
        ctx: &AuthContext<S>,
    ) -> AuthResult<()> {
        if ![
            "/sign-in",
            "/sign-up",
            "/callback",
            "/magic-link/verify",
            "/email-otp/verify-email",
            "/one-tap/callback",
            "/passkey/verify-authentication",
            "/phone-number/verify",
            "/verify-email",
        ]
        .iter()
        .any(|prefix| req.path().starts_with(prefix))
        {
            return Ok(());
        }
        let Some(cookie) = response
            .headers
            .get_all("set-cookie")
            .filter_map(|value| cookie::Cookie::parse(value.as_str()).ok())
            .find(|cookie| {
                cookie.name()
                    == ctx
                        .config
                        .auth_cookie("session_token", Default::default())
                        .name
                    && !cookie.value().is_empty()
            })
        else {
            return Ok(());
        };
        if cookie.value().split('.').next().is_none_or(str::is_empty) {
            return Ok(());
        }
        let mut session_request = req.clone();
        let mut query = session_request
            .query
            .take()
            .and_then(|query| query.as_object().cloned())
            .unwrap_or_default();
        let _ = query.insert("disableRefresh".into(), serde_json::Value::Bool(true));
        session_request.query = Some(query.into());
        let previous = ctx
            .session_manager()
            .resolve_native(
                &session_request,
                better_auth_core::session::SessionRead::Cached,
            )
            .await?
            .data;
        let previous =
            match previous.filter(|session| session.user_field("isAnonymous").is_truthy()) {
                Some(previous) => Some(previous),
                None => {
                    if let Some(user_id) = req
                        .server_context("anonymousUserId")?
                        .and_then(|value| value.as_str().map(str::to_owned))
                    {
                        if let Some(user) = ctx
                            .database
                            .get_user_by_id(&user_id)
                            .await?
                            .filter(|user| user.is_anonymous().field_value().is_truthy())
                        {
                            let mut session = None;
                            for candidate in ctx
                                .database
                                .get_user_sessions_value(&user.id.field_value())
                                .await?
                            {
                                if candidate.expires_at().is_after(chrono::Utc::now())? {
                                    session = Some(candidate);
                                    break;
                                }
                            }
                            if let Some(session) = session {
                                Some(better_auth_core::session::NativeSessionData {
                                    user: better_auth_core::FieldMap::from(
                                        ctx.internal_user_view(&user).await?,
                                    )
                                    .into(),
                                    session,
                                })
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
            };
        let Some(mut previous) = previous else {
            return Ok(());
        };
        let mut anonymous_user = previous.user_view()?;
        anonymous_user.set_field("isAnonymous", true.into());
        previous.user = better_auth_core::FieldMap::from(anonymous_user.clone()).into();
        let Some(new_session) = req.new_session()? else {
            if req.path() == "/sign-in/anonymous" {
                return Err(error(
                    400,
                    "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY",
                    "Anonymous users cannot sign in again anonymously",
                ));
            }
            return Ok(());
        };
        let link = AnonymousLink {
            anonymous_user,
            anonymous_session: previous.session.clone(),
            new_user: new_session.user.clone(),
            new_session: new_session.session.clone(),
            request: req.clone(),
        };
        if let Some(callback) = ctx
            .extensions
            .get::<Arc<AnonymousCallbacks<S>>>()
            .and_then(|callbacks| callbacks.link.as_ref())
        {
            let body = req
                .body
                .as_deref()
                .filter(|body| !body.is_empty())
                .map(super::json_body::decode)
                .transpose()
                .map_err(AuthError::from)?
                .unwrap_or(serde_json::Value::Null);
            let mut endpoint = super::endpoint_context::EndpointContext::new(
                Some(req),
                better_auth_core::FieldValue::from_json(body)?,
                ctx,
            );
            endpoint.session = Some(previous.clone());
            endpoint.response = Some(response);
            callback(&link, &endpoint).await?;
        } else if let Some(callback) = &self.on_link_account {
            callback(link).await?;
        }
        if !self.disable_delete_anonymous_user
            && !previous
                .user_field("id")
                .strict_equals(new_session.user_field("id"))
            && !new_session.user_field("isAnonymous").is_truthy()
        {
            // Upstream keeps a successful sign-in when post-link cleanup fails.
            if let Err(cause) = ctx
                .database
                .delete_user_value(previous.user_field("id"))
                .await
            {
                better_auth_core::observability::logger::current().error(
                    "Failed to clean up anonymous user during post-link cleanup",
                    &[better_auth_core::observability::LogArgument::Error(&cause)],
                );
            }
        }
        Ok(())
    }
}

fn error(status: u16, code: &'static str, message: &'static str) -> AuthError {
    AuthError::Upstream {
        status,
        code,
        message,
    }
}

better_auth_core::impl_auth_plugin!(AnonymousPlugin, "anonymous";
    routes {
        post "/sign-in/anonymous" => sign_in, "signInAnonymous";
        post "/delete-anonymous-user" => delete, "deleteAnonymousUser";
    }
    extra {
        async fn on_init(
            &self,
            ctx: &mut better_auth_core::AuthInitContext<S>,
        ) -> AuthResult<()> {
            S::User::require_plugin_fields("anonymous", &["is_anonymous"])?;
            ctx.register_native_user_fields("anonymous.enabled");
            ctx.set_metadata("anonymous.enabled", serde_json::json!(true));
            Ok(())
        }
        async fn before_request(
            &self,
            req: &AuthRequest,
            ctx: &AuthContext<S>,
        ) -> AuthResult<Option<better_auth_core::BeforeRequestAction>> {
            if req.path() != "/sign-in/social" { return Ok(None); }
            better_auth_core::observability::instrumentation::with_endpoint_hook(
                &ctx.config, req, "before", "plugin:anonymous", async {
                    let mut session_request = req.clone();
                    let mut query = session_request.query.take()
                        .and_then(|query| query.as_object().cloned()).unwrap_or_default();
                    let _ = query.insert("disableRefresh".into(), true.into());
                    session_request.query = Some(query.into());
                    let session = ctx.session_manager()
                        .resolve_native(&session_request, better_auth_core::session::SessionRead::Cached)
                        .await?.data;
                    if let Some(session) = session.filter(|session| session.user_field("isAnonymous").is_truthy()) {
                        req.set_server_context("anonymousUserId", session.user_field("id").clone())?;
                    }
                    Ok(None)
                },
            ).await
        }
        async fn after_request(
            &self,
            req: &AuthRequest,
            response: &mut AuthResponse,
            ctx: &AuthContext<S>,
        ) -> AuthResult<()> {
if !(["/sign-in","/sign-up","/callback","/magic-link/verify","/email-otp/verify-email","/one-tap/callback","/passkey/verify-authentication","/phone-number/verify","/verify-email"].iter().any(|prefix|req.path().starts_with(prefix))) { return Ok(()); }
better_auth_core::observability::instrumentation::with_endpoint_hook(
        &ctx.config, req, "after", "plugin:anonymous", async {
            self.link(req, response, ctx).await
         }
    ).await
}
    }
);

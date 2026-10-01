use super::*;
use better_auth_core::session::{SessionCookieContext, SessionCookieSigner};

const TYPE: &str = "better-auth.session-cache+jwt";
const AUDIENCE: &str = "better-auth:session-cache";

pub(super) struct CookieSigner<S: AuthSchema> {
    pub plugin: JwtPlugin,
    pub runtime: better_auth_core::plugin_runtime::PluginRuntime<S>,
}

#[async_trait::async_trait]
impl<S: AuthSchema> SessionCookieSigner<S> for CookieSigner<S> {
    async fn sign(
        &self,
        mut payload: Map<String, Value>,
        expires_in: i64,
        context: SessionCookieContext<'_, S>,
    ) -> AuthResult<String> {
        let sid = payload
            .get("session")
            .and_then(|session| session.get("token"))
            .cloned()
            .ok_or_else(|| AuthError::internal("Session cache requires a session token"))?;
        let subject = payload
            .get("user")
            .and_then(|user| user.get("id"))
            .cloned()
            .ok_or_else(|| AuthError::internal("Session cache requires a user ID"))?;
        payload.extend([
            ("sid".into(), sid),
            ("sub".into(), subject),
            ("iat".into(), Utc::now().timestamp().into()),
            ("exp".into(), (Utc::now().timestamp() + expires_in).into()),
            ("aud".into(), AUDIENCE.into()),
        ]);
        let runtime = self.runtime.context()?;
        let _ = payload.insert("iss".into(), issuer(&runtime).into());
        let mut endpoint = EndpointContext::new(
            Some(context.request),
            request_body(context.request)?,
            &runtime,
        );
        endpoint.transaction = context.transaction;
        endpoint.session = context
            .request
            .session_snapshot()?
            .map(|data| (data.user, data.session));
        self.plugin
            .sign_in_endpoint(
                payload,
                &JwtSigningOptions {
                    header: serde_json::from_value(json!({"typ": TYPE}))?,
                    ..Default::default()
                },
                &endpoint,
            )
            .await
    }

    async fn verify(
        &self,
        token: &str,
        context: SessionCookieContext<'_, S>,
    ) -> AuthResult<Option<Map<String, Value>>> {
        let Some(header) = verification::raw_header(token) else {
            return Ok(None);
        };
        if !header.has_type(TYPE) || !header.has_key_id() {
            return Ok(None);
        }
        let runtime = self.runtime.context()?;
        let mut endpoint = EndpointContext::new(
            Some(context.request),
            request_body(context.request)?,
            &runtime,
        );
        endpoint.transaction = context.transaction;
        endpoint.session = context
            .request
            .session_snapshot()?
            .map(|data| (data.user, data.session));
        let keys = match self.plugin.read_keys(&endpoint).await {
            Ok(Some(keys)) => keys,
            Ok(None) => return Ok(None),
            Err(error) => {
                better_auth_core::observability::logger::current().debug(
                    "Cookie-cache JWT verification failed",
                    &[better_auth_core::observability::LogArgument::Error(&error)],
                );
                return Ok(None);
            }
        };
        let payload = verification::verify_local(
            token,
            &keys,
            self.plugin.config.algorithm,
            Some(issuer(&runtime)),
            Some(&[AUDIENCE]),
            15,
        );
        Ok(payload.filter(|payload| {
            payload.get("sub").is_some_and(|sub| {
                sub.is_string() && Some(sub) == payload.get("user").and_then(|user| user.get("id"))
            }) && payload.get("sid").is_some_and(|sid| {
                sid.is_string()
                    && Some(sid)
                        == payload
                            .get("session")
                            .and_then(|session| session.get("token"))
            })
        }))
    }
}

fn issuer<S: AuthSchema>(context: &AuthContext<S>) -> &str {
    let base_url = context
        .config
        .base_url
        .as_static()
        .unwrap_or_else(|| context.base_url());
    if base_url.is_empty() {
        AUDIENCE
    } else {
        base_url
    }
}

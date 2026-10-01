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
            ("iss".into(), issuer(context.config).into()),
            ("aud".into(), AUDIENCE.into()),
        ]);
        let runtime = self.runtime.context()?;
        let store: &dyn better_auth_core::store::JwksStore = match context.transaction {
            Some(transaction) => transaction,
            None => runtime.database.as_ref(),
        };
        self.plugin
            .sign_with_store(
                payload,
                &JwtSigningOptions {
                    header: serde_json::from_value(json!({"typ": TYPE}))?,
                    ..Default::default()
                },
                context.config,
                store,
            )
            .await
    }

    async fn verify(
        &self,
        token: &str,
        context: SessionCookieContext<'_, S>,
    ) -> AuthResult<Option<Map<String, Value>>> {
        if verification::protected_header(token)
            .and_then(|header| header.token_type().map(str::to_owned))
            .as_deref()
            != Some(TYPE)
        {
            return Ok(None);
        }
        let runtime = self.runtime.context()?;
        let store: &dyn better_auth_core::store::JwksStore = match context.transaction {
            Some(transaction) => transaction,
            None => runtime.database.as_ref(),
        };
        let keys = store.list_jwks().await?;
        let payload = verification::verify_local(
            token,
            &keys,
            self.plugin.config.algorithm,
            issuer(context.config),
            &[AUDIENCE],
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

fn issuer(config: &better_auth_core::AuthConfig) -> &str {
    if config.base_url.is_empty() {
        AUDIENCE
    } else {
        &config.base_url
    }
}

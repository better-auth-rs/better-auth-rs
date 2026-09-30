use super::*;
use better_auth_core::session::SessionCookieSigner;
use std::sync::Arc;

const TYPE: &str = "better-auth.session-cache+jwt";
const AUDIENCE: &str = "better-auth:session-cache";

pub(super) struct CookieSigner<S: AuthSchema> {
    pub plugin: JwtPlugin,
    pub config: Arc<better_auth_core::AuthConfig>,
    pub database: Arc<dyn better_auth_core::store::AuthStore<S>>,
}

#[async_trait::async_trait]
impl<S: AuthSchema> SessionCookieSigner for CookieSigner<S> {
    async fn sign(&self, mut payload: Map<String, Value>, expires_in: i64) -> AuthResult<String> {
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
            ("iss".into(), self.issuer().into()),
            ("aud".into(), AUDIENCE.into()),
        ]);
        self.plugin
            .sign_with_options(
                payload,
                &JwtSigningOptions {
                    header: serde_json::from_value(json!({"typ": TYPE}))?,
                    ..Default::default()
                },
                &AuthContext::new(self.config.clone(), self.database.clone()),
            )
            .await
    }

    async fn verify(&self, token: &str) -> AuthResult<Option<Map<String, Value>>> {
        if verification::protected_header(token)
            .and_then(|header| header.token_type().map(str::to_owned))
            .as_deref()
            != Some(TYPE)
        {
            return Ok(None);
        }
        let keys = self.database.list_jwks().await?;
        let payload = verification::verify_local(
            token,
            &keys,
            self.plugin.config.algorithm,
            self.issuer(),
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

impl<S: AuthSchema> CookieSigner<S> {
    fn issuer(&self) -> &str {
        if self.config.base_url.is_empty() {
            AUDIENCE
        } else {
            &self.config.base_url
        }
    }
}

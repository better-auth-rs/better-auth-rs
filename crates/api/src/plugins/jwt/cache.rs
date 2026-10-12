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
        payload: FieldMap,
        expires_in: f64,
        context: SessionCookieContext<'_, S>,
    ) -> AuthResult<String> {
        let runtime = self.runtime.context()?;
        let mut endpoint = EndpointContext::new(
            Some(context.request),
            request_body(context.request)?,
            &runtime,
        );
        endpoint.transaction = context.transaction;
        endpoint.session = context.request.native_session_snapshot()?;
        let options = JwtSigningOptions {
            header: serde_json::from_value(json!({"typ": TYPE}))?,
            ..Default::default()
        };
        let key = self
            .plugin
            .resolve_local_signing_key(&options, &endpoint)
            .await?
            .ok_or_else(|| {
                AuthError::better_auth(
                    "`jwt({ sessionCookieCache: true })` requires locally managed JWT plugin keys and does not support `jwt.sign`.",
                )
            })?;
        let sid = payload
            .get("session")
            .unwrap_or(&FieldValue::Undefined)
            .model_property("token")?;
        let mut fields = payload.clone();
        let _ = fields.insert("sid".into(), sid);
        let mut fields = better_auth_core::StructuredCloneContext::new().clone_map(&fields)?;
        fields.extend([
            ("iat".into(), Utc::now().timestamp().into()),
            (
                "exp".into(),
                better_auth_core::utils::jwt::numeric_date(
                    &(Utc::now().timestamp() as f64 + expires_in).into(),
                    "setExpirationTime",
                )?,
            ),
            ("iss".into(), issuer(&runtime).into()),
            ("aud".into(), AUDIENCE.into()),
        ]);
        let subject = payload
            .get("user")
            .unwrap_or(&FieldValue::Undefined)
            .model_property("id")?;
        claims::require_string("sub", &subject)?;
        let _ = fields.insert("sub".into(), subject);
        key.sign(fields, &options)
    }

    async fn verify(
        &self,
        token: &str,
        context: SessionCookieContext<'_, S>,
    ) -> AuthResult<Option<Map<String, Value>>> {
        let Some(header) = jose::header(token) else {
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
        endpoint.session = context.request.native_session_snapshot()?;
        let payload = async {
            let keys = self.plugin.read_keys(&endpoint).await?;
            if keys.is_null() || keys.is_undefined() || !keys.model_property("length")?.is_truthy()
            {
                return Ok(None);
            }
            let key = keys::find(&keys, header.field("kid")?)?;
            if !key.is_truthy() {
                return Ok(None);
            }
            let mut algorithm = key.model_property("alg")?;
            if algorithm.is_null() || algorithm.is_undefined() {
                algorithm = overrides::optional_property(
                    &self.plugin.options.property("jwks", "keyPairConfig")?,
                    "alg",
                )?;
                if algorithm.is_null() || algorithm.is_undefined() {
                    algorithm = header.field("alg")?;
                }
            }
            if !algorithm.is_truthy() {
                return Ok(None);
            }
            let public = keys::parse_json(&key.model_property("publicKey")?)?;
            verification::verify_local(
                token,
                public,
                &algorithm,
                Some(&issuer(&runtime)),
                Some(&[AUDIENCE]),
                15,
            )
        }
        .await;
        let payload = match payload {
            Ok(payload) => payload,
            Err(error) => {
                better_auth_core::observability::logger::current().debug(
                    "Cookie-cache JWT verification failed",
                    &[better_auth_core::observability::LogArgument::Error(&error)],
                )?;
                return Ok(None);
            }
        };
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

fn issuer<S: AuthSchema>(context: &AuthContext<S>) -> String {
    let base_url = context
        .config
        .base_url
        .as_static()
        .map(str::to_owned)
        .unwrap_or_else(|| context.base_url());
    if base_url.is_empty() {
        AUDIENCE.to_owned()
    } else {
        base_url
    }
}

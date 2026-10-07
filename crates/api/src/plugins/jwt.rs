//! Persisted JWT signing keys and public JWKS discovery.

use crate::plugins::endpoint_context::EndpointContext;
use better_auth_core::{
    AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
    AuthRoute, AuthSchema, CreateJwk, HttpMethod,
};
use chrono::{Duration, Utc};
use josekit::{
    jwk::{self, Jwk},
    jws::{self, JwsHeader, JwsSigner},
};
use serde_json::{Map, Value, json};

mod adapter;
mod cache;
mod callbacks;
mod claims;
mod native;
mod options;
mod overrides;
mod signing;
mod verification;
pub use callbacks::{JwtAdapterFuture, JwtCallbacks};
pub use native::JwtApi;
pub use options::*;
pub use overrides::{JwtCallOverrides, JwtKeyOptions, JwtTokenOptions};

/// Supported asymmetric signing algorithms.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize)]
pub enum JwtAlgorithm {
    /// Ed25519, the upstream default.
    #[default]
    #[serde(rename = "EdDSA")]
    EdDsa,
    /// RSA PKCS#1 v1.5 with SHA-256 and a 2048-bit key.
    #[serde(rename = "RS256")]
    Rs256,
    /// ECDSA P-256 with SHA-256.
    #[serde(rename = "ES256")]
    Es256,
    /// ECDSA P-521 with SHA-512.
    #[serde(rename = "ES512")]
    Es512,
    /// RSA PSS with SHA-256.
    #[serde(rename = "PS256")]
    Ps256,
}

impl JwtAlgorithm {
    fn name(self) -> &'static str {
        match self {
            Self::EdDsa => "EdDSA",
            Self::Rs256 => "RS256",
            Self::Es256 => "ES256",
            Self::Es512 => "ES512",
            Self::Ps256 => "PS256",
        }
    }
    fn curve(self) -> Option<&'static str> {
        match self {
            Self::EdDsa => Some("Ed25519"),
            Self::Es256 => Some("P-256"),
            Self::Es512 => Some("P-521"),
            Self::Rs256 | Self::Ps256 => None,
        }
    }
    fn generate(self, modulus_length: u32) -> Result<Jwk, josekit::JoseError> {
        match self {
            Self::EdDsa => Jwk::generate_ed_key(jwk::Ed25519),
            Self::Rs256 | Self::Ps256 => Jwk::generate_rsa_key(modulus_length),
            Self::Es256 => Jwk::generate_ec_key(jwk::P_256),
            Self::Es512 => Jwk::generate_ec_key(jwk::P_521),
        }
    }
}

/// Local signing and discovery options.
#[derive(Clone, better_auth_core::PluginConfig)]
#[plugin(name = "JwtPlugin")]
pub struct JwtPluginConfig {
    /// Use locally managed keys for JWT session cookie caches.
    #[config(default = false)]
    pub session_cookie_cache: bool,
    /// RSA modulus length for the primary algorithm.
    #[config(default = 2048)]
    pub modulus_length: u32,
    /// Additional algorithms that explicit signing requests may provision.
    #[config(default = Vec::new())]
    pub key_pair_configs: Vec<JwtKeyPairConfig>,
    /// Remote discovery URL. Disables local discovery; does not change the verifier's adapter.
    #[config(default = None)]
    pub remote_url: Option<String>,
    /// Application-managed signing callback. Requires `remote_url`.
    #[config(default = None)]
    pub custom_sign: Option<JwtCustomSign>,
    /// Session payload callback, before default claims and subject selection.
    #[config(default = None)]
    pub define_payload: Option<JwtDefinePayload>,
    /// Session subject callback.
    #[config(default = None)]
    pub get_subject: Option<JwtGetSubject>,
    /// Public discovery path.
    #[config(default = "/jwks".to_owned())]
    pub jwks_path: String,
    /// Algorithm used for newly generated keys.
    #[config(default = JwtAlgorithm::EdDsa)]
    pub algorithm: JwtAlgorithm,
    /// Relative token lifetime or absolute expiration timestamp.
    #[config(default = JwtExpiration::After(Duration::minutes(15)), skip)]
    pub expiration_time: JwtExpiration,
    /// Issuer claim; defaults to the configured base URL.
    #[config(default = None)]
    pub issuer: Option<String>,
    /// Audience claim; defaults to the configured base URL.
    #[config(default = None)]
    pub audience: Option<JwtAudience>,
    /// Lifetime of signing keys; no automatic rotation when absent.
    #[config(default = None)]
    pub rotation_interval: Option<Duration>,
    /// Keep expired public keys discoverable for previously issued tokens.
    #[config(default = Duration::days(30))]
    pub grace_period: Duration,
    /// Store plaintext private JWKs instead of secret-encrypted JWKs.
    #[config(default = false)]
    pub disable_private_key_encryption: bool,
    /// Suppress the JWT header on successful session responses.
    #[config(default = false)]
    pub disable_setting_jwt_header: bool,
}

/// Issue session JWTs with keys persisted through `JwksStore`.
pub struct JwtPlugin {
    config: JwtPluginConfig,
}

impl JwtPlugin {
    /// Set a relative duration, an absolute date, or a NumericDate in seconds.
    pub fn expiration_time(mut self, expiration: impl Into<JwtExpiration>) -> Self {
        self.config.expiration_time = expiration.into();
        self
    }
}

#[async_trait::async_trait]
impl<S: AuthSchema> AuthPlugin<S> for JwtPlugin {
    fn name(&self) -> &'static str {
        "jwt"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get(&self.config.jwks_path, "getJSONWebKeySet"),
            AuthRoute::get("/token", "getJSONWebToken").require_headers(true),
        ]
    }
    async fn on_init(&self, ctx: &mut AuthInitContext<S>) -> AuthResult<()> {
        ctx.extensions.insert(self.config.clone());
        if self.config.custom_sign.is_some() && self.config.remote_url.is_none() {
            return Err(AuthError::config("custom_sign requires remote_url"));
        }
        if !self.config.jwks_path.starts_with('/') || self.config.jwks_path.contains("..") {
            return Err(AuthError::config(
                "jwks_path must start with '/' and must not contain '..'",
            ));
        }
        if self.config.session_cookie_cache {
            if !ctx
                .config
                .session
                .cookie_cache
                .as_ref()
                .is_some_and(|cache| {
                    matches!(
                        cache.strategy(),
                        better_auth_core::config::CookieCacheStrategy::Jwt
                    )
                })
            {
                return Err(AuthError::config(
                    "session_cookie_cache requires the JWT cookie cache strategy",
                ));
            }
            if self.config.custom_sign.is_some() {
                return Err(AuthError::config(
                    "session_cookie_cache requires locally managed JWT keys",
                ));
            }
            let signer: std::sync::Arc<dyn better_auth_core::session::SessionCookieSigner<S>> =
                std::sync::Arc::new(cache::CookieSigner {
                    plugin: Self::with_config(self.config.clone()),
                    runtime: ctx.runtime(),
                });
            ctx.extensions.insert(signer);
        }
        Ok(())
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        if req.method() != &HttpMethod::Get
            || (req.path() != self.config.jwks_path && req.path() != "/token")
        {
            return Ok(None);
        }
        let mut endpoint = EndpointContext::new(Some(req), request_body(req)?, ctx);
        if req.path() == self.config.jwks_path {
            return self.jwks(&endpoint).await.map(Some);
        }
        if req.path() == "/token" {
            let (user, session) = ctx
                .require_session(req)
                .await
                .map_err(|error| match error {
                    AuthError::Unauthenticated => AuthError::Upstream {
                        status: 401,
                        code: "UNAUTHORIZED",
                        message: "Unauthorized",
                    },
                    error => error,
                })?;
            endpoint.session = Some((user.clone(), session.clone()));
            let token = self
                .sign_session(json!({"user": user, "session": session}), &endpoint)
                .await?;
            return Ok(Some(AuthResponse::json(200, &json!({"token": token}))?));
        }
        Ok(None)
    }
    async fn after_request(
        &self,
        req: &AuthRequest,
        response: &mut AuthResponse,
        ctx: &AuthContext<S>,
    ) -> AuthResult<()> {
        if !(req.path() == "/get-session") {
            return Ok(());
        }
        better_auth_core::observability::instrumentation::with_endpoint_hook(
            &ctx.config,
            req,
            "after",
            "plugin:jwt",
            async {
                if self.config.disable_setting_jwt_header || req.path() != "/get-session" {
                    return Ok(());
                }
                let Some(data) = req.session_snapshot()?.or(req.new_session()?) else {
                    return Ok(());
                };
                let payload = serde_json::to_value(&data)?;
                let mut endpoint = EndpointContext::new(Some(req), request_body(req)?, ctx);
                endpoint.session = Some((data.user, data.session));
                endpoint.response = Some(response);
                let token = self.sign_session(payload, &endpoint).await?;
                let _ = response.headers.insert("set-auth-jwt", token);
                let mut exposed: Vec<_> = response
                    .headers
                    .get("access-control-expose-headers")
                    .map(|value| {
                        value
                            .split(',')
                            .map(str::trim)
                            .filter(|value| !value.is_empty())
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default();
                if !exposed.iter().any(|value| value == "set-auth-jwt") {
                    exposed.push("set-auth-jwt".into());
                }
                let _ = response
                    .headers
                    .insert("Access-Control-Expose-Headers", exposed.join(", "));
                Ok(())
            },
        )
        .await
    }
}

impl JwtPlugin {
    async fn create_key<S: AuthSchema>(
        &self,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<better_auth_core::Jwk> {
        self.create_key_pair_in_endpoint(
            JwtKeyPairConfig {
                algorithm: self.config.algorithm,
                modulus_length: self.config.modulus_length,
            },
            endpoint,
        )
        .await
    }

    /// Provision a local key with explicit parameters.
    pub async fn create_key_pair<S: AuthSchema>(
        &self,
        parameters: JwtKeyPairConfig,
        ctx: &AuthContext<S>,
    ) -> AuthResult<better_auth_core::Jwk> {
        ctx.with_native_context(Default::default(), |resolved| async move {
            let mut endpoint =
                EndpointContext::new(None, better_auth_core::FieldValue::Null, &resolved);
            endpoint.path = Some("virtual:");
            self.create_key_pair_in_endpoint(parameters, &endpoint)
                .await
        })
        .await
    }

    /// Provision a key with the supplied endpoint context and active transaction.
    pub async fn create_key_pair_in_endpoint<S: AuthSchema>(
        &self,
        parameters: JwtKeyPairConfig,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<better_auth_core::Jwk> {
        if matches!(
            parameters.algorithm,
            JwtAlgorithm::Rs256 | JwtAlgorithm::Ps256
        ) && parameters.modulus_length < 2048
        {
            return Err(AuthError::config(
                "RSA modulus_length must be at least 2048",
            ));
        }
        let mut key = parameters
            .algorithm
            .generate(parameters.modulus_length)
            .map_err(jose_error)?;
        key.set_parameter("use", None).map_err(jose_error)?;
        let public_key = key.to_public_key().map_err(jose_error)?.to_string();
        let private_key = if self.config.disable_private_key_encryption {
            key.to_string()
        } else {
            serde_json::to_string(&super::symmetric::encrypt(
                endpoint.auth.config.encryption_secret(),
                &key.to_string(),
            )?)?
        };
        self.persist_key(
            CreateJwk {
                additional_fields: Default::default(),
                public_key,
                private_key,
                created_at: Utc::now().into(),
                expires_at: self
                    .config
                    .rotation_interval
                    .filter(|interval| !interval.is_zero())
                    .map(|interval| (Utc::now() + interval).into()),
                alg: parameters.algorithm.name().to_owned(),
                crv: parameters.algorithm.curve().map(str::to_owned),
            },
            endpoint,
        )
        .await
    }

    async fn jwks<S: AuthSchema>(
        &self,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<AuthResponse> {
        if self.config.remote_url.is_some() {
            let mut response = AuthResponse::new(404);
            let _ = response.headers.insert("content-type", "application/json");
            return Ok(response);
        }
        let mut keys = self.read_keys(endpoint).await?;
        if keys.as_ref().is_none_or(Vec::is_empty) {
            let _ = self.create_key(endpoint).await?;
            keys = self.read_keys(endpoint).await?;
        }
        let keys = keys.filter(|keys| !keys.is_empty()).ok_or_else(|| {
            AuthError::internal("No key sets found. Make sure you have a key in your database.")
        })?;
        let mut public = Vec::new();
        for key in keys.into_iter().filter(|key| {
            key.expires_at.as_ref().is_none_or(|expiry| {
                expiry.milliseconds() + self.config.grace_period.num_milliseconds() as f64
                    > Utc::now().timestamp_millis() as f64
            })
        }) {
            let mut value: Map<String, Value> = serde_json::from_str(&key.public_key)?;
            let _ = value.entry("alg").or_insert_with(|| {
                key.alg
                    .unwrap_or_else(|| self.config.algorithm.name().to_owned())
                    .into()
            });
            if let Some(curve) = key.crv {
                let _ = value.entry("crv").or_insert(curve.into());
            }
            if let Some(id) = key.id.json()? {
                let _ = value.insert("kid".into(), id);
            }
            public.push(value);
        }
        Ok(AuthResponse::json(200, &json!({"keys": public}))?)
    }
}

fn request_body(request: &AuthRequest) -> AuthResult<better_auth_core::FieldValue> {
    if let Some(context) = better_auth_core::hooks::current_request_hook_context() {
        return Ok(context.body);
    }
    request.input_field_value()
}

fn jose_error(error: josekit::JoseError) -> AuthError {
    AuthError::internal(format!("JWT signing key: {error}"))
}

#[cfg(test)]
mod tests;

//! Persisted JWT signing keys and public JWKS discovery.

use better_auth_core::{
    AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
    AuthRoute, AuthSchema, CreateJwk, HttpMethod,
};
use chrono::{Duration, Utc};
use josekit::{
    jwk::{self, Jwk},
    jws::{self, JwsHeader, JwsSigner},
    jwt::JwtPayload,
};
use serde_json::{Map, Value, json};

/// Supported asymmetric signing algorithms.
#[derive(Clone, Copy, Debug, Default)]
pub enum JwtAlgorithm {
    /// Ed25519, the upstream default.
    #[default]
    EdDsa,
    /// RSA PKCS#1 v1.5 with SHA-256 and a 2048-bit key.
    Rs256,
    /// ECDSA P-256 with SHA-256.
    Es256,
}

impl JwtAlgorithm {
    fn name(self) -> &'static str {
        match self {
            Self::EdDsa => "EdDSA",
            Self::Rs256 => "RS256",
            Self::Es256 => "ES256",
        }
    }
    fn curve(self) -> Option<&'static str> {
        match self {
            Self::EdDsa => Some("Ed25519"),
            Self::Es256 => Some("P-256"),
            Self::Rs256 => None,
        }
    }
    fn generate(self) -> Result<Jwk, josekit::JoseError> {
        match self {
            Self::EdDsa => Jwk::generate_ed_key(jwk::Ed25519),
            Self::Rs256 => Jwk::generate_rsa_key(2048),
            Self::Es256 => Jwk::generate_ec_key(jwk::P_256),
        }
    }
}

/// Local signing and discovery options.
#[derive(Clone, better_auth_core::PluginConfig)]
#[plugin(name = "JwtPlugin")]
pub struct JwtPluginConfig {
    /// Public discovery path.
    #[config(default = "/jwks".to_owned())]
    pub jwks_path: String,
    /// Algorithm used for newly generated keys.
    #[config(default = JwtAlgorithm::EdDsa)]
    pub algorithm: JwtAlgorithm,
    /// Token lifetime.
    #[config(default = Duration::minutes(15))]
    pub expiration_time: Duration,
    /// Issuer claim; defaults to the configured base URL.
    #[config(default = None)]
    pub issuer: Option<String>,
    /// Audience claim; defaults to the configured base URL.
    #[config(default = None)]
    pub audience: Option<String>,
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

#[async_trait::async_trait]
impl<S: AuthSchema> AuthPlugin<S> for JwtPlugin {
    fn name(&self) -> &'static str {
        "jwt"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get(&self.config.jwks_path, "getJSONWebKeySet"),
            AuthRoute::get("/token", "getJSONWebToken"),
        ]
    }
    async fn on_init(&self, _ctx: &mut AuthInitContext<S>) -> AuthResult<()> {
        if !self.config.jwks_path.starts_with('/') || self.config.jwks_path.contains("..") {
            return Err(AuthError::config(
                "jwks_path must start with '/' and must not contain '..'",
            ));
        }
        Ok(())
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        if req.method() != &HttpMethod::Get {
            return Ok(None);
        }
        if req.path() == self.config.jwks_path {
            return self.jwks(ctx).await.map(Some);
        }
        if req.path() == "/token" {
            let (user, _) = ctx
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
            let token = self.sign_user(serde_json::to_value(user)?, ctx).await?;
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
        if self.config.disable_setting_jwt_header
            || req.path() != "/get-session"
            || response.status != 200
        {
            return Ok(());
        }
        let body: Value = serde_json::from_slice(&response.body)?;
        let Some(user) = body.get("user").filter(|user| user.is_object()) else {
            return Ok(());
        };
        let token = self.sign_user(user.clone(), ctx).await?;
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
    }
}

impl JwtPlugin {
    async fn create_key<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
    ) -> AuthResult<better_auth_core::Jwk> {
        let mut key = self.config.algorithm.generate().map_err(jose_error)?;
        key.set_parameter("use", None).map_err(jose_error)?;
        let public_key = key.to_public_key().map_err(jose_error)?.to_string();
        let private_key = if self.config.disable_private_key_encryption {
            key.to_string()
        } else {
            serde_json::to_string(&super::symmetric::encrypt(
                &ctx.config.secret,
                &key.to_string(),
            )?)?
        };
        ctx.database
            .create_jwk(CreateJwk {
                public_key,
                private_key,
                expires_at: self
                    .config
                    .rotation_interval
                    .filter(|interval| !interval.is_zero())
                    .map(|interval| Utc::now() + interval),
                alg: self.config.algorithm.name().to_owned(),
                crv: self.config.algorithm.curve().map(str::to_owned),
            })
            .await
    }

    async fn jwks<S: AuthSchema>(&self, ctx: &AuthContext<S>) -> AuthResult<AuthResponse> {
        let mut keys = ctx.database.list_jwks().await?;
        if keys.is_empty() {
            keys.push(self.create_key(ctx).await?);
        }
        let mut public = Vec::new();
        for key in keys.into_iter().filter(|key| {
            key.expires_at
                .is_none_or(|expiry| expiry + self.config.grace_period > Utc::now())
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
            let _ = value.insert("kid".into(), key.id.into());
            public.push(value);
        }
        Ok(AuthResponse::json(200, &json!({"keys": public}))?)
    }

    async fn sign_user<S: AuthSchema>(
        &self,
        user: Value,
        ctx: &AuthContext<S>,
    ) -> AuthResult<String> {
        let mut payload = user
            .as_object()
            .cloned()
            .ok_or_else(|| AuthError::internal("JWT user must be an object"))?;
        let subject = payload
            .get("id")
            .cloned()
            .ok_or_else(|| AuthError::internal("JWT user must have an ID"))?;
        for (field, value) in super::helpers::user_plugin_defaults(ctx) {
            let _ = payload.entry(field.to_owned()).or_insert(value);
        }
        let _ = payload
            .entry("iat")
            .or_insert_with(|| Utc::now().timestamp().into());
        let _ = payload.insert("sub".into(), subject);
        self.sign(payload, ctx).await
    }

    /// Sign an application payload with the same persisted keys as `/token`.
    pub async fn sign<S: AuthSchema>(
        &self,
        mut payload: Map<String, Value>,
        ctx: &AuthContext<S>,
    ) -> AuthResult<String> {
        let mut keys = ctx.database.list_jwks().await?;
        keys.retain(|key| key.expires_at.is_none_or(|expiry| expiry > Utc::now()));
        keys.sort_by_key(|key| std::cmp::Reverse(key.created_at));
        let key = match keys
            .iter()
            .find(|key| {
                key.alg.as_deref().unwrap_or(self.config.algorithm.name())
                    == self.config.algorithm.name()
            })
            .or(keys.first())
        {
            Some(key) => key.clone(),
            None => self.create_key(ctx).await?,
        };
        let private = if self.config.disable_private_key_encryption {
            key.private_key
        } else {
            super::symmetric::decrypt(
                &ctx.config.secret,
                &serde_json::from_str::<String>(&key.private_key)?,
            )?
        };
        let private = Jwk::from_bytes(private).map_err(jose_error)?;
        let algorithm = key.alg.as_deref().unwrap_or(self.config.algorithm.name());
        let signer: Box<dyn JwsSigner> = match algorithm {
            "EdDSA" => Box::new(jws::EdDSA.signer_from_jwk(&private).map_err(jose_error)?),
            "RS256" => Box::new(jws::RS256.signer_from_jwk(&private).map_err(jose_error)?),
            "ES256" => Box::new(jws::ES256.signer_from_jwk(&private).map_err(jose_error)?),
            _ => {
                return Err(AuthError::config(format!(
                    "Unsupported JWT signing algorithm: {algorithm}"
                )));
            }
        };
        let issued = payload
            .get("iat")
            .and_then(Value::as_i64)
            .unwrap_or_else(|| Utc::now().timestamp());
        for (claim, default) in [
            (
                "exp",
                Value::from(issued + self.config.expiration_time.num_seconds()),
            ),
            (
                "iss",
                self.config
                    .issuer
                    .as_ref()
                    .unwrap_or(&ctx.config.base_url)
                    .clone()
                    .into(),
            ),
            (
                "aud",
                self.config
                    .audience
                    .as_ref()
                    .unwrap_or(&ctx.config.base_url)
                    .clone()
                    .into(),
            ),
        ] {
            if payload.get(claim).is_none_or(Value::is_null) {
                let _ = payload.insert(claim.to_owned(), default);
            }
        }
        let payload = JwtPayload::from_map(payload).map_err(jose_error)?;
        let mut header = JwsHeader::new();
        header.set_algorithm(algorithm);
        header.set_key_id(key.id);
        josekit::jwt::encode_with_signer(&payload, &header, signer.as_ref()).map_err(jose_error)
    }
}

fn jose_error(error: josekit::JoseError) -> AuthError {
    AuthError::internal(format!("JWT signing key: {error}"))
}

#[cfg(test)]
mod tests;

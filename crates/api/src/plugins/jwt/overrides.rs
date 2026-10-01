use super::*;

/// Token defaults that replace the entire upstream `jwt` option group for one native signing call.
#[derive(Clone, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JwtTokenOptions {
    pub issuer: Option<String>,
    pub audience: Option<JwtAudience>,
    #[serde(default, deserialize_with = "input::expiration")]
    pub expiration_time: Option<JwtExpiration>,
    #[serde(skip)]
    pub custom_sign: Option<JwtCustomSign>,
}

/// Key defaults that replace the entire upstream `jwks` option group for one native signing call.
#[derive(Clone, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JwtKeyOptions {
    #[serde(rename = "keyPairConfig")]
    pub key_pair: Option<JwtKeyPairConfig>,
    pub key_pair_configs: Option<Vec<JwtKeyPairConfig>>,
    #[serde(default, deserialize_with = "input::duration")]
    pub rotation_interval: Option<Duration>,
    pub disable_private_key_encryption: Option<bool>,
}

/// Independent group replacements for upstream `signJWT.overrideOptions`.
/// An omitted group retains registration defaults. An empty adapter restores default persistence.
pub struct JwtCallOverrides<S: AuthSchema> {
    pub jwt: Option<JwtTokenOptions>,
    pub jwks: Option<JwtKeyOptions>,
    pub adapter: Option<JwtCallbacks<S>>,
}

impl<S: AuthSchema> Default for JwtCallOverrides<S> {
    fn default() -> Self {
        Self {
            jwt: None,
            jwks: None,
            adapter: None,
        }
    }
}

impl<S: AuthSchema> JwtCallOverrides<S> {
    pub(super) fn apply(self, config: &mut JwtPluginConfig, context: &mut AuthContext<S>) -> Value {
        let mut body = Map::new();
        if let Some(jwt) = self.jwt {
            let mut values = Map::new();
            if let Some(issuer) = &jwt.issuer {
                let _ = values.insert("issuer".into(), issuer.clone().into());
            }
            if let Some(audience) = &jwt.audience {
                let _ = values.insert("audience".into(), json!(audience));
            }
            if let Some(expiration) = &jwt.expiration_time {
                let value = match expiration {
                    JwtExpiration::At(value) => Value::Number(value.clone()),
                    JwtExpiration::After(duration) => {
                        format!("{}s", duration_seconds(*duration)).into()
                    }
                };
                let _ = values.insert("expirationTime".into(), value);
            }
            let _ = body.insert("jwt".into(), values.into());
            config.issuer = jwt.issuer;
            config.audience = jwt.audience;
            config.expiration_time = jwt
                .expiration_time
                .unwrap_or(JwtExpiration::After(Duration::minutes(15)));
            config.custom_sign = jwt.custom_sign;
            config.define_payload = None;
            config.get_subject = None;
        }
        if let Some(jwks) = self.jwks {
            let mut values = Map::new();
            if let Some(parameters) = jwks.key_pair {
                let _ = values.insert("keyPairConfig".into(), key_pair(parameters));
            }
            if let Some(parameters) = &jwks.key_pair_configs {
                let _ = values.insert(
                    "keyPairConfigs".into(),
                    parameters.iter().copied().map(key_pair).collect(),
                );
            }
            if let Some(rotation) = jwks.rotation_interval {
                let _ = values.insert("rotationInterval".into(), duration_seconds(rotation).into());
            }
            if let Some(disabled) = jwks.disable_private_key_encryption {
                let _ = values.insert("disablePrivateKeyEncryption".into(), disabled.into());
            }
            let _ = body.insert("jwks".into(), values.into());
            let primary = jwks
                .key_pair
                .unwrap_or(JwtKeyPairConfig::new(JwtAlgorithm::EdDsa));
            config.algorithm = primary.algorithm;
            config.modulus_length = primary.modulus_length;
            config.key_pair_configs = jwks.key_pair_configs.unwrap_or_default();
            config.rotation_interval = jwks.rotation_interval;
            config.disable_private_key_encryption =
                jwks.disable_private_key_encryption.unwrap_or(false);
        }
        if let Some(adapter) = self.adapter {
            let _ = body.insert("adapter".into(), json!({}));
            context.extensions.insert(std::sync::Arc::new(adapter));
        }
        body.into()
    }
}

fn key_pair(parameters: JwtKeyPairConfig) -> Value {
    json!({"alg": parameters.algorithm.name(), "modulusLength": parameters.modulus_length})
}

fn duration_seconds(duration: Duration) -> f64 {
    duration.num_seconds() as f64 + f64::from(duration.subsec_nanos()) / 1e9
}

#[path = "override_input.rs"]
mod input;

pub(super) fn from_input<S: AuthSchema>(
    value: &Value,
    original: &JwtPluginConfig,
    original_input: Option<&Value>,
) -> AuthResult<JwtCallOverrides<S>> {
    let object = |value: &Value| value.as_object().cloned().unwrap_or_default().into();
    let mut jwt = value
        .get("jwt")
        .map(|value| serde_json::from_value::<JwtTokenOptions>(object(value)))
        .transpose()?;
    if let Some(jwt) = &mut jwt
        && value.get("jwt").is_some_and(Value::is_object)
        && original_input.and_then(|value| value.get("jwt")).is_some()
    {
        jwt.custom_sign = original.custom_sign.clone();
    }
    let jwks = value
        .get("jwks")
        .map(|value| serde_json::from_value::<JwtKeyOptions>(object(value)))
        .transpose()?;
    Ok(JwtCallOverrides {
        jwt,
        jwks,
        adapter: None,
    })
}

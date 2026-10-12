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
    pub custom_sign: Option<JwtNativeCustomSign>,
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
    pub(super) fn into_native(self) -> AuthResult<FieldValue> {
        let mut fields = FieldMap::new();
        if let Some(jwt) = self.jwt {
            let _ = fields.insert("jwt".into(), jwt.into_native()?);
        }
        if let Some(jwks) = self.jwks {
            let _ = fields.insert("jwks".into(), jwks.into_native());
        }
        if let Some(adapter) = self.adapter {
            let _ = fields.insert("adapter".into(), adapter.into_native());
        }
        Ok(fields.into())
    }
}

impl JwtTokenOptions {
    fn into_native(self) -> AuthResult<FieldValue> {
        let mut fields = FieldMap::new();
        if let Some(issuer) = self.issuer {
            let _ = fields.insert("issuer".into(), issuer.into());
        }
        if let Some(audience) = self.audience {
            let _ = fields.insert("audience".into(), FieldValue::from_json(json!(audience))?);
        }
        if let Some(expiration) = self.expiration_time {
            let _ = fields.insert("expirationTime".into(), expiration.into_native());
        }
        if let Some(callback) = self.custom_sign {
            let _ = fields.insert("sign".into(), custom_sign(callback));
        }
        Ok(fields.into())
    }
}

impl JwtKeyOptions {
    fn into_native(self) -> FieldValue {
        let mut fields = FieldMap::new();
        if let Some(parameters) = self.key_pair {
            let _ = fields.insert("keyPairConfig".into(), parameters.into_native());
        }
        if let Some(parameters) = self.key_pair_configs {
            let _ = fields.insert(
                "keyPairConfigs".into(),
                parameters
                    .into_iter()
                    .map(JwtKeyPairConfig::into_native)
                    .collect::<Vec<_>>()
                    .into(),
            );
        }
        if let Some(rotation) = self.rotation_interval {
            let _ = fields.insert("rotationInterval".into(), duration_seconds(rotation).into());
        }
        if let Some(disabled) = self.disable_private_key_encryption {
            let _ = fields.insert("disablePrivateKeyEncryption".into(), disabled.into());
        }
        fields.into()
    }
}

impl JwtKeyPairConfig {
    pub(super) fn into_native(self) -> FieldValue {
        FieldMap::from([
            ("alg".into(), self.algorithm.name().into()),
            ("modulusLength".into(), self.modulus_length.into()),
        ])
        .into()
    }
}

impl JwtExpiration {
    pub(super) fn into_native(self) -> FieldValue {
        match self {
            Self::At(value) => Value::Number(value).into(),
            Self::After(duration) => format!("{}s", duration_seconds(duration)).into(),
        }
    }
}

fn custom_sign(callback: JwtNativeCustomSign) -> FieldValue {
    better_auth_core::FieldFunction::asynchronous_contextual(move |_, arguments| {
        callback(
            arguments.first().cloned().unwrap_or_default(),
            arguments.get(1).cloned().unwrap_or_default(),
            arguments.get(2).cloned().unwrap_or_default(),
        )
    })
    .into()
}

fn duration_seconds(duration: Duration) -> f64 {
    duration.num_seconds() as f64 + f64::from(duration.subsec_nanos()) / 1e9
}

#[path = "override_input.rs"]
pub(super) mod input;

/// The merged outer options object; nested groups retain their original native handles.
pub(super) struct NativeOptions(pub(super) FieldValue);

impl NativeOptions {
    pub(super) fn registered<S: AuthSchema>(
        config: &JwtPluginConfig,
        context: &AuthContext<S>,
    ) -> AuthResult<Self> {
        let jwt = JwtTokenOptions {
            issuer: config.issuer.clone(),
            audience: config.audience.clone(),
            expiration_time: Some(config.expiration_time.clone()),
            custom_sign: config.custom_sign.clone(),
        }
        .into_native()?;
        let jwks = JwtKeyOptions {
            key_pair: config.algorithm.map(|algorithm| JwtKeyPairConfig {
                algorithm,
                modulus_length: config.modulus_length,
            }),
            key_pair_configs: Some(config.key_pair_configs.clone()),
            rotation_interval: config.rotation_interval,
            disable_private_key_encryption: Some(config.disable_private_key_encryption),
        }
        .into_native();
        let mut fields = FieldMap::from([("jwt".into(), jwt), ("jwks".into(), jwks)]);
        if let Some(callbacks) = context
            .extensions
            .get::<std::sync::Arc<super::callbacks::RegisteredCallbacks<S>>>()
        {
            let _ = fields.insert("adapter".into(), callbacks.adapter.clone());
        }
        Ok(Self(fields.into()))
    }

    pub(super) fn merge(self, overrides: &FieldValue) -> AuthResult<Self> {
        let mut fields = self.0.enumerable_fields()?;
        keys::spread(&mut fields, overrides.clone())?;
        Ok(Self(fields.into()))
    }

    pub(super) fn property(&self, group: &str, name: &str) -> AuthResult<FieldValue> {
        optional_property(&self.0.model_property(group)?, name)
    }

    pub(super) fn primary_algorithm(&self) -> AuthResult<FieldValue> {
        let algorithm = optional_property(&self.property("jwks", "keyPairConfig")?, "alg")?;
        Ok(nullish(algorithm, || "EdDSA".into()))
    }

    pub(super) fn with_key_pair(&self, parameters: FieldValue) -> AuthResult<Self> {
        let mut fields = self.0.enumerable_fields()?;
        let mut jwks = FieldMap::new();
        keys::spread(&mut jwks, self.0.model_property("jwks")?)?;
        let parameters = if parameters.is_null() || parameters.is_undefined() {
            self.property("jwks", "keyPairConfig")?
        } else {
            parameters
        };
        let _ = jwks.insert("keyPairConfig".into(), parameters);
        let _ = fields.insert("jwks".into(), jwks.into());
        Ok(Self(fields.into()))
    }
}

pub(super) fn optional_property(value: &FieldValue, name: &str) -> AuthResult<FieldValue> {
    if value.is_null() || value.is_undefined() {
        Ok(FieldValue::Undefined)
    } else {
        value.model_property(name)
    }
}

pub(super) fn nullish(value: FieldValue, fallback: impl FnOnce() -> FieldValue) -> FieldValue {
    if value.is_null() || value.is_undefined() {
        fallback()
    } else {
        value
    }
}

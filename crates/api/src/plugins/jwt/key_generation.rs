use super::overrides::{NativeOptions, nullish};
use super::*;

impl JwtPlugin {
    pub(super) async fn create_key<S: AuthSchema>(
        &self,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<FieldValue> {
        let options = self.options.clone();
        self.create_key_native(&options, endpoint).await
    }

    /// Provision a local key with explicit parameters.
    pub async fn create_key_pair<S: AuthSchema>(
        &self,
        parameters: JwtKeyPairConfig,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<better_auth_core::Jwk>> {
        ctx.with_native_context(Default::default(), |resolved| async move {
            let mut endpoint = EndpointContext::new(None, FieldValue::Null, &resolved);
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
    ) -> AuthResult<Option<better_auth_core::Jwk>> {
        use better_auth_core::FromFieldMap as _;
        let options = self
            .options
            .clone()
            .with_key_pair(parameters.into_native())?;
        let value = self.create_key_native(&options, endpoint).await?;
        if value.is_null() || value.is_undefined() {
            return Ok(None);
        }
        better_auth_core::Jwk::from_field_values(value.enumerable_fields()?).map(Some)
    }

    pub(super) async fn create_key_native<S: AuthSchema>(
        &self,
        options: &NativeOptions,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<FieldValue> {
        let parameters = nullish(options.property("jwks", "keyPairConfig")?, || {
            FieldMap::from([
                ("alg".into(), "EdDSA".into()),
                ("crv".into(), "Ed25519".into()),
            ])
            .into()
        });
        let algorithm = parameters.model_property("alg")?;
        let config: FieldValue = parameters.enumerable_fields_except(&["alg"])?.into();
        let mut key = generate_key(&algorithm, &config)?;
        key.set_parameter("use", None).map_err(jose_error)?;
        let public = key.to_public_key().map_err(jose_error)?;
        let explicit_curve = if config.has_property("crv")? {
            config.model_property("crv")?
        } else {
            FieldValue::Undefined
        };
        let curve = nullish(explicit_curve, || {
            public.curve().map(FieldValue::from).unwrap_or_default()
        });
        let raw_private = key.to_string();
        let encrypted = !options
            .property("jwks", "disablePrivateKeyEncryption")?
            .is_truthy();
        let mut fields = FieldMap::from([("alg".into(), algorithm)]);
        if curve.is_truthy() {
            let _ = fields.insert("crv".into(), curve);
        }
        let _ = fields.insert("publicKey".into(), public.to_string().into());
        let private = if encrypted {
            serde_json::to_string(&super::super::symmetric::encrypt(
                endpoint.auth.config.encryption_secret(),
                &raw_private,
            )?)?
        } else {
            raw_private
        };
        let _ = fields.insert("privateKey".into(), private.into());
        let _ = fields.insert("createdAt".into(), Utc::now().into());
        if options.property("jwks", "rotationInterval")?.is_truthy() {
            let now = endpoint.auth.now().timestamp_millis() as f64;
            let interval = options.property("jwks", "rotationInterval")?;
            let millis = now + better_auth_core::query::field_number(&interval)? * 1_000.0;
            let _ = fields.insert(
                "expiresAt".into(),
                better_auth_core::FieldDate::from_milliseconds(millis).into(),
            );
        }
        adapter::Keyring::new(adapter::store(endpoint), options, endpoint)
            .create(fields.into())
            .await
    }
}

fn generate_key(algorithm: &FieldValue, config: &FieldValue) -> AuthResult<Jwk> {
    let algorithm = match algorithm.as_str() {
        Some("EdDSA") => JwtAlgorithm::EdDsa,
        Some("RS256") => JwtAlgorithm::Rs256,
        Some("ES256") => JwtAlgorithm::Es256,
        Some("ES512") => JwtAlgorithm::Es512,
        Some("PS256") => JwtAlgorithm::Ps256,
        _ => {
            return Err(AuthError::internal(
                "Invalid or unsupported JWK \"alg\" (Algorithm) Parameter value",
            ));
        }
    };
    if let Some(curve) = algorithm.curve() {
        let supplied = config.model_property("crv")?;
        if !supplied.is_undefined() && !supplied.strict_equals(&curve.into()) {
            return Err(AuthError::internal(format!(
                "Invalid or unsupported crv option provided, the only supported value for {} is {curve}",
                algorithm.name(),
            )));
        }
    }
    let modulus = if matches!(algorithm, JwtAlgorithm::Rs256 | JwtAlgorithm::Ps256) {
        let supplied = nullish(config.model_property("modulusLength")?, || 2048.0.into());
        let valid = supplied
            .as_f64()
            .filter(|value| value.is_finite() && value.fract() == 0.0 && *value >= 2048.0);
        let value = valid.ok_or_else(|| AuthError::internal("Invalid or unsupported modulusLength option provided, 2048 bits or larger keys must be used"))?;
        // WebCrypto converts modulusLength to an unsigned long before generating the key.
        value.rem_euclid(4_294_967_296.0) as u32
    } else {
        2048
    };
    algorithm.generate(modulus).map_err(jose_error)
}

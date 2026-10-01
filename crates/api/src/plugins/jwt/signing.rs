use super::*;

impl JwtPlugin {
    pub(super) async fn sign_session<S: AuthSchema>(
        &self,
        session: Value,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<String> {
        let user = session
            .get("user")
            .and_then(Value::as_object)
            .ok_or_else(|| AuthError::internal("JWT user must be an object"))?;
        let default_subject = user
            .get("id")
            .cloned()
            .ok_or_else(|| AuthError::internal("JWT user must have an ID"))?;
        let mut payload = match &self.config.define_payload {
            Some(callback) => callback(session.clone()).await?,
            None => user.clone(),
        };
        let subject = match &self.config.get_subject {
            Some(callback) => callback(session).await?.into(),
            None => default_subject,
        };
        let _ = payload
            .entry("iat")
            .or_insert_with(|| Utc::now().timestamp().into());
        let _ = payload.insert("sub".into(), subject);
        self.sign_in_endpoint(payload, &JwtSigningOptions::default(), endpoint)
            .await
    }

    /// Sign an application payload with the same persisted keys as `/token`.
    pub async fn sign<S: AuthSchema>(
        &self,
        payload: Map<String, Value>,
        ctx: &AuthContext<S>,
    ) -> AuthResult<String> {
        self.sign_with_options(payload, &JwtSigningOptions::default(), ctx)
            .await
    }

    /// Sign a native payload with explicit protected headers and key selection.
    /// Use `sign_in_endpoint` to retain an endpoint request and transaction.
    pub async fn sign_with_options<S: AuthSchema>(
        &self,
        payload: Map<String, Value>,
        options: &JwtSigningOptions,
        ctx: &AuthContext<S>,
    ) -> AuthResult<String> {
        ctx.with_native_context(Default::default(), |resolved| async move {
            let mut endpoint = EndpointContext::new(None, json!({"payload":payload}), &resolved);
            endpoint.path = Some("virtual:");
            self.sign_in_endpoint(payload, options, &endpoint).await
        })
        .await
    }

    /// Sign with the supplied endpoint context, including its active transaction.
    pub async fn sign_in_endpoint<S: AuthSchema>(
        &self,
        mut payload: Map<String, Value>,
        options: &JwtSigningOptions,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<String> {
        let config = &endpoint.auth.config;
        self.default_claims(&mut payload, config)?;
        if let Some(callback) = &self.config.custom_sign {
            return callback(payload, options.clone()).await;
        }
        let selected = if let Some(id) = &options.key_id {
            let key = self
                .read_key(id, endpoint)
                .await?
                .ok_or_else(|| AuthError::config("Requested JWT signing key does not exist"))?;
            if key.expires_at.is_some_and(|expiry| expiry < Utc::now())
                || options.algorithm.is_some_and(|alg| {
                    key.alg.as_deref().unwrap_or(self.config.algorithm.name()) != alg.name()
                })
            {
                return Err(AuthError::config(
                    "Requested JWT signing key is expired or has a different algorithm",
                ));
            }
            Some(key)
        } else {
            let mut keys = self.read_keys(endpoint).await?.unwrap_or_default();
            keys.sort_by_key(|key| std::cmp::Reverse(key.created_at));
            keys.retain(|key| key.expires_at.is_none_or(|expiry| expiry > Utc::now()));
            let preferred = keys
                .iter()
                .find(|key| {
                    key.alg.as_deref().unwrap_or(self.config.algorithm.name())
                        == options.algorithm.unwrap_or(self.config.algorithm).name()
                })
                .cloned();
            if preferred.is_some() || options.algorithm.is_some() {
                preferred
            } else {
                let mut fallback = self.read_keys(endpoint).await?.unwrap_or_default();
                fallback.retain(|key| key.expires_at.is_none_or(|expiry| expiry > Utc::now()));
                fallback.sort_by_key(|key| std::cmp::Reverse(key.created_at));
                fallback.into_iter().next()
            }
        };
        let key = match selected {
            Some(key) => key,
            None => {
                let algorithm = options.algorithm.unwrap_or(self.config.algorithm);
                let parameters = self
                    .config
                    .key_pair_configs
                    .iter()
                    .find(|config| config.algorithm == algorithm)
                    .copied()
                    .or_else(|| {
                        (algorithm == self.config.algorithm).then_some(JwtKeyPairConfig {
                            algorithm,
                            modulus_length: self.config.modulus_length,
                        })
                    })
                    .ok_or_else(|| {
                        AuthError::config("Requested JWT algorithm is not configured")
                    })?;
                self.create_key_pair_in_endpoint(parameters, endpoint)
                    .await?
            }
        };
        if (options.key_id.is_some() || options.algorithm.is_some())
            && key.expires_at.is_some_and(|expiry| expiry < Utc::now())
        {
            return Err(AuthError::config("Requested JWT signing key is expired"));
        }
        let private = if self.config.disable_private_key_encryption {
            key.private_key
        } else {
            crate::plugins::symmetric::decrypt(
                config.encryption_secret(),
                &serde_json::from_str::<String>(&key.private_key)?,
            )?
        };
        let private = Jwk::from_bytes(private).map_err(jose_error)?;
        let algorithm = key.alg.as_deref().unwrap_or(self.config.algorithm.name());
        let signer: Box<dyn JwsSigner> = match algorithm {
            "EdDSA" => Box::new(jws::EdDSA.signer_from_jwk(&private).map_err(jose_error)?),
            "RS256" => Box::new(jws::RS256.signer_from_jwk(&private).map_err(jose_error)?),
            "ES256" => Box::new(jws::ES256.signer_from_jwk(&private).map_err(jose_error)?),
            "ES512" => Box::new(jws::ES512.signer_from_jwk(&private).map_err(jose_error)?),
            "PS256" => Box::new(jws::PS256.signer_from_jwk(&private).map_err(jose_error)?),
            _ => {
                return Err(AuthError::config(format!(
                    "Unsupported JWT signing algorithm: {algorithm}"
                )));
            }
        };
        claims::prepare_local_claims(&mut payload)?;
        let mut header = JwsHeader::from_map(options.header.clone()).map_err(jose_error)?;
        header.set_algorithm(algorithm);
        header.set_key_id(key.id);
        josekit::jws::serialize_compact(&serde_json::to_vec(&payload)?, &header, signer.as_ref())
            .map_err(jose_error)
    }

    fn default_claims(
        &self,
        payload: &mut Map<String, Value>,
        config: &better_auth_core::AuthConfig,
    ) -> AuthResult<()> {
        let expiration =
            claims::default_expiration(&self.config.expiration_time, payload.get("iat"))?;
        for (claim, default) in [
            ("exp", expiration),
            (
                "iss",
                self.config
                    .issuer
                    .as_deref()
                    .unwrap_or_else(|| config.base_url.as_static().unwrap_or(""))
                    .into(),
            ),
            (
                "aud",
                match &self.config.audience {
                    Some(audience) => serde_json::to_value(audience)?,
                    None => config.base_url.as_static().unwrap_or("").into(),
                },
            ),
        ] {
            if payload.get(claim).is_none_or(Value::is_null) {
                let _ = payload.insert(claim.to_owned(), default);
            }
        }
        Ok(())
    }
}

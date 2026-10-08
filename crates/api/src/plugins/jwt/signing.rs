use super::*;

pub(super) struct ResolvedSigningKey {
    algorithm: String,
    key_id: FieldValue,
    signer: Box<dyn JwsSigner>,
}

impl ResolvedSigningKey {
    pub(super) fn sign(
        &self,
        payload: Map<String, Value>,
        options: &JwtSigningOptions,
    ) -> AuthResult<String> {
        let mut header = FieldMap::from_json(options.header.clone())?;
        let _ = header.insert("alg".into(), self.algorithm.clone().into());
        let _ = header.insert("kid".into(), self.key_id.clone());
        jose::sign(&payload, header, self.signer.as_ref())
    }
}

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
            let mut endpoint = EndpointContext::new(
                None,
                better_auth_core::FieldValue::from_json(json!({"payload":payload}))?,
                &resolved,
            );
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
        let key = self.resolve_local_signing_key(options, endpoint).await?;
        claims::prepare_local_claims(&mut payload)?;
        key.sign(payload, options)
    }

    pub(super) async fn resolve_local_signing_key<S: AuthSchema>(
        &self,
        options: &JwtSigningOptions,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<ResolvedSigningKey> {
        let config = &endpoint.auth.config;
        let primary = self.config.primary_algorithm();
        let mut selected = if let Some(id) = &options.key_id {
            let key = self.read_key(id, endpoint).await?.ok_or_else(|| AuthError::config(format!("signJWT: signingKeyId \"{id}\" not found in JWKS. The key must be provisioned before it can be referenced.")))?;
            if let Some(expected) = options.algorithm {
                let alg = keys::algorithm(&key, primary.name().into());
                if !alg.strict_equals(&expected.name().into()) {
                    return Err(AuthError::config(format!(
                        "signJWT: signingKeyId \"{id}\" has alg \"{}\" but signingAlgorithm was set to \"{}\".",
                        alg.display_utf16()?
                            .to_utf8()
                            .map_err(|error| AuthError::internal(error.to_string()))?,
                        expected.name()
                    )));
                }
            }
            Some(key)
        } else {
            let preferred = keys::latest(
                self.read_keys(endpoint).await?.unwrap_or_default(),
                Some(options.algorithm.unwrap_or(primary).name()),
                primary.name(),
            )?;
            if preferred.is_some() || options.algorithm.is_some() {
                preferred
            } else {
                keys::latest(
                    self.read_keys(endpoint).await?.unwrap_or_default(),
                    None,
                    primary.name(),
                )?
            }
        };
        if selected.is_none()
            && let Some(algorithm) = options.algorithm
        {
            let parameters = self
                .config
                .key_pair_configs
                .iter()
                .find(|config| config.algorithm == algorithm)
                .copied()
                .or_else(|| {
                    (algorithm == primary).then_some(JwtKeyPairConfig {
                        algorithm,
                        modulus_length: self.config.modulus_length,
                    })
                })
                .ok_or_else(|| AuthError::config("Requested JWT algorithm is not configured"))?;
            selected = Some(
                self.create_key_pair_in_endpoint(parameters, endpoint)
                    .await?,
            );
        }
        let key = match selected {
            Some(key) if !keys::expires_before(&key, Utc::now().timestamp_millis())? => key,
            _ => {
                if options.key_id.is_some() || options.algorithm.is_some() {
                    return Err(AuthError::config(
                        "signJWT: requested signing key is expired and an explicit kid/alg was provided; not auto-minting a replacement. Rotate the key explicitly.",
                    ));
                }
                self.create_key(endpoint).await?
            }
        };
        let private = if self.config.disable_private_key_encryption {
            key.private_key.field_value()
        } else {
            let ciphertext = keys::parse_json(&key.private_key.field_value())?;
            crate::plugins::symmetric::decrypt_field(
                config.encryption_secret(),
                &ciphertext,
            ).map_err(|_| AuthError::config("Failed to decrypt private key. Make sure the secret currently in use is the same as the one used to encrypt the private key. If you are using a different secret, either clean up your JWKS or disable private key encryption."))?.into()
        };
        let algorithm = keys::algorithm(&key, primary.name().into());
        let (algorithm, private) = keys::import(keys::parse_json(&private)?, &algorithm)?;
        let signer: Box<dyn JwsSigner> = match algorithm.as_str() {
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
        Ok(ResolvedSigningKey {
            algorithm,
            key_id: key.id.field_value(),
            signer,
        })
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

use super::*;

impl JwtPlugin {
    pub(super) async fn sign_session<S: AuthSchema>(
        &self,
        session: Value,
        ctx: &AuthContext<S>,
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
        self.sign(payload, ctx).await
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

    /// Sign a payload with explicit protected headers and key selection.
    pub async fn sign_with_options<S: AuthSchema>(
        &self,
        mut payload: Map<String, Value>,
        options: &JwtSigningOptions,
        ctx: &AuthContext<S>,
    ) -> AuthResult<String> {
        self.default_claims(&mut payload, ctx)?;
        if let Some(callback) = &self.config.custom_sign {
            return callback(payload, options.clone()).await;
        }
        let mut keys = ctx.database.list_jwks().await?;
        keys.sort_by_key(|key| std::cmp::Reverse(key.created_at));
        let selected = if let Some(id) = &options.key_id {
            let key = keys
                .iter()
                .find(|key| &key.id == id)
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
            keys.retain(|key| key.expires_at.is_none_or(|expiry| expiry > Utc::now()));
            keys.iter()
                .find(|key| {
                    key.alg.as_deref().unwrap_or(self.config.algorithm.name())
                        == options.algorithm.unwrap_or(self.config.algorithm).name()
                })
                .or_else(|| options.algorithm.is_none().then(|| keys.first()).flatten())
        };
        let key = match selected {
            Some(key) => key.clone(),
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
                self.create_key_pair(parameters, ctx).await?
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
                ctx.config.encryption_secret(),
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
        let payload = JwtPayload::from_map(payload).map_err(jose_error)?;
        let mut header = JwsHeader::from_map(options.header.clone()).map_err(jose_error)?;
        header.set_algorithm(algorithm);
        header.set_key_id(key.id);
        josekit::jwt::encode_with_signer(&payload, &header, signer.as_ref()).map_err(jose_error)
    }

    fn default_claims<S: AuthSchema>(
        &self,
        payload: &mut Map<String, Value>,
        ctx: &AuthContext<S>,
    ) -> AuthResult<()> {
        let issued = payload
            .get("iat")
            .and_then(Value::as_f64)
            .unwrap_or_else(|| Utc::now().timestamp() as f64);
        for (claim, default) in [
            ("exp", self.config.expiration_time.claim(issued)),
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
                match &self.config.audience {
                    Some(audience) => serde_json::to_value(audience)?,
                    None => ctx.config.base_url.clone().into(),
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

use super::*;

pub(super) struct ResolvedSigningKey {
    algorithm: String,
    key_id: FieldValue,
    signer: Box<dyn JwsSigner>,
}

impl ResolvedSigningKey {
    pub(super) fn sign(
        &self,
        payload: FieldMap,
        options: &JwtSigningOptions,
    ) -> AuthResult<String> {
        let mut header = FieldMap::from_json(options.header.clone())?;
        let _ = header.insert("alg".into(), self.algorithm.clone().into());
        let _ = header.insert("kid".into(), self.key_id.clone());
        jose::sign(payload, header, self.signer.as_ref())
    }
}

impl JwtPlugin {
    pub(super) async fn sign_session<S: AuthSchema>(
        &self,
        session: Option<better_auth_core::session::NativeSessionData>,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<FieldValue> {
        let current = || {
            session
                .as_ref()
                .map(|data| data.field_value())
                .unwrap_or(FieldValue::Null)
        };
        let user = || {
            session
                .as_ref()
                .ok_or_else(|| {
                    AuthError::type_error(
                        "null is not an object (evaluating 'ctx.context.session.user')",
                    )
                })?
                .user_value()
        };
        let options = self.options.clone();
        let defined = if options.property("jwt", "definePayload")?.is_truthy() {
            let receiver = options.0.model_property("jwt")?;
            match receiver.model_property("definePayload")? {
                FieldValue::Function(callback) => {
                    callback.call_awaited_with(&receiver, &[current()]).await?
                }
                _ => {
                    return Err(AuthError::type_error(
                        "options.jwt.definePayload is not a function",
                    ));
                }
            }
        } else {
            user()?
        };
        let mut payload = FieldMap::from([("iat".into(), endpoint.auth.now().timestamp().into())]);
        keys::spread(&mut payload, defined)?;
        let receiver = options.0.model_property("jwt")?;
        let callback = overrides::optional_property(&receiver, "getSubject")?;
        let mut subject = if callback.is_null() || callback.is_undefined() {
            FieldValue::Undefined
        } else {
            match callback {
                FieldValue::Function(callback) => {
                    callback.call_awaited_with(&receiver, &[current()]).await?
                }
                _ => {
                    return Err(AuthError::type_error(
                        "options.jwt.getSubject is not a function",
                    ));
                }
            }
        };
        if subject.is_null() || subject.is_undefined() {
            subject = match user()? {
                FieldValue::Null => {
                    return Err(AuthError::type_error(
                        "null is not an object (evaluating 'ctx.context.session.user.id')",
                    ));
                }
                FieldValue::Undefined => {
                    return Err(AuthError::type_error(
                        "Cannot read properties of undefined (reading 'id')",
                    ));
                }
                value => value.model_property("id")?,
            };
        }
        let _ = payload.insert("sub".into(), subject);
        self.sign_native_options(payload.into(), None, &options, endpoint)
            .await
    }

    /// Sign an application payload with the same persisted keys as `/token`.
    pub async fn sign<S: AuthSchema>(
        &self,
        payload: Map<String, Value>,
        ctx: &AuthContext<S>,
    ) -> AuthResult<String> {
        self.sign_context(payload, None, ctx).await
    }

    /// Sign JSON claims with explicit protected headers and key selection.
    /// Use `sign_in_endpoint` to retain an endpoint request and transaction.
    pub async fn sign_with_options<S: AuthSchema>(
        &self,
        payload: Map<String, Value>,
        options: &JwtSigningOptions,
        ctx: &AuthContext<S>,
    ) -> AuthResult<String> {
        self.sign_context(payload, Some(options), ctx).await
    }

    async fn sign_context<S: AuthSchema>(
        &self,
        payload: Map<String, Value>,
        options: Option<&JwtSigningOptions>,
        ctx: &AuthContext<S>,
    ) -> AuthResult<String> {
        ctx.with_native_context(Default::default(), |resolved| async move {
            let mut endpoint = EndpointContext::new(
                None,
                better_auth_core::FieldValue::from_json(json!({"payload":payload}))?,
                &resolved,
            );
            endpoint.path = Some("virtual:");
            self.sign_value_in_endpoint(FieldMap::from_json(payload)?.into(), options, &endpoint)
                .await?
                .decode()
        })
        .await
    }

    /// Sign JSON claims with the supplied endpoint context and active transaction.
    pub async fn sign_in_endpoint<S: AuthSchema>(
        &self,
        payload: Map<String, Value>,
        options: &JwtSigningOptions,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<String> {
        self.sign_value_in_endpoint(
            FieldMap::from_json(payload)?.into(),
            Some(options),
            endpoint,
        )
        .await?
        .decode()
    }

    /// Sign native claims and preserve the custom signer's original return value.
    /// An absent options value leaves the protected header undefined for a custom signer.
    pub async fn sign_value_in_endpoint<S: AuthSchema>(
        &self,
        fields: FieldValue,
        options: Option<&JwtSigningOptions>,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<FieldValue> {
        let native = self.options.clone();
        self.sign_native_options(fields, options, &native, endpoint)
            .await
    }

    pub(super) async fn sign_native_options<S: AuthSchema>(
        &self,
        fields: FieldValue,
        selection: Option<&JwtSigningOptions>,
        options: &overrides::NativeOptions,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<FieldValue> {
        let now = endpoint.auth.now().timestamp();
        let defaults = Self::default_claims(&fields, options, &endpoint.auth.config, now)?;
        if options.property("jwt", "sign")?.is_truthy() {
            let mut payload = FieldMap::new();
            keys::spread(&mut payload, fields)?;
            payload.extend(defaults);
            let receiver = options.0.model_property("jwt")?;
            let callback = receiver.model_property("sign")?;
            let header = selection
                .map(|options| FieldMap::from_json(options.header.clone()).map(FieldValue::from))
                .transpose()?
                .unwrap_or_default();
            let selection = FieldMap::from([
                (
                    "signingKeyId".into(),
                    selection
                        .and_then(|options| options.key_id.as_ref())
                        .map(|id| id.clone().into())
                        .unwrap_or_default(),
                ),
                (
                    "signingAlgorithm".into(),
                    selection
                        .and_then(|options| options.algorithm)
                        .map(|algorithm| algorithm.name().into())
                        .unwrap_or_default(),
                ),
            ]);
            return match callback {
                FieldValue::Function(callback) => {
                    callback
                        .call_awaited_with(&receiver, &[payload.into(), header, selection.into()])
                        .await
                }
                _ => Err(AuthError::type_error("options.jwt.sign is not a function")),
            };
        }
        let empty = JwtSigningOptions::default();
        let selection = selection.unwrap_or(&empty);
        let key = self
            .resolve_key(selection, options, endpoint)
            .await?
            .ok_or_else(|| {
                AuthError::type_error(
                    "Cannot destructure property 'alg' from null or undefined value",
                )
            })?;
        let mut payload = better_auth_core::StructuredCloneContext::new()
            .clone_value(&fields)?
            .enumerable_fields()?;
        claims::prepare_local_claims(&mut payload, &fields, &defaults)?;
        Ok(key.sign(payload, selection)?.into())
    }

    pub(super) async fn resolve_local_signing_key<S: AuthSchema>(
        &self,
        selection: &JwtSigningOptions,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<Option<ResolvedSigningKey>> {
        let options = self.options.clone();
        self.resolve_key(selection, &options, endpoint).await
    }

    async fn resolve_key<S: AuthSchema>(
        &self,
        selection: &JwtSigningOptions,
        options: &overrides::NativeOptions,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<Option<ResolvedSigningKey>> {
        if options.property("jwt", "sign")?.is_truthy() {
            return Ok(None);
        }
        let mut selected = if let Some(id) = &selection.key_id {
            let key = self.read_key(id, options, endpoint).await?;
            if !key.is_truthy() {
                return Err(AuthError::better_auth(format!(
                    "signJWT: signingKeyId \"{id}\" not found in JWKS. The key must be provisioned before it can be referenced."
                )));
            }
            if let Some(expected) = selection.algorithm {
                let primary = options.primary_algorithm()?;
                let alg = keys::algorithm(&key, primary.clone())?;
                if !alg.strict_equals(&expected.name().into()) {
                    let actual = key.model_property("alg")?;
                    let actual = if actual.is_null() || actual.is_undefined() {
                        let mut message = "unset (inherits keyPairConfig.alg \""
                            .encode_utf16()
                            .collect::<Vec<_>>();
                        message.extend_from_slice(primary.display_utf16()?.as_utf16());
                        message.extend("\")".encode_utf16());
                        better_auth_core::Utf16String::from_units(message).into()
                    } else {
                        actual
                    };
                    let mut message = format!("signJWT: signingKeyId \"{id}\" has alg \"")
                        .encode_utf16()
                        .collect::<Vec<_>>();
                    message.extend_from_slice(actual.display_utf16()?.as_utf16());
                    message.extend(
                        format!(
                            "\" but signingAlgorithm was set to \"{}\".",
                            expected.name()
                        )
                        .encode_utf16(),
                    );
                    return Err(AuthError::better_auth_native(
                        better_auth_core::Utf16String::from_units(message),
                    ));
                }
            }
            key
        } else if let Some(algorithm) = selection.algorithm {
            let mut key = self
                .read_latest_key(Some(algorithm.name().into()), options, endpoint)
                .await?;
            if !key.is_truthy() {
                let primary = options.primary_algorithm()?;
                let configurations = options.property("jwks", "keyPairConfigs")?;
                let expected: FieldValue = algorithm.name().into();
                let preconfigured = if configurations.is_null() || configurations.is_undefined() {
                    FieldValue::Undefined
                } else {
                    configurations.find_method(
                        &better_auth_core::FieldFunction::contextual(move |_, arguments| {
                            Ok(arguments
                                .first()
                                .unwrap_or(&FieldValue::Undefined)
                                .model_property("alg")?
                                .strict_equals(&expected)
                                .into())
                        }),
                        "options.jwks.keyPairConfigs",
                    )?
                };
                if preconfigured.is_truthy() || primary.strict_equals(&algorithm.name().into()) {
                    let parameters = options.with_key_pair(preconfigured)?;
                    key = self.create_key_native(&parameters, endpoint).await?;
                } else {
                    let configurations = options.property("jwks", "keyPairConfigs")?;
                    let advertised = if configurations.is_null() || configurations.is_undefined() {
                        FieldValue::Undefined
                    } else {
                        configurations
                            .map_method(
                                &better_auth_core::FieldFunction::contextual(|_, arguments| {
                                    arguments
                                        .first()
                                        .unwrap_or(&FieldValue::Undefined)
                                        .model_property("alg")
                                }),
                                "options.jwks.keyPairConfigs",
                                None,
                            )?
                            .join_method(&", ".into(), "options.jwks.keyPairConfigs.map(...)")?
                    };
                    let advertised = if advertised.is_truthy() {
                        advertised
                    } else {
                        "none".into()
                    };
                    let mut message = format!("signJWT: no key with alg \"{}\" found in JWKS. The plugin auto-mints only one key matching keyPairConfig.alg=\"", algorithm.name()).encode_utf16().collect::<Vec<_>>();
                    message.extend_from_slice(primary.display_utf16()?.as_utf16());
                    message.extend(
                        "\"; additional algs configured via keyPairConfigs: ".encode_utf16(),
                    );
                    message.extend_from_slice(advertised.display_utf16()?.as_utf16());
                    message.extend(format!(". Add \"{}\" to jwks.keyPairConfigs so the plugin provisions it on first use, or mint the key explicitly via createJwk().", algorithm.name()).encode_utf16());
                    return Err(AuthError::better_auth_native(
                        better_auth_core::Utf16String::from_units(message),
                    ));
                }
            }
            key
        } else {
            let primary = options.primary_algorithm()?;
            let preferred = self
                .read_latest_key(Some(primary), options, endpoint)
                .await?;
            if preferred.is_null() || preferred.is_undefined() {
                self.read_latest_key(None, options, endpoint).await?
            } else {
                preferred
            }
        };
        if !selected.is_truthy() || keys::expires_before(&selected)? {
            if selection.key_id.is_some() || selection.algorithm.is_some() {
                return Err(AuthError::better_auth(
                    "signJWT: requested signing key is expired and an explicit kid/alg was provided; not auto-minting a replacement. Rotate the key explicitly.",
                ));
            }
            selected = self.create_key_native(options, endpoint).await?;
        }
        let private = if options
            .property("jwks", "disablePrivateKeyEncryption")?
            .is_truthy()
        {
            selected.model_property("privateKey")?
        } else {
            let ciphertext = keys::parse_json(&selected.model_property("privateKey")?)?;
            crate::plugins::symmetric::decrypt_field(
                endpoint.auth.config.encryption_secret(),
                &ciphertext,
            ).map_err(|_| AuthError::better_auth("Failed to decrypt private key. Make sure the secret currently in use is the same as the one used to encrypt the private key. If you are using a different secret, either clean up your JWKS or disable private key encryption."))?.into()
        };
        let algorithm = selected.model_property("alg")?;
        let algorithm = if algorithm.is_null() || algorithm.is_undefined() {
            options.primary_algorithm()?
        } else {
            algorithm
        };
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
        Ok(Some(ResolvedSigningKey {
            algorithm,
            key_id: selected.model_property("id")?,
            signer,
        }))
    }

    fn default_claims(
        payload: &FieldValue,
        options: &overrides::NativeOptions,
        config: &better_auth_core::AuthConfig,
        now: i64,
    ) -> AuthResult<FieldMap> {
        let issued = payload.model_property("iat")?;
        let expiry = payload.model_property("exp")?;
        let expiration =
            overrides::nullish(options.property("jwt", "expirationTime")?, || "15m".into());
        let default_expiry = claims::default_expiration(&expiration, &issued, now)?;
        let expiry = overrides::nullish(expiry, || default_expiry);
        let not_before = payload.model_property("nbf")?;
        let issuer = payload.model_property("iss")?;
        let default_issuer = overrides::nullish(options.property("jwt", "issuer")?, || {
            config.base_url.as_static().unwrap_or("").into()
        });
        let audience = payload.model_property("aud")?;
        let default_audience = overrides::nullish(options.property("jwt", "audience")?, || {
            config.base_url.as_static().unwrap_or("").into()
        });
        Ok(FieldMap::from([
            ("iat".into(), issued),
            ("exp".into(), expiry),
            ("nbf".into(), not_before),
            ("iss".into(), overrides::nullish(issuer, || default_issuer)),
            (
                "aud".into(),
                overrides::nullish(audience, || default_audience),
            ),
        ]))
    }
}

#[cfg(test)]
#[path = "native_keyring_tests.rs"]
mod native_tests;

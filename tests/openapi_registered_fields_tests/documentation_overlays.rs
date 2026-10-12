#![expect(
    clippy::panic_in_result_fn,
    reason = "Contract assertions must fail the test while setup errors propagate through Result."
)]

use super::*;
use better_auth::plugins::{
    LastLoginMethodConfig, LastLoginMethodPlugin, UsernameConfig, UsernamePlugin,
};
use better_auth_core::{
    AuthError, FieldMap, FieldValue, OpenApiPluginMetadata,
    store::{EphemeralStore, StatelessSchema},
    user_fields::UserFieldType,
};

struct DocumentationOverlay(Arc<CallbackCalls>);

impl DocumentationOverlay {
    fn documentation_field(&self) -> UserFieldConfig {
        let defaults = self.0.clone();
        let inputs = self.0.clone();
        let outputs = self.0.clone();
        UserFieldConfig {
            default_value_fn: Some(better_auth_core::user_fields::UserFieldFactory::new(
                move || {
                    let _ = defaults.default.fetch_add(1, Ordering::SeqCst);
                    Ok("documentation-default".into())
                },
            )),
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    let _ = inputs.input.fetch_add(1, Ordering::SeqCst);
                    Ok(value)
                })),
                output: Some(UserFieldTransform::new(move |value| {
                    let _ = outputs.output.fetch_add(1, Ordering::SeqCst);
                    Ok(value)
                })),
            }),
            ..string(false, None)
        }
    }
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for DocumentationOverlay {
    fn name(&self) -> &'static str {
        "documentation-overlay"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    fn openapi(&self) -> AuthResult<OpenApiPluginMetadata> {
        OpenApiPluginMetadata::from_routes("documentation-overlay", Vec::new())?
            .model(
                "docsWidget",
                &fields([("title", self.documentation_field())]),
            )?
            .model(
                "jwks",
                &fields([
                    ("docsNote", self.documentation_field()),
                    (
                        "label",
                        UserFieldConfig {
                            field_type: UserFieldType::Number,
                            default_value: Some(99.into()),
                            ..string(false, None)
                        },
                    ),
                ]),
            )
    }
    fn schema(
        &self,
        context: &mut better_auth_core::plugin_runtime::ModelFields,
    ) -> AuthResult<()> {
        context.register_custom_model(
            "runtimeWidget",
            Some("physical_widget"),
            fields([("runtimeLabel", string(true, Some("runtime-label")))]),
        )?;
        context.register_model_fields(
            EntityRole::Jwk,
            fields([(
                "label",
                UserFieldConfig {
                    field_name: Some("stored_label".into()),
                    input: Some(false),
                    returned: Some(true),
                    ..string(true, Some("registered-label"))
                },
            )]),
        )
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

struct StaleMetadata;

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for StaleMetadata {
    fn name(&self) -> &'static str {
        "stale-documentation-overlay"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    fn openapi(&self) -> AuthResult<OpenApiPluginMetadata> {
        OpenApiPluginMetadata::from_routes("stale-documentation-overlay", Vec::new())?.model(
            "jwks",
            &fields([(
                "label",
                UserFieldConfig {
                    field_type: UserFieldType::Boolean,
                    default_value: Some(false.into()),
                    ..string(false, None)
                },
            )]),
        )
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

fn schemas(document: &Value) -> AuthResult<&serde_json::Map<String, Value>> {
    document
        .pointer("/components/schemas")
        .and_then(Value::as_object)
        .ok_or_else(|| AuthError::internal("Expected the complete component map"))
}

#[tokio::test]
async fn documentation_overlays_preserve_runtime_policies_and_final_declaration_precedence()
-> AuthResult<()> {
    let mut config =
        AuthConfig::new("documentation-overlay-contract-at-least-thirty-two-characters")
            .base_url("http://documentation-overlay.test");
    config.logger = better_auth_core::LoggerConfig {
        disabled: Some(true),
        ..Default::default()
    }
    .into();
    config.telemetry.enabled = false;
    let calls = Arc::new(CallbackCalls::default());
    let raw = EphemeralStore::new(Arc::new(config.clone()));
    let mut declarations = better_auth_core::plugin_runtime::ModelFields::default();
    AuthPlugin::<StatelessSchema>::schema(&DocumentationOverlay(calls.clone()), &mut declarations)?;
    let (_, _, runtime) = declarations.resolve(&config);
    assert_eq!(
        runtime
            .fields(EntityRole::Jwk)
            .fields()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["label"]
    );
    assert_eq!(
        runtime
            .custom_models()
            .map(|(name, physical, fields)| (
                name,
                physical,
                fields
                    .fields()
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
            ))
            .collect::<Vec<_>>(),
        [("runtimeWidget", "physical_widget", vec!["runtimeLabel"])]
    );

    let mut expected = BetterAuth::stateless(config.clone())
        .rate_limit(RateLimitConfig::new().enabled(false))
        .plugin(OpenApiPlugin::new())
        .build()
        .await?
        .openapi_spec()?
        .to_value()?;
    let expected_schemas = expected
        .pointer_mut("/components/schemas")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| AuthError::internal("Expected the complete baseline component map"))?;
    for (name, schema) in [
        (
            "DocsWidget",
            json!({
                "type": "object", "properties": {
                    "id": { "type": "string", "readOnly": true }, "title": { "type": "string" },
                }, "required": ["id"],
            }),
        ),
        (
            "Jwks",
            json!({
                "type": "object", "properties": {
                    "id": { "type": "string", "readOnly": true }, "docsNote": { "type": "string" },
                    "label": { "type": "string", "default": "registered-label", "readOnly": true },
                }, "required": ["id", "label"],
            }),
        ),
        (
            "RuntimeWidget",
            json!({
                "type": "object", "properties": {
                    "id": { "type": "string", "readOnly": true },
                    "runtimeLabel": { "type": "string", "default": "runtime-label" },
                }, "required": ["id", "runtimeLabel"],
            }),
        ),
    ] {
        let _ = expected_schemas.insert(name.into(), schema);
    }
    let auth = BetterAuth::new(config)
        .store(raw.clone())
        .rate_limit(RateLimitConfig::new().enabled(false))
        .plugin(DocumentationOverlay(calls.clone()))
        .plugin(StaleMetadata)
        .plugin(OpenApiPlugin::new())
        .build()
        .await?;
    let document = auth.openapi_spec()?.to_value()?;
    assert_eq!(document, expected);
    assert_eq!(
        schemas(&document)?.keys().collect::<Vec<_>>(),
        schemas(&expected)?.keys().collect::<Vec<_>>()
    );
    for model in ["DocsWidget", "Jwks", "RuntimeWidget"] {
        let properties = |document: &Value| -> AuthResult<Vec<String>> {
            document
                .pointer(&format!("/components/schemas/{model}/properties"))
                .and_then(Value::as_object)
                .map(|fields| fields.keys().cloned().collect())
                .ok_or_else(|| AuthError::internal("Expected all overlay component properties"))
        };
        assert_eq!(properties(&document)?, properties(&expected)?);
    }
    assert_eq!(
        (
            calls.default.load(Ordering::SeqCst),
            calls.input.load(Ordering::SeqCst),
            calls.output.load(Ordering::SeqCst)
        ),
        (0, 0, 0)
    );
    let _ = auth
        .store()
        .create_jwk_record(
            [
                ("id".into(), FieldValue::from("overlay-row")),
                ("docsNote".into(), FieldValue::from("must-not-be-stored")),
            ]
            .into(),
        )
        .await?
        .ok_or_else(|| AuthError::internal("Expected the registered JWK record"))?;
    assert_eq!(
        raw.storage_rows(EntityRole::Jwk)?,
        [FieldMap::from([
            ("stored_label".into(), "registered-label".into()),
            ("id".into(), "overlay-row".into()),
        ])]
    );
    assert_eq!(
        (
            calls.default.load(Ordering::SeqCst),
            calls.input.load(Ordering::SeqCst),
            calls.output.load(Ordering::SeqCst)
        ),
        (0, 0, 0)
    );
    assert_eq!(auth.openapi_spec()?.to_value()?, document);
    Ok(())
}

struct UserPolicyOverlay {
    default: bool,
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for UserPolicyOverlay {
    fn name(&self) -> &'static str {
        "user-policy-overlay"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    fn openapi(&self) -> AuthResult<OpenApiPluginMetadata> {
        OpenApiPluginMetadata::from_routes("user-policy-overlay", Vec::new())?.model(
            "user",
            &fields([
                (
                    "rank",
                    UserFieldConfig {
                        input: Some(false),
                        ..string(false, Some("stale"))
                    },
                ),
                ("docsInput", string(true, None)),
            ]),
        )
    }
    fn schema(
        &self,
        context: &mut better_auth_core::plugin_runtime::ModelFields,
    ) -> AuthResult<()> {
        context.register_model_fields(
            EntityRole::User,
            fields([(
                "rank",
                UserFieldConfig {
                    field_type: UserFieldType::Number,
                    default_value: self.default.then(|| 7.into()),
                    ..string(true, None)
                },
            )]),
        )
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

fn object_at<'a>(
    document: &'a mut Value,
    pointer: &str,
) -> AuthResult<&'a mut serde_json::Map<String, Value>> {
    document
        .pointer_mut(pointer)
        .and_then(Value::as_object_mut)
        .ok_or_else(|| AuthError::internal(format!("Expected the complete object at {pointer}")))
}

fn require_field(document: &mut Value, pointer: &str, name: &str) -> AuthResult<()> {
    let required = object_at(document, pointer)?
        .entry("required")
        .or_insert_with(|| json!([]));
    required
        .as_array_mut()
        .ok_or_else(|| AuthError::internal("Expected the complete required-field array"))?
        .push(json!(name));
    Ok(())
}

#[tokio::test]
async fn user_component_and_request_documentation_keep_their_distinct_runtime_policies()
-> AuthResult<()> {
    for default in [false, true] {
        let mut config =
            AuthConfig::new("user-documentation-overlay-contract-at-least-thirty-two-characters")
                .base_url("http://user-documentation-overlay.test");
        config.logger = better_auth_core::LoggerConfig {
            disabled: Some(true),
            ..Default::default()
        }
        .into();
        config.telemetry.enabled = false;
        config.user = fields([(
            "rank",
            UserFieldConfig {
                field_type: UserFieldType::Boolean,
                input: Some(false),
                default_value: Some(false.into()),
                ..string(false, None)
            },
        )]);
        let mut expected = BetterAuth::stateless(config.clone())
            .rate_limit(RateLimitConfig::new().enabled(false))
            .plugin(OpenApiPlugin::new())
            .build()
            .await?
            .openapi_spec()?
            .to_value()?;
        let _ = object_at(&mut expected, "/components/schemas/User/properties")?
            .insert("docsInput".into(), json!({"type":"string"}));
        require_field(&mut expected, "/components/schemas/User", "docsInput")?;
        let rank = if default {
            json!({"type":"number", "default":7})
        } else {
            json!({"type":"number"})
        };
        for path in ["~1sign-up~1email", "~1update-user"] {
            let pointer =
                format!("/paths/{path}/post/requestBody/content/application~1json/schema");
            let properties = object_at(&mut expected, &format!("{pointer}/properties"))?;
            let _ = properties.insert("rank".into(), rank.clone());
            let _ = properties.insert("docsInput".into(), json!({"type":"string"}));
            if path == "~1sign-up~1email" {
                if !default {
                    require_field(&mut expected, &pointer, "rank")?;
                }
                require_field(&mut expected, &pointer, "docsInput")?;
            }
        }
        let auth = BetterAuth::stateless(config)
            .rate_limit(RateLimitConfig::new().enabled(false))
            .plugin(UserPolicyOverlay { default })
            .plugin(OpenApiPlugin::new())
            .build()
            .await?;
        let document = auth.openapi_spec()?.to_value()?;
        assert_eq!(document, expected, "default={default}");
        for pointer in [
            "/components/schemas/User/properties",
            "/paths/~1sign-up~1email/post/requestBody/content/application~1json/schema/properties",
            "/paths/~1update-user/post/requestBody/content/application~1json/schema/properties",
        ] {
            let keys = |value: &Value| -> AuthResult<Vec<String>> {
                value
                    .pointer(pointer)
                    .and_then(Value::as_object)
                    .map(|fields| fields.keys().cloned().collect())
                    .ok_or_else(|| {
                        AuthError::internal(
                            "Expected complete User component and request properties",
                        )
                    })
            };
            assert_eq!(
                keys(&document)?,
                keys(&expected)?,
                "{pointer}, default={default}"
            );
        }
        let parser = &auth.config().user;
        assert_eq!(
            parser
                .fields()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["rank"]
        );
        assert_eq!(
            parser.parse_input(
                &[
                    ("rank".into(), 8.into()),
                    ("docsInput".into(), "ignored".into()),
                ]
                .into(),
                true
            )?,
            FieldMap::from([("rank".into(), 8.into())])
        );
        let missing = parser.parse_input(&FieldMap::new(), true);
        if default {
            assert_eq!(missing?, FieldMap::from([("rank".into(), 7.into())]));
        } else {
            assert!(
                matches!(missing, Err(AuthError::FieldInput { code: "MISSING_FIELD", message }) if message == "rank is required")
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn username_and_last_login_components_follow_registered_options() -> AuthResult<()> {
    let mut config =
        AuthConfig::new("user-plugin-components-contract-at-least-thirty-two-characters")
            .base_url("http://user-plugin-components.test");
    config.logger = better_auth_core::LoggerConfig {
        disabled: Some(true),
        ..Default::default()
    }
    .into();
    config.telemetry.enabled = false;
    let baseline = BetterAuth::stateless(config.clone())
        .rate_limit(RateLimitConfig::new().enabled(false))
        .plugin(OpenApiPlugin::new())
        .build()
        .await?
        .openapi_spec()?
        .to_value()?;
    for display_username in [false, true] {
        for store_in_database in [false, true] {
            let mut expected = baseline.clone();
            let properties = object_at(&mut expected, "/components/schemas/User/properties")?;
            let _ = properties.insert("username".into(), json!({"type":"string"}));
            let mut registered = vec!["username"];
            if display_username {
                let _ = properties.insert("displayUsername".into(), json!({"type":"string"}));
                registered.push("displayUsername");
            }
            if store_in_database {
                let _ = properties.insert(
                    "lastLoginMethod".into(),
                    json!({"type":"string", "readOnly":true}),
                );
                registered.push("lastLoginMethod");
            }
            let auth = BetterAuth::stateless(config.clone())
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(UsernamePlugin::new(UsernameConfig {
                    display_username,
                    ..Default::default()
                }))
                .plugin(LastLoginMethodPlugin::new(LastLoginMethodConfig {
                    store_in_database,
                    ..Default::default()
                }))
                .plugin(OpenApiPlugin::new())
                .build()
                .await?;
            let document = auth.openapi_spec()?.to_value()?;
            assert_eq!(
                schemas(&document)?,
                schemas(&expected)?,
                "display_username={display_username}, store_in_database={store_in_database}"
            );
            let property_keys = |value: &Value| -> AuthResult<Vec<String>> {
                value
                    .pointer("/components/schemas/User/properties")
                    .and_then(Value::as_object)
                    .map(|properties| properties.keys().cloned().collect())
                    .ok_or_else(|| {
                        AuthError::internal("Expected all registered User component properties")
                    })
            };
            assert_eq!(property_keys(&document)?, property_keys(&expected)?);
            assert_eq!(
                auth.config()
                    .user
                    .fields()
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                registered
            );
        }
    }
    Ok(())
}

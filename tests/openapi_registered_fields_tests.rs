use async_trait::async_trait;
use better_auth::{
    BetterAuth,
    plugins::{OpenApiPlugin, OrganizationConfig, OrganizationPlugin},
};
use better_auth_core::{
    AuthConfig, AuthContext, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
    AuthRoute, AuthSchema, OpenApiPluginMetadata, RateLimitConfig,
    organization_fields::OrganizationFields,
    store::schema::EntityRole,
    user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform},
};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Default)]
struct CallbackCalls {
    default: AtomicUsize,
    input: AtomicUsize,
    output: AtomicUsize,
}

fn string(required: bool, default: Option<&str>) -> UserFieldConfig {
    UserFieldConfig {
        required: Some(required),
        default_value: default.map(|value| json!(value)),
        ..Default::default()
    }
}

fn fields<const N: usize>(entries: [(&str, UserFieldConfig); N]) -> UserConfig {
    UserConfig {
        additional_fields: Some(
            entries
                .into_iter()
                .map(|(name, field)| (name.to_owned(), field))
                .collect(),
        ),
    }
}

struct RegisteredFields(Arc<CallbackCalls>);

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for RegisteredFields {
    fn name(&self) -> &'static str {
        "ordinary-openapi-registered-fields"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    fn openapi(&self) -> AuthResult<OpenApiPluginMetadata> {
        let documentation = string(false, Some("documentation-only"));
        Ok(
            OpenApiPluginMetadata::from_routes("ordinary-openapi-registered-fields", Vec::new())?
                .model(
                    "jwks",
                    &fields([
                        ("label", string(false, Some("stale-documentation"))),
                        ("docsNote", documentation.clone()),
                    ]),
                )
                .model("widget", &fields([("label", documentation)])),
        )
    }

    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        let core = UserFieldConfig {
            input: Some(false),
            returned: Some(false),
            ..string(true, Some("registered-core-note"))
        };
        for role in [
            EntityRole::User,
            EntityRole::Session,
            EntityRole::Account,
            EntityRole::Verification,
        ] {
            context.register_model_fields(role, fields([("coreNote", core.clone())]))?;
        }
        context.register_model_fields(
            EntityRole::DeviceCode,
            fields([(
                "label",
                UserFieldConfig {
                    field_name: Some("stored_device_label".into()),
                    ..string(true, None)
                },
            )]),
        )?;
        context.register_model_fields(
            EntityRole::Jwk,
            fields([(
                "label",
                UserFieldConfig {
                    field_name: Some("stored_jwk_label".into()),
                    input: Some(false),
                    returned: Some(false),
                    ..string(true, Some("jwk-default"))
                },
            )]),
        )?;
        let defaults = self.0.clone();
        let inputs = self.0.clone();
        let outputs = self.0.clone();
        context.register_model_fields(
            EntityRole::WalletAddress,
            fields([(
                "label",
                UserFieldConfig {
                    field_name: Some("stored_wallet_label".into()),
                    default_value_fn: Some(Arc::new(move || {
                        let _ = defaults.default.fetch_add(1, Ordering::SeqCst);
                        json!("wallet-default")
                    })),
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
                },
            )]),
        )?;
        context.register_model_fields(
            EntityRole::Passkey,
            fields([
                ("name", string(true, Some("passkey-name"))),
                (
                    "aaguid",
                    UserFieldConfig {
                        input: Some(false),
                        returned: Some(false),
                        ..string(false, Some("display-aaguid"))
                    },
                ),
            ]),
        )?;
        context.register_model_fields(
            EntityRole::ApiKey,
            fields([(
                "name",
                UserFieldConfig {
                    input: Some(false),
                    ..string(true, Some("api-key-name"))
                },
            )]),
        )?;
        for (role, default) in [
            (EntityRole::Organization, "registered-organization-label"),
            (EntityRole::Team, "registered-team-label"),
        ] {
            context
                .register_model_fields(role, fields([("label", string(false, Some(default)))]))?;
        }
        Ok(())
    }

    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

fn organization(dynamic: bool) -> OrganizationPlugin {
    let config = OrganizationConfig {
        dynamic_access_control: dynamic,
        teams: better_auth::plugins::organization::OrganizationTeamsConfig {
            enabled: true,
            ..Default::default()
        },
        schema: OrganizationFields {
            organization: fields([("label", string(true, Some("builtin-organization-label")))]),
            member: fields([(
                "note",
                UserFieldConfig {
                    input: Some(false),
                    ..string(false, Some("member-note"))
                },
            )]),
            invitation: fields([(
                "note",
                UserFieldConfig {
                    returned: Some(false),
                    ..string(true, None)
                },
            )]),
            team: fields([("label", string(true, Some("builtin-team-label")))]),
            organization_role: fields([("note", string(true, Some("role-note")))]),
        },
        ..Default::default()
    };
    OrganizationPlugin::with_config(config)
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The test propagates setup errors and compares complete captured OpenAPI components."
)]
async fn registered_fields_supply_openapi_components_without_running_callbacks()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let expected: Value = serde_json::from_str(include_str!(
        "fixtures/openapi-registered-fields-1.7.6.json"
    ))?;
    let mut cases = Vec::new();
    for name in [
        "registered-only",
        "organization-before",
        "organization-after",
        "organization-disabled",
    ] {
        let callbacks = Arc::new(CallbackCalls::default());
        let application = fields([("coreNote", string(false, Some("application-core-note")))]);
        let mut config =
            AuthConfig::new("ordinary-openapi-registered-fields-secret-at-least-32-characters")
                .base_url("http://openapi-registered-fields.test");
        config.logger.disabled = Some(true);
        config.telemetry.enabled = false;
        config.user = application.clone();
        config.session.additional_fields = application.additional_fields.clone();
        config.account.additional_fields = application.fields().clone();
        config.verification.additional_fields = application.fields().clone();
        let builder =
            BetterAuth::stateless(config).rate_limit(RateLimitConfig::new().enabled(false));
        let custom = RegisteredFields(callbacks.clone());
        let builder = match name {
            "registered-only" => builder.plugin(custom),
            "organization-after" => builder.plugin(custom).plugin(organization(true)),
            _ => builder
                .plugin(organization(name != "organization-disabled"))
                .plugin(custom),
        };
        let auth = builder.plugin(OpenApiPlugin::new()).build().await?;
        let document = auth.openapi_spec()?.to_value()?;
        let schemas = document
            .pointer("/components/schemas")
            .ok_or("OpenAPI components must include schemas")?;
        cases.push(json!({
            "name": name,
            "schemas": schemas,
            "callbackCalls": {
                "default": callbacks.default.load(Ordering::SeqCst),
                "input": callbacks.input.load(Ordering::SeqCst),
                "output": callbacks.output.load(Ordering::SeqCst),
            },
        }));
    }
    assert_eq!(json!({"version":"1.7.6", "cases":cases}), expected);
    Ok(())
}

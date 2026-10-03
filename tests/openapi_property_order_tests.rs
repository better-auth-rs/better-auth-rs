use async_trait::async_trait;
use better_auth::{
    BetterAuth,
    plugins::{DeviceAuthorizationPlugin, OpenApiPlugin, OrganizationConfig, OrganizationPlugin},
};
use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse,
    AuthResult, AuthRoute, AuthSchema, OpenApiPluginMetadata, RateLimitConfig,
    organization_fields::OrganizationFields,
    store::schema::EntityRole,
    user_fields::{UserConfig, UserFieldConfig},
};
use serde_json::{Value, json};

fn numeric_fields() -> UserConfig {
    UserConfig {
        additional_fields: Some(
            ["tail", "10", "2", "01", "4294967294", "4294967295"]
                .into_iter()
                .map(|name| {
                    (
                        name.into(),
                        UserFieldConfig {
                            required: Some(true),
                            field_name: Some(format!("display_{name}")),
                            ..Default::default()
                        },
                    )
                })
                .collect(),
        ),
    }
}

enum DisplayFields {
    NumericDevice,
    Label,
    Note,
}

impl DisplayFields {
    fn id(&self) -> &'static str {
        match self {
            Self::NumericDevice => "ordinary-openapi-numeric-fields",
            Self::Label => "ordinary-openapi-label",
            Self::Note => "ordinary-openapi-note",
        }
    }

    fn fields(&self) -> UserConfig {
        let name = match self {
            Self::NumericDevice => return numeric_fields(),
            Self::Label => "label",
            Self::Note => "note",
        };
        UserConfig {
            additional_fields: Some(
                [(
                    name.into(),
                    UserFieldConfig {
                        required: Some(true),
                        ..Default::default()
                    },
                )]
                .into_iter()
                .collect(),
            ),
        }
    }
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for DisplayFields {
    fn name(&self) -> &'static str {
        self.id()
    }

    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    fn openapi(&self) -> AuthResult<OpenApiPluginMetadata> {
        let mut metadata = OpenApiPluginMetadata::from_routes(self.id(), Vec::new())?;
        if matches!(self, Self::Note) {
            for model in ["user", "session", "account", "verification"] {
                metadata = metadata.model(model, &self.fields());
            }
        }
        Ok(metadata)
    }

    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        if matches!(self, Self::NumericDevice) {
            return context.register_model_fields(EntityRole::DeviceCode, self.fields());
        }
        context.register_user_fields(self.fields());
        for role in [
            EntityRole::Session,
            EntityRole::Account,
            EntityRole::Verification,
        ] {
            context.register_model_fields(role, self.fields())?;
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

fn organization() -> OrganizationPlugin {
    OrganizationPlugin::with_config(OrganizationConfig {
        dynamic_access_control: true,
        teams: better_auth::plugins::organization::OrganizationTeamsConfig {
            enabled: true,
            ..Default::default()
        },
        schema: OrganizationFields {
            organization: numeric_fields(),
            member: numeric_fields(),
            invitation: numeric_fields(),
            team: numeric_fields(),
            organization_role: numeric_fields(),
        },
        ..Default::default()
    })
}

fn property_keys(schema: &Value) -> AuthResult<Vec<String>> {
    schema
        .get("properties")
        .and_then(Value::as_object)
        .map(|properties| properties.keys().cloned().collect())
        .ok_or_else(|| AuthError::internal("Expected complete generated display properties"))
}

fn observe(document: &Value, name: &str) -> AuthResult<Value> {
    let numeric = name == "numeric-display-names";
    let models = if numeric {
        &[
            "User",
            "Session",
            "Account",
            "Verification",
            "Organization",
            "Member",
            "Invitation",
            "Team",
            "OrganizationRole",
            "DeviceCode",
        ][..]
    } else {
        &["User", "Session", "Account", "Verification"][..]
    };
    let mut components = Vec::new();
    for model in models {
        let schema = document
            .pointer("/components/schemas")
            .and_then(|schemas| schemas.get(model))
            .ok_or_else(|| AuthError::internal(format!("Expected complete {model} component")))?;
        components.push(
            json!({ "model": model, "schema": schema, "propertyKeys": property_keys(schema)? }),
        );
    }
    let paths = if numeric {
        &[
            "/sign-up/email",
            "/update-user",
            "/organization/create",
            "/organization/update",
            "/organization/create-role",
            "/organization/update-role",
        ][..]
    } else {
        &["/sign-up/email", "/update-user"][..]
    };
    let mut requests = Vec::new();
    for path in paths {
        let schema = document
            .get("paths")
            .and_then(|paths| paths.get(path))
            .and_then(|operation| {
                operation.pointer("/post/requestBody/content/application~1json/schema")
            })
            .ok_or_else(|| {
                AuthError::internal(format!("Expected complete request schema for {path}"))
            })?;
        let pointer = match *path {
            "/organization/update" => "/properties/data",
            "/organization/create-role" => "/properties/additionalFields",
            "/organization/update-role" => "/allOf/0/properties/data",
            _ => "",
        };
        let field_schema = schema.pointer(pointer).ok_or_else(|| {
            AuthError::internal(format!("Expected display properties for {path}"))
        })?;
        requests.push(
            json!({ "path": path, "schema": schema, "propertyKeys": property_keys(field_schema)? }),
        );
    }
    Ok(json!({ "name": name, "components": components, "requests": requests }))
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The test propagates setup errors and compares complete captured schemas and property-key arrays."
)]
async fn generated_openapi_fields_match_javascript_enumeration_and_core_declarations()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let expected: Value =
        serde_json::from_str(include_str!("fixtures/openapi-property-order-1.7.6.json"))?;
    let mut cases = Vec::new();
    for name in [
        "numeric-display-names",
        "runtime-before-explicit",
        "explicit-before-runtime",
    ] {
        let mut config =
            AuthConfig::new("ordinary-openapi-property-order-secret-at-least-32-characters")
                .base_url("http://openapi-property-order.test");
        config.logger.disabled = Some(true);
        config.telemetry.enabled = false;
        let numeric = name == "numeric-display-names";
        if numeric {
            config.user = numeric_fields();
            config.session.additional_fields = numeric_fields().additional_fields;
            config.account.additional_fields = numeric_fields().fields().clone();
            config.verification.additional_fields = numeric_fields().fields().clone();
        }
        let builder =
            BetterAuth::stateless(config).rate_limit(RateLimitConfig::new().enabled(false));
        let builder = if numeric {
            builder
                .plugin(organization())
                .plugin(DisplayFields::NumericDevice)
                .plugin(DeviceAuthorizationPlugin::new())
        } else if name == "runtime-before-explicit" {
            builder
                .plugin(DisplayFields::Label)
                .plugin(DisplayFields::Note)
        } else {
            builder
                .plugin(DisplayFields::Note)
                .plugin(DisplayFields::Label)
        };
        let auth = builder.plugin(OpenApiPlugin::new()).build().await?;
        cases.push(observe(&auth.openapi_spec()?.to_value()?, name)?);
    }
    assert_eq!(json!({ "version": "1.7.6", "cases": cases }), expected);
    Ok(())
}

use better_auth::__private_core::__private_async_trait::async_trait;
use better_auth::{
    __private_core::{
        AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
        AuthRoute, AuthSchema, AuthStore, CreateJwk,
        store::schema::EntityRole,
        user_fields::{
            FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
        },
    },
    AuthConfig, BetterAuth,
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

pub(crate) type Trace = Arc<Mutex<Vec<Value>>>;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scenario {
    Success,
    InputError,
    OutputError,
}

impl Scenario {
    pub(crate) const ALL: [Self; 3] = [Self::Success, Self::InputError, Self::OutputError];

    fn name(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::InputError => "input-error",
            Self::OutputError => "output-error",
        }
    }
}

pub(crate) struct Fields(pub(crate) UserConfig);

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Fields {
    fn name(&self) -> &'static str {
        "ordinary-jwk-additional-fields"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        context.register_model_fields(EntityRole::Jwk, self.0.clone())
    }

    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

pub(crate) fn config() -> AuthConfig {
    AuthConfig::new("ordinary-jwk-extra-fields-secret-at-least-32-characters")
        .base_url("http://jwk-fields.test")
}

#[expect(
    clippy::expect_used,
    reason = "Fixture callbacks require unpoisoned trace locks and declared string values"
)]
pub(crate) fn policies(events: Option<Trace>, scenario: Scenario) -> UserConfig {
    let mut fields = UserConfig {
        additional_fields: Some(
            [
                (
                    "label".into(),
                    UserFieldConfig {
                        field_name: Some("stored_label".into()),
                        required: Some(false),
                        ..Default::default()
                    },
                ),
                (
                    "note".into(),
                    UserFieldConfig {
                        required: Some(false),
                        default_value: Some(json!("default-note")),
                        ..Default::default()
                    },
                ),
                (
                    "settings".into(),
                    UserFieldConfig {
                        field_type: UserFieldType::Json,
                        field_name: Some("stored_settings".into()),
                        required: Some(false),
                        ..Default::default()
                    },
                ),
            ]
            .into(),
        ),
    };
    if let Some(events) = events {
        for (name, field) in fields.fields_mut() {
            let input_events = events.clone();
            let output_events = events.clone();
            let input_name = name.clone();
            let output_name = name.clone();
            field.transform = Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    input_events
                        .lock()
                        .expect("ordinary JWK trace lock")
                        .push(json!(["input", input_name, value]));
                    if input_name == "label" {
                        if scenario == Scenario::InputError {
                            return Err(AuthError::internal("ordinary JWK input-error"));
                        }
                        return Ok(value.map(|value| match value {
                            Value::String(value) => json!(value.trim()),
                            value => value,
                        }));
                    }
                    Ok(value)
                })),
                output: Some(UserFieldTransform::new(move |value| {
                    output_events
                        .lock()
                        .expect("ordinary JWK trace lock")
                        .push(json!(["output", output_name, value]));
                    if output_name == "label" {
                        if scenario == Scenario::OutputError {
                            return Err(AuthError::internal("ordinary JWK output-error"));
                        }
                        return Ok(value.map(|value| {
                            json!(format!("{}:out", value.as_str().expect("string label")))
                        }));
                    }
                    Ok(value)
                })),
            });
        }
    }
    fields
}

#[expect(
    clippy::expect_used,
    reason = "The fixture uses a fixed valid timestamp without observing native date output"
)]
pub(crate) fn input() -> CreateJwk {
    CreateJwk {
        public_key: "public".into(),
        private_key: "private".into(),
        created_at: "2030-01-01T00:00:00Z"
            .parse()
            .expect("fixed inert fixture date parses"),
        expires_at: None,
        alg: "EdDSA".into(),
        crv: None,
        additional_fields: [
            ("label".into(), json!(" Display ")),
            ("settings".into(), json!({"compact":true,"theme":"dark"})),
        ]
        .into_iter()
        .collect(),
    }
}

#[expect(
    clippy::expect_used,
    reason = "Contract assertions must fail on absent fixture records or changed observations"
)]
pub(crate) async fn contract<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    backend: &str,
    scenario: Scenario,
) -> AuthResult<()> {
    let reader = BetterAuth::new(config())
        .store_arc(raw.clone())
        .plugin(Fields(policies(None, Scenario::Success)))
        .build()
        .await?;
    let events = Trace::default();
    let auth = BetterAuth::new(config())
        .store_arc(raw)
        .plugin(Fields(policies(Some(events.clone()), scenario)))
        .build()
        .await?;
    let store = auth.store();
    let result = if scenario == Scenario::Success {
        events
            .lock()
            .expect("ordinary JWK trace lock")
            .push(json!(["operation", "create-1"]));
        let first = store.create_jwk(input()).await?;
        events
            .lock()
            .expect("ordinary JWK trace lock")
            .push(json!(["operation", "create-2"]));
        let second = store.create_jwk(input()).await?;
        events
            .lock()
            .expect("ordinary JWK trace lock")
            .push(json!(["operation", "read"]));
        let read = store
            .get_jwk(first.id.typed()?)
            .await?
            .expect("created JWK display record exists");
        events
            .lock()
            .expect("ordinary JWK trace lock")
            .push(json!(["operation", "list"]));
        let listed: Vec<_> = store
            .list_jwks()
            .await?
            .into_iter()
            .map(|row| row.additional_fields)
            .collect();
        json!({
            "created":[first.additional_fields, second.additional_fields],
            "read":read.additional_fields,
            "listed":listed,
        })
    } else {
        events
            .lock()
            .expect("ordinary JWK trace lock")
            .push(json!(["operation", "create"]));
        let message = format!("ordinary JWK {}", scenario.name());
        let same_error = match store.create_jwk(input()).await {
            Err(AuthError::Internal(actual)) if actual == message => true,
            Err(error) => return Err(error),
            Ok(_) => false,
        };
        json!({"sameError":same_error, "message":message})
    };
    let stored: Vec<_> = reader
        .store()
        .list_jwks()
        .await?
        .into_iter()
        .map(|row| row.additional_fields)
        .collect();
    let actual = json!({
        "backend":backend,
        "scenario":scenario.name(),
        "events":*events.lock().expect("ordinary JWK trace lock"),
        "result":result,
        "stored":stored,
    });
    let fixture: Value =
        serde_json::from_str(include_str!("../fixtures/jwk-additional-fields-1.7.6.json"))?;
    let expected = fixture
        .get("cases")
        .and_then(Value::as_array)
        .expect("captured JWK cases")
        .iter()
        .find(|case| case["backend"] == backend && case["scenario"] == scenario.name())
        .expect("captured JWK scenario");
    assert_eq!(&actual, expected);
    Ok(())
}

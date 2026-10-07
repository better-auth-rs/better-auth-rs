use better_auth::__private_core::__private_async_trait::async_trait;
use better_auth::{
    __private_core::{
        AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
        AuthRoute, AuthSchema, AuthStore, AuthUser, CreateUser, CreateWalletAddress, FieldMap,
        FieldValue,
        store::schema::EntityRole,
        user_fields::{
            FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
        },
    },
    AuthConfig, BetterAuth,
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

pub(crate) const ADDRESS: &str = "0x0000000000000000000000000000000000000001";
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
        "ordinary-wallet-additional-fields"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        context.register_model_fields(EntityRole::WalletAddress, self.0.clone())
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
    AuthConfig::new("ordinary-wallet-extra-fields-secret-at-least-32-characters")
        .base_url("http://wallet-fields.test")
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
                        default_value: Some("default-note".into()),
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
                        .expect("ordinary Wallet trace lock")
                        .push(json!(["input", input_name, value.json()?]));
                    if input_name == "label" {
                        if scenario == Scenario::InputError {
                            return Err(AuthError::internal("ordinary Wallet input-error"));
                        }
                        return Ok(match value {
                            FieldValue::String(value) => value.trim().into(),
                            value => value,
                        });
                    }
                    Ok(value)
                })),
                output: Some(UserFieldTransform::new(move |value| {
                    output_events
                        .lock()
                        .expect("ordinary Wallet trace lock")
                        .push(json!(["output", output_name, value.json()?]));
                    if output_name == "label" {
                        if scenario == Scenario::OutputError {
                            return Err(AuthError::internal("ordinary Wallet output-error"));
                        }
                        return Ok(match value {
                            FieldValue::Undefined => FieldValue::Undefined,
                            value => {
                                format!("{}:out", value.as_str().expect("string label")).into()
                            }
                        });
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
pub(crate) fn input(user_id: String) -> CreateWalletAddress {
    CreateWalletAddress {
        user_id,
        address: ADDRESS.into(),
        chain_id: 1,
        is_primary: false,
        created_at: "2030-01-01T00:00:00Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .expect("fixed inert fixture date parses")
            .into(),
        additional_fields: [
            ("label".into(), " Display ".into()),
            (
                "settings".into(),
                FieldMap::from([
                    ("compact".into(), true.into()),
                    ("theme".into(), "dark".into()),
                ])
                .into(),
            ),
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
    let user = reader
        .store()
        .create_user(
            CreateUser::new()
                .with_name("Display fixture")
                .with_email("display@wallet-fields.test"),
        )
        .await?;
    let user_id = user.id().typed()?.to_string();
    let events = Trace::default();
    let auth = BetterAuth::new(config())
        .store_arc(raw)
        .plugin(Fields(policies(Some(events.clone()), scenario)))
        .build()
        .await?;
    let store = auth.store();
    events
        .lock()
        .expect("ordinary Wallet trace lock")
        .push(json!(["operation", "create"]));
    let result = if scenario == Scenario::Success {
        let created = store.create_wallet_address(input(user_id)).await?;
        events
            .lock()
            .expect("ordinary Wallet trace lock")
            .push(json!(["operation", "read-exact"]));
        let read = store
            .get_wallet_address(ADDRESS, Some(1))
            .await?
            .expect("created Wallet display record exists");
        events
            .lock()
            .expect("ordinary Wallet trace lock")
            .push(json!(["operation", "read-address"]));
        let by_address = store
            .get_wallet_address(ADDRESS, None)
            .await?
            .expect("created Wallet display record exists");
        json!({
            "created":created.additional_fields.json()?,
            "readExact":read.additional_fields.json()?,
            "readAddress":by_address.additional_fields.json()?,
        })
    } else {
        let message = format!("ordinary Wallet {}", scenario.name());
        let same_error = match store.create_wallet_address(input(user_id)).await {
            Err(AuthError::Internal(actual)) if actual == message => true,
            Err(error) => return Err(error),
            Ok(_) => false,
        };
        json!({"sameError":same_error, "message":message})
    };
    let stored = reader
        .store()
        .get_wallet_address(ADDRESS, Some(1))
        .await?
        .map(|row| row.additional_fields.json())
        .transpose()?;
    let actual = json!({
        "backend":backend,
        "scenario":scenario.name(),
        "events":*events.lock().expect("ordinary Wallet trace lock"),
        "result":result,
        "stored":stored,
    });
    let fixture: Value = serde_json::from_str(include_str!(
        "../fixtures/wallet-additional-fields-1.7.6.json"
    ))?;
    let expected = fixture
        .get("cases")
        .and_then(Value::as_array)
        .expect("captured Wallet cases")
        .iter()
        .find(|case| case["backend"] == backend && case["scenario"] == scenario.name())
        .expect("captured Wallet scenario");
    assert_eq!(&actual, expected);
    Ok(())
}

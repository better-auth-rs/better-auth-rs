#![expect(
    clippy::panic,
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract. Unexpected fixture variants and deliberate callback panics must fail or exercise the recorded unwind path."
)]

use super::*;
use better_auth_core::{
    AuthConfig, FieldDate, FieldMap, FieldValue,
    id::IdGeneration,
    plugin_runtime::ModelFields,
    store::{EphemeralStore, StatelessSchema, schema::EntityRole},
    user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform},
};
use serde_json::json;
use std::sync::Mutex;

struct Projection {
    reference: FieldValue,
    events: Arc<Mutex<Vec<(&'static str, FieldValue)>>>,
}

#[async_trait::async_trait]
impl AuthPlugin<StatelessSchema> for Projection {
    fn name(&self) -> &'static str {
        "api-key-session-reference"
    }

    fn routes(&self) -> Vec<better_auth_core::AuthRoute> {
        Vec::new()
    }

    async fn on_request(
        &self,
        _: &better_auth_core::AuthRequest,
        _: &better_auth_core::AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<better_auth_core::AuthResponse>> {
        Ok(None)
    }

    fn schema(&self, fields: &mut ModelFields) -> AuthResult<()> {
        let reference = self.reference.clone();
        let events = self.events.clone();
        fields.register_model_fields(
            EntityRole::ApiKey,
            UserConfig {
                additional_fields: Some(
                    [(
                        "referenceId".into(),
                        UserFieldConfig {
                            transform: Some(FieldTransforms {
                                output: Some(UserFieldTransform::new(move |value| {
                                    events.lock().unwrap().push(("referenceId", value));
                                    Ok(reference.clone())
                                })),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    )]
                    .into(),
                ),
            },
        )
    }
}

fn date(milliseconds: f64) -> FieldValue {
    FieldDate::from_milliseconds(milliseconds).into()
}

fn user() -> FieldMap {
    let mut fields = FieldValue::from_json(json!({
        "id": 1, "name": "Owner", "email": "owner@session-reference.test",
        "emailVerified": true, "image": null,
    }))
    .unwrap()
    .enumerable_fields()
    .unwrap();
    fields.extend([
        ("createdAt".into(), date(1_893_456_000_000.0)),
        ("updatedAt".into(), date(1_893_456_000_000.0)),
    ]);
    fields
}

fn api_key(secret: &str) -> FieldMap {
    let mut fields = FieldValue::from_json(json!({
        "id": 1, "name": "Machine", "start": null, "prefix": null,
        "key": secret, "referenceId": "1", "configId": "default",
        "refillInterval": null, "refillAmount": null, "lastRefillAt": null,
        "enabled": true, "rateLimitEnabled": false, "rateLimitTimeWindow": 60000,
        "rateLimitMax": 3, "requestCount": 0, "remaining": null, "lastRequest": null,
        "permissions": null, "metadata": null,
    }))
    .unwrap()
    .enumerable_fields()
    .unwrap();
    fields.extend([
        ("createdAt".into(), date(1_893_456_000_000.0)),
        ("updatedAt".into(), date(1_893_456_000_000.0)),
        ("expiresAt".into(), date(4_102_444_800_000.0)),
    ]);
    fields
}

#[tokio::test]
async fn virtual_session_preserves_projected_reference_before_serial_user_conversion() {
    for reference in [FieldValue::from(1.0), FieldValue::from("001")] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let projection = Projection {
            reference: reference.clone(),
            events: events.clone(),
        };
        let mut config = AuthConfig::new("session-reference-secret-at-least-32-characters");
        config.advanced.database.generate_id = Some(IdGeneration::Serial);
        let user_events = events.clone();
        config.user.additional_fields = Some(
            [(
                "name".into(),
                UserFieldConfig {
                    transform: Some(FieldTransforms {
                        output: Some(UserFieldTransform::new(move |value| {
                            user_events.lock().unwrap().push(("name", value));
                            Ok("Projected owner".into())
                        })),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )]
            .into(),
        );
        let config = Arc::new(config);
        let secret = "x".repeat(64);
        let initial_user = user();
        let initial_key = api_key(&secret);
        let raw = Arc::new(
            EphemeralStore::from_storage(
                config.clone(),
                [
                    ("user".into(), vec![initial_user.clone()]),
                    ("apikey".into(), vec![initial_key.clone()]),
                    ("session".into(), Vec::new()),
                    ("account".into(), Vec::new()),
                    ("verification".into(), Vec::new()),
                ],
            )
            .unwrap(),
        );
        let plugin = ApiKeyPlugin::builder()
            .enable_session_for_api_keys(true)
            .disable_key_hashing(true)
            .defer_updates(false)
            .build();
        let context = crate::plugins::test_helpers::initialize_test_context(
            config,
            raw.clone(),
            &[&plugin, &projection],
        )
        .await
        .unwrap();
        for method in [HttpMethod::Get, HttpMethod::Post] {
            events.lock().unwrap().clear();
            let mut request = create_auth_request(method, "/get-session", None, None, None);
            let _ = request.headers.insert("x-api-key".into(), secret.clone());
            let _ = request
                .headers
                .insert("x-forwarded-for".into(), "203.0.113.9".into());
            let request = request.clone().with_original_request(request);
            let started = Utc::now().timestamp_millis() as f64;
            let action = plugin.before_request(&request, &context).await.unwrap();
            let ended = Utc::now().timestamp_millis() as f64;
            let Some(BeforeRequestAction::Respond(response)) = action else {
                panic!("API Key must answer get-session before route dispatch");
            };
            assert_eq!(response.status, 200);
            let actual = response.body.field_value().unwrap();
            let session = actual.model_property("session").unwrap();
            let created = session.model_property("createdAt").unwrap();
            let updated = session.model_property("updatedAt").unwrap();
            for value in [&created, &updated] {
                let FieldValue::Date(value) = value else {
                    panic!("Virtual Session timestamps must remain native Dates");
                };
                assert!((started..=ended).contains(&value.milliseconds()));
            }
            let mut expected_user = initial_user.clone();
            let _ = expected_user.insert("id".into(), "1".into());
            let _ = expected_user.insert("name".into(), "Projected owner".into());
            let expected_session = FieldMap::from([
                ("id".into(), "1".into()),
                ("token".into(), secret.clone().into()),
                ("userId".into(), reference.clone()),
                ("userAgent".into(), FieldValue::Null),
                ("ipAddress".into(), "203.0.113.9".into()),
                ("createdAt".into(), created),
                ("updatedAt".into(), updated),
                ("expiresAt".into(), date(4_102_444_800_000.0)),
            ]);
            let expected: FieldValue = FieldMap::from([
                ("user".into(), expected_user.into()),
                ("session".into(), expected_session.into()),
            ])
            .into();
            assert_eq!(actual, expected);
            assert_eq!(response.body.json().unwrap(), expected.json().unwrap());
            assert_eq!(
                *events.lock().unwrap(),
                [
                    ("referenceId", "1".into()),
                    ("referenceId", "1".into()),
                    ("referenceId", "1".into()),
                    ("name", "Owner".into()),
                ]
            );
            assert_eq!(
                raw.storage_rows(EntityRole::User).unwrap(),
                std::slice::from_ref(&initial_user)
            );
            let keys = raw.storage_rows(EntityRole::ApiKey).unwrap();
            let [stored] = keys.as_slice() else {
                panic!("Verification must retain exactly one API Key");
            };
            let mut expected_key = initial_key.clone();
            for name in ["lastRequest", "updatedAt"] {
                let value = stored.get(name).unwrap();
                let FieldValue::Date(time) = value else {
                    panic!("API Key usage timestamps must remain native Dates");
                };
                assert!((started..=ended).contains(&time.milliseconds()));
                let _ = expected_key.insert(name.into(), value.clone());
            }
            assert_eq!(stored, &expected_key);
            for role in [
                EntityRole::Session,
                EntityRole::Account,
                EntityRole::Verification,
            ] {
                assert!(raw.storage_rows(role).unwrap().is_empty());
            }
        }
    }
}

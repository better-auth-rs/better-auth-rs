#![expect(
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "Fixture indexing must fail when an expected record or property is missing. Assertions report exact contract mismatches while Result propagates fixture errors."
)]

//! Replay frozen endpoint values through the shared runtime observer.
//! JavaScript reflection and host diagnostics remain in the source fixtures and coverage ledger.

use super::*;
use crate::plugins::test_helpers::native_observation::{NativeObservation, assert_replay};
use better_auth_core::{
    FieldDate, UpdateAccount,
    store::schema::EntityRole,
    user_fields::{UserFieldFactory, UserFieldType},
};
use serde_json::Value as Json;
use std::sync::atomic::{AtomicUsize, Ordering};

mod native_boundary;
mod runtime;
use crate::plugins::test_helpers::native_source as source;

const NOW: f64 = 2_000_000_000_000.0;

struct Trace {
    native: Mutex<NativeObservation>,
    projected: Mutex<FieldValue>,
    projections: AtomicUsize,
    second_false: bool,
    verified: FieldValue,
    mutation: Option<String>,
    database: Arc<dyn AuthStore<StatelessSchema>>,
    store: Arc<EphemeralStore>,
}

impl Trace {
    fn record(&self, phase: &str, name: &str, value: &FieldValue) -> AuthResult<()> {
        let mut native = self.native.lock().unwrap();
        let value = native.observe(value)?;
        native.record(phase, [(name.into(), value)]);
        Ok(())
    }

    fn storage(&self) -> AuthResult<FieldValue> {
        let mut tables = FieldMap::new();
        for (name, role) in [
            ("user", EntityRole::User),
            ("session", EntityRole::Session),
            ("account", EntityRole::Account),
            ("verification", EntityRole::Verification),
            ("twoFactor", EntityRole::TwoFactor),
        ] {
            let _ = tables.insert(
                name.into(),
                self.store
                    .storage_rows(role)?
                    .into_iter()
                    .map(FieldValue::from)
                    .collect::<Vec<_>>()
                    .into(),
            );
        }
        Ok(tables.into())
    }
}

#[async_trait]
impl PasswordHasher for Trace {
    async fn hash(&self, password: &str) -> AuthResult<String> {
        assert_eq!(password, PASSWORD);
        self.record("hash", "value", &password.into())?;
        Ok("new-hash".into())
    }

    async fn verify(&self, _: &str, _: &str) -> AuthResult<bool> {
        Err(AuthError::internal(
            "The fixture must reach the native verifier",
        ))
    }

    async fn verify_native(&self, hash: &FieldValue, password: &str) -> AuthResult<FieldValue> {
        assert_eq!(password, PASSWORD);
        let same_hash = hash.strict_equals(&self.projected.lock().unwrap());
        assert!(same_hash);
        {
            let mut native = self.native.lock().unwrap();
            let arguments = native.observe(
                &FieldMap::from([
                    ("hash".into(), hash.clone()),
                    ("password".into(), password.into()),
                ])
                .into(),
            )?;
            native.record(
                "verify",
                [
                    ("arguments".into(), arguments),
                    ("sameHash".into(), same_hash.into()),
                ],
            );
        }
        if let Some(mutation) = self
            .mutation
            .as_deref()
            .filter(|mutation| *mutation != "none")
        {
            let update = match mutation {
                "provider" => UpdateAccount {
                    provider_id: "changed-provider".into(),
                    ..Default::default()
                },
                "replacement" => UpdateAccount {
                    id: "replacement".into(),
                    password: Some("replacement-hash".to_owned()).into(),
                    ..Default::default()
                },
                _ => return Err(AuthError::internal("Unknown captured Account mutation")),
            };
            let _ = self
                .database
                .update_account_by_id_value(&"credential".into(), update)
                .await?;
            let stored = self
                .store
                .storage_rows(EntityRole::Account)?
                .into_iter()
                .map(FieldValue::from)
                .collect::<Vec<_>>();
            self.record(
                if mutation == "provider" {
                    "mutate-provider"
                } else {
                    "replace-account"
                },
                "stored",
                &stored.into(),
            )?;
        }
        Ok(self.verified.clone())
    }
}

fn hash(shape: &str, trace: &Arc<Trace>) -> AuthResult<FieldValue> {
    Ok(match shape {
        "false" => false.into(),
        "zero" => 0.into(),
        "nan" => f64::NAN.into(),
        "empty" => "".into(),
        "null" => FieldValue::Null,
        "undefined" => FieldValue::Undefined,
        "string" => "projected-hash".into(),
        "number" => 17.into(),
        "array" => vec![FieldValue::from("projected-hash")].into(),
        "object" => {
            let trace = Arc::downgrade(trace);
            FieldMap::from([
                ("marker".into(), "projected-hash".into()),
                (
                    "toString".into(),
                    FieldFunction::contextual(move |_, _| {
                        let trace = trace.upgrade().ok_or_else(|| {
                            AuthError::internal("The password trace must outlive its callback")
                        })?;
                        trace.native.lock().unwrap().record("hash.toString", []);
                        Err(AuthError::internal(
                            "The password consumer must not stringify the hash",
                        ))
                    })
                    .into(),
                ),
            ])
            .into()
        }
        _ => return Err(AuthError::internal("Unknown captured password shape")),
    })
}

fn tables(query_order: bool) -> Vec<(String, Vec<FieldMap>)> {
    let date = || FieldValue::from(FieldDate::from_milliseconds(NOW));
    let mut user = FieldMap::from([
        ("id".into(), "owner".into()),
        ("name".into(), "Owner".into()),
        (
            "email".into(),
            if query_order {
                "owner@password-query.test"
            } else {
                "owner@password-native.test"
            }
            .into(),
        ),
        ("emailVerified".into(), true.into()),
        ("image".into(), FieldValue::Null),
        ("twoFactorEnabled".into(), false.into()),
    ]);
    if query_order {
        let _ = user.insert("phoneNumber".into(), "+12025550123".into());
        let _ = user.insert("phoneNumberVerified".into(), true.into());
    }
    let _ = user.insert("createdAt".into(), date());
    let _ = user.insert("updatedAt".into(), date());
    vec![
        ("user".into(), vec![user]),
        (
            "session".into(),
            vec![FieldMap::from([
                ("id".into(), "session".into()),
                ("token".into(), "session-token".into()),
                ("userId".into(), "owner".into()),
                (
                    "expiresAt".into(),
                    FieldDate::from_milliseconds(4_070_908_800_000.0).into(),
                ),
                ("createdAt".into(), date()),
                ("updatedAt".into(), date()),
                ("ipAddress".into(), FieldValue::Null),
                ("userAgent".into(), FieldValue::Null),
            ])],
        ),
        (
            "account".into(),
            vec![FieldMap::from([
                ("id".into(), "credential".into()),
                ("userId".into(), "owner".into()),
                ("accountId".into(), "owner".into()),
                ("providerId".into(), "credential".into()),
                ("password".into(), "stored-hash".into()),
                ("createdAt".into(), date()),
                ("updatedAt".into(), date()),
            ])],
        ),
        ("verification".into(), Vec::new()),
        ("twoFactor".into(), Vec::new()),
    ]
}

fn config() -> better_auth_core::AuthConfig {
    let mut config = test_helpers::create_test_config().disable_session_refresh(true);
    let _ = config.account.additional_fields.insert(
        "updatedAt".into(),
        UserFieldConfig {
            field_type: UserFieldType::Date,
            on_update: Some(UserFieldFactory::new(|| {
                Ok(FieldDate::from_milliseconds(NOW).into())
            })),
            ..Default::default()
        },
    );
    config
}

fn install_projection(config: &mut better_auth_core::AuthConfig, trace: &Arc<Trace>) {
    let trace = trace.clone();
    let _ = config.account.additional_fields.insert(
        "password".into(),
        UserFieldConfig {
            required: Some(false),
            returned: Some(false),
            transform: Some(FieldTransforms {
                input: None,
                output: Some(UserFieldTransform::new(move |value| {
                    assert!(value == "stored-hash".into() || value == "new-hash".into());
                    trace.record("projection", "input", &value)?;
                    let count = trace.projections.fetch_add(1, Ordering::SeqCst) + 1;
                    Ok(if trace.second_false && count == 2 {
                        false.into()
                    } else {
                        trace.projected.lock().unwrap().clone()
                    })
                })),
            }),
            ..Default::default()
        },
    );
}

async fn query_case(case: &Json) -> AuthResult<()> {
    let mut config = config();
    let store = Arc::new(EphemeralStore::from_storage(
        Arc::new(config.clone()),
        tables(true),
    )?);
    let raw =
        test_helpers::initialize_test_context(Arc::new(config.clone()), store.clone(), &[]).await?;
    let trace = Arc::new(Trace {
        native: Mutex::new(NativeObservation::default()),
        projected: Mutex::new(FieldValue::Undefined),
        projections: AtomicUsize::new(0),
        second_false: case["secondHash"] == "false",
        verified: (case["operation"] != "phone").into(),
        mutation: case["mutation"].as_str().map(str::to_owned),
        database: raw.database,
        store: store.clone(),
    });
    *trace.projected.lock().unwrap() = hash(case["hash"].as_str().unwrap_or("object"), &trace)?;
    install_projection(&mut config, &trace);
    let email = EmailPasswordPlugin::new().password_hasher(trace.clone());
    let password = PasswordManagementPlugin::new();
    let phone = PhoneNumberPlugin::new();
    let two_factor = TwoFactorPlugin::new()
        .allow_passwordless(case["allowPasswordless"].as_bool().unwrap_or(false))
        .totp_disabled(true);
    let plugins: [&dyn AuthPlugin<StatelessSchema>; 4] = [&email, &password, &phone, &two_factor];
    let context = test_helpers::initialize_test_context(Arc::new(config), store, &plugins).await?;
    let (plugin, path, body): (&dyn AuthPlugin<StatelessSchema>, _, _) = match case["operation"]
        .as_str()
        .unwrap()
    {
        "phone" => (
            &phone,
            "/sign-in/phone-number",
            json!({"phoneNumber":"+12025550123","password":PASSWORD}),
        ),
        "change" => (
            &password,
            "/change-password",
            json!({"currentPassword":PASSWORD,"newPassword":PASSWORD}),
        ),
        "two-factor" => (
            &two_factor,
            "/two-factor/enable",
            json!({"password":match case["password"].as_str().unwrap() {
                "long" => "x".repeat(129), "empty" => String::new(), "provided" => PASSWORD.to_owned(), _ => return Err(AuthError::internal("Unknown captured password input")),
            }}),
        ),
        _ => return Err(AuthError::internal("Unknown captured password operation")),
    };
    let request = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        path,
        Some("session-token"),
        Some(body),
    );
    let result = plugin
        .on_request(
            &request,
            context.initialize_request_context().await?.as_ref(),
        )
        .await
        .and_then(|response| {
            response.ok_or_else(|| {
                AuthError::internal("The password fixture route must return a response")
            })
        })
        .and_then(|response| response.body.field_value());
    let stored = trace.storage()?;
    let mut native = trace.native.lock().unwrap();
    let projected = native.observe(&trace.projected.lock().unwrap())?;
    let outcome = runtime::outcome(result, &mut native, None)?;
    let actual = json!({"projected":projected, "outcome":outcome, "events":native.events,
        "functionIds":native.function_ids(), "errorFunctions":[], "stored":native.observe(&stored)?});
    let expected = runtime::query_expected(case)?;
    assert_replay(&actual, &expected, case["name"].as_str().unwrap());
    Ok(())
}

#[tokio::test]
async fn query_order_fixture_replays_all_runtime_paths() -> AuthResult<()> {
    let fixture: Json = serde_json::from_str(include_str!(
        "../../../../../../tests/fixtures/password-query-order-1.7.6.json"
    ))?;
    assert_eq!(fixture["version"], "1.7.6");
    assert_eq!(fixture["now"], NOW);
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 18);
    for case in cases {
        query_case(case).await?;
    }
    Ok(())
}

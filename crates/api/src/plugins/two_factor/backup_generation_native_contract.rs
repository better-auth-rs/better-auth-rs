#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report exact contract mismatches while Result propagates fixture errors."
)]
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Pinned generation contracts require immediate failure for invalid fixture shapes or callback observations."
)]

use super::*;
use crate::plugins::test_helpers::{
    native_session::{NativeSessionHook, dispatch_plugin},
    verification_consumer_native::{
        Harness, NOW, ReplayFailures, SECRET, assert_replay, consumer_user, date, object::Root,
    },
};
use better_auth_core::{
    AuthPlugin, AuthRoute, FieldFunction, FromFieldMap, HttpMethod,
    plugin_runtime::ModelFields,
    store::{StatelessSchema, schema::EntityRole},
    user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform},
    wire::SessionView,
};
use serde_json::{Value as Json, json};
use std::sync::atomic::{AtomicUsize, Ordering};

const CIPHERTEXT: &str = "generated-native-ciphertext";

fn factor(scenario: &Json) -> FieldMap {
    FieldMap::from([
        ("id".into(), "factor-row".into()),
        ("secret".into(), "native-factor-secret".into()),
        ("backupCodes".into(), "initial-backup-codes".into()),
        ("userId".into(), "owner".into()),
        ("verified".into(), (scenario["action"] != "enable").into()),
        ("failedVerificationCount".into(), 2.into()),
        ("lockedUntil".into(), FieldValue::Null),
    ])
}

fn generated(harness: &Arc<Harness>, json_calls: &Arc<AtomicUsize>) -> (FieldValue, Option<Root>) {
    match harness.scenario["generated"].as_str().unwrap() {
        "function" => (
            FieldFunction::contextual(|_, _| Ok(FieldValue::Undefined)).into(),
            None,
        ),
        "undefined" => (FieldValue::Undefined, None),
        "null" => (FieldValue::Null, None),
        _ => {
            let root = Root::new("object");
            root.data("marker", "native-generated-codes".into());
            root.data("ownUndefined", FieldValue::Undefined);
            let owner = root.owner();
            let harness = harness.clone();
            let calls = json_calls.clone();
            let callback: FieldValue = FieldFunction::contextual(move |receiver, arguments| {
                let original = owner.upgrade().unwrap();
                let same_receiver = receiver.strict_equals(original.get().unwrap());
                let call = calls.fetch_add(1, Ordering::SeqCst) + 1;
                harness.record(
                    "toJSON",
                    [
                        ("sameReceiver".into(), same_receiver.into()),
                        ("key".into(), harness.observe(&arguments[0])?),
                        ("call".into(), call.into()),
                    ],
                );
                assert!(same_receiver);
                assert_eq!(arguments, &[FieldValue::from("")]);
                if harness.scenario["fail"] == "toJSON" {
                    return harness.fail("throw:toJSON");
                }
                Ok(FieldMap::from([("kept".into(), true.into())]).into())
            })
            .into();
            root.getter("toJSON", false, move |_| Ok(callback.clone()));
            (root.value.clone(), Some(root))
        }
    }
}

struct Cipher(Arc<Harness>);

#[async_trait]
impl TwoFactorCipher for Cipher {
    async fn encrypt(&self, _: &str) -> AuthResult<String> {
        Err(AuthError::internal(
            "Generation requires the native cipher input",
        ))
    }

    async fn decrypt(&self, _: &str) -> AuthResult<String> {
        Err(AuthError::internal(
            "Generation must not decrypt backup codes",
        ))
    }

    async fn encrypt_native(&self, value: &FieldValue) -> AuthResult<FieldValue> {
        self.0
            .record("encrypt", [("value".into(), self.0.observe(value)?)]);
        if self.0.scenario["fail"] == "encrypt" {
            return self.0.fail("throw:encrypt");
        }
        Ok(CIPHERTEXT.into())
    }
}

struct OutputPolicy(Arc<Harness>);

#[async_trait]
impl AuthPlugin<StatelessSchema> for OutputPolicy {
    fn name(&self) -> &'static str {
        "backup-generation-output"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }

    fn schema(&self, fields: &mut ModelFields) -> AuthResult<()> {
        if self.0.scenario["fail"] != "output" {
            return Ok(());
        }
        let harness = self.0.clone();
        fields.register_model_fields(
            EntityRole::TwoFactor,
            UserConfig {
                additional_fields: Some(
                    [(
                        "backupCodes".into(),
                        UserFieldConfig {
                            transform: Some(FieldTransforms {
                                input: None,
                                output: Some(UserFieldTransform::new(move |value| {
                                    harness.record(
                                        "output",
                                        [("value".into(), harness.observe(&value)?)],
                                    );
                                    if value.strict_equals(&CIPHERTEXT.into()) {
                                        return harness.fail("throw:output");
                                    }
                                    Ok(value)
                                })),
                            }),
                            ..Default::default()
                        },
                    )]
                    .into_iter()
                    .collect(),
                ),
            },
        )
    }
}

fn enrollment(runtime: &Json) -> AuthResult<Json> {
    let encrypted = runtime["after"]["database"]["twoFactor"][0]["secret"]
        .as_str()
        .unwrap();
    let plaintext = better_auth_core::utils::symmetric::decrypt(SECRET, encrypted)?;
    let uri = url::Url::parse(runtime["outcome"]["result"]["totpURI"].as_str().unwrap())
        .map_err(|error| AuthError::internal(error.to_string()))?;
    let pairs = uri
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    let decoded = totp_rs::Secret::Encoded(pairs[0].1.clone())
        .to_bytes()
        .map_err(|error| AuthError::internal(error.to_string()))?;
    assert_eq!(decoded, plaintext.as_bytes());
    assert_eq!(plaintext.len(), 32);
    let encoded = totp_rs::Secret::Raw(plaintext.as_bytes().to_vec()).to_encoded();
    assert_eq!(
        runtime["outcome"]["result"]["totpURI"],
        format!(
            "otpauth://totp/Better%20Auth:owner%40verification-consumer-native.test?secret={encoded}&issuer=Better+Auth&digits=6&period=30"
        )
    );
    assert_eq!(uri.scheme(), "otpauth");
    assert_eq!(uri.host_str(), Some("totp"));
    assert_eq!(
        uri.path(),
        "/Better%20Auth:owner%40verification-consumer-native.test"
    );
    assert_eq!(
        pairs,
        vec![
            ("secret".into(), pairs[0].1.clone()),
            ("issuer".into(), "Better Auth".into()),
            ("digits".into(), "6".into()),
            ("period".into(), "30".into())
        ]
    );
    Ok(json!({"uriMatchesCiphertext":true,"secretLength":32,"digits":"6","period":"30"}))
}

async fn capture(scenario: &Json) -> AuthResult<Json> {
    let harness = Arc::new(
        Harness::new(scenario, "backup-generation-unused-challenge")?.with_model_rows(
            "twoFactor",
            EntityRole::TwoFactor,
            vec![factor(scenario)],
        ),
    );
    let json_calls = Arc::new(AtomicUsize::new(0));
    let (codes, _root) = generated(&harness, &json_calls);
    let codes_before = harness.observe(&codes)?;
    let observed = harness.clone();
    let returned_codes = codes.clone();
    let storage = if scenario["storage"] == "plain" {
        BackupCodeStorage::Plain
    } else {
        BackupCodeStorage::Custom(Arc::new(Cipher(harness.clone())))
    };
    let plugin = TwoFactorPlugin::with_config(TwoFactorConfig {
        allow_passwordless: true,
        backup_code_options: BackupCodeOptions {
            generate_native: Some(Arc::new(move || {
                observed.record("generate", []);
                if observed.scenario["fail"] == "generate" {
                    return observed.fail("throw:generate");
                }
                Ok(returned_codes.clone())
            })),
            storage,
            ..Default::default()
        },
        ..Default::default()
    });
    let policy = OutputPolicy(harness.clone());
    let (mut context, inner) = harness.context(&[&plugin, &policy]).await?;
    let routes = <TwoFactorPlugin as AuthPlugin<StatelessSchema>>::routes(&plugin);
    let hook = NativeSessionHook::install(&mut context, routes);
    let session = SessionView::from_field_values(FieldMap::from([
        ("id".into(), "generation-session".into()),
        ("token".into(), "generation-token".into()),
        ("userId".into(), "owner".into()),
        ("expiresAt".into(), date((NOW + 60_000) as f64)),
        ("createdAt".into(), date(NOW as f64)),
        ("updatedAt".into(), date(NOW as f64)),
    ]))?;
    let path = if scenario["action"] == "enable" {
        "/two-factor/enable"
    } else {
        "/two-factor/generate-backup-codes"
    };
    let request = hook.request(
        &context,
        &session,
        consumer_user().into(),
        HttpMethod::Post,
        path,
        json!({}),
    )?;
    let before = harness.state(&inner)?;
    harness.activate();
    let result = dispatch_plugin(&request, &context, &plugin)
        .await
        .and_then(|response| response.unwrap().body.field_value());
    let same_codes = match &result {
        Ok(value) => {
            let same = value.model_property("backupCodes")?.strict_equals(&codes);
            assert!(same);
            assert!(value.enumerable_fields()?.contains_key("backupCodes"));
            FieldValue::from(same)
        }
        Err(_) => FieldValue::Undefined,
    };
    let success = result.is_ok();
    let mut captured = harness.finish(before, harness.outcome(result)?, &inner)?;
    captured["codes"] = json!({"before":codes_before,"after":harness.observe(&codes)?});
    captured["returnedSameCodes"] = harness.observe(&same_codes)?;
    captured["jsonCalls"] = json_calls.load(Ordering::SeqCst).into();
    captured["enrollment"] = if success && scenario["action"] == "enable" {
        enrollment(&captured)?
    } else {
        harness.observe(&FieldValue::Undefined)?
    };
    Ok(captured)
}

#[tokio::test]
async fn backup_generation_matches_native_routes_and_failure_persistence() -> AuthResult<()> {
    let fixture: Json = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/two-factor-backup-generation-1.7.6.json"),
        )
        .unwrap(),
    )?;
    assert_eq!(fixture["version"], "1.7.6");
    assert_eq!(fixture["contract"], "two-factor-backup-generation");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 12);
    let mut failures = ReplayFailures::default();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let actual = capture(&case["scenario"]).await?;
        let mut expected = case["runtime"].clone();
        if name == "enable-native-object" {
            assert_eq!(enrollment(&expected)?, expected["enrollment"]);
            // Each execution generates a fresh TOTP secret and nonce. Validate their relationship before pairing the remaining fields.
            for path in [
                "/outcome/result/totpURI",
                "/after/database/twoFactor/0/secret",
            ] {
                *expected.pointer_mut(path).unwrap() = actual.pointer(path).unwrap().clone();
                eprintln!("{name}: {path} is an independently validated random value");
            }
        }
        failures.record(name, || assert_replay(&actual, &expected, name));
    }
    failures.finish();
    Ok(())
}

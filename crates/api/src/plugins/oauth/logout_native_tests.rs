#![expect(
    clippy::panic_in_result_fn,
    reason = "The logout contract asserts complete native observations and persistent session deletion."
)]

use super::*;
use better_auth_core::{
    AuthConfig, FieldDate, FieldMap, FieldObject, HttpMethod, NativeRequest,
    observability::{LogArgument, LogLevel, LogSink},
    store::{EphemeralStore, schema::EntityRole},
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform, UserFieldType},
    utils::cookie_utils::sign_cookie_value,
};
use serde_json::{Value as Json, json};
use std::sync::{Arc, Mutex};

#[path = "logout_native_tests/values.rs"]
mod values;

use crate::plugins::test_helpers::native_observation::{NativeObservation, assert_replay};

type Observer = Arc<Mutex<NativeObservation>>;
const NOW: f64 = 2_000_000_000_000.0;
const ORIGIN: &str = "http://oauth-logout-native.test";
const SECRET: &str = "oauth-logout-native-contract-secret-at-least-32-characters";
const TOKEN: &str = "logout-native-session";

fn lock<T>(value: &Mutex<T>) -> AuthResult<std::sync::MutexGuard<'_, T>> {
    value
        .lock()
        .map_err(|_| AuthError::internal("Logout contract observation lock poisoned"))
}

struct Sink {
    observer: Observer,
    original: FieldValue,
}

impl LogSink for Sink {
    #[expect(
        clippy::expect_used,
        reason = "A malformed native log must fail the contract at its observation boundary."
    )]
    fn log(
        &self,
        level: LogLevel,
        message: LogArgument<'_>,
        arguments: &[LogArgument<'_>],
    ) -> better_auth_core::AuthResult<()> {
        self.capture(level, message, arguments)
            .expect("The native logout log must remain observable");
        Ok(())
    }
}

impl Sink {
    fn capture(
        &self,
        level: LogLevel,
        message: LogArgument<'_>,
        arguments: &[LogArgument<'_>],
    ) -> AuthResult<()> {
        let arguments = arguments
            .iter()
            .map(|argument| match argument {
                LogArgument::Native(value) => Ok((*value).clone()),
                LogArgument::Error(error) => error
                    .downcast_ref::<AuthError>()
                    .and_then(AuthError::raw_value)
                    .cloned()
                    .ok_or_else(|| AuthError::internal("Logout log replaced the native error")),
                _ => Err(AuthError::internal(
                    "Logout log must retain the native error argument",
                )),
            })
            .collect::<AuthResult<Vec<_>>>()?;
        let same = arguments
            .first()
            .is_some_and(|error| error.strict_equals(&self.original));
        let mut observer = lock(&self.observer)?;
        let arguments = observer.observe(&arguments.into())?;
        observer.record(
            "logger",
            [
                ("level".into(), level.as_str().into()),
                ("message".into(), message.to_string().into()),
                ("arguments".into(), arguments),
                ("sameOriginal".into(), same.into()),
            ],
        );
        Ok(())
    }
}

fn date(milliseconds: f64) -> FieldValue {
    FieldDate::from_milliseconds(milliseconds).into()
}

fn tables() -> Vec<(String, Vec<FieldMap>)> {
    vec![
        (
            "user".into(),
            vec![FieldMap::from([
                ("id".into(), "owner".into()),
                ("name".into(), "Logout Owner".into()),
                ("email".into(), "owner@oauth-logout-native.test".into()),
                ("emailVerified".into(), true.into()),
                ("image".into(), FieldValue::Null),
                ("createdAt".into(), date(NOW)),
                ("updatedAt".into(), date(NOW)),
            ])],
        ),
        (
            "session".into(),
            vec![FieldMap::from([
                ("id".into(), "session".into()),
                ("token".into(), TOKEN.into()),
                ("userId".into(), "owner".into()),
                ("expiresAt".into(), date(4_102_444_800_000.0)),
                ("createdAt".into(), date(NOW)),
                ("updatedAt".into(), date(NOW)),
                ("ipAddress".into(), "".into()),
                ("userAgent".into(), "logout-native".into()),
            ])],
        ),
        (
            "account".into(),
            ["first", "second", "excluded"]
                .into_iter()
                .zip([0.0, 1.0, 2.0])
                .map(|(label, index)| {
                    FieldMap::from([
                        ("id".into(), format!("account-{label}").into()),
                        ("accountId".into(), format!("subject-{label}").into()),
                        (
                            "providerId".into(),
                            if label == "excluded" {
                                "excluded"
                            } else {
                                "alpha"
                            }
                            .into(),
                        ),
                        ("userId".into(), "owner".into()),
                        ("idToken".into(), format!("id-token-{label}").into()),
                        ("createdAt".into(), date(NOW)),
                        ("updatedAt".into(), date(NOW + index)),
                        (
                            "retainedExtra".into(),
                            FieldMap::from([
                                ("label".into(), label.into()),
                                ("ownUndefined".into(), FieldValue::Undefined),
                            ])
                            .into(),
                        ),
                    ])
                })
                .collect(),
        ),
        ("verification".into(), Vec::new()),
    ]
}

fn storage(store: &EphemeralStore, observer: &Observer) -> AuthResult<Json> {
    let value = [
        ("user", EntityRole::User),
        ("session", EntityRole::Session),
        ("account", EntityRole::Account),
        ("verification", EntityRole::Verification),
    ]
    .into_iter()
    .map(|(name, role)| {
        Ok((
            name.into(),
            store
                .storage_rows(role)?
                .into_iter()
                .map(FieldValue::from)
                .collect::<Vec<_>>()
                .into(),
        ))
    })
    .collect::<AuthResult<FieldMap>>()?;
    lock(observer)?.observe(&value.into())
}

async fn run_case(name: &str) -> AuthResult<Json> {
    let observer = Observer::default();
    let original: FieldValue = FieldMap::from([
        ("failure".into(), name.into()),
        ("ownUndefined".into(), FieldValue::Undefined),
    ])
    .into();
    let projected = values::projected(name, &observer, &original)?;
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.logger = better_auth_core::LoggerConfig {
        level: Some(LogLevel::Error),
        log: Some(Arc::new(Sink {
            observer: observer.clone(),
            original,
        })),
        ..Default::default()
    }
    .into();
    let observed = observer.clone();
    let _ = config.account.additional_fields.insert(
        "updatedAt".into(),
        UserFieldConfig {
            field_type: UserFieldType::Date,
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(move |input| {
                    let timestamp = input
                        .as_date()
                        .ok_or_else(|| AuthError::internal("Stored updatedAt must be a Date"))?
                        .milliseconds();
                    let (index, result) = [NOW, NOW + 1.0, NOW + 2.0]
                        .into_iter()
                        .zip(&projected)
                        .enumerate()
                        .find_map(|(index, (expected, value))| {
                            (expected == timestamp).then_some((index, value))
                        })
                        .ok_or_else(|| AuthError::internal("Unknown Account updatedAt marker"))?;
                    let mut observer = lock(&observed)?;
                    let input = observer.observe(&input)?;
                    let output = observer.observe(result)?;
                    observer.record(
                        "output:updatedAt",
                        [
                            ("index".into(), index.into()),
                            ("input".into(), input),
                            ("result".into(), output),
                        ],
                    );
                    Ok(result.as_ref().clone())
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let config = Arc::new(config);
    let store = Arc::new(EphemeralStore::from_storage(config.clone(), tables())?);
    let oauth = super::super::OAuthPlugin::new().add_generic_provider(
        "alpha",
        super::super::GenericOAuthConfig {
            client_id: "logout-client".into(),
            authorization_url: Some("https://idp.example.test/authorize".into()),
            token_url: Some("https://idp.example.test/token".into()),
            end_session_endpoint: Some("https://idp.example.test/logout".into()),
            ..Default::default()
        },
    );
    let context =
        crate::plugins::test_helpers::initialize_test_context(config, store.clone(), &[&oauth])
            .await?;
    let before = storage(&store, &observer)?;
    let mut request = AuthRequest::new(HttpMethod::Post, "/sign-out");
    request.body = Some(serde_json::to_vec(&json!({"disableRedirect":true}))?);
    let _ = request.headers.insert(
        "cookie".into(),
        format!(
            "{}={}",
            context
                .config
                .auth_cookie("session_token", Default::default())
                .name,
            sign_cookie_value(TOKEN, SECRET)
        ),
    );
    let _ = request.headers.insert("origin".into(), ORIGIN.into());
    let _ = request
        .headers
        .insert("content-type".into(), "application/json".into());
    let request = &request;
    let response = context
        .with_native_context(
            NativeRequest {
                request: Some(request),
                headers: Some(&request.headers),
            },
            |resolved| async move {
                let mut response = handle_sign_out(request, &resolved).await?;
                resolved
                    .session_manager()
                    .finish_response(request, &mut response)?;
                Ok(response)
            },
        )
        .await?;
    let response = json!({
        "status":response.status,
        "body":serde_json::from_slice::<Json>(&response.body.bytes()?)?,
        "location":response.headers.get("location"),
        "cookies":response.headers.get_all("set-cookie").collect::<Vec<_>>(),
    });
    assert!(store.storage_rows(EntityRole::Session)?.is_empty());
    let after = storage(&store, &observer)?;
    let observer = lock(&observer)?;
    Ok(
        json!({"before":before, "response":response, "events":observer.events,
        "after":after, "functionIds":observer.function_ids()}),
    )
}

#[tokio::test]
async fn native_provider_logout_matches_complete_upstream_runtime() -> AuthResult<()> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/oauth-logout-native-1.7.6.json");
    let fixture: Json = serde_json::from_str(&std::fs::read_to_string(path).map_err(|error| {
        AuthError::internal(format!("Cannot read OAuth logout observations: {error}"))
    })?)?;
    assert_eq!(fixture.get("version"), Some(&json!("1.7.6")));
    let cases = fixture
        .get("cases")
        .and_then(Json::as_array)
        .ok_or_else(|| AuthError::internal("OAuth logout source cases are absent"))?;
    let mut names = Vec::new();
    for case in cases {
        let name = case
            .get("name")
            .and_then(Json::as_str)
            .ok_or_else(|| AuthError::internal("OAuth logout source name is absent"))?;
        let expected = case
            .get("runtime")
            .ok_or_else(|| AuthError::internal("OAuth logout runtime observation is absent"))?;
        assert_replay(&run_case(name).await?, expected, name);
        names.push(name);
    }
    assert_eq!(
        names,
        [
            "builtin-dates",
            "date-own-get-time",
            "object-get-time",
            "deferred-number-conversion",
            "get-time-getter-error",
            "get-time-method-error",
            "later-method-precedes-conversion-error",
            "value-of-error",
            "nan-stable-order",
            "infinity-stable-order"
        ]
    );
    Ok(())
}

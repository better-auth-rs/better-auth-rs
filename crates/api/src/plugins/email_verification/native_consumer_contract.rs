//! Replay the published token helper and native send-verification endpoint without flattening descriptor graphs.

#![expect(
    clippy::panic_in_result_fn,
    clippy::indexing_slicing,
    reason = "Pinned source captures define complete outcomes, native graphs, JWT bytes, and storage snapshots."
)]

use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::{
    AuthPlugin, FieldFunction, FieldMap, FieldValue, HttpMethod, Utf16String,
    store::StatelessSchema,
};
use serde_json::{Value as Json, json};
use std::sync::Mutex;

use crate::plugins::test_helpers::{
    self,
    native_email_consumers::{self as shared, Trace, lock},
    native_session,
    verification_consumer_native::object::Root,
};

fn json_result(trace: &Arc<Trace>, failure: FieldValue, rejects: bool) -> Root {
    let root = Root::new("object");
    root.data("marker", "original-result".into());
    root.data("calls", 0.into());
    root.data(
        "toJSON",
        FieldFunction::contextual({
            let trace = Arc::downgrade(trace);
            let owner = root.owner();
            move |receiver, arguments| {
                let owner = owner
                    .upgrade()
                    .and_then(|owner| owner.get().cloned())
                    .ok_or_else(|| AuthError::internal("Token result owner was released"))?;
                trace
                    .upgrade()
                    .ok_or_else(|| AuthError::internal("Token observer was released"))?
                    .call("result.toJSON:call", receiver, &owner, arguments)?;
                let calls: usize = owner.model_property("calls")?.decode()?;
                owner.set_model_property("calls", (calls + 1).into())?;
                if rejects {
                    return Err(AuthError::from_thrown(failure.clone()));
                }
                Ok(FieldMap::from([
                    ("transformed".into(), 17.into()),
                    ("nullable".into(), FieldValue::Null),
                    ("optional".into(), FieldValue::Undefined),
                ])
                .into())
            }
        })
        .into(),
    );
    root
}

fn inspect_token(token: &str) -> AuthResult<Json> {
    let payload = crate::plugins::jwt::verify_hs256_raw(token, shared::SECRET)?;
    let payload = String::from_utf8(payload)
        .map_err(|error| AuthError::internal(format!("Token payload is not UTF-8: {error}")))?;
    let header = token
        .split('.')
        .next()
        .ok_or_else(|| AuthError::internal("Token header is missing"))?;
    let header: Json = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(header)
            .map_err(|error| AuthError::internal(format!("Token header base64: {error}")))?,
    )?;
    assert_eq!(header, json!({"alg":"HS256"}));
    Ok(json!({"token":token,"header":header,"payload":payload,"signatureVerified":true}))
}

fn token_case(case: &Json, path: &str) -> AuthResult<Vec<String>> {
    let trace = Trace::new(case, path);
    let mode = case["scenario"]["mode"]
        .as_str()
        .ok_or_else(|| AuthError::internal("Token scenario mode is missing"))?;
    let failure = shared::throwing_value("token-json");
    let root = match mode {
        "undefined" | "null" => None,
        "utf16" | "native-json" | "json-error" => {
            Some(json_result(&trace, failure.clone(), mode == "json-error"))
        }
        _ => {
            return Err(AuthError::internal(format!(
                "Unknown token scenario: {mode}"
            )));
        }
    };
    let result = match &root {
        Some(root) => root.value.clone(),
        None if mode == "undefined" => FieldValue::Undefined,
        None => FieldValue::Null,
    };
    let lower = (mode != "utf16")
        .then(|| shared::native_lower(&trace, "email", result.clone(), failure.clone(), None));
    let email = lower.as_ref().map_or_else(
        || {
            let mut units = "MIXED".encode_utf16().collect::<Vec<_>>();
            units.push(0xd800);
            units.extend("@EXAMPLE.TEST".encode_utf16());
            FieldValue::from(Utf16String::from_units(units))
        },
        |root| root.value.clone(),
    );
    let values = FieldMap::from([
        ("email".into(), email.clone()),
        ("result".into(), result),
        ("failure".into(), failure.clone()),
    ])
    .into();
    trace.snapshot("input", &values)?;
    let now = shared::clock()?;
    let token = trace.outcome(
        token::create_native_token_with_clock(
            shared::SECRET,
            &email,
            None,
            Duration::hours(1),
            None,
            || now,
        )
        .map(FieldValue::from),
        &failure,
    )?;
    trace.snapshot("after", &values)?;
    if let Some(token) = token.as_str() {
        assert_eq!(
            inspect_token(token)?,
            case["jwt"],
            "{path}: exact signed JWT"
        );
    } else {
        assert!(token.is_undefined(), "{path}: token result");
        assert!(
            case.get("jwt").is_none(),
            "{path}: failed signing must not return a JWT"
        );
    }
    trace.finish()
}

async fn verification_case(case: &Json, path: &str) -> AuthResult<Vec<String>> {
    let trace = Trace::new(case, path);
    let mode = case["scenario"]["mode"]
        .as_str()
        .ok_or_else(|| AuthError::internal("Verification scenario mode is missing"))?;
    let failure = shared::throwing_value("email-second-getter");
    let first = shared::native_lower(
        &trace,
        "first",
        shared::OWNER_EMAIL.into(),
        failure.clone(),
        None,
    );
    let second = shared::native_lower(
        &trace,
        "second",
        "SECOND@native-email-consumers.test".into(),
        failure.clone(),
        None,
    );
    let user = shared::native_user(
        &trace,
        {
            let first = first.value.clone();
            let second = second.value.clone();
            let failure = failure.clone();
            let rejects = mode == "second-getter-error";
            move |count| {
                if count == 2 && rejects {
                    return Err(AuthError::from_thrown(failure.clone()));
                }
                Ok(if count == 1 {
                    first.clone()
                } else {
                    second.clone()
                })
            }
        },
        if mode == "verified-short-circuit" {
            Vec::<FieldValue>::new().into()
        } else {
            false.into()
        },
    );
    let mut values = FieldMap::from([
        ("user".into(), user.root.value.clone()),
        ("first".into(), first.value.clone()),
        ("second".into(), second.value.clone()),
        ("failure".into(), failure.clone()),
    ]);
    trace.snapshot("input", &values.clone().into())?;
    let messages = Arc::new(Mutex::new(Vec::<FieldValue>::new()));
    let callback = EmailVerificationCallbacks::<StatelessSchema>::send({
        let trace = trace.clone();
        let expected = user.root.value.clone();
        let messages = messages.clone();
        move |message, endpoint| {
            let data: FieldValue = FieldMap::from([
                ("user".into(), message.user.clone()),
                ("url".into(), message.url.clone().into()),
                ("token".into(), message.token.clone().into()),
            ])
            .into();
            trace.record(
                "sender:call",
                FieldMap::from([
                    (
                        "sameUser".into(),
                        message.user.strict_equals(&expected).into(),
                    ),
                    ("hasRequest".into(), endpoint.request.is_some().into()),
                    ("data".into(), data.clone()),
                ]),
            )?;
            lock(&messages)?.push(data);
            Ok(Some(better_auth_core::background::BackgroundFuture::new(
                async { Ok(()) },
            )))
        }
    });
    let plugin = EmailVerificationPlugin::new().callbacks(callback);
    let config = Arc::new(shared::config());
    let raw = shared::memory_from_capture(case, config.clone())?;
    let now = shared::clock()?;
    let mut context = test_helpers::initialize_test_context(config, raw.clone(), &[&plugin])
        .await?
        .with_clock(move || now);
    let request = shared::native_request(
        &trace,
        &mut context,
        plugin.routes(),
        user.root.value.clone(),
        HttpMethod::Post,
        "/send-verification-email",
        json!({"email":shared::OWNER_EMAIL,"callbackURL":"/verified"}),
    )?;
    trace.snapshot("before", &shared::memory_snapshot(&raw)?)?;
    let response = trace.endpoint_outcome(
        native_session::dispatch_plugin(&request, &context, &plugin).await,
        &failure,
    )?;
    trace.snapshot("after", &shared::memory_snapshot(&raw)?)?;
    assert_eq!(case["reads"], user.reads(), "{path}: complete email reads");
    let messages = lock(&messages)?.clone();
    let jwt = messages
        .first()
        .map(|message| {
            let token = message.model_property("token")?;
            inspect_token(
                token
                    .as_str()
                    .ok_or_else(|| AuthError::internal("Delivered token is not a string"))?,
            )
        })
        .transpose()?;
    let _ = values.insert("messages".into(), messages.into());
    let _ = values.insert("response".into(), response);
    trace.snapshot("afterValues", &values.into())?;
    match jwt {
        Some(jwt) => assert_eq!(jwt, case["jwt"], "{path}: complete delivered JWT"),
        None => assert!(case.get("jwt").is_none(), "{path}: no delivered JWT"),
    }
    trace.finish()
}

async fn replay(fixture: &Json) -> AuthResult<Vec<String>> {
    assert_eq!(fixture["version"], "1.7.6");
    assert_eq!(fixture["contract"], "native-email-consumers");
    let cases = fixture["cases"]
        .as_array()
        .ok_or_else(|| AuthError::internal("Native email capture cases are missing"))?;
    let mut covered = Vec::new();
    let mut unpaired = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        let path = format!("/cases/{index}");
        let paths = match case["scenario"]["group"].as_str() {
            Some("token") => token_case(case, &path)?,
            Some("verification") => verification_case(case, &path).await?,
            Some("invitation" | "selector") => continue,
            _ => return Err(AuthError::internal("Unknown native email scenario group")),
        };
        covered.push(case["name"].clone());
        unpaired.extend(paths);
    }
    assert_eq!(
        covered,
        [
            "token/utf16",
            "token/native-json",
            "token/undefined",
            "token/null",
            "token/json-error",
            "verification/reread",
            "verification/second-getter-error",
            "verification/verified-short-circuit"
        ]
        .map(Json::from)
    );
    Ok(unpaired)
}

#[tokio::test]
async fn native_email_consumers_token_send_frozen_contract() -> AuthResult<()> {
    let fixture = shared::fixture()?;
    let mut unpaired = replay(&fixture).await?;
    unpaired.sort();
    let coverage: Json = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/native-email-token-send-1.7.6.coverage.json"
    )))?;
    assert_eq!(json!(unpaired), coverage["unpairedPaths"]);
    Ok(())
}

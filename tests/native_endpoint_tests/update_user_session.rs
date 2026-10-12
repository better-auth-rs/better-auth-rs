use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth::config::{FieldTransforms, UserFieldConfig, UserFieldTransform, UserFieldType};
use better_auth::server_api::EndpointInput;
use better_auth_core::{
    ApiErrorClass, AuthInitContext, AuthPlugin, AuthRoute, CookieCacheConfig, FieldDate, FieldMap,
    FieldValue, FromFieldMap, HttpMethod, SessionView, UserView,
    config::CookieCacheVersion,
    session::NativeSessionData,
    store::{
        EphemeralStore, SecondaryStorage,
        database_hooks::{DatabaseHookContext, DatabaseHookUpdate, DatabaseHooks},
        schema::EntityRole,
    },
};
use std::collections::{BTreeMap, HashMap};

#[path = "update_user_session/getter.rs"]
mod getter;
#[path = "update_user_session/phone.rs"]
mod phone;
#[path = "update_user_session/support.rs"]
mod support;
#[path = "update_user_session/username.rs"]
mod username;
use support::*;

#[tokio::test]
async fn update_user_consumes_injected_native_sessions_through_storage_and_cookies()
-> AuthResult<()> {
    for &case in CASES {
        for signed_cookie in [false, true] {
            check(case, signed_cookie).await?;
        }
    }
    Ok(())
}

#[expect(
    clippy::indexing_slicing,
    reason = "The contract checks recorder and cookie lengths before selecting their elements."
)]
async fn check(case: &'static str, signed_cookie: bool) -> AuthResult<()> {
    let shared: FieldValue = FieldMap::from([("value".into(), FieldValue::Undefined)]).into();
    let state = Arc::new(Mutex::new(Observed::default()));
    let thrown = FieldValue::from(FieldMap::from([("failure".into(), case.into())]));
    let data = NativeSessionData::new(
        SessionView::from_field_values(session("injected-token", "snapshot-user"))?,
        getter::injected_user(case, &shared, &state, &thrown)?,
    );
    let hooks = SessionHooks {
        case,
        data: data.clone(),
        thrown,
        state: state.clone(),
    };
    let mut config = AuthConfig::new(SECRET);
    config.base_url = ORIGIN.into();
    config.logger = better_auth_core::LoggerConfig {
        disabled: Some(true),
        ..Default::default()
    }
    .into();
    config.session.store_session_in_database = Some(true);
    let _ = config
        .user
        .fields_mut()
        .insert("marker".into(), UserFieldConfig::default());
    let _ = config.user.fields_mut().insert(
        "private".into(),
        UserFieldConfig {
            field_type: UserFieldType::Boolean,
            returned: Some(false),
            ..Default::default()
        },
    );
    let _ = config.user.fields_mut().insert(
        "updatedAt".into(),
        UserFieldConfig {
            field_type: UserFieldType::Date,
            on_update: Some(better_auth_core::user_fields::UserFieldFactory::new(|| {
                Ok(date())
            })),
            ..Default::default()
        },
    );
    if case == "output-transform" {
        let hooks = hooks.clone();
        let _ = config.user.fields_mut().insert(
            "name".into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new(move |value| {
                        hooks.event("output")?;
                        Ok(vec![value].into())
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
    }
    let version_hooks = hooks.clone();
    config.session.cookie_cache = Some(CookieCacheConfig {
        enabled: Some(true),
        version: CookieCacheVersion::dynamic(move |data| {
            let hooks = version_hooks.clone();
            async move {
                hooks.event("version")?;
                lock(&hooks.state)?.versions.push(data);
                Ok("native-v1".into())
            }
        }),
        ..Default::default()
    });
    let raw = EphemeralStore::from_storage(
        Arc::new(config.clone()),
        [
            ("user".into(), vec![user("7"), user("cookie-owner")]),
            (
                "session".into(),
                vec![session("stored-token", "cookie-owner")],
            ),
            ("account".into(), Vec::new()),
            ("verification".into(), Vec::new()),
        ],
    )?;
    let initial_cache = BTreeMap::from([
        ("active-sessions-7".into(), json!([{"token":"cached-token","expiresAt":EXPIRES}]).to_string()),
        ("cached-token".into(), json!({"session": FieldValue::from(session("cached-token", "7")).json()?, "user": FieldValue::from(user("7")).json()?}).to_string()),
    ]);
    let cache = Arc::new(Cache {
        values: Mutex::new(initial_cache.clone()),
        state: state.clone(),
    });
    let auth = BetterAuth::stateless(config)
        .store(raw.clone())
        .secondary_storage(cache.clone())
        .hooks(EndpointHooks {
            before: Some(Arc::new(hooks.clone())),
            after: Some(Arc::new(hooks.clone())),
        })
        .plugin(hooks.clone())
        .build()
        .await?;
    lock(&state)?.events.clear();
    let mut headers = HashMap::new();
    if signed_cookie {
        let _ = headers.insert(
            "cookie".into(),
            format!(
                "better-auth.session_token={}",
                better_auth_core::utils::cookie_utils::sign_cookie_value("stored-token", SECRET)
            ),
        );
    }
    let started = chrono::Utc::now().timestamp_millis();
    let result = auth
        .call_endpoint(
            HttpMethod::Post,
            "/update-user",
            EndpointInput {
                headers: Some(headers),
                body: Some(body(case)),
                ..Default::default()
            },
        )
        .await;
    let ended = chrono::Utc::now().timestamp_millis();
    let wrote = matches_row(case) && !matches!(case, "cancel" | "getter-cancel" | "before-error");
    let mut stored = user("7");
    if wrote {
        stored = expected_fields(case, stored);
    }
    assert_eq!(
        raw.storage_rows(EntityRole::User)?,
        [stored.clone(), user("cookie-owner")],
        "{case}/{signed_cookie}"
    );
    assert_eq!(
        raw.storage_rows(EntityRole::Session)?,
        [session("stored-token", "cookie-owner")]
    );
    assert!(raw.storage_rows(EntityRole::Account)?.is_empty());
    assert!(raw.storage_rows(EntityRole::Verification)?.is_empty());
    let mut updated = stored.clone();
    if case == "output-transform" {
        let _ = updated.insert("name".into(), vec![FieldValue::from(17)].into());
    }
    let refreshed = wrote && case != "after-error";
    let mut expected_cache = initial_cache;
    if refreshed {
        let _ = expected_cache.insert("cached-token".into(), json!({"session":FieldValue::from(session("cached-token", "7")).json()?,"user":FieldValue::from(updated.clone()).json()?}).to_string());
    }
    let actual_cache = lock(&cache.values)?.clone();
    assert_eq!(
        actual_cache.keys().collect::<Vec<_>>(),
        expected_cache.keys().collect::<Vec<_>>()
    );
    for (key, value) in expected_cache {
        assert_eq!(
            serde_json::from_str::<Value>(&actual_cache[&key])?,
            serde_json::from_str::<Value>(&value)?,
            "{case}/{key}"
        );
    }
    let observed = lock(&state)?.clone();
    let mut events = vec!["endpoint.before".to_owned()];
    if case.starts_with("getter-") && !matches!(case, "getter-no-fields" | "getter-email") {
        events.push("user.id".into());
    }
    if !matches!(
        case,
        "null-user"
            | "undefined-user"
            | "null-no-fields"
            | "undefined-email"
            | "getter-error"
            | "getter-no-fields"
            | "getter-email"
    ) {
        events.push("db.before".into());
        let input = body(case);
        let mut expected_input = FieldMap::from([
            (
                "name".into(),
                input
                    .get("name")
                    .cloned()
                    .map(FieldValue::from_json)
                    .transpose()?
                    .unwrap_or_default(),
            ),
            (
                "image".into(),
                input
                    .get("image")
                    .cloned()
                    .map(FieldValue::from_json)
                    .transpose()?
                    .unwrap_or_default(),
            ),
        ]);
        if let Some(marker) = input.get("marker") {
            let _ = expected_input.insert("marker".into(), FieldValue::from_json(marker.clone())?);
        }
        assert_eq!(observed.inputs.len(), 1);
        ordered(&observed.inputs[0], &expected_input);
        if !matches!(case, "cancel" | "getter-cancel" | "before-error") {
            if case == "output-transform" {
                events.push("output".into());
            }
            events.push("db.after".into());
            assert_eq!(
                observed.updates,
                [matches_row(case).then_some(updated.clone())]
            );
        } else {
            assert!(observed.updates.is_empty());
        }
    } else {
        assert!(observed.inputs.is_empty());
        assert!(observed.updates.is_empty());
    }
    if refreshed {
        events.extend([
            "cache.get:active-sessions-7".into(),
            "cache.get:cached-token".into(),
            "cache.set:cached-token".into(),
        ]);
    }
    if matches!(case, "getter-cancel" | "getter-fallback-error") {
        events.push("user.id".into());
    }
    if case == "getter-fallback-error" {
        events.push("user.unread".into());
    }
    if !fails(case) {
        events.push("version".into());
    }
    if !fails(case)
        || matches!(
            case,
            "null-no-fields" | "undefined-email" | "getter-no-fields" | "getter-email"
        )
    {
        events.push("endpoint.after".into());
    }
    assert_eq!(observed.events, events, "{case}/{signed_cookie}");
    if fails(case) {
        let error = result
            .err()
            .ok_or_else(|| AuthError::internal("Expected rejected native update"))?;
        assert!(observed.versions.is_empty());
        if matches!(
            case,
            "null-no-fields" | "undefined-email" | "getter-no-fields" | "getter-email"
        ) {
            assert!(error.is_api_error_instance(ApiErrorClass::BetterAuth));
            assert_eq!(error.status_value()?, FieldValue::from("BAD_REQUEST"));
            let expected = if matches!(case, "null-no-fields" | "getter-no-fields") {
                json!({"message":"No fields to update"})
            } else {
                json!({"message":"Email can not be updated","code":"EMAIL_CAN_NOT_BE_UPDATED"})
            };
            assert_eq!(error.body_value()?.json()?, Some(expected));
            assert_eq!(observed.issued.len(), 1);
            assert!(observed.issued[0].is_none());
        } else {
            assert!(observed.issued.is_empty());
            assert!(!error.is_api_error()?);
            if matches!(
                case,
                "before-error" | "after-error" | "getter-error" | "getter-fallback-error"
            ) {
                let raw = error.raw_value().ok_or_else(|| {
                    AuthError::internal(format!(
                        "Expected native thrown value for {case}/{signed_cookie}"
                    ))
                })?;
                assert!(raw.strict_equals(&hooks.thrown));
            } else {
                let receiver = match case {
                    "null-user" => "null",
                    "undefined-user" => "undefined",
                    _ => {
                        return Err(AuthError::internal(format!(
                            "Unexpected runtime error case {case}/{signed_cookie}"
                        )));
                    }
                };
                assert!(
                    matches!(&error, AuthError::TypeError(message)
                        if message == &format!("Cannot read properties of {receiver} (reading 'id')")),
                    "{case}/{signed_cookie}: {error:?}"
                );
            }
        }
        return Ok(());
    }
    let response = result?;
    assert_eq!(response.body.json()?, Some(json!({"status":true})));
    let expected = if refreshed {
        updated
    } else {
        expected_fields(case, snapshot_user(case, &shared).enumerable_fields()?)
    };
    assert_eq!(observed.versions.len(), 1);
    assert_eq!(observed.issued.len(), 1);
    let issued = observed.issued[0]
        .as_ref()
        .ok_or_else(|| AuthError::internal("Expected issued native session"))?;
    assert!(
        observed.versions[0]
            .user_value()?
            .strict_equals(&issued.user_value()?)
    );
    for snapshot in [&observed.versions[0], issued] {
        ordered(&snapshot.user_value()?.enumerable_fields()?, &expected);
        assert_eq!(
            snapshot.session_value()?.enumerable_fields()?,
            session("injected-token", "snapshot-user")
        );
        if !refreshed && data.user_value()?.is_object() {
            assert!(
                snapshot
                    .user_value()?
                    .model_property("shared")?
                    .strict_equals(&shared)
            );
            assert!(
                snapshot
                    .user_value()?
                    .model_property("alias")?
                    .strict_equals(&shared)
            );
        }
        if case == "array-user" {
            assert!(
                snapshot
                    .user_value()?
                    .model_property("0")?
                    .strict_equals(&shared)
            );
            assert!(
                snapshot
                    .user_value()?
                    .model_property("1")?
                    .strict_equals(&shared)
            );
        }
    }
    let cookies = response
        .headers
        .get_all("set-cookie")
        .map(|value| value.split(';').next().unwrap_or_default())
        .collect::<Vec<_>>();
    assert_eq!(cookies.len(), 2);
    assert_eq!(
        cookies[0],
        format!(
            "better-auth.session_token={}",
            better_auth_core::utils::cookie_utils::sign_cookie_value("injected-token", SECRET)
        )
    );
    let encoded = cookies[1]
        .strip_prefix("better-auth.session_data=")
        .ok_or_else(|| AuthError::internal("Expected cookie cache"))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|error| AuthError::internal(format!("Invalid cookie cache: {error}")))?;
    let envelope: Value = serde_json::from_slice(&bytes)?;
    let mut public = expected;
    let _ = public.shift_remove("private");
    assert_eq!(
        envelope["session"]["user"],
        FieldValue::from(public.clone())
            .json()?
            .unwrap_or(Value::Null)
    );
    assert_eq!(
        envelope["session"]["session"],
        FieldValue::from(session("injected-token", "snapshot-user"))
            .json()?
            .unwrap_or(Value::Null)
    );
    assert_eq!(envelope["session"]["version"], "native-v1");
    let updated_at = envelope["session"]["updatedAt"]
        .as_i64()
        .ok_or_else(|| AuthError::internal("Expected cookie timestamp"))?;
    assert!((started..=ended).contains(&updated_at));
    assert!(
        envelope["expiresAt"]
            .as_i64()
            .is_some_and(|value| value > updated_at)
    );
    assert!(
        envelope["signature"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
    assert_eq!(
        envelope,
        json!({
            "session": {
                "user": FieldValue::from(public).json()?.unwrap_or(Value::Null),
                "session": FieldValue::from(session("injected-token", "snapshot-user")).json()?.unwrap_or(Value::Null),
                "version": "native-v1", "updatedAt": updated_at,
            },
            "expiresAt": envelope["expiresAt"], "signature": envelope["signature"],
        })
    );
    Ok(())
}

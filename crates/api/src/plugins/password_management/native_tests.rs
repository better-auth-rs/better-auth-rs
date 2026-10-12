#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "Native endpoint regressions require valid fixture setup and fail immediately on missing observations."
)]

use super::*;
use crate::plugins::{
    email_password::EmailPasswordPlugin,
    have_i_been_pwned::{HaveIBeenPwnedConfig, HaveIBeenPwnedPlugin},
    phone_number::PhoneNumberPlugin,
    test_helpers,
    two_factor::TwoFactorPlugin,
    user_management::UserManagementPlugin,
    username::{UsernameConfig, UsernamePlugin},
};
use better_auth_core::{
    AuthRecordFields, AuthSchema, CreateAccount, CreateUser, FieldFunction, FieldMap, FieldValue,
    store::{AuthStore, EphemeralStore, StatelessSchema},
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform},
};
use serde_json::json;
use std::{collections::VecDeque, sync::Mutex};

const PASSWORD: &str = "CorrectHorseBattery1!";

mod authoritative_session;
mod change_success;
mod fixture_replay;
mod session_boundary;

#[derive(Default)]
struct State {
    events: Mutex<Vec<&'static str>>,
    projected: Mutex<FieldValue>,
    result: Mutex<FieldValue>,
    thrown: Mutex<Option<FieldValue>>,
    projection_results: Mutex<VecDeque<FieldValue>>,
}

#[async_trait]
impl PasswordHasher for State {
    async fn hash(&self, password: &str) -> AuthResult<String> {
        assert_eq!(password, PASSWORD);
        self.events.lock().unwrap().push("hash");
        Ok("new-hash".into())
    }

    async fn verify(&self, _: &str, _: &str) -> AuthResult<bool> {
        Err(AuthError::internal(
            "The typed bridge must not narrow a native verifier's hash",
        ))
    }

    async fn verify_native(&self, hash: &FieldValue, password: &str) -> AuthResult<FieldValue> {
        self.events.lock().unwrap().push("verify");
        assert!(hash.strict_equals(&self.projected.lock().unwrap()));
        assert_eq!(password, PASSWORD);
        if let Some(error) = self.thrown.lock().unwrap().as_ref() {
            return Err(AuthError::from_thrown(error.clone()));
        }
        Ok(self.result.lock().unwrap().clone())
    }
}

fn native_hash() -> FieldValue {
    FieldMap::from([
        ("marker".into(), "projected-hash".into()),
        (
            "toString".into(),
            FieldFunction::contextual(|_, _| {
                Err(AuthError::internal(
                    "Password verification must not coerce the hash",
                ))
            })
            .into(),
        ),
    ])
    .into()
}

async fn check_consumers<S: AuthSchema>(database: Arc<dyn AuthStore<S>>) -> AuthResult<()> {
    let state = Arc::new(State::default());
    *state.projected.lock().unwrap() = native_hash();
    *state.result.lock().unwrap() = false.into();
    let plugins: Vec<Box<dyn AuthPlugin<S>>> = vec![
        Box::new(EmailPasswordPlugin::new().password_hasher(state.clone())),
        Box::new(PasswordManagementPlugin::new()),
        Box::new(UsernamePlugin::new(UsernameConfig::default())),
        Box::new(PhoneNumberPlugin::new()),
        Box::new(UserManagementPlugin::new().delete_user_enabled(true)),
        Box::new(
            TwoFactorPlugin::new()
                .allow_passwordless(true)
                .totp_disabled(true),
        ),
        Box::new(HaveIBeenPwnedPlugin::with_config(HaveIBeenPwnedConfig {
            enabled: false,
            ..Default::default()
        })),
    ];
    let plugin_refs = plugins.iter().map(Box::as_ref).collect::<Vec<_>>();
    let mut config = test_helpers::create_test_config().disable_session_refresh(true);
    let raw = test_helpers::initialize_bound_test_context(
        Arc::new(config.clone()),
        database.clone(),
        &plugin_refs,
    )
    .await?;
    let user = raw
        .database
        .create_user(CreateUser {
            username: Some(Some("nativeowner".into())),
            phone_number: Some("+12025550123".into()),
            phone_number_verified: Some(true),
            ..CreateUser::new()
                .with_name("Owner")
                .with_email("owner@password-native.test")
        })
        .await?;
    let _ = raw
        .database
        .create_account(CreateAccount {
            user_id: user.id.clone(),
            account_id: user.id.clone(),
            provider_id: "credential".to_owned().into(),
            password: Some("stored-hash".to_owned()).into(),
            ..Default::default()
        })
        .await?;
    let session =
        test_helpers::create_session(&raw, user.id.typed()?.clone(), chrono::Duration::hours(1))
            .await;
    let stored_accounts = raw
        .database
        .get_user_accounts(user.id.typed()?)
        .await?
        .into_iter()
        .map(|account| account.field_values())
        .collect::<AuthResult<Vec<_>>>()?;
    let stored_sessions = raw
        .database
        .get_user_sessions(user.id.typed()?)
        .await?
        .into_iter()
        .map(FieldMap::from)
        .collect::<Vec<_>>();
    let output_state = state.clone();
    let _ = config.account.additional_fields.insert(
        "password".into(),
        UserFieldConfig {
            required: Some(false),
            returned: Some(false),
            transform: Some(FieldTransforms {
                input: None,
                output: Some(UserFieldTransform::new(move |value| {
                    assert_eq!(value, "stored-hash".into());
                    output_state.events.lock().unwrap().push("projection");
                    Ok(output_state
                        .projection_results
                        .lock()
                        .unwrap()
                        .pop_front()
                        .unwrap_or_else(|| output_state.projected.lock().unwrap().clone()))
                })),
            }),
            ..Default::default()
        },
    );
    let context =
        test_helpers::initialize_bound_test_context(Arc::new(config), database, &plugin_refs)
            .await?;
    let cases = [
        (
            "email-password",
            "/sign-in/email",
            json!({"email":"owner@password-native.test","password":PASSWORD}),
            "INVALID_EMAIL_OR_PASSWORD",
            "Invalid email or password",
        ),
        (
            "username",
            "/sign-in/username",
            json!({"username":"nativeowner","password":PASSWORD}),
            "INVALID_USERNAME_OR_PASSWORD",
            "Invalid username or password",
        ),
        (
            "phone-number",
            "/sign-in/phone-number",
            json!({"phoneNumber":"+12025550123","password":PASSWORD}),
            "INVALID_PHONE_NUMBER_OR_PASSWORD",
            "Invalid phone number or password",
        ),
        (
            "password-management",
            "/verify-password",
            json!({"password":PASSWORD}),
            "INVALID_PASSWORD",
            "Invalid password",
        ),
        (
            "password-management",
            "/change-password",
            json!({"currentPassword":PASSWORD,"newPassword":PASSWORD}),
            "INVALID_PASSWORD",
            "Invalid password",
        ),
        (
            "user-management",
            "/delete-user",
            json!({"password":PASSWORD}),
            "INVALID_PASSWORD",
            "Invalid password",
        ),
        (
            "two-factor",
            "/two-factor/enable",
            json!({"password":PASSWORD}),
            "INVALID_PASSWORD",
            "Invalid password",
        ),
    ];
    let original: FieldValue = FieldMap::from([
        ("reason".into(), "verification callback failed".into()),
        ("ownUndefined".into(), FieldValue::Undefined),
    ])
    .into();
    for throws in [false, true] {
        *state.thrown.lock().unwrap() = throws.then(|| original.clone());
        for (name, path, body, code, message) in &cases {
            state.events.lock().unwrap().clear();
            let req = test_helpers::create_auth_json_request_no_query(
                HttpMethod::Post,
                path,
                Some(session.token.typed()?),
                Some(body.clone()),
            );
            let ctx = context.initialize_request_context().await?;
            let plugin = plugins
                .iter()
                .find(|plugin| plugin.name() == *name)
                .unwrap();
            let error = plugin.on_request(&req, &ctx).await.expect_err(path);
            if throws {
                assert!(
                    error.raw_value().unwrap().strict_equals(&original),
                    "{path}"
                );
            } else {
                assert_eq!(
                    error.body_value()?.json()?,
                    Some(json!({"code":code,"message":message})),
                    "{path}"
                );
                assert_eq!(
                    error.status_code()?,
                    if path.starts_with("/sign-in/") {
                        401
                    } else {
                        400
                    },
                    "{path}"
                );
            }
            assert_eq!(
                *state.events.lock().unwrap(),
                match *path {
                    "/change-password" => vec!["projection", "hash", "verify"],
                    "/two-factor/enable" => vec!["projection", "projection", "verify"],
                    _ => vec!["projection", "verify"],
                },
                "{path}"
            );
            assert_eq!(
                raw.database
                    .get_user_accounts(user.id.typed()?)
                    .await?
                    .into_iter()
                    .map(|account| account.field_values())
                    .collect::<AuthResult<Vec<_>>>()?,
                stored_accounts,
                "{path}"
            );
            assert_eq!(
                raw.database
                    .get_user_sessions(user.id.typed()?)
                    .await?
                    .into_iter()
                    .map(FieldMap::from)
                    .collect::<Vec<_>>(),
                stored_sessions,
                "{path}"
            );
            assert_eq!(
                raw.database
                    .get_user_by_id(user.id.typed()?)
                    .await?
                    .unwrap(),
                user,
                "{path}"
            );
        }
    }
    *state.thrown.lock().unwrap() = None;
    let verify = plugins
        .iter()
        .find(|plugin| plugin.name() == "password-management")
        .unwrap();
    for projected in [
        native_hash(),
        17.into(),
        vec![FieldValue::from("hash")].into(),
    ] {
        *state.projected.lock().unwrap() = projected;
        for result in [
            FieldMap::new().into(),
            Vec::<FieldValue>::new().into(),
            "false".into(),
        ] {
            *state.result.lock().unwrap() = result;
            state.events.lock().unwrap().clear();
            let req = test_helpers::create_auth_json_request_no_query(
                HttpMethod::Post,
                "/verify-password",
                Some(session.token.typed()?),
                Some(json!({"password":PASSWORD})),
            );
            let response = verify
                .on_request(&req, context.initialize_request_context().await?.as_ref())
                .await?
                .unwrap();
            assert_eq!(response.body.json()?, Some(json!({"status":true})));
            assert_eq!(*state.events.lock().unwrap(), ["projection", "verify"]);
        }
    }
    // Missing hashes preserve each sign-in endpoint's timing and error behavior.
    *state.projected.lock().unwrap() = false.into();
    *state.result.lock().unwrap() = false.into();
    for (name, path, body, code, message) in cases
        .iter()
        .filter(|(_, path, _, _, _)| matches!(*path, "/sign-in/email" | "/sign-in/username"))
    {
        state.events.lock().unwrap().clear();
        let req = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            path,
            None,
            Some(body.clone()),
        );
        let error = plugins
            .iter()
            .find(|plugin| plugin.name() == *name)
            .unwrap()
            .on_request(&req, context.initialize_request_context().await?.as_ref())
            .await
            .err()
            .unwrap();
        assert_eq!(
            error.body_value()?.json()?,
            Some(json!({"code":code,"message":message}))
        );
        assert_eq!(
            *state.events.lock().unwrap(),
            if *path == "/sign-in/email" {
                vec!["projection", "hash"]
            } else {
                vec!["projection"]
            }
        );
    }
    for missing in [
        false.into(),
        0.into(),
        f64::NAN.into(),
        "".into(),
        FieldValue::Null,
        FieldValue::Undefined,
    ] {
        *state.projected.lock().unwrap() = missing;
        state.events.lock().unwrap().clear();
        let req = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/sign-in/phone-number",
            None,
            Some(json!({"phoneNumber":"+12025550123","password":PASSWORD})),
        );
        let error = plugins
            .iter()
            .find(|plugin| plugin.name() == "phone-number")
            .unwrap()
            .on_request(&req, context.initialize_request_context().await?.as_ref())
            .await
            .err()
            .unwrap();
        assert_eq!(
            error.body_value()?.json()?,
            Some(json!({"code":"UNEXPECTED_ERROR","message":"Unexpected error"}))
        );
        assert_eq!(*state.events.lock().unwrap(), ["projection"]);
        assert_eq!(error.status_code()?, 401);
    }
    for (allow_passwordless, password, second_false, expected) in [
        (
            true,
            PASSWORD.to_owned(),
            false,
            vec!["projection", "projection", "verify"],
        ),
        (
            false,
            PASSWORD.to_owned(),
            false,
            vec!["projection", "verify"],
        ),
        (false, String::new(), false, vec![]),
        (false, "x".repeat(129), false, vec![]),
        (true, "x".repeat(129), false, vec!["projection"]),
        (
            true,
            PASSWORD.to_owned(),
            true,
            vec!["projection", "projection"],
        ),
    ] {
        let hash = native_hash();
        *state.projected.lock().unwrap() = hash.clone();
        *state.result.lock().unwrap() = true.into();
        if second_false {
            *state.projection_results.lock().unwrap() = VecDeque::from([hash, false.into()]);
        }
        state.events.lock().unwrap().clear();
        let plugin = TwoFactorPlugin::new()
            .allow_passwordless(allow_passwordless)
            .totp_disabled(true);
        let req = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/two-factor/enable",
            Some(session.token.typed()?),
            Some(json!({"password":password})),
        );
        let error = plugin
            .on_request(&req, context.initialize_request_context().await?.as_ref())
            .await
            .err()
            .unwrap();
        let (code, message) = if password.len() > 128 {
            ("PASSWORD_TOO_LONG", "Password too long")
        } else if password.is_empty() || second_false {
            ("INVALID_PASSWORD", "Invalid password")
        } else {
            ("TOTP_NOT_CONFIGURED", "TOTP is not available")
        };
        assert_eq!(
            error.body_value()?.json()?,
            Some(json!({"code":code,"message":message}))
        );
        assert_eq!(*state.events.lock().unwrap(), expected);
    }
    assert_eq!(
        raw.database
            .get_user_accounts(user.id.typed()?)
            .await?
            .into_iter()
            .map(|account| account.field_values())
            .collect::<AuthResult<Vec<_>>>()?,
        stored_accounts
    );
    assert_eq!(
        raw.database
            .get_user_sessions(user.id.typed()?)
            .await?
            .into_iter()
            .map(FieldMap::from)
            .collect::<Vec<_>>(),
        stored_sessions
    );
    assert_eq!(
        raw.database
            .get_user_by_id(user.id.typed()?)
            .await?
            .unwrap(),
        user
    );
    Ok(())
}

#[tokio::test]
async fn password_consumers_preserve_native_hashes_errors_order_and_storage() -> AuthResult<()> {
    let memory: Arc<dyn AuthStore<StatelessSchema>> = Arc::new(EphemeralStore::default());
    check_consumers(memory).await?;
    check_consumers(test_helpers::create_test_database().await).await
}

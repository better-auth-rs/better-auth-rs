#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "The shared runtime contract fails immediately on invalid case shapes or mismatched observations"
)]

use better_auth_core::{
    AuthResult, FieldMap, FieldValue,
    store::{RuntimeStore, UserStore},
};
use std::sync::Arc;

#[path = "support/user_runtime_output_contract.rs"]
#[expect(
    dead_code,
    reason = "The shared contract also supplies cache payload helpers"
)]
mod contract;

#[path = "common/id_runtime.rs"]
mod http;

async fn output_case(
    name: &str,
    replacement: FieldValue,
    fail: bool,
    calls: usize,
) -> AuthResult<()> {
    let mut config = contract::config()?;
    let (raw, seeded) = contract::seed(&config).await?;
    let before = FieldMap::from(seeded);
    let trace = contract::replace(&mut config, name, replacement.clone(), fail);
    let store = raw.with_runtime(Arc::new(config), Vec::new(), Default::default())?;
    let result = store.get_user_by_id(contract::OWNER).await;
    let events = trace.lock().unwrap().clone();
    assert_eq!(events.len(), calls, "{name}");
    if calls == 1 {
        assert_eq!(
            contract::observe(&events[0])?,
            contract::observe(before.get(name).unwrap())?,
            "{name}"
        );
    }
    if fail {
        assert_eq!(
            result.unwrap_err().to_string(),
            "Internal server error: user-output-stop"
        );
    } else {
        let fields = FieldMap::from(result?.unwrap());
        let mut expected = before.clone();
        if calls != 0 {
            let _ = expected.insert(name.into(), replacement.clone());
        }
        assert_eq!(
            contract::observe(&fields.clone().into())?,
            contract::observe(&expected.into())?,
            "{name}"
        );
        assert!(
            fields.contains_key(name),
            "{name} must retain own undefined"
        );
        if matches!(
            replacement,
            FieldValue::Object(_) | FieldValue::Array(_) | FieldValue::Date(_)
        ) && calls != 0
        {
            assert!(
                fields.get(name).unwrap().strict_equals(&replacement),
                "{name} must retain the selected value handle"
            );
        }
    }
    assert_eq!(
        FieldMap::from(raw.get_user_by_id(contract::OWNER).await?.unwrap()),
        before
    );
    Ok(())
}

#[tokio::test]
async fn every_user_output_slot_preserves_replacement_types_without_mutating_storage()
-> AuthResult<()> {
    let cases = contract::cases()?;
    for field in cases["fields"].as_array().unwrap() {
        output_case(
            field["name"].as_str().unwrap(),
            contract::revive(&field["replacement"])?,
            false,
            field["calls"].as_u64().unwrap_or(1) as usize,
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn user_email_boolean_and_date_outputs_preserve_presence_and_propagate_callback_errors()
-> AuthResult<()> {
    let cases = contract::cases()?;
    for name in cases["representativeFields"].as_array().unwrap() {
        for case in cases["values"].as_array().unwrap() {
            output_case(
                name.as_str().unwrap(),
                contract::revive(&case["value"])?,
                case.get("error").is_some(),
                1,
            )
            .await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn email_signin_uses_runtime_truthiness_before_issuing_a_session() -> AuthResult<()> {
    use better_auth::{BetterAuth, plugins::EmailPasswordPlugin};
    use better_auth_core::{
        CreateAccount,
        store::{AccountStore, SessionStore},
    };
    for case in contract::cases()?["verifiedConsumers"].as_array().unwrap() {
        let mut config = contract::config()?;
        let (raw, _) = contract::seed(&config).await?;
        let _ = raw
            .create_account(CreateAccount {
                account_id: contract::OWNER.into(),
                user_id: contract::OWNER.into(),
                provider_id: "credential".into(),
                password: Some("hashed:runtime-password".to_owned()).into(),
                ..Default::default()
            })
            .await?;
        let calls = contract::replace(
            &mut config,
            "emailVerified",
            contract::revive(&case["value"])?,
            false,
        );
        let auth = BetterAuth::stateless(config)
            .store_arc(raw.clone())
            .plugin(
                EmailPasswordPlugin::new()
                    .require_email_verification(true)
                    .password_hasher(Arc::new(http::Hasher)),
            )
            .build()
            .await?;
        let (status, body, cookies) = http::request(
            &auth,
            "/sign-in/email",
            Some(serde_json::json!({
                "email": contract::EMAIL, "password": "runtime-password"
            })),
            "",
        )
        .await;
        assert_eq!(
            u64::from(status),
            case["status"].as_u64().unwrap(),
            "{}: {body}",
            case["name"]
        );
        assert_eq!(calls.lock().unwrap().as_slice(), &[FieldValue::Bool(false)]);
        let issued = status == 200;
        assert_eq!(
            raw.get_user_sessions(contract::OWNER).await?.len(),
            usize::from(issued)
        );
        assert_eq!(cookies.contains("better-auth.session_token="), issued);
        assert_eq!(
            raw.get_user_by_id(contract::OWNER)
                .await?
                .unwrap()
                .email_verified
                .field_value(),
            FieldValue::Bool(false)
        );
    }
    Ok(())
}

async fn authenticated_cookie(
    raw: &better_auth_core::store::EphemeralStore,
    config: &better_auth_core::AuthConfig,
) -> AuthResult<String> {
    use better_auth_core::{CreateSession, store::SessionStore};
    let session = raw
        .create_session(CreateSession {
            inherited_fields: FieldMap::new(),
            additional_fields: FieldMap::new(),
            user_id: contract::OWNER.into(),
            expires_at: (chrono::Utc::now() + config.session.expires_in()).into(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await?;
    Ok(
        better_auth_core::utils::cookie_utils::create_session_cookie(
            session.token.typed()?,
            config,
        )?
        .split(';')
        .next()
        .unwrap()
        .to_owned(),
    )
}

#[tokio::test]
async fn admin_role_consumer_uses_truthy_fallback_and_requires_the_string_split_operation()
-> AuthResult<()> {
    use better_auth::{BetterAuth, plugins::AdminPlugin};
    use better_auth_core::store::SessionStore;
    for case in contract::cases()?["roleConsumers"].as_array().unwrap() {
        let mut config = contract::config()?;
        let (raw, before) = contract::seed(&config).await?;
        let cookie = authenticated_cookie(&raw, &config).await?;
        let _ = contract::replace(
            &mut config,
            "role",
            contract::revive(&case["value"])?,
            false,
        );
        let auth = BetterAuth::stateless(config)
            .store_arc(raw.clone())
            .plugin(AdminPlugin::new())
            .build()
            .await?;
        let (status, body, cookies) =
            http::request(&auth, "/admin/list-users", None, &cookie).await;
        assert_eq!(
            u64::from(status),
            case["status"].as_u64().unwrap(),
            "{}: {body}",
            case["name"]
        );
        assert!(cookies.is_empty());
        assert_eq!(raw.get_user_sessions(contract::OWNER).await?.len(), 1);
        assert_eq!(
            FieldMap::from(raw.get_user_by_id(contract::OWNER).await?.unwrap()),
            FieldMap::from(before)
        );
    }
    Ok(())
}

#[tokio::test]
async fn selected_email_must_support_lowercase_before_any_verification_delivery() -> AuthResult<()>
{
    use better_auth::{
        BetterAuth,
        plugins::{EmailVerificationPlugin, email_verification::EmailVerificationCallbacks},
    };
    use better_auth_core::store::StatelessSchema;
    for case in contract::cases()?["emailConsumers"].as_array().unwrap() {
        let mut config = contract::config()?;
        let (raw, before) = contract::seed(&config).await?;
        let cookie = authenticated_cookie(&raw, &config).await?;
        let _ = contract::replace(
            &mut config,
            "email",
            contract::revive(&case["value"])?,
            false,
        );
        let delivered = contract::Calls::default();
        let observed = delivered.clone();
        let auth = BetterAuth::stateless(config)
            .store_arc(raw.clone())
            .plugin(
                EmailVerificationPlugin::new().callbacks(EmailVerificationCallbacks::<
                    StatelessSchema,
                >::send(
                    move |message, _| {
                        observed
                            .lock()
                            .unwrap()
                            .push(message.user.email.field_value());
                        Ok(None)
                    },
                )),
            )
            .build()
            .await?;
        let (status, body, cookies) = http::request(
            &auth,
            "/send-verification-email",
            Some(serde_json::json!({"email": contract::EMAIL})),
            &cookie,
        )
        .await;
        assert_eq!(
            u64::from(status),
            case["status"].as_u64().unwrap(),
            "{}: {body}",
            case["name"]
        );
        assert_eq!(
            delivered.lock().unwrap().len() as u64,
            case["sent"].as_u64().unwrap()
        );
        if status == 200 {
            assert_eq!(
                contract::observe(&delivered.lock().unwrap()[0])?,
                case["value"]
            );
        }
        assert!(cookies.is_empty());
        assert_eq!(
            FieldMap::from(raw.get_user_by_id(contract::OWNER).await?.unwrap()),
            FieldMap::from(before)
        );
    }
    Ok(())
}

#[tokio::test]
async fn ban_expiry_consumption_uses_truthiness_and_date_coercion_before_session_mutation()
-> AuthResult<()> {
    use better_auth::{
        BetterAuth,
        plugins::{AdminPlugin, EmailPasswordPlugin},
    };
    use better_auth_core::{
        CreateAccount,
        store::{AccountStore, SessionStore},
    };
    for case in contract::cases()?["banConsumers"].as_array().unwrap() {
        let mut config = contract::config()?;
        let (raw, before) = contract::seed(&config).await?;
        let _ = raw
            .create_account(CreateAccount {
                account_id: contract::OWNER.into(),
                user_id: contract::OWNER.into(),
                provider_id: "credential".into(),
                password: Some("hashed:runtime-password".to_owned()).into(),
                ..Default::default()
            })
            .await?;
        let _ = contract::replace(
            &mut config,
            "banned",
            contract::revive(&case["banned"])?,
            false,
        );
        let _ = contract::replace(
            &mut config,
            "banExpires",
            contract::revive(&case["expires"])?,
            false,
        );
        let auth = BetterAuth::stateless(config)
            .store_arc(raw.clone())
            .plugin(EmailPasswordPlugin::new().password_hasher(Arc::new(http::Hasher)))
            .plugin(AdminPlugin::new())
            .build()
            .await?;
        let (status, body, cookies) = http::request(
            &auth,
            "/sign-in/email",
            Some(serde_json::json!({
                "email": contract::EMAIL, "password": "runtime-password"
            })),
            "",
        )
        .await;
        assert_eq!(
            u64::from(status),
            case["status"].as_u64().unwrap(),
            "{}: {body}",
            case["name"]
        );
        assert_eq!(
            raw.get_user_sessions(contract::OWNER).await?.len(),
            usize::from(status == 200)
        );
        assert_eq!(
            cookies.contains("better-auth.session_token="),
            status == 200
        );
        let after = raw.get_user_by_id(contract::OWNER).await?.unwrap();
        if case["clear"].as_bool().unwrap() {
            assert_eq!(after.banned.field_value(), FieldValue::Bool(false));
            assert_eq!(after.ban_reason.field_value(), FieldValue::Null);
            assert_eq!(after.ban_expires.field_value(), FieldValue::Null);
        } else {
            assert_eq!(FieldMap::from(after), FieldMap::from(before));
        }
    }
    Ok(())
}

#[tokio::test]
async fn change_email_requires_strict_true_before_deferring_an_unverified_update() -> AuthResult<()>
{
    use better_auth::{BetterAuth, plugins::UserManagementPlugin};
    for case in contract::cases()?["changeEmailConsumers"]
        .as_array()
        .unwrap()
    {
        let mut config = contract::config()?;
        let (raw, _) = contract::seed(&config).await?;
        let cookie = authenticated_cookie(&raw, &config).await?;
        let _ = contract::replace(
            &mut config,
            "emailVerified",
            contract::revive(&case["value"])?,
            false,
        );
        let auth = BetterAuth::stateless(config)
            .store_arc(raw.clone())
            .plugin(
                UserManagementPlugin::new()
                    .change_email_enabled(true)
                    .update_without_verification(true),
            )
            .build()
            .await?;
        let (status, body, cookies) = http::request(
            &auth,
            "/change-email",
            Some(serde_json::json!({"newEmail": "changed@runtime.test"})),
            &cookie,
        )
        .await;
        assert_eq!(
            u64::from(status),
            case["status"].as_u64().unwrap(),
            "{}: {body}",
            case["name"]
        );
        let changed = case["changed"].as_bool().unwrap();
        assert_eq!(
            raw.get_user_by_id(contract::OWNER)
                .await?
                .unwrap()
                .email
                .field_value(),
            FieldValue::from(if changed {
                "changed@runtime.test"
            } else {
                contract::EMAIL
            })
        );
        assert_eq!(cookies.contains("better-auth.session_token="), changed);
    }
    Ok(())
}

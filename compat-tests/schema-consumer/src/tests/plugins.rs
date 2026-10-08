use std::sync::Arc;

use axum::{Router, http::StatusCode};
use better_auth::{
    __private_core::{
        AuthContext, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
        AuthSchema,
        store::schema::EntityRole,
        user_fields::{UserConfig, UserFieldConfig},
    },
    AuthConfig, BetterAuth,
    integrations::axum::AxumIntegration,
    plugins::{
        ApiKeyPlugin, EmailPasswordPlugin, JwtPlugin, LastLoginMethodConfig, LastLoginMethodPlugin,
        SessionManagementPlugin, TwoFactorPlugin,
    },
    prelude::{
        CreateDeviceCode, CreatePasskey, CreateWalletAddress, UpdateApiKey, UpdateDeviceCode,
        UpdatePasskeyAuthentication,
    },
    seaorm::{
        Database, SeaOrmStore,
        sea_orm::{ConnectionTrait, EntityTrait, PaginatorTrait},
    },
};
use serde_json::json;

use super::request;

mod generated {
    include!(env!("BETTER_AUTH_PLUGIN_SCHEMA"));
}

struct DisplayFields;

#[better_auth::__private_core::__private_async_trait::async_trait]
impl<S: AuthSchema> AuthPlugin<S> for DisplayFields {
    fn name(&self) -> &'static str {
        "mapped-plugin-display-fields"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        for (role, names) in [
            (EntityRole::ApiKey, &["name"][..]),
            (EntityRole::Passkey, &["name", "aaguid"][..]),
        ] {
            let mut fields = UserConfig::default();
            for name in names {
                let _ = fields.fields_mut().insert(
                    (*name).into(),
                    UserFieldConfig {
                        field_name: Some(format!("stored_{name}")),
                        required: Some(false),
                        ..Default::default()
                    },
                );
            }
            context.register_model_fields(role, fields)?;
        }
        Ok(())
    }

    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

#[tokio::test]
async fn renamed_plugin_tables_preserve_authentication_and_atomic_storage() {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    generated::create_auth_tables(&database).await.unwrap();
    let mut config = AuthConfig::new("mapped-plugin-schema-secret-at-least-32-characters")
        .base_url("http://localhost:3000");
    config.session.bearer = Some(Default::default());
    let auth = Arc::new(
        BetterAuth::<generated::AppAuthSchema>::new(config.clone())
            .store(
                SeaOrmStore::<generated::AppAuthSchema>::new(config, database.clone())
                    .with_organization_schema::<generated::AppOrganizationSchema>()
                    .with_plugin_schema::<generated::AppPluginSchema>(),
            )
            .plugin(EmailPasswordPlugin::new().enable_signup(true))
            .plugin(LastLoginMethodPlugin::new(LastLoginMethodConfig {
                store_in_database: true,
                field_name: Some("login_method".into()),
                ..Default::default()
            }))
            .plugin(SessionManagementPlugin::new())
            .plugin(ApiKeyPlugin::builder().build())
            .plugin(DisplayFields)
            .plugin(TwoFactorPlugin::new())
            .plugin(JwtPlugin::new())
            .build()
            .await
            .unwrap(),
    );
    let router = Router::new()
        .nest("/auth", auth.clone().axum_router())
        .with_state(auth.clone());
    let credentials =
        json!({"email":"mapped@example.com","name":"Mapped", "password":"test-password-123"});
    let (status, signup) = request(
        &router,
        "/auth/sign-up/email",
        Some(credentials.clone()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{signup}");
    let token = signup["token"].as_str().unwrap();
    let user_id = signup["user"]["id"].as_str().unwrap();
    let user = generated::user::Entity::find_by_id(user_id)
        .one(&database)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user.email.as_deref(), Some("mapped@example.com"));
    assert_eq!(user.last_login_method.as_deref(), Some("email"));
    assert_eq!(signup["user"]["lastLoginMethod"], "email");
    database
        .execute_unprepared("UPDATE mapped_user SET login_method = NULL")
        .await
        .unwrap();
    let (status, signed_in) = request(
        &router,
        "/auth/sign-in/email",
        Some(credentials.clone()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{signed_in}");
    assert_eq!(
        generated::user::Entity::find_by_id(user_id)
            .one(&database)
            .await
            .unwrap()
            .unwrap()
            .last_login_method
            .as_deref(),
        Some("email")
    );
    assert_eq!(
        request(&router, "/auth/get-session", None, Some(token))
            .await
            .0,
        StatusCode::OK
    );

    let keys = auth.api_keys().unwrap();
    let key = keys
        .create(
            user_id,
            better_auth::server_api::CreateKeyOptions {
                name: Some("mapped".into()),
                remaining: Some(2.0),
                rate_limit_enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        generated::api_key::Entity::find_by_id(key.api_key.id.typed().unwrap())
            .one(&database)
            .await
            .unwrap()
            .unwrap()
            .remaining,
        Some(2.0)
    );
    assert_eq!(key.api_key.name.typed().unwrap().as_deref(), Some("mapped"));
    let renamed = auth
        .store()
        .update_api_key(
            &key.api_key.id,
            UpdateApiKey {
                name: Some(Some("renamed key".into()).into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        renamed.name.typed().unwrap().as_deref(),
        Some("renamed key")
    );
    let raw_key = generated::api_key::Entity::find_by_id(key.api_key.id.typed().unwrap())
        .one(&database)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(raw_key.name.as_deref(), Some("renamed key"));
    let serialized_key = serde_json::to_value(&raw_key).unwrap();
    assert_eq!(serialized_key.get("name"), Some(&json!("renamed key")));
    assert!(serialized_key.get("stored_name").is_none());
    for remaining in [1.0, 0.0] {
        let verified = keys.verify(&key.key, Default::default()).await.unwrap();
        assert_eq!(verified.remaining, Some(remaining));
        assert_eq!(
            auth.store()
                .get_api_key_by_id(key.api_key.id.typed().unwrap())
                .await
                .unwrap()
                .unwrap()
                .remaining,
            Some(remaining)
        );
    }
    assert!(keys.verify(&key.key, Default::default()).await.is_err());
    assert!(
        auth.store()
            .get_api_key_by_id(key.api_key.id.typed().unwrap())
            .await
            .unwrap()
            .is_none()
    );

    let (status, enabled) = request(
        &router,
        "/auth/two-factor/enable",
        Some(json!({"password":"test-password-123"})),
        Some(token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{enabled}");
    let totp = totp_rs::TOTP::from_url(enabled["totpURI"].as_str().unwrap()).unwrap();
    let (status, verified) = request(
        &router,
        "/auth/two-factor/verify-totp",
        Some(json!({"code":totp.generate_current().unwrap()})),
        Some(token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{verified}");
    let factor = auth
        .store()
        .get_two_factor_by_user_id(user_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(factor.verified, Some(true));
    assert!(
        generated::user::Entity::find_by_id(user_id)
            .one(&database)
            .await
            .unwrap()
            .unwrap()
            .two_factor_enabled
    );
    assert!(
        auth.store()
            .compare_exchange_two_factor_backup_codes(
                &factor.id,
                &factor.backup_codes,
                "replacement"
            )
            .await
            .unwrap()
    );
    assert!(
        !auth
            .store()
            .compare_exchange_two_factor_backup_codes(&factor.id, &factor.backup_codes, "replay")
            .await
            .unwrap()
    );
    let (status, challenge) =
        request(&router, "/auth/sign-in/email", Some(credentials), None).await;
    assert_eq!(status, StatusCode::OK, "{challenge}");
    assert_eq!(challenge["twoFactorRedirect"], true);

    let device = auth
        .store()
        .create_device_code(CreateDeviceCode {
            additional_fields: Default::default(),
            device_code: "device-secret".into(),
            user_code: "ABCD2345".into(),
            user_id: None,
            expires_at: user.created_at.into(),
            status: "pending".into(),
            last_polled_at: None,
            polling_interval: Some(5.0),
            client_id: Some("consumer".into()),
            scope: Some("read".into()).into(),
        })
        .await
        .unwrap();
    let device_owner = better_auth::SchemaValue::from(user_id.to_owned());
    let (first, replay) = tokio::join!(
        auth.store().claim_device_code(&device.id, &device_owner),
        auth.store().claim_device_code(&device.id, &device_owner),
    );
    assert_eq!(
        usize::from(first.unwrap()) + usize::from(replay.unwrap()),
        1
    );
    assert_eq!(
        auth.store()
            .get_device_code_by_user_code("ABCD2345")
            .await
            .unwrap()
            .unwrap()
            .user_id
            .typed()
            .unwrap()
            .as_deref(),
        Some(user_id)
    );
    assert!(
        auth.store()
            .update_device_code_if_status(
                &device.id,
                "pending",
                UpdateDeviceCode {
                    status: Some("approved".into()),
                    ..Default::default()
                }
            )
            .await
            .unwrap()
    );
    assert!(
        !auth
            .store()
            .delete_device_code_if_status(&device.id, "pending")
            .await
            .unwrap()
    );
    assert!(
        auth.store()
            .delete_device_code_if_status(&device.id, "approved")
            .await
            .unwrap()
    );

    let passkey = auth
        .store()
        .create_passkey(CreatePasskey {
            additional_fields: Default::default(),
            user_id: user_id.into(),
            name: Some("key".into()).into(),
            credential_id: "credential".into(),
            public_key: "public".into(),
            counter: 3,
            device_type: "singleDevice".into(),
            backed_up: false,
            transports: Some("usb".into()),
            credential: "credential-state".into(),
            aaguid: Some("ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4".into()).into(),
        })
        .await
        .unwrap();
    assert_eq!(passkey.name.typed().unwrap().as_deref(), Some("key"));
    assert_eq!(
        passkey.aaguid.typed().unwrap().as_deref(),
        Some("ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4")
    );
    let renamed = auth
        .store()
        .update_passkey_name(passkey.id.typed().unwrap(), "renamed passkey")
        .await
        .unwrap();
    assert_eq!(
        renamed.name.typed().unwrap().as_deref(),
        Some("renamed passkey")
    );
    let raw_passkey = generated::passkey::Entity::find_by_id(passkey.id.typed().unwrap())
        .one(&database)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(raw_passkey.name.as_deref(), Some("renamed passkey"));
    assert_eq!(
        raw_passkey.aaguid.as_deref(),
        Some("ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4")
    );
    let serialized_passkey = serde_json::to_value(&raw_passkey).unwrap();
    assert_eq!(
        serialized_passkey.get("name"),
        Some(&json!("renamed passkey"))
    );
    assert!(serialized_passkey.get("stored_name").is_none());
    assert!(serialized_passkey.get("stored_aaguid").is_none());
    let updated = auth
        .store()
        .update_passkey_authentication(
            &passkey.id,
            UpdatePasskeyAuthentication::Legacy {
                credential: "updated-state".into(),
                counter: 4,
                backed_up: true,
                device_type: "multiDevice".into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.counter, 4);
    let persisted = auth
        .store()
        .get_passkey_by_credential_id("credential")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(persisted.credential.typed().unwrap(), "updated-state");
    assert!(*persisted.backed_up.typed().unwrap());
    assert_eq!(
        auth.store()
            .list_passkeys_by_user(user_id)
            .await
            .unwrap()
            .len(),
        1
    );
    auth.store()
        .delete_passkey(passkey.id.typed().unwrap())
        .await
        .unwrap();
    assert!(
        auth.store()
            .get_passkey_by_id(passkey.id.typed().unwrap())
            .await
            .unwrap()
            .is_none()
    );

    auth.store()
        .create_wallet_address(CreateWalletAddress {
            additional_fields: Default::default(),
            user_id: user_id.into(),
            address: "0x1234".into(),
            chain_id: 1,
            is_primary: true,
            created_at: user.created_at.into(),
        })
        .await
        .unwrap();
    assert_eq!(
        auth.store()
            .get_wallet_address("0x1234", Some(1))
            .await
            .unwrap()
            .unwrap()
            .user_id,
        user_id
    );
    assert!(
        auth.store()
            .get_wallet_address("0x1234", Some(2))
            .await
            .unwrap()
            .is_none()
    );

    let (status, jwks) = request(&router, "/auth/jwks", None, None).await;
    assert_eq!(status, StatusCode::OK, "{jwks}");
    assert!(!jwks["keys"].as_array().unwrap().is_empty());
    let keys = auth.store().list_jwks().await.unwrap();
    assert!(!keys[0].private_key.is_empty());
    assert!(!jwks.to_string().contains(&keys[0].private_key));
    assert_eq!(
        generated::jwk::Entity::find()
            .count(&database)
            .await
            .unwrap(),
        keys.len() as u64
    );

    for (statement, expected) in [
        (
            "UPDATE mapped_session SET subject = 'missing'",
            "FOREIGN KEY constraint failed",
        ),
        (
            "INSERT INTO mapped_two_factor SELECT 'duplicate', stored_secret, stored_backup_codes, stored_user_id, stored_verified, stored_failed_verification_count, stored_locked_until, stored_created_at, stored_updated_at FROM mapped_two_factor",
            "UNIQUE constraint failed: mapped_two_factor.stored_user_id",
        ),
    ] {
        let error = database.execute_unprepared(statement).await.unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
    }
    for default in [
        "user",
        "users",
        "sessions",
        "session",
        "account",
        "accounts",
        "verifications",
        "verification",
        "api_keys",
        "device_code",
        "two_factor",
        "passkeys",
        "jwks",
        "wallet_address",
    ] {
        assert!(
            database
                .execute_unprepared(&format!("SELECT 1 FROM {default}"))
                .await
                .is_err(),
            "unexpected default table {default}"
        );
    }
}

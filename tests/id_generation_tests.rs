#![cfg(feature = "seaorm2")]
#![allow(
    clippy::unwrap_used,
    reason = "Contract fixtures stop on unexpected setup or assertion failures"
)]

use better_auth::config::{IdGeneration, IdGenerator};
use better_auth::{AuthConfig, BetterAuth};
use better_auth_core::store::{MemoryCacheAdapter, UserStore};
use better_auth_core::{
    AuthError, AuthSession, CreateAccount, CreateSession, CreateUser, CreateVerification,
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::Database,
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use chrono::{Duration, Utc};
use std::sync::{Arc, Mutex};

fn config() -> AuthConfig {
    AuthConfig::new("model-aware-id-fixture-secret-at-least-thirty-two-characters")
        .base_url("http://localhost:3000")
}

fn session(user_id: &str) -> CreateSession {
    CreateSession {
        additional_fields: Default::default(),
        user_id: user_id.into(),
        expires_at: Utc::now() + Duration::hours(1),
        ip_address: None,
        user_agent: None,
        impersonated_by: None,
        active_organization_id: None,
    }
}

async fn database() -> SeaOrmStore<BundledSchema> {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    SeaOrmStore::new(config(), database)
}

#[tokio::test]
async fn configured_generator_reaches_every_core_insert_and_preserves_forced_user_ids() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let observed = calls.clone();
    let mut config = config();
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(move |request| {
            let mut calls = observed.lock().unwrap();
            calls.push((request.model.to_owned(), request.size));
            Ok(Some(format!("{}_{}", request.model, calls.len())))
        })));
    let auth = BetterAuth::<BundledSchema>::new(config)
        .store(database().await)
        .build()
        .await
        .unwrap();
    let store = auth.store();
    let user = store
        .create_user(
            CreateUser::new()
                .with_email("generated@example.com")
                .with_name("Fixture"),
        )
        .await
        .unwrap();
    let account = store
        .create_account(CreateAccount {
            user_id: user.id.clone(),
            account_id: "remote-account".into(),
            provider_id: "fixture".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    let session = store
        .create_session(session(user.id.typed().unwrap()))
        .await
        .unwrap();
    let verification = store
        .create_verification(CreateVerification {
            identifier: "fixture-code".into(),
            value: "123456".into(),
            expires_at: (Utc::now() + Duration::minutes(5)).into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(user.id.clone(), "user_1");
    assert_eq!(account.id, "account_2");
    assert_eq!(session.id.clone(), "session_3");
    assert_eq!(verification.id, "verification_4");
    assert_eq!(account.user_id, user.id.clone());
    assert_eq!(session.user_id.clone(), user.id.clone());
    assert_eq!(session.token().len(), 32);
    assert!(
        session
            .token()
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric())
    );
    let forced = store
        .create_user(CreateUser {
            id: Some("forced-user".into()),
            ..CreateUser::new()
                .with_email("forced@example.com")
                .with_name("Fixture")
        })
        .await
        .unwrap();
    assert_eq!(forced.id.clone(), "forced-user");
    assert_eq!(
        *calls.lock().unwrap(),
        ["user", "account", "session", "verification"].map(|name| (name.to_owned(), None))
    );
}

#[tokio::test]
async fn generator_failure_prevents_the_write_and_does_not_retry() {
    let calls = Arc::new(Mutex::new(0));
    let observed = calls.clone();
    let mut config = config();
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(move |_| {
            *observed.lock().unwrap() += 1;
            Err(AuthError::internal("id-generator-rejected"))
        })));
    let auth = BetterAuth::<BundledSchema>::new(config)
        .store(database().await)
        .build()
        .await
        .unwrap();
    let result = auth
        .store()
        .create_user(CreateUser::new().with_email("rejected@example.com"))
        .await;
    assert!(
        matches!(result, Err(AuthError::Internal(ref message)) if message == "id-generator-rejected")
    );
    assert_eq!(*calls.lock().unwrap(), 1);
    assert!(
        auth.store()
            .get_user_by_email("rejected@example.com")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn pure_secondary_sessions_use_context_ids_and_independent_tokens() {
    for policy in [
        IdGeneration::Database,
        IdGeneration::Serial,
        IdGeneration::Custom(IdGenerator::new(|_| Ok(None))),
    ] {
        let store = database().await;
        let user = store
            .create_user(CreateUser {
                id: Some("16".into()),
                ..CreateUser::new()
                    .with_email("cache@example.com")
                    .with_name("Fixture")
            })
            .await
            .unwrap();
        let mut config = config();
        config.advanced.database.generate_id = Some(policy);
        let auth = BetterAuth::<BundledSchema>::new(config)
            .store(store)
            .secondary_storage(Arc::new(MemoryCacheAdapter::new()))
            .build()
            .await
            .unwrap();
        let row = auth
            .store()
            .create_session(session(user.id.typed().unwrap()))
            .await
            .unwrap();
        assert_eq!(row.id.typed().unwrap().len(), 32);
        assert!(
            row.id
                .typed()
                .unwrap()
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric())
        );
        assert_ne!(row.id.clone(), row.token());
        assert_eq!(
            auth.store()
                .get_session(row.token())
                .await
                .unwrap()
                .unwrap()
                .id,
            row.id.clone()
        );
    }
    let calls = Arc::new(Mutex::new(Vec::new()));
    let observed = calls.clone();
    let mut config = config();
    config.advanced.generate_id = Some(IdGenerator::new(move |request| {
        observed
            .lock()
            .unwrap()
            .push((request.model.to_owned(), request.size));
        Ok(Some("legacy-session".into()))
    }));
    config.advanced.database.generate_id = Some(IdGeneration::Custom(IdGenerator::new(|_| {
        Ok(Some("database-user".into()))
    })));
    let auth = BetterAuth::<BundledSchema>::new(config)
        .store(database().await)
        .secondary_storage(Arc::new(MemoryCacheAdapter::new()))
        .build()
        .await
        .unwrap();
    let user = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_email("legacy@example.com")
                .with_name("Fixture"),
        )
        .await
        .unwrap();
    let row = auth
        .store()
        .create_session(session(user.id.typed().unwrap()))
        .await
        .unwrap();
    assert_eq!(user.id.clone(), "database-user");
    assert_eq!(row.id.clone(), "legacy-session");
    assert_eq!(*calls.lock().unwrap(), [("session".into(), None)]);
}

#[tokio::test]
async fn plugin_ids_use_logical_models_and_preserve_forced_organization_ids() {
    use better_auth_core::{
        CreateDeviceCode, CreateJwk, CreateMember, CreateOrganization, CreateTeam, CreateTwoFactor,
    };
    let calls = Arc::new(Mutex::new(Vec::new()));
    let observed = calls.clone();
    let mut config = config();
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(move |request| {
            observed.lock().unwrap().push(request.model.to_owned());
            Ok(Some(format!("{}-generated", request.model)))
        })));
    let auth = BetterAuth::<BundledSchema>::new(config)
        .store(database().await)
        .build()
        .await
        .unwrap();
    let store = auth.store();
    let user = store
        .create_user(
            CreateUser::new()
                .with_email("plugins@example.com")
                .with_name("Fixture"),
        )
        .await
        .unwrap();
    let org = store
        .create_organization(CreateOrganization::new("Fixture", "fixture"))
        .await
        .unwrap();
    assert_eq!(org.id, "organization-generated");
    let member = store
        .create_member(CreateMember::new(
            org.id.typed().unwrap(),
            user.id.typed().unwrap(),
            "owner",
        ))
        .await
        .unwrap();
    assert_eq!(member.id, "member-generated");
    let team = store
        .create_team(CreateTeam {
            id: None,
            created_at: None,
            additional_fields: Default::default(),
            updated_at: None,
            name: "Team".to_owned().into(),
            organization_id: org.id.clone(),
        })
        .await
        .unwrap();
    assert_eq!(team.id, "team-generated");
    let team_member = store
        .add_team_member(&team.id, user.id.typed().unwrap(), None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(team_member.id, "teamMember-generated");
    let device = store
        .create_device_code(CreateDeviceCode {
            device_code: "credential".into(),
            user_code: "ABCD2345".into(),
            user_id: None,
            expires_at: Utc::now() + Duration::minutes(5),
            status: "pending".into(),
            last_polled_at: None,
            polling_interval: Some(5.0),
            client_id: None,
            scope: Default::default(),
        })
        .await
        .unwrap();
    assert_eq!(device.id, "deviceCode-generated");
    assert_eq!(device.device_code, "credential");
    let two_factor = store
        .create_two_factor(CreateTwoFactor {
            user_id: user.id.typed().unwrap().clone(),
            secret: "secret".into(),
            backup_codes: "[]".into(),
            verified: false,
        })
        .await
        .unwrap();
    assert_eq!(two_factor.id, "twoFactor-generated");
    let key = store
        .create_jwk(CreateJwk {
            created_at: Utc::now(),
            public_key: "{}".into(),
            private_key: "{}".into(),
            expires_at: None,
            alg: "EdDSA".into(),
            crv: None,
        })
        .await
        .unwrap();
    assert_eq!(key.id, "jwks-generated");
    let wallet = store
        .create_wallet_address(better_auth_core::types::CreateWalletAddress {
            user_id: user.id.typed().unwrap().clone(),
            address: "0x1234".into(),
            chain_id: 1,
            is_primary: true,
            created_at: Utc::now(),
        })
        .await
        .unwrap();
    assert_eq!(wallet.id, "walletAddress-generated");
    let mut input = CreateOrganization::new("Forced", "forced");
    input.id = Some("forced-organization".into());
    assert_eq!(
        store.create_organization(input).await.unwrap().id,
        "forced-organization"
    );
    assert_eq!(
        *calls.lock().unwrap(),
        [
            "user",
            "organization",
            "member",
            "team",
            "teamMember",
            "deviceCode",
            "twoFactor",
            "jwks",
            "walletAddress"
        ]
    );
}

#[tokio::test]
async fn omitted_ids_reach_database_defaults_and_invalid_forced_ids_are_not_replaced() {
    for policy in [
        IdGeneration::Database,
        IdGeneration::Custom(IdGenerator::new(|_| Ok(None))),
        IdGeneration::Custom(IdGenerator::new(|_| Ok(Some(String::new())))),
    ] {
        let mut config = config();
        config.advanced.database.generate_id = Some(policy);
        let auth = BetterAuth::<BundledSchema>::new(config)
            .store(database().await)
            .build()
            .await
            .unwrap();
        let result = auth
            .store()
            .create_user(
                CreateUser::new()
                    .with_email("database@example.com")
                    .with_name("Fixture"),
            )
            .await;
        assert!(
            result.is_err(),
            "A text primary key without a SQL default must reject an omitted ID"
        );
        assert!(
            auth.store()
                .get_user_by_email("database@example.com")
                .await
                .unwrap()
                .is_none()
        );
    }
    let mut config = config();
    config.advanced.database.generate_id = Some(IdGeneration::Uuid);
    let auth = BetterAuth::<BundledSchema>::new(config)
        .store(database().await)
        .build()
        .await
        .unwrap();
    for id in [
        "invalid-uuid",
        "",
        "63747488417541a0a68e153881808aec",
        "{63747488-4175-41a0-a68e-153881808aec}",
        "urn:uuid:63747488-4175-41a0-a68e-153881808aec",
        "63747488-4175-71a0-a68e-153881808aec",
    ] {
        let input = CreateUser {
            id: Some(id.into()),
            ..CreateUser::new()
                .with_email(format!("{id}@example.com"))
                .with_name("Fixture")
        };
        assert!(auth.store().create_user(input).await.is_err());
    }
    let valid = "63747488-4175-41a0-a68e-153881808aec";
    let row = auth
        .store()
        .create_user(CreateUser {
            id: Some(valid.into()),
            ..CreateUser::new()
                .with_email("valid@example.com")
                .with_name("Fixture")
        })
        .await
        .unwrap();
    assert_eq!(row.id, valid);
    let generated = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_email("generated@example.com")
                .with_name("Fixture"),
        )
        .await
        .unwrap();
    assert_eq!(
        uuid::Uuid::parse_str(generated.id.typed().unwrap())
            .unwrap()
            .get_version_num(),
        4
    );
}

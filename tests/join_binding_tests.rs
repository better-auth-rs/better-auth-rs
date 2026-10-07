#![cfg(feature = "seaorm2")]

use std::sync::Arc;

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, AuthStore, CreateAccount, CreateUser,
    id::IdGeneration,
    store::{EphemeralStore, JoinValue},
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::Database,
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};

async fn verify<S: AuthSchema>(store: &impl AuthStore<S>) -> AuthResult<()> {
    let user = store
        .create_user(
            CreateUser::new()
                .with_email("owner@example.test")
                .with_name("Owner"),
        )
        .await?;
    let account = store
        .create_account(CreateAccount {
            user_id: user.id.clone(),
            provider_id: "fixture".into(),
            account_id: "normal-account".into(),
            ..Default::default()
        })
        .await?;
    let joined = store
        .get_user_with_accounts("owner@example.test")
        .await?
        .ok_or_else(|| AuthError::internal("Expected user account join"))?;
    assert_eq!(joined.user.id, user.id);
    let JoinValue::Many(accounts) = joined.accounts else {
        return Err(AuthError::internal(
            "Expected the Account relationship page",
        ));
    };
    assert_eq!(accounts.len(), 1);
    let joined_account = accounts
        .first()
        .ok_or_else(|| AuthError::internal("Expected joined account"))?;
    assert_eq!(joined_account.id, account.id);
    assert_eq!(joined_account.user_id, user.id);
    let owner = store
        .get_account_owner("fixture", "normal-account")
        .await?
        .ok_or_else(|| AuthError::internal("Expected account owner join"))?;
    assert_eq!(owner.account.id, account.id);
    assert_eq!(owner.account.user_id, user.id);
    let JoinValue::One(owner_user) = owner.user else {
        return Err(AuthError::internal("Expected a single Account owner"));
    };
    assert_eq!(
        owner_user
            .ok_or_else(|| AuthError::internal("Expected owner"))?
            .id,
        user.id
    );
    Ok(())
}

#[tokio::test]
async fn ordinary_serial_and_uuid_relationships_use_canonical_stored_ids() -> AuthResult<()> {
    for mode in [IdGeneration::Serial, IdGeneration::Uuid] {
        for joins in [false, true] {
            let mut config = AuthConfig::default();
            config.advanced.database.generate_id = Some(mode.clone());
            config.advanced.database.joins = Some(joins);
            verify(&EphemeralStore::new(Arc::new(config))).await?;
        }
    }
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?;
    migrator::run_migrations(&database)
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?;
    let mut config = AuthConfig::default();
    config.advanced.database.generate_id = Some(IdGeneration::Uuid);
    verify(&SeaOrmStore::<BundledSchema>::new(config, database)).await
}

#![cfg(feature = "seaorm2")]

use better_auth::config::{FieldTransforms, UserFieldTransform};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, AuthSession, AuthStore, CreateAccount,
    CreateSession, CreateUser, CreateVerification,
    store::{
        EphemeralStore, RuntimeStore,
        database_hooks::{DatabaseHookContext, DatabaseHookControl, DatabaseHooks},
    },
    user_fields::UserFieldConfig,
    wire::AccountView,
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::Database,
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use chrono::{Duration, Utc};

#[derive(Clone, Default)]
struct AccountDeletes {
    before: Arc<AtomicUsize>,
    after: Arc<AtomicUsize>,
}

#[better_auth::database_hooks]
impl<S: AuthSchema> DatabaseHooks<S> for AccountDeletes {
    async fn before_delete_account(
        &self,
        _: &AccountView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        let _ = self.before.fetch_add(1, Ordering::SeqCst);
        Ok(DatabaseHookControl::Continue)
    }

    async fn after_delete_account(
        &self,
        _: &AccountView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        let _ = self.after.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn check_page<T>(result: AuthResult<Vec<T>>, expected: Option<usize>) -> AuthResult<()> {
    if let Some(count) = expected {
        assert_eq!(result?.len(), count);
    } else {
        let Err(error) = result else {
            return Err(AuthError::internal("SQLite accepted a noninteger LIMIT"));
        };
        assert!(error.to_string().contains("datatype mismatch"));
    }
    Ok(())
}

async fn check_limit<S: AuthSchema>(
    store: Arc<dyn AuthStore<S>>,
    expected: Option<usize>,
    projections: Arc<AtomicUsize>,
    hooks: AccountDeletes,
) -> AuthResult<()> {
    let user = store
        .create_user(
            CreateUser::new()
                .with_email("limit@example.test")
                .with_name("Fixture"),
        )
        .await?;
    let user_id = user.id.typed()?.clone();
    let mut tokens = Vec::new();
    for index in 0..4 {
        let _ = store
            .create_account(CreateAccount {
                user_id: user_id.clone().into(),
                provider_id: format!("provider-{index}").into(),
                account_id: format!("account-{index}").into(),
                ..Default::default()
            })
            .await?;
        let session = store
            .create_session(CreateSession {
                additional_fields: Default::default(),
                user_id: user_id.clone().into(),
                expires_at: Utc::now() + Duration::hours(1),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await?;
        tokens.push(session.token().to_owned());
        let _ = store
            .create_verification(CreateVerification {
                identifier: format!("expired-{index}").into(),
                value: "value".into(),
                expires_at: (Utc::now() - Duration::hours(1)).into(),
                ..Default::default()
            })
            .await?;
    }
    projections.store(0, Ordering::SeqCst);
    check_page(store.get_user_accounts(&user_id).await, expected)?;
    assert_eq!(projections.load(Ordering::SeqCst), expected.unwrap_or(0));
    check_page(store.get_user_sessions(&user_id).await, expected)?;

    assert!(
        store
            .get_verification_including_expired("expired-0")
            .await?
            .is_some()
    );
    assert_eq!(store.delete_expired_verifications().await?, 4);
    for index in 0..4 {
        assert!(
            store
                .get_verification_including_expired(&format!("expired-{index}"))
                .await?
                .is_none()
        );
    }

    assert!(store.delete_user_optional(&user_id, true).await?.is_some());
    assert_eq!(hooks.before.load(Ordering::SeqCst), expected.unwrap_or(0));
    assert_eq!(hooks.after.load(Ordering::SeqCst), expected.unwrap_or(0));
    for index in 0..4 {
        assert!(
            store
                .get_account(&format!("provider-{index}"), &format!("account-{index}"))
                .await?
                .is_none()
        );
    }
    for token in tokens {
        assert!(store.get_session(&token).await?.is_none());
    }
    assert!(store.get_user_by_id(&user_id).await?.is_none());
    Ok(())
}

fn config_with_projection_counter(
    limit: Option<f64>,
    projections: Arc<AtomicUsize>,
) -> Arc<AuthConfig> {
    let mut config = AuthConfig::default();
    config.advanced.database.default_find_many_limit = limit;
    let _ = config.account.additional_fields.insert(
        "providerId".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(move |value| {
                    let _ = projections.fetch_add(1, Ordering::SeqCst);
                    Ok(value)
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    Arc::new(config)
}

#[tokio::test]
async fn default_limits_apply_before_projection_and_cap_snapshots_without_capping_writes()
-> AuthResult<()> {
    for sqlite in [false, true] {
        for (limit, memory_count, sql_count) in [
            (None, 4, Some(4)),
            (Some(0.0), 0, Some(0)),
            (Some(1.0), 1, Some(1)),
            (Some(-1.0), 3, Some(4)),
            (Some(1.5), 1, None),
            (Some(f64::NAN), 0, None),
            (Some(f64::INFINITY), 4, None),
            (Some(f64::NEG_INFINITY), 0, None),
        ] {
            let projections = Arc::new(AtomicUsize::new(0));
            let config = config_with_projection_counter(limit, projections.clone());
            let hooks = AccountDeletes::default();
            if sqlite {
                let database = Database::connect("sqlite::memory:")
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                migrator::run_migrations(&database)
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                let store = SeaOrmStore::<BundledSchema>::new((*config).clone(), database)
                    .with_runtime(config, vec![Arc::new(hooks.clone())], Default::default())?;
                check_limit(store, sql_count, projections, hooks).await?;
            } else {
                let store = EphemeralStore::default().with_runtime(
                    config,
                    vec![Arc::new(hooks.clone())],
                    Default::default(),
                )?;
                check_limit(store, Some(memory_count), projections, hooks).await?;
            }
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and permission to create isolated test schemas"]
async fn live_postgres_integer_limits_preserve_projections_and_uncapped_writes()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use better_auth_seaorm::sea_orm::{ConnectOptions, ConnectionTrait};

    let mut options = ConnectOptions::new(std::env::var("BETTER_AUTH_TEST_POSTGRES_URL")?);
    let _ = options.max_connections(1).sqlx_logging(false);
    let database = Database::connect(options).await?;
    let schema = format!("ba_default_limit_{}", uuid::Uuid::new_v4().simple());
    let _ = database
        .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
        .await?;
    let worker = database.clone();
    let worker_schema = schema.clone();
    let result = tokio::spawn(async move {
        let _ = worker
            .execute_unprepared(&format!("SET search_path TO {worker_schema}"))
            .await?;
        migrator::run_migrations(&worker).await?;
        for (limit, count) in [(None, 4), (Some(0.0), 0), (Some(1.0), 1), (Some(8.0), 4)] {
            let projections = Arc::new(AtomicUsize::new(0));
            let config = config_with_projection_counter(limit, projections.clone());
            let hooks = AccountDeletes::default();
            let store = SeaOrmStore::<BundledSchema>::new((*config).clone(), worker.clone())
                .with_runtime(config, vec![Arc::new(hooks.clone())], Default::default())?;
            check_limit(store, Some(count), projections, hooks).await?;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await;
    let _ = database
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await?;
    database.close().await?;
    result??;
    Ok(())
}

#[tokio::test]
async fn secondary_session_lists_do_not_apply_database_find_many_limits() -> AuthResult<()> {
    use better_auth_core::store::{
        MemoryCacheAdapter, SessionStore, UserStore, secondary::SecondaryStore,
    };

    for persist_sessions in [false, true] {
        let mut config = AuthConfig::default();
        config.advanced.database.default_find_many_limit = Some(0.0);
        config.session.store_session_in_database = Some(persist_sessions);
        let config = Arc::new(config);
        let database = Arc::new(EphemeralStore::new(config.clone()));
        let store = SecondaryStore::new(
            database.clone(),
            Arc::new(MemoryCacheAdapter::new()),
            config,
            Default::default(),
        )?;
        let user = store
            .create_user(
                CreateUser::new()
                    .with_email("cached@example.test")
                    .with_name("Fixture"),
            )
            .await?;
        let mut tokens = Vec::new();
        for _ in 0..4 {
            let session = store
                .create_session(CreateSession {
                    additional_fields: Default::default(),
                    user_id: user.id.clone(),
                    expires_at: Utc::now() + Duration::hours(1),
                    ip_address: None,
                    user_agent: None,
                    impersonated_by: None,
                    active_organization_id: None,
                })
                .await?;
            tokens.push(session.token().to_owned());
        }
        assert_eq!(store.get_user_sessions(user.id.typed()?).await?.len(), 4);
        for token in tokens {
            assert_eq!(
                database.get_session(&token).await?.is_some(),
                persist_sessions
            );
        }
    }
    Ok(())
}

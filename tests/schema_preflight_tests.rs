#![cfg(feature = "seaorm2")]
#![allow(
    clippy::unwrap_used,
    reason = "Schema fixtures fail immediately when setup or observations differ"
)]

use async_trait::async_trait;
use better_auth::{AuthBuilder, AuthConfig, BetterAuth, server_api::EndpointInput};
use better_auth_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    HttpMethod,
    store::{
        UserStore,
        schema::{SchemaCheckError, SchemaFinding},
    },
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, DatabaseConnection, Statement},
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[path = "schema_preflight_tests/mysql.rs"]
mod mysql;

#[derive(Clone)]
struct Observe(Arc<AtomicUsize>);

#[async_trait]
impl AuthPlugin<BundledSchema> for Observe {
    fn name(&self) -> &'static str {
        "preflight-observer"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_http_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<BundledSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        let _ = self.0.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<BundledSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

fn config() -> AuthConfig {
    AuthConfig::new("schema-preflight-test-secret-at-least-thirty-two-characters")
        .base_url("http://localhost:3000")
}

async fn execute(db: &DatabaseConnection, sql: &str) {
    let _ = db
        .execute_raw(Statement::from_string(db.get_database_backend(), sql))
        .await
        .unwrap();
}

async fn build(
    store: SeaOrmStore<BundledSchema>,
    config: AuthConfig,
    observer: Observe,
) -> BetterAuth<BundledSchema> {
    AuthBuilder::new(config)
        .store(store)
        .plugin(observer)
        .build()
        .await
        .unwrap()
}

fn mismatch(error: AuthError) -> Arc<SchemaCheckError> {
    let AuthError::SchemaCheck(error) = error else {
        panic!("expected typed schema mismatch: {error}")
    };
    assert!(matches!(error.as_ref(), SchemaCheckError::Mismatch(_)));
    error
}

fn findings(error: &SchemaCheckError) -> &[SchemaFinding] {
    let SchemaCheckError::Mismatch(error) = error else {
        panic!("expected mismatch")
    };
    assert_eq!(error.code, "SCHEMA_MISMATCH");
    assert_eq!(error.source, "database");
    &error.findings
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and permission to create isolated test schemas"]
async fn live_postgres_preflight_tracks_migrations_defaults_and_search_path() {
    let mut options = better_auth_seaorm::sea_orm::ConnectOptions::new(
        std::env::var("BETTER_AUTH_TEST_POSTGRES_URL").unwrap(),
    );
    let _ = options.max_connections(1);
    let database = Database::connect(options).await.unwrap();
    let schema = format!("ba_preflight_{}", uuid::Uuid::new_v4().simple());
    let shadow = format!("{schema}_shadow");
    execute(&database, &format!("CREATE SCHEMA {schema}")).await;
    execute(&database, &format!("SET search_path TO {schema}")).await;
    let store = SeaOrmStore::new(config(), database.clone());
    let auth = build(store.clone(), config(), Observe(Default::default())).await;
    let missing = mismatch(http(&auth).await.unwrap_err());
    assert_eq!(findings(&missing).len(), 4);

    migrator::run_migrations(&database).await.unwrap();
    assert!(Arc::ptr_eq(
        &missing,
        &mismatch(http(&auth).await.unwrap_err())
    ));
    store.invalidate_schema_check();
    assert_eq!(http(&auth).await.unwrap().status, 200);
    assert_eq!(
        auth.call_endpoint(HttpMethod::Get, "/ok", EndpointInput::default())
            .await
            .unwrap()
            .status,
        200
    );

    execute(
        &database,
        "ALTER TABLE accounts ADD COLUMN legacy TEXT NOT NULL",
    )
    .await;
    assert_eq!(http(&auth).await.unwrap().status, 200);
    store.invalidate_schema_check();
    assert_eq!(
        findings(&mismatch(http(&auth).await.unwrap_err())),
        &[SchemaFinding::UnexpectedRequiredColumn {
            table: "accounts".into(),
            column: "legacy".into(),
        }]
    );
    execute(
        &database,
        "ALTER TABLE accounts ALTER COLUMN legacy SET DEFAULT ''",
    )
    .await;
    execute(
        &database,
        "ALTER TABLE accounts ADD COLUMN sequence_value BIGSERIAL",
    )
    .await;
    store.invalidate_schema_check();
    assert_eq!(http(&auth).await.unwrap().status, 200);

    execute(&database, &format!("CREATE SCHEMA {shadow}")).await;
    execute(
        &database,
        &format!("CREATE TABLE {shadow}.users (LIKE {schema}.users INCLUDING ALL)"),
    )
    .await;
    execute(
        &database,
        &format!("ALTER TABLE {shadow}.users DROP COLUMN email"),
    )
    .await;
    execute(&database, &format!("SET search_path TO {shadow}, {schema}")).await;
    store.invalidate_schema_check();
    assert_eq!(
        findings(&mismatch(http(&auth).await.unwrap_err())),
        &[SchemaFinding::MissingColumn {
            table: "users".into(),
            column: "email".into(),
        }]
    );
    execute(&database, &format!("SET search_path TO {schema}, {shadow}")).await;
    store.invalidate_schema_check();
    assert_eq!(http(&auth).await.unwrap().status, 200);
    execute(&database, &format!("DROP SCHEMA {shadow} CASCADE")).await;
    execute(&database, &format!("DROP SCHEMA {schema} CASCADE")).await;
    database.close().await.unwrap();
}

async fn http(auth: &BetterAuth<BundledSchema>) -> AuthResult<AuthResponse> {
    auth.handle_request(AuthRequest::new(HttpMethod::Get, "/api/auth/ok"))
        .await
}

#[tokio::test]
async fn missing_schema_rejects_shared_entries_before_hooks_but_not_disabled_http_or_raw_crud() {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    let store = SeaOrmStore::<BundledSchema>::new(config(), database);
    let observer = Observe(Default::default());
    let auth = build(store.clone(), config(), observer.clone()).await;
    let first = mismatch(http(&auth).await.unwrap_err());
    assert_eq!(
        findings(&first),
        &[
            SchemaFinding::MissingTable {
                table: "users".into()
            },
            SchemaFinding::MissingTable {
                table: "sessions".into()
            },
            SchemaFinding::MissingTable {
                table: "accounts".into()
            },
            SchemaFinding::MissingTable {
                table: "verifications".into()
            },
        ]
    );
    let native = mismatch(
        auth.call_endpoint(HttpMethod::Get, "/ok", EndpointInput::default())
            .await
            .unwrap_err(),
    );
    assert!(Arc::ptr_eq(&first, &native));
    let entered = Arc::new(AtomicUsize::new(0));
    let marker = entered.clone();
    let transaction = auth
        .context()
        .database
        .transaction_boxed(Box::new(move |_| {
            Box::pin(async move {
                let _ = marker.fetch_add(1, Ordering::SeqCst);
                Ok(Box::new(()) as better_auth_core::store::BoxedTransactionValue)
            })
        }))
        .await
        .err()
        .unwrap();
    assert!(Arc::ptr_eq(&first, &mismatch(transaction)));
    assert_eq!(entered.load(Ordering::SeqCst), 0);
    assert_eq!(observer.0.load(Ordering::SeqCst), 0);
    assert!(matches!(
        store.get_user_by_id("absent").await,
        Err(AuthError::Database(_))
    ));

    let mut disabled = config();
    disabled.disabled_paths.push("/ok".into());
    let disabled = build(store, disabled, observer).await;
    assert_eq!(http(&disabled).await.unwrap().status, 404);
    let _ = mismatch(
        disabled
            .call_endpoint(HttpMethod::Get, "/ok", EndpointInput::default())
            .await
            .unwrap_err(),
    );
}

#[tokio::test]
async fn runtime_disabled_retains_an_explicit_check() {
    let mut settings = config();
    settings.advanced.database.validate_schema = Some(false);
    let database = Database::connect("sqlite::memory:").await.unwrap();
    let queries = Arc::new(AtomicUsize::new(0));
    let count = queries.clone();
    let mut database = database;
    database.set_metric_callback(move |query| {
        if query.statement.sql.contains("sqlite_schema") {
            let _ = count.fetch_add(1, Ordering::SeqCst);
        }
    });
    let store = SeaOrmStore::new(settings.clone(), database);
    let auth = build(store, settings, Observe(Default::default())).await;
    assert_eq!(http(&auth).await.unwrap().status, 200);
    assert_eq!(
        auth.call_endpoint(HttpMethod::Get, "/ok", EndpointInput::default())
            .await
            .unwrap()
            .status,
        200
    );
    assert_eq!(queries.load(Ordering::SeqCst), 0);
    let _ = mismatch(
        auth.context()
            .database
            .schema_validation()
            .unwrap()
            .check
            .check()
            .await
            .unwrap_err(),
    );
    assert_eq!(queries.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cloned_stores_share_revision_but_auth_builds_have_independent_cached_verdicts() {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    let store = SeaOrmStore::new(config(), database.clone());
    let observer = Observe(Default::default());
    let first = build(store.clone(), config(), observer.clone()).await;
    let second = build(store.clone(), config(), observer.clone()).await;
    assert_eq!(http(&first).await.unwrap().status, 200);
    assert_eq!(http(&second).await.unwrap().status, 200);
    execute(
        &database,
        "ALTER TABLE accounts ADD COLUMN legacy TEXT NOT NULL",
    )
    .await;
    assert_eq!(http(&first).await.unwrap().status, 200);
    let independently_constructed = SeaOrmStore::new(config(), database.clone());
    let third = build(independently_constructed.clone(), config(), observer).await;
    let original = mismatch(http(&third).await.unwrap_err());
    assert_eq!(
        findings(&original),
        &[SchemaFinding::UnexpectedRequiredColumn {
            table: "accounts".into(),
            column: "legacy".into()
        }]
    );
    store.invalidate_schema_check();
    let _ = mismatch(http(&first).await.unwrap_err());
    let _ = mismatch(http(&second).await.unwrap_err());
    execute(&database, "ALTER TABLE accounts DROP COLUMN legacy").await;
    store.invalidate_schema_check();
    assert_eq!(http(&first).await.unwrap().status, 200);
    assert_eq!(http(&second).await.unwrap().status, 200);
    assert!(Arc::ptr_eq(
        &original,
        &mismatch(http(&third).await.unwrap_err())
    ));
    independently_constructed.invalidate_schema_check();
    assert_eq!(http(&third).await.unwrap().status, 200);
}

#[tokio::test]
async fn concurrent_http_and_native_calls_share_one_sqlite_introspection() {
    let mut database = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    let queries = Arc::new(AtomicUsize::new(0));
    let count = queries.clone();
    database.set_metric_callback(move |query| {
        if query.statement.sql.contains("sqlite_schema") {
            let _ = count.fetch_add(1, Ordering::SeqCst);
        }
    });
    let auth = Arc::new(
        build(
            SeaOrmStore::new(config(), database),
            config(),
            Observe(Default::default()),
        )
        .await,
    );
    let mut requests = tokio::task::JoinSet::new();
    for index in 0..16 {
        let auth = auth.clone();
        let _ = requests.spawn(async move {
            if index % 2 == 0 {
                http(&auth).await
            } else {
                auth.call_endpoint(HttpMethod::Get, "/ok", EndpointInput::default())
                    .await
            }
        });
    }
    while let Some(result) = requests.join_next().await {
        assert_eq!(result.unwrap().unwrap().status, 200);
    }
    assert_eq!(queries.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn active_transaction_does_not_reenter_global_schema_queries_after_invalidation() {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    let store = SeaOrmStore::new(config(), database.clone());
    let auth = build(store.clone(), config(), Observe(Default::default())).await;
    let auth = Arc::new(auth);
    let nested = auth.clone();
    let source = store.clone();
    let _ = auth
        .context()
        .database
        .transaction_boxed(Box::new(move |_| {
            Box::pin(async move {
                source.invalidate_schema_check();
                assert_eq!(
                    nested
                        .call_endpoint(HttpMethod::Get, "/ok", EndpointInput::default())
                        .await?
                        .status,
                    200
                );
                Ok(Box::new(()) as better_auth_core::store::BoxedTransactionValue)
            })
        }))
        .await
        .unwrap();
    assert_eq!(http(&auth).await.unwrap().status, 200);
}

#[allow(unreachable_pub, reason = "SeaORM derives require public entity types")]
mod mapped_user {
    use better_auth_seaorm::{
        AuthEntity,
        sea_orm::{self, entity::prelude::*},
    };
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "user")]
    #[sea_orm(table_name = "physical_people")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false, column_name = "person_pk")]
        pub id: String,
        pub name: Option<String>,
        #[sea_orm(column_name = "mail_address")]
        pub email: Option<String>,
        pub email_verified: bool,
        pub image: Option<String>,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
        #[serde(rename = "storedLabel")]
        #[sea_orm(column_name = "physical_label")]
        pub storage_label: Option<String>,
        pub unconfigured: String,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

struct Mapped;
impl better_auth_core::AuthSchema for Mapped {
    type User = mapped_user::Model;
    type Session = <BundledSchema as better_auth_core::AuthSchema>::Session;
    type Account = <BundledSchema as better_auth_core::AuthSchema>::Account;
    type Verification = <BundledSchema as better_auth_core::AuthSchema>::Verification;
}

#[tokio::test]
async fn physical_aliases_and_field_policies_do_not_hide_unconfigured_required_columns_or_execute_factories()
 {
    let mut settings = config();
    let factories = Arc::new(AtomicUsize::new(0));
    let calls = factories.clone();
    let _ = settings.user.fields_mut().insert(
        "label".into(),
        better_auth_core::user_fields::UserFieldConfig {
            field_name: Some("storedLabel".into()),
            required: Some(false),
            default_value_fn: Some(Arc::new(move || {
                let _ = calls.fetch_add(1, Ordering::SeqCst);
                "default".into()
            })),
            ..Default::default()
        },
    );
    let database = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    execute(&database, "CREATE TABLE physical_people (person_pk BLOB, name BLOB, mail_address BLOB, email_verified BLOB, image BLOB, created_at BLOB, updated_at BLOB, unconfigured TEXT NOT NULL)").await;
    let store = SeaOrmStore::<Mapped>::new(settings.clone(), database.clone());
    let auth = AuthBuilder::new(settings)
        .store(store.clone())
        .build()
        .await
        .unwrap();
    let check = &auth.context().database.schema_validation().unwrap().check;
    let error = mismatch(check.check().await.unwrap_err());
    assert_eq!(
        findings(&error),
        &[
            SchemaFinding::MissingColumn {
                table: "physical_people".into(),
                column: "physical_label".into()
            },
            SchemaFinding::UnexpectedRequiredColumn {
                table: "physical_people".into(),
                column: "unconfigured".into()
            },
        ]
    );
    assert_eq!(factories.load(Ordering::SeqCst), 0);
    execute(
        &database,
        "ALTER TABLE physical_people ADD COLUMN physical_label BLOB",
    )
    .await;
    execute(
        &database,
        "ALTER TABLE physical_people DROP COLUMN unconfigured",
    )
    .await;
    store.invalidate_schema_check();
    check.check().await.unwrap();
    assert_eq!(factories.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn pure_secondary_storage_does_not_require_session_or_verification_tables() {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    execute(&database, "DROP TABLE sessions").await;
    execute(&database, "DROP TABLE verifications").await;
    let store = SeaOrmStore::<BundledSchema>::new(config(), database);
    let auth = AuthBuilder::new(config())
        .store(store)
        .secondary_storage(Arc::new(better_auth_core::store::MemoryCacheAdapter::new()))
        .build()
        .await
        .unwrap();
    assert_eq!(http(&auth).await.unwrap().status, 200);
}

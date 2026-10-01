use super::*;
use better_auth::config::IdGeneration;
use better_auth::config::{FieldTransforms, UserFieldTransform};
use better_auth_core::CreateAccount;
use better_auth_core::UpdateAccount;
use better_auth_core::store::{AuthTransaction, transaction};
use sea_orm::{ConnectOptions, Statement};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone)]
struct Graph {
    user: String,
    session: String,
    token: String,
    account: String,
    verification: String,
}

fn session_input(user_id: &str) -> CreateSession {
    CreateSession {
        user_id: user_id.into(),
        expires_at: Utc::now() + chrono::Duration::hours(1),
        ip_address: None,
        user_agent: None,
        impersonated_by: None,
        active_organization_id: None,
        additional_fields: Default::default(),
    }
}

async fn create_graph(tx: &dyn AuthTransaction<LegacySchema>, label: &str) -> AuthResult<Graph> {
    let user = tx
        .create_user(
            CreateUser::new()
                .with_name(label)
                .with_email(format!("{label}@ids.test")),
        )
        .await?;
    let id = user.id.typed()?.clone();
    let session = tx.create_session(session_input(&id)).await?;
    let account = tx
        .create_account(CreateAccount {
            user_id: id.clone().into(),
            account_id: format!("provider-{label}").into(),
            provider_id: "fixture".into(),
            ..Default::default()
        })
        .await?;
    let verification = tx
        .create_verification(CreateVerification {
            identifier: label.into(),
            value: "verification".into(),
            expires_at: (Utc::now() + chrono::Duration::minutes(10)).into(),
            ..Default::default()
        })
        .await?;
    assert_eq!(session.user_id.typed()?, &id);
    assert_eq!(account.user_id.typed()?, &id);
    Ok(Graph {
        user: id,
        session: session.id.typed()?.clone(),
        token: session.token,
        account: account.id.typed()?.clone(),
        verification: verification.id.typed()?.clone(),
    })
}

async fn sql(database: &DatabaseConnection, statement: impl Into<String>) -> TestResult {
    let _ = database
        .execute_raw(Statement::from_string(
            database.get_database_backend(),
            statement,
        ))
        .await?;
    Ok(())
}

async fn verify_mode(database: DatabaseConnection, mode: IdGeneration) -> TestResult {
    run_app_migrations(&database).await?;
    for table in ["sessions", "accounts"] {
        sql(
            &database,
            format!("ALTER TABLE {table} ADD FOREIGN KEY (user_id) REFERENCES users(id)"),
        )
        .await?;
    }
    let mut config = test_config();
    config.advanced.database.generate_id = Some(mode);
    let auth = BetterAuth::<LegacySchema>::new(config.clone())
        .store(SeaOrmStore::<LegacySchema>::new(config, database.clone()))
        .plugin(EmailPasswordPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .plugin(AccountManagementPlugin::new())
        .build()
        .await?;
    let response = auth
        .handle_request(request(
            HttpMethod::Post,
            "/sign-up/email",
            Some(json!({
                "email":"owner@ids.test", "password":"Password123!", "name":"Owner"
            })),
        ))
        .await?;
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    let body: serde_json::Value = serde_json::from_slice(&response.body)?;
    let public_id = body["user"]["id"]
        .as_str()
        .expect("public ID must be a string");
    let physical_id: i32 = public_id.parse()?;
    let owner = user::Entity::find_by_id(physical_id)
        .one(&database)
        .await?
        .expect("created user");
    assert!(owner.id > 0);
    assert_eq!(owner.tenant_id, 1);
    assert_eq!(owner.locale, "en");
    let stored_session = session::Entity::find()
        .one(&database)
        .await?
        .expect("created session");
    let stored_account = account::Entity::find()
        .one(&database)
        .await?
        .expect("created account");
    assert_eq!(stored_session.user_id, physical_id);
    assert_eq!(stored_account.user_id, physical_id);
    let session_response = auth
        .handle_request(auth_request(
            HttpMethod::Get,
            "/get-session",
            body["token"].as_str().expect("signup token"),
        ))
        .await?;
    assert_eq!(session_response.status, 200);
    let session_body: serde_json::Value = serde_json::from_slice(&session_response.body)?;
    assert_eq!(session_body["user"]["id"], public_id);
    assert_eq!(session_body["session"]["id"], stored_session.id.to_string());
    assert_eq!(session_body["session"]["userId"], public_id);

    let committed = transaction(auth.store().as_ref(), |tx| {
        Box::pin(async move { create_graph(tx, "commit").await })
    })
    .await?;
    let committed_user: i32 = committed.user.parse()?;
    assert_eq!(
        session::Entity::find_by_id(committed.session.parse::<i32>()?)
            .one(&database)
            .await?
            .expect("committed session")
            .user_id,
        committed_user
    );
    assert_eq!(
        account::Entity::find_by_id(committed.account.parse::<i32>()?)
            .one(&database)
            .await?
            .expect("committed account")
            .user_id,
        committed_user
    );
    assert!(
        verification::Entity::find_by_id(committed.verification.parse::<i32>()?)
            .one(&database)
            .await?
            .is_some()
    );

    let captured = Arc::new(std::sync::Mutex::new(None));
    let rollback_capture = captured.clone();
    let result: AuthResult<()> = transaction(auth.store().as_ref(), move |tx| {
        Box::pin(async move {
            let graph = create_graph(tx, "rollback").await?;
            *rollback_capture.lock().expect("capture lock") = Some(graph);
            Err(AuthError::internal("numeric identity rollback"))
        })
    })
    .await;
    assert!(result.is_err());
    let rolled_back = captured
        .lock()
        .expect("capture lock")
        .clone()
        .expect("rollback graph");
    assert!(
        auth.store()
            .get_user_by_id(&rolled_back.user)
            .await?
            .is_none()
    );
    assert!(
        auth.store()
            .get_session(&rolled_back.token)
            .await?
            .is_none()
    );
    assert!(
        account::Entity::find_by_id(rolled_back.account.parse::<i32>()?)
            .one(&database)
            .await?
            .is_none()
    );
    assert!(
        verification::Entity::find_by_id(rolled_back.verification.parse::<i32>()?)
            .one(&database)
            .await?
            .is_none()
    );
    let next = auth
        .store()
        .create_user(CreateUser::new().with_email("next@ids.test"))
        .await?;
    // PostgreSQL sequences advance even when the surrounding transaction rolls back.
    assert!(next.id.typed()?.parse::<i32>()? > rolled_back.user.parse::<i32>()?);
    let session_count = session::Entity::find().count(&database).await?;
    assert!(
        auth.store()
            .create_session(session_input("2147483647"))
            .await
            .is_err()
    );
    assert_eq!(
        session::Entity::find().count(&database).await?,
        session_count
    );
    auth.store()
        .delete_verification(&committed.verification)
        .await?;
    assert!(
        verification::Entity::find_by_id(committed.verification.parse::<i32>()?)
            .one(&database)
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and permission to create isolated test schemas"]
async fn live_postgres_numeric_ids_preserve_defaults_references_and_transactions() -> TestResult {
    for mode in [IdGeneration::Serial, IdGeneration::Database] {
        let mut options = ConnectOptions::new(std::env::var("BETTER_AUTH_TEST_POSTGRES_URL")?);
        let _ = options.max_connections(1).sqlx_logging(false);
        let database = Database::connect(options).await?;
        let schema = format!("ba_numeric_{}", uuid::Uuid::new_v4().simple());
        sql(&database, format!("CREATE SCHEMA {schema}")).await?;
        sql(&database, format!("SET search_path TO {schema}")).await?;
        let worker_database = database.clone();
        // A failed assertion still releases the transaction before the isolated schema is removed.
        let result = tokio::spawn(async move { verify_mode(worker_database, mode).await }).await;
        sql(&database, format!("DROP SCHEMA {schema} CASCADE")).await?;
        database.close().await?;
        result??;
    }
    Ok(())
}

async fn verify_serial_coercion(database: DatabaseConnection) -> TestResult {
    run_app_migrations(&database).await?;
    if database.get_database_backend() == sea_orm::DbBackend::Postgres {
        for table in ["sessions", "accounts"] {
            sql(
                &database,
                format!("ALTER TABLE {table} ADD FOREIGN KEY (user_id) REFERENCES users(id)"),
            )
            .await?;
        }
    }
    let mut config = test_config();
    let inputs = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed = inputs.clone();
    let _ = config.account.additional_fields.insert(
        "userId".into(),
        better_auth_core::user_fields::UserFieldConfig {
            references: Some(better_auth_core::user_fields::UserFieldReference {
                model: "user".into(),
                field: "id".into(),
            }),
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    observed
                        .lock()
                        .expect("reference observations")
                        .push(value.clone());
                    Ok(if value.as_ref() == Some(&json!("alias")) {
                        Some(json!("0x10"))
                    } else {
                        value
                    })
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let auth = BetterAuth::<LegacySchema>::new(config.clone())
        .store(SeaOrmStore::<LegacySchema>::new(config, database.clone()))
        .build()
        .await?;
    let owner = auth
        .store()
        .create_user(CreateUser {
            id: Some("16".into()),
            ..CreateUser::new().with_email("coercion@ids.test")
        })
        .await?;
    assert_eq!(owner.id.typed()?, "16");
    let zero = auth
        .store()
        .create_user(CreateUser {
            id: Some("0".into()),
            ..CreateUser::new().with_email("zero@ids.test")
        })
        .await?;
    assert_eq!(zero.id.typed()?, "0");
    assert_eq!(
        auth.store()
            .get_user_by_id("")
            .await?
            .expect("zero owner")
            .id
            .typed()?,
        "0"
    );
    for alias in ["1.6e1", " 16 ", "0x10", "0o20", "0b10000"] {
        assert_eq!(
            auth.store()
                .get_user_by_id(alias)
                .await?
                .expect("owner")
                .id
                .typed()?,
            "16"
        );
    }
    let session = auth.store().create_session(session_input("0x10")).await?;
    assert_eq!(session.user_id.typed()?, "16");
    assert_eq!(auth.store().get_user_sessions("1.6e1").await?.len(), 1);
    let account = transaction(auth.store().as_ref(), |tx| {
        Box::pin(async move {
            assert_eq!(
                tx.get_user_by_id("0x10")
                    .await?
                    .expect("transaction owner")
                    .id
                    .typed()?,
                "16"
            );
            let session = tx.create_session(session_input("1.6e1")).await?;
            assert_eq!(session.user_id.typed()?, "16");
            tx.create_account(CreateAccount {
                user_id: "alias".into(),
                provider_id: "fixture".into(),
                account_id: "subject".into(),
                ..Default::default()
            })
            .await
        })
    })
    .await?;
    assert_eq!(
        *inputs.lock().expect("reference observations"),
        vec![Some(json!("alias"))]
    );
    let account_alias = format!("{}e0", account.id.typed()?);
    let account = auth
        .store()
        .update_account(
            &account_alias,
            UpdateAccount {
                user_id: "0b10000".into(),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(account.user_id.typed()?, "16");
    assert_eq!(auth.store().get_user_accounts("0x10").await?.len(), 1);
    let updated = auth
        .store()
        .update_user(
            "1.6e1",
            UpdateUser {
                name: Some("Updated".into()).into(),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(updated.name.typed().unwrap().as_deref(), Some("Updated"));
    let verification = auth
        .store()
        .create_verification(CreateVerification {
            identifier: "coerced-delete".into(),
            value: "token".into(),
            expires_at: (Utc::now() + chrono::Duration::minutes(10)).into(),
            ..Default::default()
        })
        .await?;
    auth.store()
        .delete_verification(&format!("{}e0", verification.id.typed()?))
        .await?;
    assert!(
        auth.store()
            .get_verification_by_identifier("coerced-delete")
            .await?
            .is_none()
    );
    for invalid in ["invalid", "1.5"] {
        assert!(auth.store().get_user_by_id(invalid).await.is_err());
    }
    // A database-generated identity does not enable the serial adapter's Number conversion.
    let mut config = test_config();
    config.advanced.database.generate_id = Some(IdGeneration::Database);
    let ordinary = BetterAuth::<LegacySchema>::new(config.clone())
        .store(SeaOrmStore::<LegacySchema>::new(config, database))
        .build()
        .await?;
    assert!(ordinary.store().get_user_by_id("1.6e1").await.is_err());
    assert!(ordinary.store().get_user_by_id("16").await?.is_some());
    Ok(())
}

#[tokio::test]
async fn sqlite_serial_ids_coerce_shared_reads_writes_and_transactions() -> TestResult {
    verify_serial_coercion(Database::connect("sqlite::memory:").await?).await
}

async fn verify_uuid_defaults(database: DatabaseConnection) -> TestResult {
    use better_auth_seaorm::store::__private_test_support::{
        bundled_schema::BundledSchema, migrator,
    };
    migrator::run_migrations(&database).await?;
    sql(
        &database,
        "ALTER TABLE users ALTER COLUMN id SET DEFAULT gen_random_uuid()::text",
    )
    .await?;
    let mut config = test_config();
    config.advanced.database.generate_id = Some(IdGeneration::Uuid);
    let auth = BetterAuth::<BundledSchema>::new(config.clone())
        .store(SeaOrmStore::new(config, database.clone()))
        .build()
        .await?;
    let canonical = "63747488-4175-41a0-a68e-153881808aec";
    for (index, value) in [
        canonical.to_owned(),
        canonical.replace('-', ""),
        format!("{{{canonical}}}"),
        format!("urn:uuid:{canonical}"),
        canonical.replace("41a0", "71a0"),
    ]
    .into_iter()
    .enumerate()
    {
        let row = auth
            .store()
            .create_user(CreateUser {
                id: Some(value.clone()),
                ..CreateUser::new()
                    .with_name(format!("UUID User {index}"))
                    .with_email(format!("uuid-{index}@ids.test"))
            })
            .await?;
        if index == 0 {
            assert_eq!(row.id.typed()?, canonical);
        } else {
            let id = row.id.typed()?;
            assert_ne!(id, &value);
            assert_ne!(id, canonical);
            assert_eq!(uuid::Uuid::parse_str(id)?.get_version_num(), 4);
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and permission to create isolated test schemas"]
async fn live_postgres_serial_coercion_and_uuid_defaults() -> TestResult {
    for uuid_mode in [false, true] {
        let mut options = ConnectOptions::new(std::env::var("BETTER_AUTH_TEST_POSTGRES_URL")?);
        let _ = options.max_connections(1).sqlx_logging(false);
        let database = Database::connect(options).await?;
        let schema = format!("ba_coercion_{}", uuid::Uuid::new_v4().simple());
        sql(&database, format!("CREATE SCHEMA {schema}")).await?;
        sql(&database, format!("SET search_path TO {schema}")).await?;
        let worker_database = database.clone();
        let result = tokio::spawn(async move {
            if !uuid_mode {
                return verify_serial_coercion(worker_database).await;
            }
            verify_uuid_defaults(worker_database).await
        })
        .await;
        sql(&database, format!("DROP SCHEMA {schema} CASCADE")).await?;
        database.close().await?;
        result??;
    }
    Ok(())
}

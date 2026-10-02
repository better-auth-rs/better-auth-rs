use better_auth::{
    AuthConfig, AuthSchema, BetterAuth,
    config::{IdGeneration, UserFieldConfig, UserFieldReference},
    prelude::{CreateAccount, CreateSession, CreateUser, CreateVerification},
    seaorm::{
        Database, SeaOrmAccountModel, SeaOrmOrganizationSchema, SeaOrmPluginSchema,
        SeaOrmSessionModel, SeaOrmStore, SeaOrmUserModel, SeaOrmVerificationModel,
        sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement},
    },
};
use serde_json::json;

#[path = "id_writes.rs"]
mod writes;

mod serial {
    include!(env!("BETTER_AUTH_SERIAL_SCHEMA"));
}
mod uuid {
    include!(env!("BETTER_AUTH_UUID_SCHEMA"));
}
mod database {
    include!(env!("BETTER_AUTH_DATABASE_SCHEMA"));
}
mod postgres_uuid {
    include!(env!("BETTER_AUTH_POSTGRES_UUID_SCHEMA"));
}
mod postgres_serial {
    include!(env!("BETTER_AUTH_POSTGRES_SERIAL_SCHEMA"));
}
async fn core_writes<S: AuthSchema, O: SeaOrmOrganizationSchema, P: SeaOrmPluginSchema>(
    database: DatabaseConnection,
    generation: IdGeneration,
) where
    S::User: SeaOrmUserModel,
    S::Session: SeaOrmSessionModel,
    S::Account: SeaOrmAccountModel,
    S::Verification: SeaOrmVerificationModel,
{
    let serial = matches!(generation, IdGeneration::Serial | IdGeneration::Database);
    let mut config = AuthConfig::new("generated-id-consumer-secret-at-least-32-characters");
    config.advanced.database.generate_id = Some(generation);
    config.account.additional_fields.insert(
        "owner".into(),
        UserFieldConfig {
            required: Some(false),
            field_name: Some("owner_id".into()),
            references: Some(UserFieldReference {
                model: "user".into(),
                field: "id".into(),
            }),
            ..Default::default()
        },
    );
    config.account.additional_fields.insert(
        "userId".into(),
        UserFieldConfig {
            required: Some(true),
            field_name: Some("user_id".into()),
            references: Some(UserFieldReference {
                model: "user".into(),
                field: "id".into(),
            }),
            ..Default::default()
        },
    );
    let auth = BetterAuth::<S>::new(config.clone())
        .store(
            SeaOrmStore::<S>::new(config, database.clone())
                .with_organization_schema::<O>()
                .with_plugin_schema::<P>(),
        )
        .build()
        .await
        .unwrap();
    let store = auth.store();
    store
        .schema_validation()
        .unwrap()
        .check_runtime()
        .await
        .unwrap();
    let user = store
        .create_user(
            CreateUser::new()
                .with_name("Generated")
                .with_email("generated@example.com"),
        )
        .await
        .unwrap();
    let id = user.id.typed().unwrap();
    if serial {
        assert_eq!(id, "1");
    } else {
        assert!(better_auth::__private_core::uuid::Uuid::parse_str(id).is_ok());
    }
    let session = store
        .create_session(CreateSession {
            user_id: user.id.clone(),
            expires_at: user.created_at + std::time::Duration::from_secs(3600),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            additional_fields: Default::default(),
        })
        .await
        .unwrap();
    assert_eq!(session.user_id.typed().unwrap(), id);
    let account = store
        .create_account(CreateAccount {
            user_id: user.id.clone(),
            account_id: "subject".into(),
            provider_id: "fixture".into(),
            additional_fields: [("owner".into(), json!(id))].into_iter().collect(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(account.user_id.typed().unwrap(), id);
    assert_eq!(account.additional_fields["owner"], json!(id));
    let verification = store
        .create_verification(CreateVerification {
            identifier: "proof".into(),
            value: "proof-value".into(),
            expires_at: (user.created_at + std::time::Duration::from_secs(3600)).into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(!verification.id.typed().unwrap().is_empty());
    assert!(store.get_user_by_id(id).await.unwrap().is_some());
    assert!(store.get_session(&session.token).await.unwrap().is_some());
    let backend = database.get_database_backend();
    let type_function = if backend == DbBackend::Postgres {
        "pg_typeof"
    } else {
        "typeof"
    };
    let row = database.query_one_raw(Statement::from_string(backend,
        format!("SELECT CAST({type_function}(users.id) AS TEXT) AS id_type, CAST({type_function}(sessions.user_id) AS TEXT) AS reference_type, CAST({type_function}(accounts.owner_id) AS TEXT) AS owner_type FROM users JOIN sessions ON sessions.user_id = users.id JOIN accounts ON accounts.user_id = users.id")
    )).await.unwrap().unwrap();
    for column in ["id_type", "reference_type", "owner_type"] {
        assert_eq!(
            row.try_get::<String>("", column).unwrap(),
            if serial {
                "integer"
            } else if backend == DbBackend::Postgres {
                "uuid"
            } else {
                "text"
            }
        );
    }
    let absent_id = if serial {
        "2147483647"
    } else {
        "00000000-0000-4000-8000-000000000000"
    };
    assert!(
        database
            .execute_unprepared(&format!("UPDATE accounts SET owner_id = '{absent_id}'"))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn generated_serial_ids_and_references_use_database_identity() {
    for generation in [IdGeneration::Serial, IdGeneration::Database] {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        serial::create_auth_tables(&database).await.unwrap();
        core_writes::<serial::AppAuthSchema, serial::AppOrganizationSchema, serial::AppPluginSchema>(database, generation).await;
    }
}

#[tokio::test]
async fn generated_uuid_ids_and_references_use_sqlite_text() {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    uuid::create_auth_tables(&database).await.unwrap();
    core_writes::<uuid::AppAuthSchema, uuid::AppOrganizationSchema, uuid::AppPluginSchema>(
        database,
        IdGeneration::Uuid,
    )
    .await;
}

async fn plugin_writes<S: AuthSchema, O: SeaOrmOrganizationSchema, P: SeaOrmPluginSchema>(
    database: DatabaseConnection,
    generation: IdGeneration,
) where
    S::User: SeaOrmUserModel,
    S::Session: SeaOrmSessionModel,
    S::Account: SeaOrmAccountModel,
    S::Verification: SeaOrmVerificationModel,
{
    use better_auth::__private_core::{CreateDeviceCode, UpdateDeviceCode};
    use better_auth::prelude::{CreateMember, CreateOrganization, CreateTeam, CreateTwoFactor};

    let serial_policy = matches!(generation, IdGeneration::Serial);
    let mut config = AuthConfig::new("generated-plugin-id-consumer-secret-at-least-32-characters");
    config.advanced.database.generate_id = Some(generation.clone());
    let auth = BetterAuth::<S>::new(config.clone())
        .store(
            SeaOrmStore::<S>::new(config, database.clone())
                .with_organization_schema::<O>()
                .with_plugin_schema::<P>(),
        )
        .build()
        .await
        .unwrap();
    let store = auth.store();
    let user = store
        .create_user(CreateUser::new().with_name("Plugin owner"))
        .await
        .unwrap();
    let owner = user.id.typed().unwrap();
    let factor = store
        .create_two_factor(CreateTwoFactor {
            user_id: owner.clone(),
            secret: "secret".into(),
            backup_codes: "codes".into(),
            verified: false,
        })
        .await
        .unwrap();
    assert!(!factor.id.typed().unwrap().is_empty());
    assert_eq!(factor.user_id, *owner);
    let organization = store
        .create_organization(CreateOrganization::new("Generated", "generated"))
        .await
        .unwrap();
    let member = store
        .create_member(CreateMember::new(
            organization.id.typed().unwrap(),
            owner,
            "owner",
        ))
        .await
        .unwrap();
    assert_eq!(member.organization_id, organization.id);
    assert_eq!(member.user_id, user.id);
    let team = store
        .create_team(CreateTeam {
            name: "Generated".into(),
            organization_id: organization.id.clone(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(team.organization_id, organization.id);
    let team_member = store
        .add_team_member(&team.id, owner, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(team_member.team_id, team.id);
    assert_eq!(team_member.user_id, *owner);
    assert!(
        store
            .get_two_factor_by_user_id(owner)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(store.list_user_teams(owner).await.unwrap()[0].id, team.id);
    assert_eq!(
        store
            .list_team_members(team.id.typed().unwrap())
            .await
            .unwrap()[0]
            .user_id,
        *owner
    );
    if serial_policy {
        let alias = format!("0x{:x}", owner.parse::<u64>().unwrap());
        assert_eq!(
            store
                .get_two_factor_by_user_id(&alias)
                .await
                .unwrap()
                .unwrap()
                .user_id,
            *owner
        );
        let alias = format!("{}e0", team.id.typed().unwrap());
        assert_eq!(
            store.list_team_members(&alias).await.unwrap()[0].user_id,
            *owner
        );
    }
    if database.get_database_backend() == DbBackend::Postgres {
        assert!(store.get_two_factor_by_user_id("invalid-id").await.is_err());
    }
    let device = store
        .create_device_code(CreateDeviceCode {
            device_code: "generated-device".into(),
            user_code: "generated-user-code".into(),
            user_id: None,
            expires_at: user.created_at + std::time::Duration::from_secs(300),
            status: "pending".into(),
            last_polled_at: None,
            polling_interval: Some(5),
            client_id: None,
            scope: Default::default(),
        })
        .await
        .unwrap();
    assert!(
        store
            .update_device_code_if_status(
                &device.id,
                "pending",
                UpdateDeviceCode {
                    user_id: Some(Some(owner.clone())),
                    ..Default::default()
                }
            )
            .await
            .unwrap()
    );
    assert_eq!(
        store
            .get_device_code_by_device_code("generated-device")
            .await
            .unwrap()
            .unwrap()
            .user_id
            .as_ref(),
        Some(owner)
    );
    assert!(
        store
            .update_device_code_if_status(
                &device.id,
                "pending",
                UpdateDeviceCode {
                    user_id: Some(None),
                    ..Default::default()
                }
            )
            .await
            .unwrap()
    );
    assert!(
        store
            .get_device_code_by_device_code("generated-device")
            .await
            .unwrap()
            .unwrap()
            .user_id
            .is_none()
    );
    store.delete_two_factor(owner).await.unwrap();
    assert!(
        store
            .get_two_factor_by_user_id(owner)
            .await
            .unwrap()
            .is_none()
    );
    writes::reference_writes::<S, O, P>(database, generation).await;
}

#[tokio::test]
async fn generated_serial_plugin_models_keep_public_reference_ids() {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    serial::create_auth_tables(&database).await.unwrap();
    plugin_writes::<serial::AppAuthSchema, serial::AppOrganizationSchema, serial::AppPluginSchema>(
        database,
        IdGeneration::Serial,
    )
    .await;
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and permission to create isolated test schemas"]
async fn live_postgres_generated_ids() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use better_auth::seaorm::sea_orm::ConnectOptions;
    for generation in [
        IdGeneration::Serial,
        IdGeneration::Database,
        IdGeneration::Uuid,
    ] {
        let mut options = ConnectOptions::new(std::env::var("BETTER_AUTH_TEST_POSTGRES_URL")?);
        options.max_connections(1).sqlx_logging(false);
        let database = Database::connect(options).await?;
        let schema = format!(
            "ba_generated_{}",
            better_auth::__private_core::uuid::Uuid::new_v4().simple()
        );
        database
            .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
            .await?;
        database
            .execute_unprepared(&format!("SET search_path TO {schema}"))
            .await?;
        let worker = database.clone();
        let result = tokio::spawn(async move {
            if matches!(generation, IdGeneration::Uuid) {
                postgres_uuid::create_auth_tables(&worker).await.unwrap();
                core_writes::<
                    postgres_uuid::AppAuthSchema,
                    postgres_uuid::AppOrganizationSchema,
                    postgres_uuid::AppPluginSchema,
                >(worker.clone(), generation.clone())
                .await;
                plugin_writes::<
                    postgres_uuid::AppAuthSchema,
                    postgres_uuid::AppOrganizationSchema,
                    postgres_uuid::AppPluginSchema,
                >(worker, generation)
                .await;
            } else {
                postgres_serial::create_auth_tables(&worker).await.unwrap();
                core_writes::<
                    postgres_serial::AppAuthSchema,
                    postgres_serial::AppOrganizationSchema,
                    postgres_serial::AppPluginSchema,
                >(worker.clone(), generation.clone())
                .await;
                plugin_writes::<
                    postgres_serial::AppAuthSchema,
                    postgres_serial::AppOrganizationSchema,
                    postgres_serial::AppPluginSchema,
                >(worker, generation)
                .await;
            }
        })
        .await;
        database
            .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
            .await?;
        database.close().await?;
        result?;
    }
    Ok(())
}

#[tokio::test]
async fn database_id_mode_requires_application_defaults() {
    let connection = Database::connect("sqlite::memory:").await.unwrap();
    database::create_auth_tables(&connection).await.unwrap();
    let mut config =
        AuthConfig::new("generated-database-id-consumer-secret-at-least-32-characters");
    config.advanced.database.generate_id = Some(IdGeneration::Database);
    let auth = BetterAuth::<database::AppAuthSchema>::new(config.clone())
        .store(
            SeaOrmStore::<database::AppAuthSchema>::new(config, connection)
                .with_organization_schema::<database::AppOrganizationSchema>()
                .with_plugin_schema::<database::AppPluginSchema>(),
        )
        .build()
        .await
        .unwrap();
    assert!(
        auth.store()
            .create_user(CreateUser::new().with_name("No default"))
            .await
            .is_err()
    );
}

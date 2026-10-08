#![cfg(feature = "seaorm2")]

use better_auth::AuthBuilder;
use better_auth_core::{
    AuthConfig, AuthResult, AuthSchema,
    plugin_runtime::ModelFields,
    store::{
        AccountOwner, MemoryCacheAdapter, UserAccounts,
        schema::{EntityRole, SchemaConfiguration},
    },
    user_fields::{UserFieldConfig, UserFieldReference},
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, Schema},
    store::{__private_test_support::migrator, entities},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Case {
    name: String,
    user_table: String,
    account_table: String,
    account_reference: Option<String>,
    #[serde(default)]
    user_references: bool,
    #[serde(default)]
    secondary_storage: bool,
    #[serde(default)]
    store_core: bool,
    joins: bool,
    operation: Operation,
    #[serde(rename = "invalid")]
    _invalid: bool,
    #[serde(rename = "events")]
    _events: Vec<Value>,
    result: Value,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Operation {
    Accounts,
    Owner,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    version: String,
    cases: Vec<Case>,
}

fn reference(model: &str) -> UserFieldConfig {
    UserFieldConfig {
        references: Some(UserFieldReference {
            model: model.into(),
            field: "id".into(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn result(value: AuthResult<()>) -> Value {
    match value {
        Ok(()) => Value::Null,
        Err(error) => json!({ "error": error.instrumentation_message() }),
    }
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The contract asserts complete captured results while propagating fixture I/O and decoding errors."
)]
fn logical_reference_resolution_matches_the_pinned_adapter_boundary()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture: Fixture = serde_json::from_slice(&std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/schema-join-reference-conflict-1.7.6.json"),
    )?)?;
    assert_eq!(fixture.version, "1.7.6");
    assert_eq!(fixture.cases.len(), 52);
    for case in fixture.cases {
        let mut config = AuthConfig::default();
        config.advanced.database.joins = Some(case.joins);
        config.session.store_session_in_database = Some(case.store_core);
        config.verification.store_in_database = case.store_core;
        let _ = config.account.additional_fields.insert(
            "userId".into(),
            reference(case.account_reference.as_deref().unwrap_or("user")),
        );
        if case.user_references {
            config.user.fields_mut().extend([
                ("name".into(), reference(&case.account_table)),
                ("image".into(), reference(&case.account_table)),
            ]);
        }
        let settings = SchemaConfiguration {
            config: Arc::new(config),
            plugins: Vec::new(),
            metadata: Default::default(),
            secondary_storage: case.secondary_storage,
            database_rate_limit: false,
        };
        let mut fields = ModelFields::default();
        fields.set_schema_configuration(&settings);
        let table_matches = |role, candidate: &str| match role {
            EntityRole::User => candidate == case.user_table,
            EntityRole::Account => candidate == case.account_table,
            EntityRole::Session => candidate == "auth_sessions",
            EntityRole::Verification => candidate == "auth_verifications",
            _ => false,
        };
        let actual = match case.operation {
            Operation::Accounts => {
                UserAccounts::validate_schema(&settings.config, &fields, table_matches)
            }
            Operation::Owner => {
                AccountOwner::validate_schema(&settings.config, &fields, table_matches)
            }
        };
        assert_eq!(
            result(actual),
            case.result,
            "{} {:?}",
            case.name,
            case.operation
        );
    }
    Ok(())
}

#[expect(
    unreachable_pub,
    reason = "SeaORM derives require public fixture entity types"
)]
mod session_named_user {
    use better_auth_seaorm::sea_orm::{self, entity::prelude::*};
    use serde::Serialize;

    #[derive(
        better_auth_seaorm::AuthEntity, Clone, Debug, PartialEq, Serialize, DeriveEntityModel,
    )]
    #[auth(role = "user")]
    #[sea_orm(table_name = "session")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: Option<String>,
        pub email: Option<String>,
        pub email_verified: bool,
        pub image: Option<String>,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

struct SessionNamedUserSchema;

impl AuthSchema for SessionNamedUserSchema {
    type User = session_named_user::Model;
    type Session = entities::session::Model;
    type Account = entities::account::Model;
    type Verification = entities::verification::Model;
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The contract asserts schema selection while propagating real database and authentication errors."
)]
async fn runtime_join_resolution_uses_secondary_storage_schema_presence()
-> Result<(), Box<dyn std::error::Error>> {
    for store_session in [false, true] {
        let database = Database::connect("sqlite::memory:").await?;
        migrator::run_migrations(&database).await?;
        let schema = Schema::new(database.get_database_backend());
        let _ = database
            .execute(&schema.create_table_from_entity(session_named_user::Entity))
            .await?;
        let mut config =
            AuthConfig::new("schema-reference-conflict-at-least-thirty-two-characters");
        config.logger.disabled = Some(true);
        config.telemetry.enabled = false;
        config.session.store_session_in_database = Some(store_session);
        let _ = config
            .account
            .additional_fields
            .insert("userId".into(), reference("session"));
        let auth = AuthBuilder::<SessionNamedUserSchema>::new(config.clone())
            .store(SeaOrmStore::<SessionNamedUserSchema>::new(config, database))
            .secondary_storage(Arc::new(MemoryCacheAdapter::new()))
            .build()
            .await?;
        let observed = auth
            .store()
            .get_user_with_accounts("absent@schema-reference.test")
            .await;
        if store_session {
            assert_eq!(
                result(observed.map(|_| ())),
                json!({ "error":
                    "No foreign key found for model account and base model user while performing join operation."
                })
            );
        } else {
            assert!(observed?.is_none());
        }
    }
    Ok(())
}

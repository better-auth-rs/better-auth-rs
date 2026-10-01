use better_auth::config::UserFieldTransform;
use better_auth::{
    AuthConfig, BetterAuth,
    config::{UserFieldConfig, UserFieldReference, UserFieldType},
    plugins::organization::{OrganizationConfig, OrganizationPlugin},
    prelude::CreateOrganization,
    seaorm::{
        Database, SeaOrmStore,
        sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, EntityTrait, Statement},
    },
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

mod generated {
    include!(env!("BETTER_AUTH_FIELD_ATTRIBUTES_SCHEMA"));
}

async fn setup() -> DatabaseConnection {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    database
        .execute_unprepared("CREATE TABLE external_tenants (tenant_code TEXT PRIMARY KEY)")
        .await
        .unwrap();
    generated::create_auth_tables(&database).await.unwrap();
    database
}

fn statement(sql: impl Into<String>) -> Statement {
    Statement::from_string(DbBackend::Sqlite, sql)
}

async fn insert_organization(database: &DatabaseConnection, id: &str, column: &str, value: &str) {
    database.execute_raw(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        format!("INSERT INTO app_organizations (id, display_name, slug, implicitRequired, created_at, updated_at, \"{column}\") VALUES (?, 'Attributes', 'shared-slug', 'required', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?)"),
        [id.into(), value.into()],
    )).await.unwrap();
}

#[tokio::test]
async fn generated_attributes_enforce_indexes_references_and_delete_actions() {
    let database = setup().await;
    let columns: BTreeMap<String, String> = database
        .query_all_raw(statement("PRAGMA table_info(app_organizations)"))
        .await
        .unwrap()
        .into_iter()
        .map(|row| {
            (
                row.try_get("", "name").unwrap(),
                row.try_get("", "type").unwrap(),
            )
        })
        .collect();
    assert_eq!(
        columns.get("fractional").map(String::as_str),
        Some("INTEGER")
    );
    assert_eq!(
        columns.get("wideFractional").map(String::as_str),
        Some("BIGINT")
    );
    assert_eq!(columns.get("owner_id").map(String::as_str), Some("TEXT"));
    assert_eq!(columns.get("bigOwner").map(String::as_str), Some("TEXT"));
    assert!(database.execute_unprepared("INSERT INTO app_organizations (id, display_name, slug, created_at, updated_at) VALUES ('missing-required', 'Invalid', 'invalid', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)").await.unwrap_err().to_string().contains("NOT NULL constraint failed"));
    assert!(database.execute_unprepared("INSERT INTO app_organizations (id, display_name, slug, implicitRequired, created_at, updated_at) VALUES ('null-required', 'Invalid', 'invalid', NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)").await.unwrap_err().to_string().contains("NOT NULL constraint failed"));
    database.execute_unprepared("INSERT INTO app_organizations (id, display_name, slug, implicitRequired, lookup, unique_code, created_at, updated_at) VALUES ('nullable-fields', 'Nullable', 'nullable', 'present', NULL, NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)").await.unwrap();

    let mut indexes = BTreeMap::<Vec<String>, Vec<bool>>::new();
    for row in database
        .query_all_raw(statement("PRAGMA index_list(app_organizations)"))
        .await
        .unwrap()
    {
        let name: String = row.try_get("", "name").unwrap();
        let unique: i64 = row.try_get("", "unique").unwrap();
        let columns = database
            .query_all_raw(statement(format!("PRAGMA index_info('{name}')")))
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.try_get("", "name").unwrap())
            .collect();
        indexes.entry(columns).or_default().push(unique != 0);
    }
    assert_eq!(
        indexes.get(&vec!["display_name".into()]),
        Some(&vec![false])
    );
    assert_eq!(indexes.get(&vec!["lookup".into()]), Some(&vec![false]));
    assert_eq!(indexes.get(&vec!["unique_code".into()]), Some(&vec![true]));
    assert!(!indexes.contains_key(&vec!["sorted".into()]));
    assert!(!indexes.contains_key(&vec!["slug".into()]));

    let member_keys = database
        .query_all_raw(statement("PRAGMA foreign_key_list(app_members)"))
        .await
        .unwrap();
    assert!(
        !member_keys
            .iter()
            .any(|row| row.try_get::<String>("", "from").unwrap() == "workspace_id")
    );
    let team_keys = database
        .query_all_raw(statement("PRAGMA foreign_key_list(app_teams)"))
        .await
        .unwrap();
    let team_key = team_keys
        .iter()
        .find(|row| row.try_get::<String>("", "from").unwrap() == "workspace_id")
        .unwrap();
    assert_eq!(
        team_key.try_get::<String>("", "table").unwrap(),
        "app_organizations"
    );
    assert_eq!(
        team_key.try_get::<String>("", "on_delete").unwrap(),
        "RESTRICT"
    );

    for (column, action) in [
        ("cascadeOwner", "CASCADE"),
        ("restrictedOwner", "RESTRICT"),
        ("noActionOwner", "NO ACTION"),
        ("nullOwner", "SET NULL"),
        ("defaultOwner", "SET DEFAULT"),
    ] {
        database
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "INSERT INTO external_tenants VALUES (?)",
                [column.into()],
            ))
            .await
            .unwrap();
        insert_organization(&database, column, column, column).await;
        let deletion = database
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "DELETE FROM external_tenants WHERE tenant_code = ?",
                [column.into()],
            ))
            .await;
        if matches!(action, "RESTRICT" | "NO ACTION") {
            assert!(
                deletion
                    .unwrap_err()
                    .to_string()
                    .contains("FOREIGN KEY constraint failed")
            );
        } else {
            deletion.unwrap();
            let row = database
                .query_one_raw(Statement::from_sql_and_values(
                    DbBackend::Sqlite,
                    format!("SELECT \"{column}\" AS value FROM app_organizations WHERE id = ?"),
                    [column.into()],
                ))
                .await
                .unwrap();
            if action == "CASCADE" {
                assert!(row.is_none());
            } else {
                assert_eq!(
                    row.unwrap().try_get::<Option<String>>("", "value").unwrap(),
                    None
                );
            }
        }
    }
    let invalid = database
        .execute_unprepared("UPDATE app_organizations SET cascadeOwner = 'missing-tenant'")
        .await
        .unwrap_err();
    assert!(
        invalid
            .to_string()
            .contains("FOREIGN KEY constraint failed")
    );

    insert_organization(&database, "unique-parent", "unique_code", "parent-code").await;
    insert_organization(&database, "mapped-child", "mapped_owner", "parent-code").await;
    let duplicate = database
        .execute_unprepared(
            "UPDATE app_organizations SET unique_code = 'parent-code' WHERE id = 'mapped-child'",
        )
        .await
        .unwrap_err();
    assert!(duplicate.to_string().contains("UNIQUE constraint failed"));
    database
        .execute_unprepared("DELETE FROM app_organizations WHERE id = 'unique-parent'")
        .await
        .unwrap();
    let child = database
        .query_one_raw(statement(
            "SELECT mapped_owner FROM app_organizations WHERE id = 'mapped-child'",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        child.try_get::<Option<String>>("", "mapped_owner").unwrap(),
        None
    );
}

fn runtime_fields(output_calls: Arc<AtomicUsize>) -> OrganizationConfig {
    let schema: Value =
        serde_json::from_str(include_str!("../../field-attributes-schema.json")).unwrap();
    let mut config = OrganizationConfig::default();
    for (model, definition) in schema.as_object().unwrap() {
        let fields = match model.as_str() {
            "organization" => &mut config.schema.organization,
            "member" => &mut config.schema.member,
            "team" => &mut config.schema.team,
            _ => continue,
        };
        for (name, definition) in definition
            .get("additionalFields")
            .unwrap()
            .as_object()
            .unwrap()
        {
            let field_type = match definition.get("type").and_then(Value::as_str).unwrap() {
                "string" => UserFieldType::String,
                "number" => UserFieldType::Number,
                "boolean" => UserFieldType::Boolean,
                "json" => UserFieldType::Json,
                "string[]" => UserFieldType::StringArray,
                field_type => panic!("unexpected fixture type {field_type}"),
            };
            let mut field = UserFieldConfig {
                field_type,
                required: definition.get("required").and_then(Value::as_bool),
                field_name: definition
                    .get("fieldName")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                default_value: definition.get("defaultValue").cloned(),
                references: definition
                    .get("references")
                    .map(|reference| UserFieldReference {
                        model: reference
                            .get("model")
                            .and_then(Value::as_str)
                            .unwrap()
                            .to_owned(),
                        field: reference
                            .get("field")
                            .and_then(Value::as_str)
                            .unwrap()
                            .to_owned(),
                    }),
                ..Default::default()
            };
            if name == "transformedOwner" {
                let calls = output_calls.clone();
                field.output_transform = Some(UserFieldTransform::new(move |value| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(value, Some(json!("12.5")));
                    Ok(Some(json!({"original":value})))
                }));
            }
            fields.additional_fields.insert(name.clone(), field);
        }
    }
    config
}

#[tokio::test]
async fn generated_id_references_keep_database_bindings_and_output_conversion_order() {
    let database = setup().await;
    for id in [
        "12.5",
        "1",
        "{\"tenant\":\"A\"}",
        "[\"A\",\"B\"]",
        "1.0e+20",
        "0.0",
    ] {
        database.execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO app_users (id, name, email, email_verified, created_at, updated_at) VALUES (?, 'Reference', ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
            [id.into(), format!("{id}@reference.example").into()],
        )).await.unwrap();
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let config = AuthConfig::new("consumer-field-attributes-secret-at-least-32-characters");
    let auth = BetterAuth::<generated::AppAuthSchema>::new(config.clone())
        .store(
            SeaOrmStore::<generated::AppAuthSchema>::new(config, database.clone())
                .with_organization_schema::<generated::AppOrganizationSchema>(),
        )
        .plugin(OrganizationPlugin::with_config(runtime_fields(
            calls.clone(),
        )))
        .build()
        .await
        .unwrap();
    let mut input = CreateOrganization::new("Attributes", "attributes");
    input.additional_fields = json!({
        "fractional":1.25, "wideFractional":1.25, "owner":12.5, "bigOwner":12.5, "transformedOwner":12.5,
        "flagOwner":true, "jsonOwner":{"tenant":"A"}, "arrayOwner":["A","B"]
    })
    .as_object()
    .unwrap()
    .clone();
    let created = auth.store().create_organization(input).await.unwrap();
    let found = auth
        .store()
        .get_organization_by_id(created.id.typed().unwrap())
        .await
        .unwrap()
        .unwrap();
    for organization in [created.clone(), found] {
        let fields = serde_json::to_value(organization).unwrap();
        assert_eq!(fields.get("owner"), Some(&json!("12.5")));
        assert_eq!(fields.get("bigOwner"), Some(&json!("12.5")));
        assert_eq!(
            fields.get("transformedOwner"),
            Some(&json!("[object Object]"))
        );
        assert_eq!(fields.get("flagOwner"), Some(&json!("1")));
        assert_eq!(fields.get("jsonOwner"), Some(&json!("{\"tenant\":\"A\"}")));
        assert_eq!(fields.get("arrayOwner"), Some(&json!("[\"A\",\"B\"]")));
        assert_eq!(fields.get("fractional"), Some(&json!(1.25)));
        assert_eq!(fields.get("wideFractional"), Some(&json!(1.25)));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let stored = generated::organization::Entity::find_by_id(created.id.typed().unwrap())
        .one(&database)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.fractional.map(f64::from), Some(1.25));
    assert_eq!(stored.wide_fractional.map(f64::from), Some(1.25));
    assert_eq!(serde_json::to_value(stored.owner).unwrap(), json!("12.5"));

    // The SQL driver, not JavaScript String(), determines text affinity for numeric input.
    for (value, expected) in [(json!(1e20), "1.0e+20"), (json!(-0.0), "0.0")] {
        let mut update = better_auth::prelude::UpdateOrganization::default();
        update.additional_fields.insert("owner".into(), value);
        let updated = auth
            .store()
            .update_organization(created.id.typed().unwrap(), update)
            .await
            .unwrap();
        assert_eq!(
            serde_json::to_value(updated).unwrap().get("owner"),
            Some(&json!(expected))
        );
    }
}

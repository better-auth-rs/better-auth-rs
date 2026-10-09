use super::{
    contract::{TestResult, stored},
    lifecycle_models::Schema,
    trace::{Event, Trace},
};
use better_auth_core::{
    AuthConfig, AuthResult, FieldMap, FieldValue, UpdateUser,
    store::{
        AuthStore, RuntimeStore,
        database_hooks::{DatabaseHookContext, DatabaseHookUpdate, DatabaseHooks},
    },
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform, UserFieldType},
    wire::UserView,
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, DatabaseConnection},
};
use serde_json::{Value, json};
use std::sync::Arc;

struct Hooks(Trace);

#[better_auth::database_hooks()]
impl DatabaseHooks<Schema> for Hooks {
    async fn before_update_user(
        &self,
        fields: &mut FieldMap,
        _: &DatabaseHookContext<'_, Schema>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        self.0
            .callback(json!({"phase": "before", "data": fields.json()?}));
        Ok(DatabaseHookUpdate::Continue)
    }

    async fn after_update_user(
        &self,
        user: Option<&UserView>,
        _: &DatabaseHookContext<'_, Schema>,
    ) -> AuthResult<()> {
        self.0.callback(json!({
            "phase": "after",
            "data": user.cloned().map(FieldMap::from).map(|fields| fields.json()).transpose()?,
        }));
        Ok(())
    }
}

pub(super) async fn check(mut database: DatabaseConnection) -> TestResult {
    let _ = database.execute_unprepared(
        "CREATE TABLE `user` (`id` VARCHAR(255) PRIMARY KEY, `name` TEXT, `email` VARCHAR(255), `emailVerified` BOOLEAN NOT NULL, `image` TEXT, `createdAt` TIMESTAMP(3) NOT NULL, `updatedAt` TIMESTAMP(3) NOT NULL)",
    ).await?;
    let _ = database.execute_unprepared(
        "INSERT INTO `user` VALUES ('owner', 'Owner', 'before', 0, NULL, '2030-01-02 03:04:05.000', '2030-01-02 03:04:05.000'), ('other', 'Other', 'unrelated', 0, NULL, '2030-01-02 03:04:05.000', '2030-01-02 03:04:05.000')",
    ).await?;
    let mut expected_storage = stored(&database, "user", "id").await?;
    let trace = Trace::default();
    trace.capture(&mut database);
    let mut config = AuthConfig::new("mysql-update-readback-secret-at-least-32-characters");
    config.logger.disabled = Some(true);
    config.telemetry.enabled = false;
    let _ = config.user.fields_mut().insert(
        "updatedAt".into(),
        UserFieldConfig {
            field_type: UserFieldType::Date,
            ..Default::default()
        },
    );
    let input = trace.clone();
    let output = trace.clone();
    let _ = config.user.fields_mut().insert(
        "contact".into(),
        UserFieldConfig {
            field_name: Some("email".into()),
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    input.callback(json!({"phase":"input", "value":value.json()?}));
                    Ok(value)
                })),
                output: Some(UserFieldTransform::new(move |value| {
                    output.callback(json!({"phase":"output", "value":value.json()?}));
                    Ok(value)
                })),
            }),
            ..Default::default()
        },
    );
    let config = Arc::new(config);
    let raw: Arc<dyn AuthStore<Schema>> = Arc::new(SeaOrmStore::<Schema>::new(
        config.as_ref().clone(),
        database.clone(),
    ));
    let store = RuntimeStore::with_runtime(
        raw.as_ref(),
        config,
        vec![Arc::new(Hooks(trace.clone()))],
        Default::default(),
    )?;
    let mut expected = FieldMap::from(store.get_user_by_id("owner").await?.expect("seeded owner"));

    for (selector, previous, next) in [
        ("email", "before".into(), "after".into()),
        ("contact", "after".into(), FieldValue::Null),
        ("contact", FieldValue::Null, "final".into()),
    ] {
        let _ = trace.take();
        let mut fields = FieldMap::new();
        let _ = fields.insert(selector.into(), next.clone());
        let returned = store
            .update_user_by_field_value(
                selector,
                &previous,
                UpdateUser {
                    additional_fields: fields.clone(),
                    ..Default::default()
                },
            )
            .await?
            .expect("the updated selector must reselect the written row");
        let _ = expected.insert("email".into(), next.clone());
        let _ = expected.insert("contact".into(), next.clone());
        assert_eq!(
            FieldMap::from(returned),
            expected,
            "{selector} complete output"
        );

        let events = trace.take();
        let phases = events
            .iter()
            .map(|event| match event {
                Event::Callback(value) => value["phase"].as_str().expect("callback phase"),
                Event::Sql { statement, .. } if statement.sql.starts_with("UPDATE ") => "write",
                Event::Sql { .. } => "read",
                event => panic!("Unexpected update event: {event:?}"),
            })
            .collect::<Vec<_>>();
        let mut expected_phases = vec!["before"];
        if selector == "contact" {
            expected_phases.push("input");
        }
        expected_phases.extend(["write", "read", "output", "after"]);
        assert_eq!(
            phases, expected_phases,
            "{selector} complete lifecycle order"
        );
        let callbacks = events
            .iter()
            .filter_map(|event| match event {
                Event::Callback(value) => Some(value.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let mut expected_callbacks = vec![json!({"phase":"before", "data":fields.json()?})];
        if selector == "contact" {
            expected_callbacks.push(json!({"phase":"input", "value":next.json()?}));
        }
        expected_callbacks.extend([
            json!({"phase":"output", "value":next.json()?}),
            json!({"phase":"after", "data":expected.json()?}),
        ]);
        assert_eq!(
            callbacks, expected_callbacks,
            "{selector} callback order and values"
        );
        let sql = events
            .iter()
            .filter_map(|event| match event {
                Event::Sql { statement, failed } => {
                    assert!(!failed, "{statement:?}");
                    Some(statement)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(sql.len(), 2, "only UPDATE and readback: {events:?}");
        assert!(sql[0].sql.starts_with("UPDATE `user` SET "));
        let ending = if next.is_null() {
            "WHERE `user`.`email` IS NULL"
        } else {
            "WHERE `user`.`email` = ?"
        };
        assert!(sql[1].sql.ends_with(ending), "{}", sql[1].sql);
        let expected_binding = next
            .as_str()
            .map(|value| vec![better_auth_seaorm::sea_orm::Value::from(value)])
            .unwrap_or_default();
        assert_eq!(
            sql[1]
                .values
                .as_ref()
                .map(|values| values.0.clone())
                .unwrap_or_default(),
            expected_binding
        );

        let rows = expected_storage.as_array_mut().expect("stored rows");
        let row = rows
            .iter_mut()
            .find(|row| row["row"]["id"] == "owner")
            .expect("stored owner");
        row["row"]["email"] = next.json()?.unwrap_or(Value::Null);
        assert_eq!(
            stored(&database, "user", "id").await?,
            expected_storage,
            "{selector} complete storage and unrelated row"
        );
    }
    Ok(())
}

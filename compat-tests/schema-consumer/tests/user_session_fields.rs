use better_auth::{
    AuthConfig, BetterAuth, FieldDate, FieldMap, FieldValue,
    config::{FieldTransforms, UserFieldConfig, UserFieldTransform, UserFieldType},
    prelude::{CreateSession, CreateUser, UpdateUser},
    seaorm::{
        Database, SeaOrmStore,
        sea_orm::{ConnectionTrait, DbBackend, Statement},
    },
};
use serde_json::{Value, json};

mod generated {
    include!(env!("BETTER_AUTH_USER_SESSION_FIELDS_SCHEMA"));
}

#[tokio::test]
async fn generated_user_and_session_fields_preserve_storage_and_projection() {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    generated::create_auth_tables(&database).await.unwrap();
    let mut config = AuthConfig::new("generated-user-session-fields-consumer-secret");
    config.user.fields_mut().insert(
        "label".into(),
        UserFieldConfig {
            required: Some(false),
            field_name: Some("stored_user_label".into()),
            ..Default::default()
        },
    );
    config.session.fields_mut().extend([
        (
            "label".into(),
            UserFieldConfig {
                required: Some(false),
                field_name: Some("stored_label".into()),
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(|value| {
                        if value.is_undefined() {
                            return Ok(value);
                        }
                        Ok(format!("stored:{}", value.as_str().unwrap()).into())
                    })),
                    output: Some(UserFieldTransform::new(|value| {
                        if value.is_undefined() {
                            return Ok(value);
                        }
                        Ok(FieldMap::from([("stored".into(), value)]).into())
                    })),
                }),
                ..Default::default()
            },
        ),
        (
            "rating".into(),
            UserFieldConfig {
                field_type: UserFieldType::Number,
                required: Some(false),
                field_name: Some("stored_rating".into()),
                ..Default::default()
            },
        ),
        (
            "details".into(),
            UserFieldConfig {
                field_type: UserFieldType::Json,
                required: Some(false),
                field_name: Some("stored_details".into()),
                ..Default::default()
            },
        ),
        (
            "pinned".into(),
            UserFieldConfig {
                field_type: UserFieldType::Boolean,
                required: Some(false),
                default_value: Some(false.into()),
                ..Default::default()
            },
        ),
    ]);
    let auth = BetterAuth::<generated::AppAuthSchema>::new(config.clone())
        .store(SeaOrmStore::<generated::AppAuthSchema>::new(
            config,
            database.clone(),
        ))
        .build()
        .await
        .unwrap();
    let store = auth.store();
    let mut input = CreateUser::new()
        .with_email("session-display@example.com")
        .with_name("Display");
    input.additional_fields = [("label".into(), "reader".into())].into_iter().collect();
    let user = store.create_user(input).await.unwrap();
    assert_eq!(
        json!(user.additional_fields.json().unwrap()),
        json!({ "label": "reader" })
    );
    let session = store
        .create_session(CreateSession {
            inherited_fields: Default::default(),
            user_id: user.id.clone(),
            expires_at: FieldDate::from_milliseconds(
                user.created_at.date_milliseconds().unwrap() + 3_600_000.0,
            ),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            additional_fields: [
                ("label".into(), "create".into()),
                ("rating".into(), 1.25.into()),
                (
                    "details".into(),
                    FieldValue::from_json(json!({ "topic": "sample" })).unwrap(),
                ),
            ]
            .into_iter()
            .collect(),
        })
        .await
        .unwrap();
    assert_eq!(
        json!(session.additional_fields.json().unwrap()),
        json!({
            "label": { "stored": "stored:create" },
            "rating": 1.25,
            "details": { "topic": "sample" },
            "pinned": false,
        })
    );
    let user = store
        .update_user(
            user.id.typed().unwrap(),
            UpdateUser {
                additional_fields: [("label".into(), "editor".into())].into_iter().collect(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        json!(user.additional_fields.json().unwrap()),
        json!({ "label": "editor" })
    );
    let updated = store
        .update_session_fields(
            session.token.typed().unwrap(),
            [
                ("label".into(), "edit".into()),
                ("rating".into(), 2.25.into()),
            ]
            .into_iter()
            .collect(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        json!(updated.additional_fields.json().unwrap()),
        json!({
            "label": { "stored": "stored:edit" },
            "rating": 2.25,
            "details": { "topic": "sample" },
            "pinned": false,
        })
    );
    let found = store
        .get_session(session.token.typed().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.additional_fields, updated.additional_fields);
    let found = store
        .get_user_by_id(user.id.typed().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.additional_fields, user.additional_fields);
    let stored = database
        .query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT stored_label, stored_rating, stored_details, pinned FROM display_sessions",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.try_get::<String>("", "stored_label").unwrap(),
        "stored:edit"
    );
    assert_eq!(stored.try_get::<f64>("", "stored_rating").unwrap(), 2.25);
    assert_eq!(
        serde_json::from_str::<Value>(&stored.try_get::<String>("", "stored_details").unwrap())
            .unwrap(),
        json!({ "topic": "sample" })
    );
    assert!(!stored.try_get::<bool>("", "pinned").unwrap());
    let stored = database
        .query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT stored_user_label FROM user",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.try_get::<String>("", "stored_user_label").unwrap(),
        "editor"
    );
    database.close().await.unwrap();
}

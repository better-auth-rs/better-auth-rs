use super::*;

#[expect(unreachable_pub, reason = "SeaORM derives require public model items")]
mod user {
    use super::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[sea_orm(table_name = "skipped_nullable_query_users")]
    #[auth(role = "user")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: Option<String>,
        pub email: Option<String>,
        pub email_verified: bool,
        pub image: Option<String>,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
        pub stored_marker: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub stored_label: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

struct Tables;
impl AuthSchema for Tables {
    type User = user::Model;
    type Account = entities::account::Model;
    type Session = entities::session::Model;
    type Verification = entities::verification::Model;
}

async fn contract() -> Result<(), Box<dyn std::error::Error>> {
    let trace = Trace::default();
    let config = config(&trace);
    let db = Database::connect("sqlite::memory:").await?;
    let _ = db
        .execute(&Schema::new(db.get_database_backend()).create_table_from_entity(user::Entity))
        .await?;
    let store = SeaOrmStore::<Tables>::new(config, db);
    for (marker, label) in [
        ("alpha", None),
        ("beta", Some(Value::Null)),
        ("gamma", Some(json!("ordinary"))),
    ] {
        let mut additional_fields = Map::from_iter([("marker".into(), json!(marker))]);
        if let Some(label) = label {
            let _ = additional_fields.insert("label".into(), label);
        }
        let _ = store
            .create_user(CreateUser {
                name: Some(format!("Skipped Null {marker}")).into(),
                email: Some(format!("{marker}@skipped-null-query.test")),
                email_verified: Some(false),
                additional_fields: FieldMap::from_json(additional_fields)?,
                ..Default::default()
            })
            .await?;
    }
    let _ = take_events(&trace)?;
    let (users, total) = store
        .list_users(params("label", FieldValue::Null, "ne"))
        .await?;
    assert_eq!(
        json!({
            "events":take_events(&trace)?,
            "result":{"users":users.into_iter().map(display).collect::<AuthResult<Vec<_>>>()?,"total":total},
        }),
        json!({
            "events":[["output","label",{"defined":true,"value":"ordinary"}]],
            "result":{
                "users":[{
                    "marker":{"own":true,"value":{"defined":true,"value":"gamma"}},
                    "label":{"own":true,"value":{"defined":true,"value":"ordinary"}},
                }],
                "total":1,
            },
        }),
    );
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::expect_used,
    reason = "Setup errors and complete SQL null query differences must fail this regression"
)]
async fn sqlite_ne_null_uses_column_values_when_serde_omits_null() {
    contract()
        .await
        .expect("SQL null queries use actual column values");
}

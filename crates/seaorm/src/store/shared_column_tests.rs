#![expect(
    clippy::panic_in_result_fn,
    reason = "Tests intentionally panic when fixture setup or adapter contract assertions fail."
)]

use better_auth_core::{
    AuthRecordFields, FieldMap, FieldValue,
    user_fields::{UserConfig, UserFieldConfig},
};
use sea_orm::{ActiveModelTrait, ConnectionTrait, Database, DbBackend, IdenStatic};

use crate::{
    SeaOrmOrganizationModel, SeaOrmSessionModel, SeaOrmUserModel, SeaOrmVerificationModel,
};

mod user {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, crate::AuthEntity)]
    #[sea_orm(table_name = "shared_user")]
    #[auth(role = "user")]
    #[expect(
        unreachable_pub,
        reason = "SeaORM derives expose this type through public generated trait implementations inside the private fixture module."
    )]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub email: Option<String>,
        #[sea_orm(column_name = "shared")]
        #[auth(alias = "image")]
        pub name: Option<String>,
        pub email_verified: bool,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    #[expect(
        unreachable_pub,
        reason = "SeaORM derives expose this type through public generated trait implementations inside the private fixture module."
    )]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

mod session {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, crate::AuthEntity)]
    #[sea_orm(table_name = "shared_session")]
    #[auth(role = "session")]
    #[expect(
        unreachable_pub,
        reason = "SeaORM derives expose this type through public generated trait implementations inside the private fixture module."
    )]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub user_id: String,
        pub token: String,
        #[sea_orm(column_name = "shared")]
        #[auth(alias = "user_agent")]
        pub ip_address: Option<String>,
        pub expires_at: DateTimeUtc,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
        pub active: bool,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    #[expect(
        unreachable_pub,
        reason = "SeaORM derives expose this type through public generated trait implementations inside the private fixture module."
    )]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

mod verification {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, crate::AuthEntity)]
    #[sea_orm(table_name = "shared_verification")]
    #[auth(role = "verification")]
    #[expect(
        unreachable_pub,
        reason = "SeaORM derives expose this type through public generated trait implementations inside the private fixture module."
    )]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false, column_name = "id")]
        #[auth(alias = "id")]
        pub primary_key: i64,
        #[sea_orm(column_name = "shared")]
        #[auth(alias = "value")]
        pub identifier: String,
        pub expires_at: DateTimeUtc,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    #[expect(
        unreachable_pub,
        reason = "SeaORM derives expose this type through public generated trait implementations inside the private fixture module."
    )]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

mod organization {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, crate::AuthEntity)]
    #[sea_orm(table_name = "shared_organization")]
    #[auth(role = "organization")]
    #[expect(
        unreachable_pub,
        reason = "SeaORM derives expose this type through public generated trait implementations inside the private fixture module."
    )]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "shared")]
        #[auth(alias = "slug")]
        pub name: String,
        pub logo: Option<String>,
        pub metadata: Option<serde_json::Value>,
        pub created_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    #[expect(
        unreachable_pub,
        reason = "SeaORM derives expose this type through public generated trait implementations inside the private fixture module."
    )]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

fn declarations(names: [&str; 2]) -> UserConfig {
    UserConfig {
        additional_fields: Some(
            names
                .into_iter()
                .map(|name| {
                    (
                        name.to_owned(),
                        UserFieldConfig {
                            field_name: Some("shared".into()),
                            ..Default::default()
                        },
                    )
                })
                .collect(),
        ),
    }
}

#[tokio::test]
async fn user_and_session_aliases_share_legacy_writes_and_native_getters()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    let _ = database.execute_unprepared("CREATE TABLE shared_user (id TEXT PRIMARY KEY, email TEXT, shared TEXT, email_verified INTEGER NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)").await?;
    let _ = database.execute_unprepared("CREATE TABLE shared_session (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token TEXT NOT NULL, shared TEXT, expires_at TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, active INTEGER NOT NULL)").await?;
    let date = chrono::DateTime::parse_from_rfc3339("2030-01-02T03:04:05.000Z")?.to_utc();
    let mut input = better_auth_core::CreateUser::new().with_name("first");
    input.image = Some("last".to_owned()).into();
    let row = user::Model::new_active(Some("user".into()), input, date)?
        .insert(&database)
        .await?;
    let view = better_auth_core::UserView::from_model(&row)?;
    assert_eq!(view.name, Some("last".to_owned()));
    assert_eq!(view.image, Some("last".to_owned()));
    let mut active: user::ActiveModel = row.into();
    user::Model::apply_update(
        &mut active,
        better_auth_core::UpdateUser {
            image: Some("updated".to_owned()).into(),
            ..Default::default()
        },
        date,
    )?;
    let row = active.update(&database).await?;
    assert_eq!(row.name.as_deref(), Some("updated"));

    let mut active = session::Model::new_active(Some("session".into()), &FieldMap::new())?;
    session::Model::apply_fields(
        &mut active,
        FieldMap::from([
            ("userId".into(), "user".into()),
            ("token".into(), "token".into()),
            ("ipAddress".into(), "first".into()),
            ("userAgent".into(), "last".into()),
            ("expiresAt".into(), date.into()),
            ("createdAt".into(), date.into()),
            ("updatedAt".into(), date.into()),
        ]),
    )?;
    let row = active.insert(&database).await?;
    let view = better_auth_core::SessionView::from(&row);
    assert_eq!(view.ip_address, Some("last".to_owned()));
    assert_eq!(view.user_agent, Some("last".to_owned()));
    assert!(better_auth_core::AuthSession::active(&row));
    let mut active: session::ActiveModel = row.into();
    session::Model::apply_update(
        &mut active,
        crate::SessionUpdate {
            user_agent: Some(None),
            ..Default::default()
        },
    )?;
    let row = active.update(&database).await?;
    assert_eq!(row.ip_address, None);
    assert!(row.active);
    Ok(())
}

#[tokio::test]
async fn verification_aliases_share_typed_writes_and_project_every_logical_field()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    let _ = database.execute_unprepared("CREATE TABLE shared_verification (id INTEGER PRIMARY KEY, shared TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)").await?;
    let date = chrono::DateTime::parse_from_rfc3339("2030-01-02T03:04:05.000Z")?.to_utc();
    let mut active = verification::Model::new_active(None, &FieldMap::new())?;
    verification::Model::apply_fields(
        &mut active,
        FieldMap::from([
            ("id".into(), "41".into()),
            ("identifier".into(), "first".into()),
            ("value".into(), "last".into()),
            ("expires_at".into(), date.into()),
            ("created_at".into(), date.into()),
            ("updated_at".into(), date.into()),
        ]),
    )?;
    let row = active.insert(&database).await?;
    assert_eq!(row.primary_key, 41);
    assert_eq!(row.identifier, "last");
    let record = row
        .record(&declarations(["identifier", "value"]), false, true)
        .await?;
    assert_eq!(record.identifier, "last");
    assert_eq!(record.value, "last");
    assert_eq!(
        verification::Model::value_column().as_str(),
        verification::Model::identifier_column().as_str()
    );
    assert!(verification::Model::field_column("unknown").is_err());
    Ok(())
}

#[tokio::test]
async fn organization_aliases_preserve_projected_slots_without_duplicate_storage_members()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    let _ = database.execute_unprepared("CREATE TABLE shared_organization (id TEXT PRIMARY KEY, shared TEXT NOT NULL, logo TEXT, metadata TEXT, created_at TEXT NOT NULL)").await?;
    let date = chrono::DateTime::parse_from_rfc3339("2030-01-02T03:04:05.000Z")?.to_utc();
    let mut active = <organization::ActiveModel as Default>::default();
    organization::Model::apply_fields(
        &mut active,
        FieldMap::from([
            ("id".into(), "organization".into()),
            ("name".into(), "first".into()),
            ("slug".into(), "last".into()),
            ("logo".into(), FieldValue::Null),
            ("metadata".into(), FieldValue::Null),
            ("created_at".into(), date.into()),
        ]),
    )?;
    let row = active.insert(&database).await?;
    assert_eq!(row.name, "last");
    let fields = declarations(["name", "slug"]);
    let record = row.record(&fields, DbBackend::Sqlite).await?;
    assert_eq!(record.name, "last");
    assert_eq!(record.slug, "last");
    let native = FieldMap::from([
        ("name".into(), FieldValue::Undefined),
        ("slug".into(), FieldValue::Null),
    ]);
    assert_eq!(
        row.record_from_fields(&fields, native.clone())?
            .field_values()?,
        native
    );
    assert!(organization::Model::column("unknown").is_err());
    Ok(())
}

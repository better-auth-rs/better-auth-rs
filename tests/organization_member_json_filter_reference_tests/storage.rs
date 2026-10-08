use better_auth_core::{
    AuthError, AuthResult, AuthSchema, AuthStore, CreateUser, FieldMap, FieldValue, Member,
    Organization,
};
use better_auth_seaorm::{
    OrganizationModels, SeaOrmStore,
    sea_orm::{
        ConnectionTrait, Database, DatabaseConnection, DbErr, EntityTrait, QueryOrder, Schema,
    },
    store::{__private_test_support::bundled_schema::BundledSchema, entities},
};
use serde_json::{Value, json};
use std::sync::Arc;

pub(super) const ORGANIZATION_ID: &str = "json-filter-organization";

#[expect(
    unreachable_pub,
    reason = "SeaORM derives require public fixture entity types"
)]
mod member {
    use better_auth_seaorm::sea_orm::{self, entity::prelude::*};

    #[derive(
        Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, better_auth_seaorm::AuthEntity,
    )]
    #[auth(role = "member")]
    #[sea_orm(table_name = "json_filter_member")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub organization_id: String,
        pub user_id: String,
        pub role: String,
        pub created_at: DateTimeUtc,
        #[serde(rename = "stored_settings")]
        #[sea_orm(column_name = "stored_settings")]
        pub settings: Option<better_auth_seaorm::SqlText>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

type Organizations = OrganizationModels<entities::organization::Model, member::Model>;

fn database_error(error: DbErr) -> AuthError {
    AuthError::internal(format!("Member JSON fixture database failed: {error}"))
}

pub(super) async fn sqlite() -> AuthResult<(Arc<dyn AuthStore<BundledSchema>>, DatabaseConnection)>
{
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(database_error)?;
    let schema = Schema::new(database.get_database_backend());
    for statement in [
        schema.create_table_from_entity(entities::user::Entity),
        schema.create_table_from_entity(entities::session::Entity),
        schema.create_table_from_entity(entities::account::Entity),
        schema.create_table_from_entity(entities::verification::Entity),
        schema.create_table_from_entity(entities::organization::Entity),
        schema.create_table_from_entity(member::Entity),
        schema.create_table_from_entity(entities::invitation::Entity),
    ] {
        let _ = database.execute(&statement).await.map_err(database_error)?;
    }
    Ok((
        Arc::new(
            SeaOrmStore::<BundledSchema>::new(super::policies::config(), database.clone())
                .with_organization_schema::<Organizations>(),
        ),
        database,
    ))
}

pub(super) async fn seed<S: AuthSchema>(store: &dyn AuthStore<S>) -> AuthResult<Vec<Member>> {
    let date = "2030-01-02T03:04:05.123Z"
        .parse::<chrono::DateTime<chrono::Utc>>()
        .map_err(|error| {
            AuthError::internal(format!("Invalid Member JSON fixture date: {error}"))
        })?;
    for suffix in ["a", "b", "c"] {
        let _ = store
            .create_user(CreateUser {
                id: Some(format!("user-{suffix}")),
                name: Some(format!("user-{suffix}")).into(),
                email: Some(format!("user-{suffix}@member-json-filter.test")),
                email_verified: Some(false),
                image: None::<String>.into(),
                created_at: Some(date.into()),
                updated_at: Some(date.into()),
                ..Default::default()
            })
            .await?;
    }
    let _ = store
        .insert_organization(Organization {
            id: ORGANIZATION_ID.into(),
            name: "JSON filter organization".into(),
            slug: "json-filter-organization".into(),
            logo: None::<String>.into(),
            metadata: None::<FieldValue>.into(),
            created_at: date.into(),
            additional_fields: FieldMap::new(),
        })
        .await?;
    let mut created = Vec::new();
    for (suffix, role, settings) in [
        ("a", "owner", json!(["red", "blue"])),
        ("b", "member", json!({ "control": true })),
        ("c", "member", Value::Null),
    ] {
        created.push(
            store
                .insert_member(Member {
                    id: format!("member-{suffix}").into(),
                    organization_id: ORGANIZATION_ID.into(),
                    user_id: format!("user-{suffix}").into(),
                    role: role.into(),
                    created_at: date.into(),
                    additional_fields: FieldMap::from([(
                        "settings".into(),
                        super::values::revive(&settings)?,
                    )]),
                })
                .await?,
        );
    }
    Ok(created)
}

pub(super) async fn members<S: AuthSchema>(store: &dyn AuthStore<S>) -> AuthResult<Vec<Member>> {
    let mut rows = store.list_organization_members(ORGANIZATION_ID).await?;
    rows.sort_by(|left, right| left.id.as_str().cmp(&right.id.as_str()));
    Ok(rows)
}

pub(super) async fn physical(database: &DatabaseConnection) -> AuthResult<Value> {
    Ok(json!({
        "user": entities::user::Entity::find().order_by_asc(entities::user::Column::Id).into_json().all(database).await.map_err(database_error)?,
        "session": entities::session::Entity::find().order_by_asc(entities::session::Column::Id).into_json().all(database).await.map_err(database_error)?,
        "account": entities::account::Entity::find().order_by_asc(entities::account::Column::Id).into_json().all(database).await.map_err(database_error)?,
        "verification": entities::verification::Entity::find().order_by_asc(entities::verification::Column::Id).into_json().all(database).await.map_err(database_error)?,
        "organization": entities::organization::Entity::find().order_by_asc(entities::organization::Column::Id).into_json().all(database).await.map_err(database_error)?,
        "member": member::Entity::find().order_by_asc(member::Column::Id).into_json().all(database).await.map_err(database_error)?,
        "invitation": entities::invitation::Entity::find().order_by_asc(entities::invitation::Column::Id).into_json().all(database).await.map_err(database_error)?,
    }))
}

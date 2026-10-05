use better_auth::seaorm::AuthEntity;
use better_auth::seaorm::sea_orm;
use better_auth::seaorm::sea_orm::entity::prelude::*;
use better_auth::seaorm::sea_orm::{ConnectionTrait, Schema, Statement};

#[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
#[auth(role = "passkey", native_passkey)]
#[sea_orm(table_name = "passkey")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub name: Option<String>,
    #[sea_orm(column_name = "publicKey")]
    pub public_key: String,
    #[sea_orm(column_name = "userId")]
    pub user_id: String,
    #[sea_orm(column_name = "credentialID")]
    pub credential_id: String,
    #[sea_orm(column_type = "Integer")]
    pub counter: i64,
    #[sea_orm(column_name = "deviceType")]
    pub device_type: String,
    #[sea_orm(column_name = "backedUp")]
    pub backed_up: bool,
    pub transports: Option<String>,
    #[sea_orm(column_name = "createdAt")]
    pub created_at: Option<DateTimeUtc>,
    pub aaguid: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "crate::user_fields::Entity",
        from = "Column::UserId",
        to = "crate::user_fields::Column::Id",
        on_delete = "Cascade"
    )]
    User,
}

impl ActiveModelBehavior for ActiveModel {}

pub type Models = better_auth::seaorm::PluginModels<
    better_auth_seaorm::store::entities::api_key::Model,
    better_auth_seaorm::store::entities::device_code::Model,
    Model,
>;

pub async fn create_tables(db: &impl ConnectionTrait) -> Result<(), sea_orm::DbErr> {
    use sea_orm::sea_query::{Alias, Index, Table};

    // Remove the empty bundled table so route success requires the Native model.
    db.execute(&Table::drop().table(Alias::new("passkeys")).to_owned())
        .await?;
    let schema = Schema::new(db.get_database_backend());
    db.execute(&schema.create_table_from_entity(Entity).to_owned())
        .await?;
    for column in ["userId", "credentialID"] {
        db.execute(
            &Index::create()
                .name(format!("passkey_{column}_idx"))
                .table(Alias::new("passkey"))
                .col(Alias::new(column))
                .to_owned(),
        )
        .await?;
    }
    let columns = db
        .query_all_raw(Statement::from_string(
            db.get_database_backend(),
            "SELECT name FROM pragma_table_info('passkey') ORDER BY cid",
        ))
        .await?
        .into_iter()
        .map(|row| row.try_get::<String>("", "name"))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        columns,
        [
            "id",
            "name",
            "publicKey",
            "userId",
            "credentialID",
            "counter",
            "deviceType",
            "backedUp",
            "transports",
            "createdAt",
            "aaguid",
        ]
    );
    Ok(())
}

pub async fn reset(db: &impl ConnectionTrait) -> Result<(), sea_orm::DbErr> {
    Entity::delete_many().exec(db).await?;
    Ok(())
}

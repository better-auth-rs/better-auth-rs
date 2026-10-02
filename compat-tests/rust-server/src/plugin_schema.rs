use better_auth::seaorm::AuthEntity;
use better_auth::seaorm::sea_orm;
use better_auth::seaorm::sea_orm::entity::prelude::*;
use better_auth::seaorm::sea_orm::{ConnectionTrait, Schema};
pub mod api_key {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "api_key")]
    #[sea_orm(table_name = "mapped_api_key")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "stored_name")]
        pub name: Option<String>,
        #[sea_orm(column_name = "stored_start")]
        pub start: Option<String>,
        #[sea_orm(column_name = "stored_prefix")]
        pub prefix: Option<String>,
        #[sea_orm(column_name = "stored_key_hash")]
        pub key_hash: String,
        #[sea_orm(column_name = "stored_reference_id")]
        pub reference_id: String,
        #[sea_orm(column_name = "stored_config_id")]
        pub config_id: String,
        #[sea_orm(column_name = "stored_refill_interval")]
        pub refill_interval: Option<f64>,
        #[sea_orm(column_name = "stored_refill_amount")]
        pub refill_amount: Option<f64>,
        #[sea_orm(column_name = "stored_last_refill_at")]
        pub last_refill_at: Option<DateTimeUtc>,
        #[sea_orm(column_name = "stored_enabled")]
        pub enabled: bool,
        #[sea_orm(column_name = "stored_rate_limit_enabled")]
        pub rate_limit_enabled: bool,
        #[sea_orm(column_name = "stored_rate_limit_time_window")]
        pub rate_limit_time_window: Option<f64>,
        #[sea_orm(column_name = "stored_rate_limit_max")]
        pub rate_limit_max: Option<f64>,
        #[sea_orm(column_name = "stored_request_count")]
        pub request_count: Option<f64>,
        #[sea_orm(column_name = "stored_remaining")]
        pub remaining: Option<f64>,
        #[sea_orm(column_name = "stored_last_request")]
        pub last_request: Option<DateTimeUtc>,
        #[sea_orm(column_name = "stored_expires_at")]
        pub expires_at: Option<DateTimeUtc>,
        #[sea_orm(column_name = "stored_created_at")]
        pub created_at: DateTimeUtc,
        #[sea_orm(column_name = "stored_updated_at")]
        pub updated_at: DateTimeUtc,
        #[sea_orm(column_name = "stored_permissions")]
        pub permissions: Option<String>,
        #[sea_orm(column_name = "stored_metadata")]
        pub metadata: Option<String>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

pub mod device_code {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "device_code")]
    #[sea_orm(table_name = "mapped_device_code")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "stored_device_code")]
        pub device_code: String,
        #[sea_orm(column_name = "stored_user_code")]
        pub user_code: String,
        #[sea_orm(column_name = "stored_user_id")]
        pub user_id: Option<String>,
        #[sea_orm(column_name = "stored_expires_at")]
        pub expires_at: DateTimeUtc,
        #[sea_orm(column_name = "stored_status")]
        pub status: String,
        #[sea_orm(column_name = "stored_last_polled_at")]
        pub last_polled_at: Option<DateTimeUtc>,
        #[sea_orm(column_name = "stored_polling_interval", column_type = "Integer", nullable)]
        pub polling_interval: Option<better_auth::seaorm::SqlNumber>,
        #[sea_orm(column_name = "stored_client_id")]
        pub client_id: Option<String>,
        #[sea_orm(column_name = "stored_scope")]
        pub scope: Option<String>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

pub mod passkey {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "passkey")]
    #[sea_orm(table_name = "mapped_passkey")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "stored_name")]
        pub name: Option<String>,
        #[sea_orm(column_name = "stored_public_key")]
        pub public_key: String,
        #[sea_orm(column_name = "stored_user_id")]
        pub user_id: String,
        #[sea_orm(column_name = "stored_credential_id")]
        pub credential_id: String,
        #[sea_orm(column_name = "stored_counter")]
        pub counter: i64,
        #[sea_orm(column_name = "stored_device_type")]
        pub device_type: String,
        #[sea_orm(column_name = "stored_backed_up")]
        pub backed_up: bool,
        #[sea_orm(column_name = "stored_transports")]
        pub transports: Option<String>,
        #[sea_orm(column_name = "stored_credential")]
        pub credential: String,
        #[sea_orm(column_name = "stored_aaguid")]
        pub aaguid: Option<String>,
        #[sea_orm(column_name = "stored_created_at")]
        pub created_at: DateTimeUtc,
        #[sea_orm(column_name = "stored_updated_at")]
        pub updated_at: DateTimeUtc,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

pub mod two_factor {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "two_factor")]
    #[sea_orm(table_name = "mapped_two_factor")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "stored_secret")]
        pub secret: String,
        #[sea_orm(column_name = "stored_backup_codes")]
        pub backup_codes: String,
        #[sea_orm(column_name = "stored_user_id")]
        pub user_id: String,
        #[sea_orm(column_name = "stored_verified")]
        pub verified: bool,
        #[sea_orm(column_name = "stored_failed_verification_count")]
        pub failed_verification_count: i64,
        #[sea_orm(column_name = "stored_locked_until")]
        pub locked_until: Option<DateTimeUtc>,
        #[sea_orm(column_name = "stored_created_at")]
        pub created_at: DateTimeUtc,
        #[sea_orm(column_name = "stored_updated_at")]
        pub updated_at: DateTimeUtc,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

pub mod jwk {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "jwk")]
    #[sea_orm(table_name = "mapped_jwk")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "stored_public_key")]
        pub public_key: String,
        #[sea_orm(column_name = "stored_private_key")]
        pub private_key: String,
        #[sea_orm(column_name = "stored_created_at")]
        pub created_at: DateTimeUtc,
        #[sea_orm(column_name = "stored_expires_at")]
        pub expires_at: Option<DateTimeUtc>,
        #[sea_orm(column_name = "stored_alg")]
        pub alg: Option<String>,
        #[sea_orm(column_name = "stored_crv")]
        pub crv: Option<String>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

pub mod wallet_address {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "wallet_address")]
    #[sea_orm(table_name = "mapped_wallet_address")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "stored_user_id")]
        pub user_id: String,
        #[sea_orm(column_name = "stored_address")]
        pub address: String,
        #[sea_orm(column_name = "stored_chain_id")]
        pub chain_id: i64,
        #[sea_orm(column_name = "stored_is_primary")]
        pub is_primary: bool,
        #[sea_orm(column_name = "stored_created_at")]
        pub created_at: DateTimeUtc,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
pub type Models = better_auth::seaorm::PluginModels<
    api_key::Model,
    device_code::Model,
    passkey::Model,
    two_factor::Model,
    jwk::Model,
    wallet_address::Model,
>;
pub async fn create_tables(db: &impl ConnectionTrait) -> Result<(), sea_orm::DbErr> {
    let schema = Schema::new(db.get_database_backend());
    let _ = db
        .execute(&schema.create_table_from_entity(api_key::Entity).to_owned())
        .await?;
    let _ = db
        .execute(
            &schema
                .create_table_from_entity(device_code::Entity)
                .to_owned(),
        )
        .await?;
    let _ = db
        .execute(&schema.create_table_from_entity(passkey::Entity).to_owned())
        .await?;
    let _ = db
        .execute(
            &schema
                .create_table_from_entity(two_factor::Entity)
                .to_owned(),
        )
        .await?;
    let _ = db
        .execute(&schema.create_table_from_entity(jwk::Entity).to_owned())
        .await?;
    let _ = db
        .execute(
            &schema
                .create_table_from_entity(wallet_address::Entity)
                .to_owned(),
        )
        .await?;
    for (table, column) in [
        ("mapped_api_key", "stored_key_hash"),
        ("mapped_device_code", "stored_device_code"),
        ("mapped_device_code", "stored_user_code"),
        ("mapped_two_factor", "stored_user_id"),
        ("mapped_passkey", "stored_credential_id"),
    ] {
        let _ = db
            .execute(
                &sea_orm::sea_query::Index::create()
                    .name(format!("idx_{table}_{column}"))
                    .table(sea_orm::sea_query::Alias::new(table))
                    .col(sea_orm::sea_query::Alias::new(column))
                    .unique()
                    .to_owned(),
            )
            .await?;
    }
    Ok(())
}
pub async fn reset(db: &impl ConnectionTrait) -> Result<(), sea_orm::DbErr> {
    let _ = api_key::Entity::delete_many().exec(db).await?;
    let _ = device_code::Entity::delete_many().exec(db).await?;
    let _ = passkey::Entity::delete_many().exec(db).await?;
    let _ = two_factor::Entity::delete_many().exec(db).await?;
    let _ = jwk::Entity::delete_many().exec(db).await?;
    let _ = wallet_address::Entity::delete_many().exec(db).await?;
    Ok(())
}

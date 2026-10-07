macro_rules! passkey_model {
    ($module:ident, $owner:literal, $credential:literal, $counter:literal) => {
        #[expect(
            unreachable_pub,
            reason = "SeaORM entity derives require public fixture types"
        )]
        pub mod $module {
            use better_auth::seaorm::{
                AuthEntity,
                sea_orm::{self, entity::prelude::*},
            };

            #[derive(Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, AuthEntity)]
            #[auth(role = "passkey", native_passkey)]
            #[sea_orm(table_name = "shared_display_passkey")]
            #[serde(rename_all = "camelCase")]
            pub struct Model {
                #[sea_orm(primary_key, auto_increment = false)]
                pub id: String,
                #[serde(rename = "display")]
                #[sea_orm(column_name = "display")]
                pub name: Option<String>,
                #[sea_orm(column_name = "publicKey")]
                pub public_key: String,
                #[sea_orm(column_name = $owner)]
                pub user_id: String,
                #[serde(rename = "credentialID")]
                #[sea_orm(column_name = $credential)]
                pub credential_id: String,
                #[sea_orm(column_name = $counter)]
                pub counter: i64,
                #[sea_orm(column_name = "deviceType")]
                pub device_type: String,
                #[sea_orm(column_name = "backedUp")]
                pub backed_up: bool,
                pub transports: Option<String>,
                #[sea_orm(column_name = "createdAt")]
                pub created_at: Option<DateTimeUtc>,
            }

            #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
            pub enum Relation {}

            impl ActiveModelBehavior for ActiveModel {}
        }
    };
}

passkey_model!(model, "userId", "credentialID", "counter");
passkey_model!(
    protected,
    "stored_owner",
    "stored_credential",
    "stored_counter"
);

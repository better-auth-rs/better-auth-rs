use super::*;

#[expect(
    unreachable_pub,
    reason = "SeaORM derives require public fixture entity types."
)]
pub(super) mod account {
    use better_auth_seaorm::sea_orm::{self, entity::prelude::*};
    #[derive(
        Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, better_auth_seaorm::AuthEntity,
    )]
    #[auth(role = "account")]
    #[sea_orm(table_name = "account")]
    #[serde(rename_all = "camelCase")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "accountId")]
        pub account_id: String,
        #[sea_orm(column_name = "providerId")]
        pub provider_id: String,
        #[sea_orm(column_name = "userId")]
        pub user_id: String,
        #[sea_orm(column_name = "accessToken")]
        pub access_token: Option<String>,
        #[sea_orm(column_name = "refreshToken")]
        pub refresh_token: Option<String>,
        #[sea_orm(column_name = "idToken")]
        pub id_token: Option<String>,
        #[sea_orm(column_name = "accessTokenExpiresAt")]
        pub access_token_expires_at: Option<DateTimeUtc>,
        #[sea_orm(column_name = "refreshTokenExpiresAt")]
        pub refresh_token_expires_at: Option<DateTimeUtc>,
        pub scope: Option<String>,
        pub password: Option<String>,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
        #[sea_orm(column_name = "updatedAt")]
        pub updated_at: DateTimeUtc,
        #[sea_orm(column_name = "badgeId")]
        pub badge_id: Option<String>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

pub(super) struct Core;
impl AuthSchema for Core {
    type User = <core_models::Core as AuthSchema>::User;
    type Account = account::Model;
    type Session = <core_models::Core as AuthSchema>::Session;
    type Verification = <core_models::Core as AuthSchema>::Verification;
}

pub mod ordinary {
    use better_auth_seaorm::sea_orm::{self, entity::prelude::*};
    use serde::Serialize;

    #[derive(
        better_auth_seaorm::AuthEntity, Clone, Debug, PartialEq, Serialize, DeriveEntityModel,
    )]
    #[auth(role = "user")]
    #[sea_orm(table_name = "users")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: Option<String>,
        pub email: Option<String>,
        pub email_verified: bool,
        pub image: Option<String>,
        #[serde(rename = "username")]
        pub username: Option<String>,
        #[serde(rename = "displayUsername")]
        pub display_username: Option<String>,
        pub phone_number: Option<String>,
        pub phone_number_verified: Option<bool>,
        pub role: Option<String>,
        pub banned: bool,
        pub ban_reason: Option<String>,
        pub ban_expires: Option<DateTimeUtc>,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

pub mod mapped {
    use better_auth_seaorm::sea_orm::{self, entity::prelude::*};
    use serde::Serialize;

    #[derive(
        better_auth_seaorm::AuthEntity, Clone, Debug, PartialEq, Serialize, DeriveEntityModel,
    )]
    #[auth(role = "user")]
    #[sea_orm(table_name = "username_users")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: Option<String>,
        pub email: Option<String>,
        pub email_verified: bool,
        pub image: Option<String>,
        #[sea_orm(column_name = "login_name")]
        #[serde(rename = "login_name")]
        pub username: Option<String>,
        #[sea_orm(column_name = "display_label")]
        #[serde(rename = "display_label")]
        pub display_username: Option<String>,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

pub mod no_display {
    use better_auth_seaorm::sea_orm::{self, entity::prelude::*};
    use serde::Serialize;

    #[derive(
        better_auth_seaorm::AuthEntity, Clone, Debug, PartialEq, Serialize, DeriveEntityModel,
    )]
    #[auth(role = "user")]
    #[sea_orm(table_name = "users")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: Option<String>,
        pub email: Option<String>,
        pub email_verified: bool,
        pub image: Option<String>,
        #[serde(rename = "username")]
        pub username: Option<String>,

        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

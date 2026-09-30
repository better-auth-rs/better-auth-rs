pub mod organization {
    use better_auth_seaorm::sea_orm::{self, entity::prelude::*};

    #[derive(
        Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, better_auth_seaorm::AuthEntity,
    )]
    #[auth(role = "organization")]
    #[sea_orm(table_name = "app_organization")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "physical_name")]
        pub name: String,
        pub slug: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub logo: Option<String>,
        pub metadata: Option<Json>,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
        #[serde(rename = "storedLabel")]
        #[sea_orm(column_name = "physical_label")]
        pub stored_label: Option<String>,
        pub secret: Option<String>,
        pub protected: Option<String>,
        pub marker: Option<String>,
        pub score: Option<f64>,
        pub tags: Option<Json>,
        pub payload: Option<Json>,
        #[serde(rename = "requiredTag")]
        pub required_tag: Option<String>,
        #[serde(rename = "implicitTag")]
        pub implicit_tag: Option<String>,
        pub category: Option<String>,
        #[serde(rename = "joinedAt")]
        pub joined_at: Option<DateTimeUtc>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod member {
    use better_auth_seaorm::sea_orm::{self, entity::prelude::*};

    #[derive(
        Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, better_auth_seaorm::AuthEntity,
    )]
    #[auth(role = "member")]
    #[sea_orm(table_name = "app_member")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub organization_id: String,
        pub user_id: String,
        #[sea_orm(column_name = "physical_role")]
        pub role: String,
        pub created_at: DateTimeUtc,
        #[serde(rename = "storedLabel")]
        #[sea_orm(column_name = "physical_label")]
        pub stored_label: Option<String>,
        pub secret: Option<String>,
        pub protected: Option<String>,
        pub marker: Option<String>,
        pub score: Option<f64>,
        pub tags: Option<Json>,
        pub payload: Option<Json>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod invitation {
    use better_auth_seaorm::sea_orm::{self, entity::prelude::*};

    #[derive(
        Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, better_auth_seaorm::AuthEntity,
    )]
    #[auth(role = "invitation")]
    #[sea_orm(table_name = "app_invitation")]
    pub struct Model {
        pub team_id: Option<String>,
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub organization_id: String,
        pub email: String,
        #[sea_orm(column_name = "physical_role")]
        pub role: String,
        pub status: String,
        pub inviter_id: String,
        pub expires_at: DateTimeUtc,
        pub created_at: DateTimeUtc,
        #[serde(rename = "storedLabel")]
        #[sea_orm(column_name = "physical_label")]
        pub stored_label: Option<String>,
        pub secret: Option<String>,
        pub protected: Option<String>,
        pub marker: Option<String>,
        pub score: Option<f64>,
        pub tags: Option<Json>,
        pub payload: Option<Json>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod team {
    use better_auth_seaorm::sea_orm::{self, entity::prelude::*};

    #[derive(
        Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, better_auth_seaorm::AuthEntity,
    )]
    #[auth(role = "team")]
    #[sea_orm(table_name = "app_team")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "physical_name")]
        pub name: String,
        pub organization_id: String,
        pub created_at: DateTimeUtc,
        pub updated_at: Option<DateTimeUtc>,
        pub member_count: i64,
        #[serde(rename = "storedLabel")]
        #[sea_orm(column_name = "physical_label")]
        pub stored_label: Option<String>,
        pub secret: Option<String>,
        pub protected: Option<String>,
        pub marker: Option<String>,
        pub score: Option<f64>,
        pub tags: Option<Json>,
        pub payload: Option<Json>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

pub mod team_member {
    use better_auth_seaorm::sea_orm::{self, entity::prelude::*};

    #[derive(
        Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, better_auth_seaorm::AuthEntity,
    )]
    #[auth(role = "team_member")]
    #[sea_orm(table_name = "app_team_member")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub team_id: String,
        pub user_id: String,
        #[sea_orm(unique)]
        #[sea_orm(column_name = "physical_membership_key")]
        pub membership_key: Option<String>,
        pub created_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

pub mod organization_role {
    use better_auth_seaorm::sea_orm::{self, entity::prelude::*};

    #[derive(
        Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, better_auth_seaorm::AuthEntity,
    )]
    #[auth(role = "organization_role")]
    #[sea_orm(table_name = "app_organization_role")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub organization_id: String,
        #[sea_orm(column_name = "physical_role")]
        pub role: String,
        pub permission: Json,
        pub created_at: DateTimeUtc,
        pub updated_at: Option<DateTimeUtc>,
        #[serde(rename = "storedLabel")]
        #[sea_orm(column_name = "physical_label")]
        pub stored_label: Option<String>,
        pub secret: Option<String>,
        pub protected: Option<String>,
        pub marker: Option<String>,
        pub score: Option<f64>,
        pub tags: Option<Json>,
        pub payload: Option<Json>,
        #[serde(rename = "roleRequired")]
        pub role_required: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

pub type Models = better_auth_seaorm::OrganizationModels<
    organization::Model,
    member::Model,
    invitation::Model,
    team::Model,
    team_member::Model,
    organization_role::Model,
>;

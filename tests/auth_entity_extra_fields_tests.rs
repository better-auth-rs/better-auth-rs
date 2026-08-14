//! Verifies that `AuthEntity` derive accepts extra fields beyond the core set.

#![allow(
    unreachable_pub,
    reason = "SeaORM DeriveEntityModel requires pub types"
)]

use better_auth::seaorm::AuthEntity;
use better_auth::seaorm::sea_orm;
use better_auth::seaorm::sea_orm::entity::prelude::*;

mod user_with_extras {
    use super::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "user")]
    #[sea_orm(table_name = "users_extra")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: Option<String>,
        pub email: Option<String>,
        pub email_verified: bool,
        pub image: Option<String>,
        pub username: Option<String>,
        pub display_username: Option<String>,
        pub two_factor_enabled: bool,
        pub role: Option<String>,
        pub banned: bool,
        pub ban_reason: Option<String>,
        pub ban_expires: Option<DateTimeUtc>,
        pub metadata: Json,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
        // Extra fields — AuthEntity sets these to NotSet on creation
        pub locale: Option<String>,
        pub tenant_id: Option<i64>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[test]
fn extra_fields_get_not_set_in_new_active() {
    use better_auth::prelude::CreateUser;
    use better_auth::seaorm::SeaOrmUserModel;
    use chrono::Utc;
    use sea_orm::ActiveValue;

    let now = Utc::now();
    let create = CreateUser::new()
        .with_email("test@example.com")
        .with_name("Test");
    let active = user_with_extras::Model::new_active(None, create, now);

    // Core fields should be Set
    assert!(matches!(active.email, ActiveValue::Set(_)));
    assert!(matches!(active.name, ActiveValue::Set(_)));
    assert!(matches!(active.created_at, ActiveValue::Set(_)));

    // Extra fields should be NotSet
    assert!(matches!(active.locale, ActiveValue::NotSet));
    assert!(matches!(active.tenant_id, ActiveValue::NotSet));
}

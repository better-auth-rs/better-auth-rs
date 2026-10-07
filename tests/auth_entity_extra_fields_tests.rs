//! Verifies that `AuthEntity` derive accepts extra fields beyond the core set.

#![cfg(feature = "seaorm2")]
#![allow(
    unreachable_pub,
    reason = "SeaORM DeriveEntityModel requires pub types"
)]

use better_auth::seaorm::AuthEntity;
use better_auth::seaorm::SeaOrmUserModel;
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
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions fail by panic; model setup propagates typed errors"
)]
fn extra_fields_get_not_set_in_new_active() -> better_auth::AuthResult<()> {
    use better_auth::prelude::CreateUser;
    use chrono::Utc;
    use sea_orm::ActiveValue;

    let now = Utc::now();
    let create = CreateUser::new()
        .with_email("test@example.com")
        .with_name("Test");
    let active = user_with_extras::Model::new_active(None, create, now)?;

    // Core fields should be Set
    assert!(matches!(active.email, ActiveValue::Set(_)));
    assert!(matches!(active.name, ActiveValue::Set(_)));
    assert!(matches!(active.created_at, ActiveValue::Set(_)));

    // Extra fields should be NotSet
    assert!(matches!(active.locale, ActiveValue::NotSet));
    assert!(matches!(active.tenant_id, ActiveValue::NotSet));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions fail by panic; model setup propagates typed errors"
)]
fn typed_user_models_preserve_omission_and_null_and_reject_incompatible_fields()
-> better_auth::AuthResult<()> {
    use better_auth::prelude::{CreateUser, UpdateUser};
    use chrono::Utc;
    use sea_orm::ActiveValue::{NotSet, Set};
    use serde_json::json;

    let now = Utc::now();
    let mut active = user_with_extras::Model::new_active(None, CreateUser::new(), now)?;
    assert_eq!(active.name, NotSet);
    assert_eq!(active.image, NotSet);
    user_with_extras::Model::apply_update(
        &mut active,
        serde_json::from_value::<UpdateUser>(json!({"name":"Updated","image":null}))?,
        now,
    )?;
    assert_eq!(active.name, Set(Some("Updated".into())));
    assert_eq!(active.image, Set(None));
    user_with_extras::Model::apply_update(&mut active, UpdateUser::default(), now)?;
    assert_eq!(active.name, Set(Some("Updated".into())));
    let incompatible = serde_json::from_value::<CreateUser>(json!({"name":{"raw":true}}))?;
    assert!(matches!(
        user_with_extras::Model::new_active(None, incompatible, now),
        Err(better_auth::AuthError::Internal(message))
            if message == "Adapter field cannot be decoded as SQL String"
    ));
    Ok(())
}

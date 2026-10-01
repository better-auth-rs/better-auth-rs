//! SeaORM model bindings for Better Auth schemas.

use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelBehavior, ActiveModelTrait, ColumnTrait, EntityTrait, FromQueryResult,
    IntoActiveModel, Value,
};

use better_auth_core::entity::{AuthAccount, AuthSession, AuthUser, AuthVerification};
use better_auth_core::error::AuthResult;
pub use better_auth_core::schema::AuthSchema;
use better_auth_core::types::{
    CreateAccount, CreateSession, CreateUser, CreateVerification, UpdateAccount, UpdateUser,
};

pub trait SeaOrmUserModel:
    AuthUser + IntoActiveModel<Self::ActiveModel> + Clone + Send + Sync + 'static + FromQueryResult
{
    type Id: Clone + Into<Value> + Send + Sync + 'static;
    type Entity: EntityTrait<Model = Self>;
    type ActiveModel: ActiveModelTrait<Entity = Self::Entity> + ActiveModelBehavior + Send;
    type Column: ColumnTrait;

    fn id_column() -> Self::Column;
    fn email_column() -> Self::Column;
    /// Returns the username column, or `None` if the username plugin is not enabled.
    fn phone_number_column() -> Option<Self::Column> {
        None
    }
    fn username_column() -> Option<Self::Column> {
        None
    }
    fn name_column() -> Self::Column;
    fn created_at_column() -> Self::Column;
    fn parse_id(id: &str) -> AuthResult<Self::Id>;
    /// Return whether an application field uses a native JSON column type.
    fn native_json_field(_name: &str) -> bool {
        false
    }

    /// Resolve an application field's serialized name to its database column.
    fn field_column(name: &str) -> AuthResult<<Self::Entity as EntityTrait>::Column> {
        Err(better_auth_core::AuthError::config(format!(
            "The user model does not resolve reference field: {name}"
        )))
    }

    fn new_active(
        id: Option<Self::Id>,
        create_user: CreateUser,
        now: DateTime<Utc>,
    ) -> Self::ActiveModel;
    fn apply_update(active: &mut Self::ActiveModel, update: UpdateUser, now: DateTime<Utc>);
    /// Persist configured application fields in the same insert or update as core user fields.
    fn apply_fields(
        _active: &mut Self::ActiveModel,
        fields: serde_json::Map<String, serde_json::Value>,
    ) -> AuthResult<()> {
        if fields.is_empty() {
            return Ok(());
        }
        Err(better_auth_core::AuthError::config(
            "The user model does not implement additional fields",
        ))
    }
}

pub trait SeaOrmSessionModel:
    AuthSession + IntoActiveModel<Self::ActiveModel> + Clone + Send + Sync + 'static + FromQueryResult
{
    type Id: Clone + Into<Value> + Send + Sync + 'static;
    type UserId: Clone + Into<Value> + Send + Sync + 'static;
    type Entity: EntityTrait<Model = Self>;
    type ActiveModel: ActiveModelTrait<Entity = Self::Entity> + ActiveModelBehavior + Send;
    type Column: ColumnTrait;

    fn id_column() -> Self::Column;
    fn token_column() -> Self::Column;
    fn user_id_column() -> Self::Column;
    fn active_column() -> Self::Column;
    fn expires_at_column() -> Self::Column;
    fn created_at_column() -> Self::Column;
    fn parse_id(id: &str) -> AuthResult<Self::Id>;
    fn parse_user_id(user_id: &str) -> AuthResult<Self::UserId>;
    /// Return whether an application field uses a native JSON column type.
    fn native_json_field(_name: &str) -> bool {
        false
    }

    /// Resolve an application field's serialized name to its database column.
    fn field_column(name: &str) -> AuthResult<<Self::Entity as EntityTrait>::Column> {
        Err(better_auth_core::AuthError::config(format!(
            "The session model does not resolve reference field: {name}"
        )))
    }

    fn new_active(
        id: Option<Self::Id>,
        token: String,
        create_session: CreateSession,
        now: DateTime<Utc>,
    ) -> Self::ActiveModel;
    fn set_expires_at(active: &mut Self::ActiveModel, expires_at: DateTime<Utc>);
    fn set_updated_at(active: &mut Self::ActiveModel, updated_at: DateTime<Utc>);
    /// Apply core and enabled plugin values returned by session update hooks.
    fn apply_update(active: &mut Self::ActiveModel, update: crate::SessionUpdate)
    -> AuthResult<()>;
    /// Persist the active team after plugin field validation.
    fn set_active_team_id(_active: &mut Self::ActiveModel, _team_id: Option<String>) {}
    fn set_active_organization_id(active: &mut Self::ActiveModel, organization_id: Option<String>);
    /// Apply fields validated against the application's session configuration.
    fn apply_fields(
        _active: &mut Self::ActiveModel,
        fields: serde_json::Map<String, serde_json::Value>,
    ) -> AuthResult<()> {
        if fields.is_empty() {
            return Ok(());
        }
        Err(better_auth_core::AuthError::Config(
            "The session model does not implement additional field updates".into(),
        ))
    }
}

pub trait SeaOrmAccountModel:
    AuthAccount + IntoActiveModel<Self::ActiveModel> + Clone + Send + Sync + 'static + FromQueryResult
{
    type Id: Clone + Into<Value> + Send + Sync + 'static;
    type UserId: Clone + Into<Value> + Send + Sync + 'static;
    type Entity: EntityTrait<Model = Self>;
    type ActiveModel: ActiveModelTrait<Entity = Self::Entity> + ActiveModelBehavior + Send;
    type Column: ColumnTrait;

    fn id_column() -> Self::Column;
    fn provider_id_column() -> Self::Column;
    fn account_id_column() -> Self::Column;
    fn user_id_column() -> Self::Column;
    fn created_at_column() -> Self::Column;
    fn parse_id(id: &str) -> AuthResult<Self::Id>;
    fn parse_user_id(user_id: &str) -> AuthResult<Self::UserId>;

    fn new_active(
        id: Option<Self::Id>,
        create_account: CreateAccount,
        now: DateTime<Utc>,
    ) -> Self::ActiveModel;
    fn apply_update(active: &mut Self::ActiveModel, update: UpdateAccount, now: DateTime<Utc>);
}

pub trait SeaOrmVerificationModel:
    AuthVerification
    + IntoActiveModel<Self::ActiveModel>
    + Clone
    + Send
    + Sync
    + 'static
    + FromQueryResult
{
    type Id: Clone + Into<Value> + Send + Sync + 'static;
    type Entity: EntityTrait<Model = Self>;
    type ActiveModel: ActiveModelTrait<Entity = Self::Entity> + ActiveModelBehavior + Send;
    type Column: ColumnTrait;

    fn id_column() -> Self::Column;
    fn identifier_column() -> Self::Column;
    fn value_column() -> Self::Column;
    fn expires_at_column() -> Self::Column;
    fn created_at_column() -> Self::Column;
    fn parse_id(id: &str) -> AuthResult<Self::Id>;

    fn new_active(
        id: Option<Self::Id>,
        verification: CreateVerification,
        now: DateTime<Utc>,
    ) -> Self::ActiveModel;
    /// Apply values returned by verification update hooks.
    fn apply_update(
        active: &mut Self::ActiveModel,
        update: crate::VerificationUpdate,
    ) -> AuthResult<()>;
}

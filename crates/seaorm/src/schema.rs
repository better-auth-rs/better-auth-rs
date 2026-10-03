//! SeaORM model bindings for Better Auth schemas.

use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelBehavior, ActiveModelTrait, ColumnTrait, EntityTrait, FromQueryResult,
    IntoActiveModel, Value,
};

use better_auth_core::entity::{AuthSession, AuthUser};
use better_auth_core::error::AuthResult;
pub use better_auth_core::schema::AuthSchema;
use better_auth_core::types::{CreateSession, CreateUser, UpdateUser};

pub trait SeaOrmUserModel:
    AuthUser + IntoActiveModel<Self::ActiveModel> + Clone + Send + Sync + 'static + FromQueryResult
{
    type Id: Clone + Into<Value> + Send + Sync + 'static;
    type Entity: EntityTrait<Model = Self, Column = Self::Column>;
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

    /// Columns written by a handwritten insert beyond core and configured application fields.
    fn extra_insert_columns() -> Vec<<Self::Entity as EntityTrait>::Column> {
        Vec::new()
    }

    /// Resolve every core and configured application field to its database column.
    fn field_column(name: &str) -> AuthResult<<Self::Entity as EntityTrait>::Column> {
        Err(better_auth_core::AuthError::config(format!(
            "The user model does not resolve reference field: {name}"
        )))
    }

    fn new_active(
        id: Option<Self::Id>,
        create_user: CreateUser,
        now: DateTime<Utc>,
    ) -> AuthResult<Self::ActiveModel>;
    fn apply_update(
        active: &mut Self::ActiveModel,
        update: UpdateUser,
        now: DateTime<Utc>,
    ) -> AuthResult<()>;
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
    type Entity: EntityTrait<Model = Self, Column = Self::Column>;
    type ActiveModel: ActiveModelTrait<Entity = Self::Entity> + ActiveModelBehavior + Send;
    type Column: ColumnTrait;

    fn id_column() -> Self::Column;
    fn token_column() -> Self::Column;
    fn user_id_column() -> Self::Column;
    /// Return the independent active column, or `None` for an explicitly selected row-presence model.
    /// Existing inactive rows require their active-backed model until an application-owned migration.
    fn active_column() -> Option<Self::Column>;
    fn expires_at_column() -> Self::Column;
    fn created_at_column() -> Self::Column;
    fn parse_id(id: &str) -> AuthResult<Self::Id>;
    fn parse_user_id(user_id: &str) -> AuthResult<Self::UserId>;
    /// Return whether an application field uses a native JSON column type.
    fn native_json_field(_name: &str) -> bool {
        false
    }

    /// Columns written by a handwritten insert beyond core and configured application fields.
    fn extra_insert_columns() -> Vec<<Self::Entity as EntityTrait>::Column> {
        Vec::new()
    }

    /// Resolve every core and configured application field to its database column.
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
    IntoActiveModel<Self::ActiveModel> + Clone + Send + Sync + 'static + FromQueryResult
{
    type Id: Clone + Into<Value> + Send + Sync + 'static;
    type UserId: Clone + Into<Value> + Send + Sync + 'static;
    type Entity: EntityTrait<Model = Self, Column = Self::Column>;
    type ActiveModel: ActiveModelTrait<Entity = Self::Entity> + ActiveModelBehavior + Send;
    type Column: ColumnTrait;

    fn id_column() -> Self::Column;
    fn provider_id_column() -> Self::Column;
    fn account_id_column() -> Self::Column;
    fn user_id_column() -> Self::Column;
    fn created_at_column() -> Self::Column;
    fn parse_id(id: &str) -> AuthResult<Self::Id>;
    fn parse_user_id(user_id: &str) -> AuthResult<Self::UserId>;

    /// Build a model from adapter-transformed fields, after before hooks complete.
    fn new_active(
        id: Option<Self::Id>,
        fields: serde_json::Map<String, serde_json::Value>,
    ) -> AuthResult<Self::ActiveModel>;
    /// Resolve logical names and declared model aliases to the same database column.
    fn field_column(name: &str) -> AuthResult<<Self::Entity as EntityTrait>::Column>;
    fn native_json_field(name: &str) -> bool;
    /// Return application columns populated by inserts outside configured field policies.
    fn extra_insert_columns() -> Vec<<Self::Entity as EntityTrait>::Column> {
        Vec::new()
    }
    /// Decode a create record or update patch into its declared SQL column types.
    fn apply_fields(
        active: &mut Self::ActiveModel,
        fields: serde_json::Map<String, serde_json::Value>,
    ) -> AuthResult<()>;
    /// Extract model values before output policies run, preserving mapped storage columns.
    fn record_fields(
        &self,
        fields: &better_auth_core::user_fields::UserConfig,
    ) -> AuthResult<better_auth_core::user_fields::AdapterRecord>;

    /// Apply output policies once without decoding their results back into SQL column types.
    fn record(
        &self,
        fields: &better_auth_core::user_fields::UserConfig,
        supports_native_json: bool,
        supports_native_dates: bool,
    ) -> impl std::future::Future<Output = AuthResult<better_auth_core::wire::AccountView>> + Send
    {
        async move {
            let records = vec![self.record_fields(fields)?];
            // Projection preserves the one input row.
            Ok(better_auth_core::wire::AccountView::from_adapter_fields(
                fields
                    .project_adapter_records(records, supports_native_json, supports_native_dates)
                    .await?
                    .remove(0),
            ))
        }
    }
}

pub trait SeaOrmVerificationModel:
    IntoActiveModel<Self::ActiveModel> + Clone + Send + Sync + 'static + FromQueryResult
{
    type Id: Clone + Into<Value> + Send + Sync + 'static;
    type Entity: EntityTrait<Model = Self, Column = Self::Column>;
    type ActiveModel: ActiveModelTrait<Entity = Self::Entity> + ActiveModelBehavior + Send;
    type Column: ColumnTrait;

    fn id_column() -> Self::Column;
    fn identifier_column() -> Self::Column;
    fn value_column() -> Self::Column;
    fn expires_at_column() -> Self::Column;
    fn created_at_column() -> Self::Column;
    fn parse_id(id: &str) -> AuthResult<Self::Id>;

    /// Build a model from adapter-transformed fields, after before hooks complete.
    fn new_active(
        id: Option<Self::Id>,
        fields: serde_json::Map<String, serde_json::Value>,
    ) -> AuthResult<Self::ActiveModel>;
    /// Resolve logical names and declared model aliases to the same database column.
    fn field_column(name: &str) -> AuthResult<<Self::Entity as EntityTrait>::Column>;
    fn native_json_field(name: &str) -> bool;
    /// Return application columns populated by inserts outside configured field policies.
    fn extra_insert_columns() -> Vec<<Self::Entity as EntityTrait>::Column> {
        Vec::new()
    }
    /// Decode a create record or update patch into its declared SQL column types.
    fn apply_fields(
        active: &mut Self::ActiveModel,
        fields: serde_json::Map<String, serde_json::Value>,
    ) -> AuthResult<()>;
    /// Extract model values before output policies run, preserving mapped storage columns.
    fn record_fields(
        &self,
        fields: &better_auth_core::user_fields::UserConfig,
    ) -> AuthResult<better_auth_core::user_fields::AdapterRecord>;

    /// Apply output policies once without decoding their results back into SQL column types.
    fn record(
        &self,
        fields: &better_auth_core::user_fields::UserConfig,
        supports_native_json: bool,
        supports_native_dates: bool,
    ) -> impl std::future::Future<Output = AuthResult<better_auth_core::wire::VerificationView>> + Send
    {
        async move {
            let records = vec![self.record_fields(fields)?];
            // Projection preserves the one input row.
            Ok(
                better_auth_core::wire::VerificationView::from_adapter_fields(
                    fields
                        .project_adapter_records(
                            records,
                            supports_native_json,
                            supports_native_dates,
                        )
                        .await?
                        .remove(0),
                ),
            )
        }
    }
}

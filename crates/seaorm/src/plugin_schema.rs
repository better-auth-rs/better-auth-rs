//! Typed model bindings for plugin-owned persistence tables.
use better_auth_core::AuthResult;
use sea_orm::{
    ActiveModelBehavior, ActiveModelTrait, ColumnTrait, EntityTrait, FromQueryResult,
    IntoActiveModel,
};
use serde_json::{Map, Value};
use std::marker::PhantomData;

/// Derive this binding with `AuthEntity` and a plugin entity role.
pub trait SeaOrmPluginModel:
    Clone + Send + Sync + FromQueryResult + IntoActiveModel<Self::ActiveModel> + 'static
{
    /// Plugin record returned by the store.
    type Record;
    /// Entity containing the application table name.
    type Entity: EntityTrait<Model = Self, Column = Self::Column>;
    /// Typed insert and update values.
    type ActiveModel: ActiveModelTrait<Entity = Self::Entity> + ActiveModelBehavior + Default + Send;
    /// Entity columns.
    type Column: ColumnTrait;
    /// Original model options, independent of the resolved SQL table name.
    fn model_declaration() -> Option<better_auth_core::schema::ModelDeclaration> {
        None
    }
    /// Select the passkey columns supported by this model.
    fn passkey_storage() -> better_auth_core::PasskeyStorage {
        better_auth_core::PasskeyStorage::Legacy
    }
    /// Resolve a logical field name to its typed column.
    fn column(name: &str) -> AuthResult<Self::Column>;
    /// Return the canonical public name of a built-in column.
    fn core_field_name(column: &Self::Column) -> Option<&'static str>;
    /// Project the stored model into its plugin record.
    fn record(&self) -> AuthResult<Self::Record>;
    /// Extract configured storage values before adapter output policies run.
    fn record_fields(
        &self,
        fields: &better_auth_core::user_fields::UserConfig,
    ) -> AuthResult<better_auth_core::user_fields::AdapterRecord>;
    /// Return whether the column references another model ID.
    fn is_id_reference(column: &Self::Column) -> bool;
    /// Assign fields through the application's typed model.
    fn apply_fields(active: &mut Self::ActiveModel, fields: Map<String, Value>) -> AuthResult<()>;
    /// Construct an insert or partial update.
    fn active(fields: Map<String, Value>) -> AuthResult<Self::ActiveModel> {
        let mut active = <Self::ActiveModel as Default>::default();
        Self::apply_fields(&mut active, fields)?;
        Ok(active)
    }
}

/// Application-owned plugin models, independent of the core and organization schemas.
pub trait SeaOrmPluginSchema: Send + Sync + 'static {
    /// ApiKey persistence model.
    type ApiKey: SeaOrmPluginModel<Record = better_auth_core::ApiKey>;
    /// DeviceCode persistence model.
    type DeviceCode: SeaOrmPluginModel<Record = better_auth_core::DeviceCode>;
    /// Passkey persistence model.
    type Passkey: SeaOrmPluginModel<Record = better_auth_core::Passkey>;
    /// TwoFactor persistence model.
    type TwoFactor: SeaOrmPluginModel<Record = better_auth_core::TwoFactor>;
    /// Jwk persistence model.
    type Jwk: SeaOrmPluginModel<Record = better_auth_core::Jwk>;
    /// WalletAddress persistence model.
    type WalletAddress: SeaOrmPluginModel<Record = better_auth_core::WalletAddress>;
    /// Rate-limit database counters.
    type RateLimit: SeaOrmPluginModel<Record = better_auth_core::store::RateLimitRecord>;
}

/// Select plugin models. Omitted parameters use the bundled tables.
pub struct PluginModels<
    M0 = crate::store::entities::api_key::Model,
    M1 = crate::store::entities::device_code::Model,
    M2 = crate::store::entities::passkey::Model,
    M3 = crate::store::entities::two_factor::Model,
    M4 = crate::store::entities::jwk::Model,
    M5 = crate::store::entities::wallet_address::Model,
    M6 = crate::store::entities::rate_limit::Model,
>(PhantomData<(M0, M1, M2, M3, M4, M5, M6)>);

impl<M0, M1, M2, M3, M4, M5, M6> SeaOrmPluginSchema for PluginModels<M0, M1, M2, M3, M4, M5, M6>
where
    M0: SeaOrmPluginModel<Record = better_auth_core::ApiKey>,
    M1: SeaOrmPluginModel<Record = better_auth_core::DeviceCode>,
    M2: SeaOrmPluginModel<Record = better_auth_core::Passkey>,
    M3: SeaOrmPluginModel<Record = better_auth_core::TwoFactor>,
    M4: SeaOrmPluginModel<Record = better_auth_core::Jwk>,
    M5: SeaOrmPluginModel<Record = better_auth_core::WalletAddress>,
    M6: SeaOrmPluginModel<Record = better_auth_core::store::RateLimitRecord>,
{
    type ApiKey = M0;
    type DeviceCode = M1;
    type Passkey = M2;
    type TwoFactor = M3;
    type Jwk = M4;
    type WalletAddress = M5;
    type RateLimit = M6;
}

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
    /// Resolve a logical field name to its typed column.
    fn column(name: &str) -> AuthResult<Self::Column>;
    /// Project the stored model into its plugin record.
    fn record(&self) -> AuthResult<Self::Record>;
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
}

/// Select plugin models. Omitted parameters use the bundled tables.
pub struct PluginModels<
    M0 = crate::store::entities::api_key::Model,
    M1 = crate::store::entities::device_code::Model,
    M2 = crate::store::entities::passkey::Model,
    M3 = crate::store::entities::two_factor::Model,
    M4 = crate::store::entities::jwk::Model,
    M5 = crate::store::entities::wallet_address::Model,
>(PhantomData<(M0, M1, M2, M3, M4, M5)>);

impl<M0, M1, M2, M3, M4, M5> SeaOrmPluginSchema for PluginModels<M0, M1, M2, M3, M4, M5>
where
    M0: SeaOrmPluginModel<Record = better_auth_core::ApiKey>,
    M1: SeaOrmPluginModel<Record = better_auth_core::DeviceCode>,
    M2: SeaOrmPluginModel<Record = better_auth_core::Passkey>,
    M3: SeaOrmPluginModel<Record = better_auth_core::TwoFactor>,
    M4: SeaOrmPluginModel<Record = better_auth_core::Jwk>,
    M5: SeaOrmPluginModel<Record = better_auth_core::WalletAddress>,
{
    type ApiKey = M0;
    type DeviceCode = M1;
    type Passkey = M2;
    type TwoFactor = M3;
    type Jwk = M4;
    type WalletAddress = M5;
}

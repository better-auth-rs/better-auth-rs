//! Typed model bindings for Organization plugin persistence.

use better_auth_core::FieldMap;
use better_auth_core::{
    AuthResult,
    user_fields::{AdapterRecord, UserConfig},
};
use sea_orm::{
    ActiveModelBehavior, ActiveModelTrait, ColumnTrait, DbBackend, EntityTrait, FromQueryResult,
    IntoActiveModel,
};
use serde::Serialize;
use std::marker::PhantomData;

/// A typed organization model. Derive this binding with `AuthEntity` and an organization entity role.
pub trait SeaOrmOrganizationModel:
    Serialize + Clone + Send + Sync + FromQueryResult + IntoActiveModel<Self::ActiveModel> + 'static
{
    /// Public domain record returned by the store.
    type Record;
    /// SeaORM entity containing the configured table name.
    type Entity: EntityTrait<Model = Self, Column = Self::Column>;
    /// Typed insert and update values.
    type ActiveModel: ActiveModelTrait<Entity = Self::Entity> + ActiveModelBehavior + Default + Send;
    /// Entity columns, including application-owned fields.
    type Column: ColumnTrait;
    /// Resolve a logical or serialized field name to the application's column.
    fn column(name: &str) -> AuthResult<Self::Column>;
    /// Return whether the column stores a typed built-in field.
    fn is_core_column(column: &Self::Column) -> bool;
    /// Return the canonical public name of a built-in column.
    fn core_field_name(column: &Self::Column) -> Option<&'static str>;
    /// Extract logical core fields and stored application fields before projection.
    fn record_fields(&self, fields: &UserConfig) -> AuthResult<AdapterRecord>;
    /// Decode projected fields while retaining typed model values for unconfigured fields.
    fn record_from_fields(
        &self,
        fields: &UserConfig,
        projected: FieldMap,
    ) -> AuthResult<Self::Record>;
    /// Project one stored model with the same policy ordering as a batch.
    fn record(
        &self,
        fields: &UserConfig,
        backend: DbBackend,
    ) -> impl Future<Output = AuthResult<Self::Record>> + Send {
        async move {
            Ok(Self::records(std::slice::from_ref(self), fields, backend)
                .await?
                .remove(0))
        }
    }
    /// Project a batch before decoding records, preserving callback and result order.
    fn records(
        rows: &[Self],
        fields: &UserConfig,
        backend: DbBackend,
    ) -> impl Future<Output = AuthResult<Vec<Self::Record>>> + Send {
        async move {
            let records = rows
                .iter()
                .map(|row| crate::store::organization_record_fields(row, fields, backend))
                .collect::<AuthResult<Vec<_>>>()?;
            let projected = fields
                .organization_output_records(records, backend == DbBackend::Postgres)
                .await?;
            rows.iter()
                .zip(projected)
                .map(|(row, projected)| row.record_from_fields(fields, projected))
                .collect()
        }
    }
    /// Return whether the column references another model ID.
    fn is_id_reference(column: &Self::Column) -> bool;
    /// Assign typed fields in an insert or update.
    fn apply_fields(active: &mut Self::ActiveModel, fields: FieldMap) -> AuthResult<()>;

    /// Construct an insert or partial update without bypassing typed column conversion.
    fn active(fields: FieldMap) -> AuthResult<Self::ActiveModel> {
        let mut active = <Self::ActiveModel as Default>::default();
        Self::apply_fields(&mut active, fields)?;
        Ok(active)
    }
}

/// Application-owned organization models; independent of the core authentication schema.
pub trait SeaOrmOrganizationSchema: Send + Sync + 'static {
    /// Organization table.
    type Organization: SeaOrmOrganizationModel<Record = better_auth_core::Organization>;
    /// Organization membership table.
    type Member: SeaOrmOrganizationModel<Record = better_auth_core::Member>;
    /// Organization invitation table.
    type Invitation: SeaOrmOrganizationModel<Record = better_auth_core::Invitation>;
    /// Organization team table.
    type Team: SeaOrmOrganizationModel<Record = better_auth_core::Team>;
    /// Team membership table.
    type TeamMember: SeaOrmOrganizationModel<Record = better_auth_core::TeamMember>;
    /// Dynamic organization role table.
    type OrganizationRole: SeaOrmOrganizationModel<Record = better_auth_core::OrganizationRole>;
}

/// Select organization models. Omitted model parameters use the bundled tables.
pub struct OrganizationModels<
    O = crate::store::entities::organization::Model,
    M = crate::store::entities::member::Model,
    I = crate::store::entities::invitation::Model,
    T = crate::store::entities::team::Model,
    TM = crate::store::entities::team_member::Model,
    R = crate::store::entities::organization_role::Model,
>(PhantomData<(O, M, I, T, TM, R)>);

impl<O, M, I, T, TM, R> SeaOrmOrganizationSchema for OrganizationModels<O, M, I, T, TM, R>
where
    O: SeaOrmOrganizationModel<Record = better_auth_core::Organization>,
    M: SeaOrmOrganizationModel<Record = better_auth_core::Member>,
    I: SeaOrmOrganizationModel<Record = better_auth_core::Invitation>,
    T: SeaOrmOrganizationModel<Record = better_auth_core::Team>,
    TM: SeaOrmOrganizationModel<Record = better_auth_core::TeamMember>,
    R: SeaOrmOrganizationModel<Record = better_auth_core::OrganizationRole>,
{
    type Organization = O;
    type Member = M;
    type Invitation = I;
    type Team = T;
    type TeamMember = TM;
    type OrganizationRole = R;
}

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
    /// Resolve optional adapter storage. Unknown mappings must retain their errors.
    fn private_column(name: &str) -> AuthResult<Option<Self::Column>> {
        Self::column(name).map(Some)
    }
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

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Tests intentionally panic when fixture setup or adapter contract assertions fail."
)]
mod tests {
    use super::*;
    use better_auth_core::{AuthRecordFields, FieldValue};

    #[expect(
        clippy::panic_in_result_fn,
        reason = "Contract assertions panic while model conversion errors retain their types"
    )]
    fn check_projected_record<M: SeaOrmOrganizationModel>(model: &M) -> AuthResult<M::Record>
    where
        M::Record: AuthRecordFields + Serialize + serde::de::DeserializeOwned,
    {
        let role: FieldValue = FieldMap::from([("custom".into(), true.into())]).into();
        let projected = FieldMap::from([
            ("role".into(), role.clone()),
            ("extra".into(), false.into()),
            ("id".into(), FieldValue::Undefined),
            ("createdAt".into(), FieldValue::Null),
        ]);
        let record = model.record_from_fields(&UserConfig::default(), projected.clone())?;
        let actual = record.field_values()?;
        assert_eq!(actual, projected);
        assert_eq!(
            actual.keys().collect::<Vec<_>>(),
            projected.keys().collect::<Vec<_>>()
        );
        assert!(
            actual
                .get("role")
                .and_then(FieldValue::as_object)
                .zip(role.as_object())
                .is_some_and(|(actual, expected)| actual.same_object(expected))
        );
        assert_eq!(
            serde_json::to_string(&record)?,
            r#"{"role":{"custom":true},"extra":false,"createdAt":null}"#
        );
        let decoded: M::Record = serde_json::from_str(&serde_json::to_string(&record)?)?;
        let mut json_fields = projected;
        let _ = json_fields.remove("id");
        let decoded_fields = decoded.field_values()?;
        assert_eq!(decoded_fields, json_fields);
        assert_eq!(
            decoded_fields.keys().collect::<Vec<_>>(),
            json_fields.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            serde_json::to_string(&decoded)?,
            r#"{"role":{"custom":true},"extra":false,"createdAt":null}"#
        );
        Ok(record)
    }

    #[test]
    fn organization_models_preserve_projected_presence_order_and_identity() -> AuthResult<()> {
        use crate::store::entities::{
            invitation, member, organization, organization_role, team, team_member,
        };

        let organization = check_projected_record(&organization::Model {
            id: "organization".into(),
            name: "Organization".into(),
            slug: "organization".into(),
            logo: None,
            metadata: None,
            created_at: Default::default(),
            auth_updated_at: Default::default(),
        })?;
        let copied = better_auth_core::Organization::from(&organization);
        assert_eq!(copied.field_order, organization.field_order);
        assert_eq!(copied.field_values()?, organization.field_values()?);
        let view = better_auth_core::OrganizationView::from(&organization);
        assert_eq!(view.field_order, organization.field_order);
        let view_fields = view.field_values()?;
        let organization_fields = organization.field_values()?;
        assert_eq!(view_fields, organization_fields);
        assert_eq!(
            view_fields.keys().collect::<Vec<_>>(),
            organization_fields.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            serde_json::to_string(&view)?,
            r#"{"role":{"custom":true},"extra":false,"createdAt":null}"#
        );
        let mut reordered_view = view.clone();
        reordered_view.field_order.reverse();
        assert_eq!(reordered_view, view);
        let mut reordered = organization.clone();
        reordered.field_order.reverse();
        assert_eq!(reordered, organization);

        let _ = check_projected_record(&member::Model {
            id: "member".into(),
            organization_id: "organization".into(),
            user_id: "user".into(),
            role: "member".into(),
            created_at: Default::default(),
        })?;
        let _ = check_projected_record(&invitation::Model {
            team_id: Some("team".into()),
            id: "invitation".into(),
            organization_id: "organization".into(),
            email: "invitee@example.com".into(),
            role: "member".into(),
            status: "pending".into(),
            inviter_id: "user".into(),
            expires_at: Default::default(),
            created_at: Default::default(),
        })?;
        let _ = check_projected_record(&team::Model {
            id: "team".into(),
            name: "Team".into(),
            organization_id: "organization".into(),
            created_at: Default::default(),
            updated_at: None,
            member_count: 0,
        })?;
        let _ = check_projected_record(&team_member::Model {
            id: "team-member".into(),
            team_id: "team".into(),
            user_id: "user".into(),
            membership_key: Some("internal-key".into()),
            created_at: None,
        })?;
        let role = check_projected_record(&organization_role::Model {
            id: "role".into(),
            organization_id: "organization".into(),
            role: "reader".into(),
            permission: serde_json::json!({}),
            created_at: Default::default(),
            updated_at: None,
        })?;
        let mut reordered = role.clone();
        reordered.field_order.reverse();
        assert_eq!(reordered, role);
        Ok(())
    }
}

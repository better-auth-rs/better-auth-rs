use super::*;
use crate::store::query_compile::Execute;
use sea_orm::IdenStatic;

impl<
    S: better_auth_core::AuthSchema,
    O: crate::SeaOrmOrganizationSchema,
    P: crate::SeaOrmPluginSchema,
> SeaOrmStore<S, O, P>
{
    pub(super) async fn delete_team_with_context(
        &self,
        id: &FieldValue,
        request_organization: Option<&FieldValue>,
    ) -> AuthResult<()> {
        let tx = self.connection().begin().await.map_err(map_db_err)?;
        let (organization_id, public_id) = match request_organization {
            Some(organization_id) => (organization_id.clone(), id.clone()),
            None => {
                let team = self
                    .find_organization_model::<O::Team>(&tx, EntityRole::Team, id)
                    .await?
                    .ok_or_else(|| AuthError::not_found("Team not found"))?;
                let schema = self.organization_query_schema(EntityRole::Team)?;
                let organization_column =
                    O::Team::column(schema.record_storage_key("organizationId"))?;
                let organization_id = team.value(organization_column.as_str())?;
                let raw_id = team.value(O::Team::column("id")?.as_str())?;
                let public_id = if raw_id.is_null() || raw_id.is_undefined() {
                    raw_id
                } else {
                    raw_id.display_utf16()?.into()
                };
                (organization_id, public_id)
            }
        };
        let _ = Entity::<O::TeamMember>::delete_many()
            .filter(self.organization_field_equals::<O::TeamMember>(
                EntityRole::TeamMember,
                "teamId",
                id,
            )?)
            .exec_native(&tx)
            .await?;
        let _ = Entity::<O::Team>::delete_many()
            .filter(self.organization_field_equals::<O::Team>(EntityRole::Team, "id", id)?)
            .exec_native(&tx)
            .await?;
        let config = self.organization_fields()?.invitation;
        let pending = self
            .pending_invitation_rows(&tx, &organization_id, None)
            .await?;
        for row in pending {
            if let Some(ids) = row.team_id.typed()? {
                let retained: Vec<_> = ids
                    .split(',')
                    .filter(|team_id| !FieldValue::from(*team_id).strict_equals(&public_id))
                    .collect();
                if retained.len() != ids.split(',').count() {
                    let _ = self
                        .update_organization_model::<O::Invitation>(
                            &tx,
                            EntityRole::Invitation,
                            &row.id.field_value(),
                            values([(
                                "team_id",
                                ((!retained.is_empty()).then(|| retained.join(","))).into_field(),
                            )]),
                            Default::default(),
                            &config,
                        )
                        .await?;
                }
            }
        }
        tx.commit().await.map_err(map_db_err)
    }
}

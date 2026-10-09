use super::*;
use better_auth_schema_registry::EntityRole;

impl EphemeralStore {
    pub(super) async fn delete_member_subject(
        &self,
        id: &Value,
        subject: Option<(&Value, &Value)>,
    ) -> AuthResult<()> {
        let id = self.organization_query(EntityRole::Member, "id", id.clone())?;
        let (organization_id, user_id) = match subject {
            Some((organization_id, user_id)) if user_id.is_truthy() => (
                crate::SchemaValue::from_field(organization_id.clone()),
                crate::SchemaValue::from_field(user_id.clone()),
            ),
            Some((organization_id, _)) => {
                let member = self
                    .lock()?
                    .members
                    .get(&id)?
                    .ok_or_else(|| AuthError::not_found("Member not found"))?;
                let member = self.output_member(member).await?;
                (
                    crate::SchemaValue::from_field(organization_id.clone()),
                    member.user_id,
                )
            }
            None => {
                let Some(member) = self.lock()?.members.get(&id)? else {
                    return Ok(());
                };
                let member = self.output_member(member).await?;
                (member.organization_id, member.user_id)
            }
        };
        let organization_id = self.organization_reference_query(
            EntityRole::Team,
            "organizationId",
            &organization_id,
        )?;
        let user_id = user_id.field_value();
        let teams = {
            let mut state = self.lock()?;
            let _ = state.members.remove(&id)?;
            state
                .teams
                .snapshot()?
                .into_iter()
                .filter(|team| team.organization_id == organization_id)
                .collect()
        };
        let teams = crate::query::paginate_memory(
            teams,
            Some(self.config.advanced.database.find_many_limit()),
            None,
        );
        let teams = self.output_records(EntityRole::Team, teams).await?;
        for team in teams {
            crate::store::TeamStore::remove_team_member_value(
                self,
                &team.id.field_value(),
                &user_id,
            )
            .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CreateTeam,
        organization_fields::OrganizationFields,
        store::TeamStore,
        user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform},
    };

    #[tokio::test]
    async fn falsy_member_subject_uses_projected_user_and_preserves_supplied_organization()
    -> AuthResult<()> {
        for subject in [
            Value::Undefined,
            Value::Null,
            false.into(),
            0.0.into(),
            "".into(),
        ] {
            let store = EphemeralStore::new(test_config());
            let member = store
                .create_member(CreateMember::new("source", "stored-user", "member"))
                .await?;
            let selected = store
                .create_team(CreateTeam {
                    name: "Selected".into(),
                    organization_id: "selected".into(),
                    ..Default::default()
                })
                .await?;
            let other = store
                .create_team(CreateTeam {
                    name: "Other".into(),
                    organization_id: "source".into(),
                    ..Default::default()
                })
                .await?;
            let _ = store
                .add_team_member(&selected.id, "projected-user", Some(2))
                .await?;
            let retained = store
                .add_team_member(&selected.id, "stored-user", Some(2))
                .await?
                .unwrap();
            let elsewhere = store
                .add_team_member(&other.id, "projected-user", Some(1))
                .await?
                .unwrap();
            let mut fields = OrganizationFields::default();
            let _ = fields.member.fields_mut().insert(
                "userId".into(),
                UserFieldConfig {
                    transform: Some(FieldTransforms {
                        output: Some(UserFieldTransform::new(|_| Ok("projected-user".into()))),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            );
            store.configure_organization_fields(fields)?;
            store
                .delete_member_for_user_value(
                    &member.id.field_value(),
                    &"selected".into(),
                    &subject,
                )
                .await?;
            assert!(store.get_member_by_id(member.id.typed()?).await?.is_none());
            assert_eq!(
                store.list_team_members(selected.id.typed()?).await?,
                vec![retained]
            );
            assert_eq!(
                store.list_team_members(other.id.typed()?).await?,
                vec![elsewhere]
            );
            assert_eq!(store.count_team_members(selected.id.typed()?).await?, 1);
            assert_eq!(
                store
                    .lock()?
                    .teams
                    .get(&selected.id)?
                    .unwrap()
                    .additional_fields["memberCount"],
                Value::Number(1.0)
            );
        }
        Ok(())
    }
}

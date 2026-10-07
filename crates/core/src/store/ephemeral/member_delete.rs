use super::*;
use better_auth_schema_registry::EntityRole;

impl EphemeralStore {
    pub(super) async fn delete_member_subject(
        &self,
        id: &str,
        subject: Option<(&str, &str)>,
    ) -> AuthResult<()> {
        let id = self.organization_query(EntityRole::Member, "id", Value::from(id))?;
        let (organization_id, user_id) = match subject {
            Some((organization_id, user_id)) => (organization_id.into(), user_id.into()),
            None => {
                let Some(member) = self.lock()?.members.get(&id)? else {
                    return Ok(());
                };
                (member.organization_id, member.user_id)
            }
        };
        let organization_id = self.organization_reference_query(
            EntityRole::Team,
            "organizationId",
            &organization_id,
        )?;
        let user_id = self.organization_primary_id(&user_id)?;
        let user_id = Self::project_id(&user_id)?;
        let user_id = user_id.typed()?;
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
            crate::store::TeamStore::remove_team_member(self, team.id.typed()?, user_id).await?;
        }
        Ok(())
    }
}

use super::fields::PreparedOrganizationFields;
use super::*;
use crate::Team;
use better_auth_schema_registry::EntityRole;

fn member_count(team: &Team) -> AuthResult<Option<f64>> {
    match team.additional_fields.get("memberCount") {
        Some(Value::Null) | None => Ok(None),
        Some(Value::Number(value)) => Ok(Some(*value)),
        _ => Err(AuthError::internal(
            "Team memberCount must be numeric for this operation",
        )),
    }
}

/// Prepared callbacks cannot be replayed when another writer changes the seat calculation.
pub(super) struct PreparedTeamSeats {
    count: Option<f64>,
    actual: usize,
    patch: Option<PreparedOrganizationFields>,
    next_count: Option<Option<f64>>,
    pub(super) reserved: bool,
}

impl PreparedTeamSeats {
    pub(super) fn is_current(&self, team: &Team, actual: usize) -> AuthResult<bool> {
        Ok(actual == self.actual && member_count(team)? == self.count)
    }

    pub(super) fn apply(self, mut team: Team, actual: usize) -> AuthResult<Team> {
        if !self.is_current(&team, actual)? {
            return Err(AuthError::conflict(
                "Team capacity changed while field transforms were pending",
            ));
        }
        if let Some(patch) = self.patch {
            team = patch.apply(team)?;
        }
        if let Some(count) = self.next_count {
            let _ = team
                .additional_fields
                .insert("memberCount".into(), count.into_field());
        }
        Ok(team)
    }
}

impl EphemeralStore {
    pub(super) async fn prepare_team_reservation(
        &self,
        mut team: Team,
        actual: usize,
        maximum: Option<usize>,
    ) -> AuthResult<PreparedTeamSeats> {
        let initial_count = member_count(&team)?;
        let patch = self
            .prepare_record_patch(
                EntityRole::Team,
                [("memberCount".into(), Value::from(actual))]
                    .into_iter()
                    .collect(),
                FieldMap::new(),
            )
            .await?;
        let patch = if initial_count.is_some_and(|count| count < actual as f64) {
            team = patch.clone().apply(team)?;
            let _ = self.output_team(team.clone()).await?;
            Some(patch)
        } else {
            None
        };
        let count = member_count(&team)?;
        let reserved = maximum.is_none_or(|maximum| {
            actual < maximum && count.is_some_and(|count| count < maximum as f64)
        });
        let next_count = if reserved {
            let count = count.map(|count| count + 1.0);
            let _ = team
                .additional_fields
                .insert("memberCount".into(), count.into_field());
            let _ = self.output_team(team).await?;
            Some(count)
        } else {
            None
        };
        Ok(PreparedTeamSeats {
            count: initial_count,
            actual,
            patch,
            next_count,
            reserved,
        })
    }

    pub(super) async fn prepare_team_release(
        &self,
        mut team: Team,
        actual: usize,
        deleted: usize,
    ) -> AuthResult<PreparedTeamSeats> {
        let count = member_count(&team)?;
        let next_count = if deleted > 0 {
            count.filter(|count| *count >= deleted as f64)
        } else {
            None
        };
        if let Some(count) = next_count {
            let _ = team
                .additional_fields
                .insert("memberCount".into(), Value::Number(count - deleted as f64));
            let _ = self.output_team(team).await?;
        }
        Ok(PreparedTeamSeats {
            count,
            actual,
            patch: None,
            next_count: next_count.map(|count| Some(count - deleted as f64)),
            reserved: false,
        })
    }
}

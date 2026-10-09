use super::fields::PreparedOrganizationFields;
use super::rows::{RowRef, Rows};
use super::*;
use better_auth_schema_registry::EntityRole;

fn member_count(team: &FieldMap, column: &str) -> AuthResult<Option<f64>> {
    match team.get(column) {
        Some(Value::Null) | None => Ok(None),
        Some(Value::Number(value)) => Ok(Some(*value)),
        _ => Err(AuthError::internal(
            "Team memberCount must be numeric for this operation",
        )),
    }
}

/// Prepared callbacks cannot be replayed when another writer changes the seat calculation.
pub(super) struct PreparedTeamSeats {
    source: RowRef<FieldMap>,
    count: Option<f64>,
    column: String,
    actual: usize,
    patch: Option<PreparedOrganizationFields>,
    next_count: Option<Option<f64>>,
    pub(super) reserved: bool,
}

impl PreparedTeamSeats {
    pub(super) fn current(&self, teams: &Rows<FieldMap>) -> AuthResult<FieldMap> {
        if !teams.contains_ref(&self.source) {
            return Err(AuthError::conflict(
                "Team changed while field transforms were pending",
            ));
        }
        self.source.read(|row| Ok(row.clone()))
    }

    pub(super) fn is_current(&self, teams: &Rows<FieldMap>, actual: usize) -> AuthResult<bool> {
        let team = self.current(teams)?;
        Ok(actual == self.actual && member_count(&team, &self.column)? == self.count)
    }

    pub(super) fn apply(
        self,
        teams: &Rows<FieldMap>,
        actual: usize,
    ) -> AuthResult<(RowRef<FieldMap>, FieldMap)> {
        if !self.is_current(teams, actual)? {
            return Err(AuthError::conflict(
                "Team capacity changed while field transforms were pending",
            ));
        }
        let mut team = self.current(teams)?;
        if let Some(patch) = self.patch {
            team = patch.apply(team);
        }
        if let Some(count) = self.next_count {
            let _ = team.insert(self.column, count.into_field());
        }
        Ok((self.source, team))
    }
}

impl EphemeralStore {
    pub(super) async fn prepare_team_reservation(
        &self,
        source: RowRef<FieldMap>,
        actual: usize,
        maximum: Option<usize>,
    ) -> AuthResult<PreparedTeamSeats> {
        let mut team = source.read(|row| Ok(row.clone()))?;
        let column = self
            .field_config(EntityRole::Team)?
            .record_storage_key("memberCount")
            .to_owned();
        let initial_count = member_count(&team, &column)?;
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
            team = patch.clone().apply(team);
            let _ = self.output_team(team.clone()).await?;
            Some(patch)
        } else {
            None
        };
        let count = member_count(&team, &column)?;
        let reserved = maximum.is_none_or(|maximum| {
            actual < maximum && count.is_some_and(|count| count < maximum as f64)
        });
        let next_count = if reserved {
            let count = count.map(|count| count + 1.0);
            let _ = team.insert(column.clone(), count.into_field());
            let _ = self.output_team(team).await?;
            Some(count)
        } else {
            None
        };
        Ok(PreparedTeamSeats {
            source,
            count: initial_count,
            column,
            actual,
            patch,
            next_count,
            reserved,
        })
    }

    pub(super) async fn prepare_team_release(
        &self,
        source: RowRef<FieldMap>,
        actual: usize,
        deleted: usize,
    ) -> AuthResult<PreparedTeamSeats> {
        let mut team = source.read(|row| Ok(row.clone()))?;
        let column = self
            .field_config(EntityRole::Team)?
            .record_storage_key("memberCount")
            .to_owned();
        let count = member_count(&team, &column)?;
        let next_count = if deleted > 0 {
            count.filter(|count| *count >= deleted as f64)
        } else {
            None
        };
        if let Some(count) = next_count {
            let _ = team.insert(column.clone(), Value::Number(count - deleted as f64));
            let _ = self.output_team(team).await?;
        }
        Ok(PreparedTeamSeats {
            source,
            count,
            column,
            actual,
            patch: None,
            next_count: next_count.map(|count| Some(count - deleted as f64)),
            reserved: false,
        })
    }
}

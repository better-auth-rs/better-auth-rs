use super::fields::PreparedOrganizationFields;
use super::rows::{RowRef, Rows};
use super::*;
use better_auth_schema_registry::EntityRole;

pub(super) struct StagedTeamMember {
    pub(super) member: crate::TeamMember,
    pub(super) created: bool,
    pub(super) base: Rows<FieldMap>,
    pub(super) working: Rows<FieldMap>,
}

fn increment_count(team: &FieldMap, column: &str, delta: f64) -> Value {
    // Memory incrementOne uses zero for every stored value whose JavaScript type is not number.
    let count = team.get(column).and_then(Value::as_f64).unwrap_or(0.0);
    Value::Number(count + delta)
}

fn count_compare(
    team: &FieldMap,
    column: &str,
    count: &Value,
) -> AuthResult<Option<std::cmp::Ordering>> {
    crate::query::field_compare(team.get(column).unwrap_or(&Value::Undefined), count)
}

/// Prepared callbacks cannot be replayed when another writer changes the seat calculation.
pub(super) struct PreparedTeamSeats {
    source: RowRef<FieldMap>,
    count: Option<Value>,
    column: String,
    actual: usize,
    patch: Option<PreparedOrganizationFields>,
    next_count: Option<Value>,
    pub(super) reserved: bool,
}

impl PreparedTeamSeats {
    fn fields(&self) -> AuthResult<FieldMap> {
        let mut team = self.source.read(|row| Ok(row.clone()))?;
        if let Some(patch) = &self.patch {
            team = patch.clone().apply(team);
        }
        if let Some(count) = &self.next_count {
            let _ = team.insert(self.column.clone(), count.clone());
        }
        Ok(team)
    }

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
        let unchanged = match (team.get(&self.column), &self.count) {
            (Some(current), Some(original)) => current.same_value_zero(original),
            (None, None) => true,
            _ => false,
        };
        Ok(actual == self.actual && unchanged)
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
        let team = self.fields()?;
        Ok((self.source, team))
    }
}

impl EphemeralStore {
    pub(super) fn team_member_selectors(
        &self,
        team_id: &Value,
        user_id: Option<&Value>,
    ) -> AuthResult<Vec<(String, Value)>> {
        let mut values = vec![("teamId", team_id.clone())];
        if let Some(user_id) = user_id {
            values.push(("userId", user_id.clone()));
        }
        self.team_member_field_selectors(values)
    }

    fn team_member_field_selectors(
        &self,
        values: Vec<(&str, Value)>,
    ) -> AuthResult<Vec<(String, Value)>> {
        let schema = self.field_config(EntityRole::TeamMember)?;
        values
            .into_iter()
            .map(|(name, value)| {
                Ok((
                    schema.record_storage_key(name).to_owned(),
                    self.organization_query(EntityRole::TeamMember, name, value)?
                        .field_value(),
                ))
            })
            .collect()
    }

    pub(super) fn matches_team_member(row: &FieldMap, selectors: &[(String, Value)]) -> bool {
        selectors.iter().all(|(name, value)| {
            row.get(name)
                .unwrap_or(&Value::Undefined)
                .strict_equals(value)
        })
    }

    pub(super) fn team_member_by_key_or_pair(
        &self,
        state: &State,
        team_id: &Value,
        user_id: &Value,
        key: &str,
    ) -> AuthResult<Option<RowRef<FieldMap>>> {
        let selectors = self.team_member_field_selectors(vec![("membershipKey", key.into())])?;
        if let Some(row) = state
            .team_members
            .first_ref(|row| Self::matches_team_member(row, &selectors))?
        {
            return Ok(Some(row));
        }
        let selectors = self.team_member_selectors(team_id, Some(user_id))?;
        state
            .team_members
            .first_ref(|row| Self::matches_team_member(row, &selectors))
    }

    pub(super) async fn find_team_member_by_key_or_pair(
        &self,
        team_id: &Value,
        user_id: &Value,
        key: &str,
    ) -> AuthResult<Option<crate::TeamMember>> {
        let row = {
            let state = self.lock()?;
            self.team_member_by_key_or_pair(&state, team_id, user_id, key)?
        };
        Ok(self
            .output_record_refs(EntityRole::TeamMember, row.into_iter().collect())
            .await?
            .into_iter()
            .next())
    }

    pub(super) async fn stage_team_member(
        &self,
        team_id: &Value,
        user_id: &Value,
        key: &str,
    ) -> AuthResult<StagedTeamMember> {
        let (base, staged, _queue) = self.begin_transaction()?;
        let (member, created) = staged
            .create_team_member_with_key(team_id, user_id, key)
            .await?;
        let working = staged.lock()?.team_members.clone();
        Ok(StagedTeamMember {
            member,
            created,
            base: base.team_members,
            working,
        })
    }

    pub(super) async fn create_team_member_with_key(
        &self,
        team_id: &Value,
        user_id: &Value,
        key: &str,
    ) -> AuthResult<(crate::TeamMember, bool)> {
        let result = async {
            let mut fields = self
                .organization_storage_fields(
                    EntityRole::TeamMember,
                    [
                        ("teamId".into(), team_id.clone()),
                        ("userId".into(), user_id.clone()),
                        ("membershipKey".into(), key.into()),
                        ("createdAt".into(), Value::from(Utc::now())),
                    ]
                    .into(),
                    FieldMap::new(),
                    true,
                )
                .await?;
            let row = {
                let mut state = self.lock()?;
                if let Some(id) = self.next_serial_id(state.team_members.len()) {
                    let _ = fields.insert("id".into(), id);
                }
                state.team_members.push_ref(fields)
            };
            self.output_record_refs(EntityRole::TeamMember, vec![row])
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| AuthError::internal("Team membership projection returned no row"))
        }
        .await;
        Ok(match result {
            Ok(member) => (member, true),
            Err(error) => match self
                .find_team_member_by_key_or_pair(team_id, user_id, key)
                .await?
            {
                Some(member) => (member, false),
                None => return Err(error),
            },
        })
    }

    pub(super) async fn release_prepared_team_seat(
        &self,
        prepared: &mut PreparedTeamSeats,
    ) -> AuthResult<()> {
        let minimum = self
            .organization_query(EntityRole::Team, "memberCount", Value::from(1))?
            .field_value();
        let mut team = prepared.fields()?;
        if count_compare(&team, &prepared.column, &minimum)?.is_some_and(|order| !order.is_lt()) {
            let count = increment_count(&team, &prepared.column, -1.0);
            let _ = team.insert(prepared.column.clone(), count.clone());
            let _ = self.output_team(team).await?;
            prepared.next_count = Some(count);
        }
        Ok(())
    }

    pub(super) async fn increment_prepared_team_seat(
        &self,
        prepared: &mut PreparedTeamSeats,
    ) -> AuthResult<()> {
        let mut team = prepared.fields()?;
        let count = increment_count(&team, &prepared.column, 1.0);
        let _ = team.insert(prepared.column.clone(), count.clone());
        let _ = self.output_team(team).await?;
        prepared.next_count = Some(count);
        Ok(())
    }

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
        let initial_count = team.get(&column).cloned();
        let actual_count = self
            .organization_query(EntityRole::Team, "memberCount", Value::from(actual))?
            .field_value();
        let patch = self
            .prepare_record_patch(
                EntityRole::Team,
                [("memberCount".into(), Value::from(actual))]
                    .into_iter()
                    .collect(),
                FieldMap::new(),
            )
            .await?;
        let patch =
            if count_compare(&team, &column, &actual_count)?.is_some_and(|order| order.is_lt()) {
                team = patch.clone().apply(team);
                let _ = self.output_team(team.clone()).await?;
                Some(patch)
            } else {
                None
            };
        let reserved = match maximum {
            Some(maximum) => {
                let bound = self
                    .organization_query(EntityRole::Team, "memberCount", Value::from(maximum))?
                    .field_value();
                actual < maximum
                    && count_compare(&team, &column, &bound)?.is_some_and(|order| order.is_lt())
            }
            None => true,
        };
        let next_count = if reserved && maximum.is_some() {
            let count = increment_count(&team, &column, 1.0);
            let _ = team.insert(column.clone(), count.clone());
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

    pub(super) async fn release_team_seats(
        &self,
        team_id: &Value,
        deleted: usize,
    ) -> AuthResult<()> {
        if deleted == 0 {
            return Ok(());
        }
        let team_id = self.organization_query(EntityRole::Team, "id", team_id.clone())?;
        let minimum =
            self.organization_query(EntityRole::Team, "memberCount", Value::from(deleted))?;
        let column = self
            .field_config(EntityRole::Team)?
            .record_storage_key("memberCount")
            .to_owned();
        let source = {
            let state = self.lock()?;
            let Some(source) = state.teams.first_ref(|row| {
                row.get("id")
                    .unwrap_or(&Value::Undefined)
                    .strict_equals(&team_id.field_value())
            })?
            else {
                return Ok(());
            };
            let changed = source.write(|row| {
                if !crate::query::field_compare(
                    row.get(&column).unwrap_or(&Value::Undefined),
                    &minimum.field_value(),
                )?
                .is_some_and(|order| !order.is_lt())
                {
                    return Ok(false);
                }
                let count = increment_count(row, &column, -(deleted as f64));
                let _ = row.insert(column, count);
                Ok(true)
            })?;
            changed.then_some(source)
        };
        let _ = self
            .output_record_refs::<FieldMap>(EntityRole::Team, source.into_iter().collect())
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::TeamStore;
    use crate::user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    #[tokio::test]
    async fn membership_output_keeps_rows_and_seats_isolated_until_success() -> AuthResult<()> {
        for mode in ["commit", "reject", "cancel"] {
            let mut store = EphemeralStore::new(test_config());
            let team = store
                .create_team(crate::CreateTeam {
                    name: "Staged membership".into(),
                    organization_id: "organization".into(),
                    ..Default::default()
                })
                .await?;
            let original = store.lock()?.teams.snapshot()?;
            let started = Arc::new(Notify::new());
            let release = Arc::new(Notify::new());
            let calls = Arc::new(AtomicUsize::new(0));
            store.model_fields.register(
                EntityRole::TeamMember,
                UserConfig {
                    additional_fields: Some(
                        [(
                            "userId".into(),
                            UserFieldConfig {
                                transform: Some(FieldTransforms {
                                    output: Some(UserFieldTransform::new_async({
                                        let started = started.clone();
                                        let release = release.clone();
                                        let calls = calls.clone();
                                        move |value| {
                                            let started = started.clone();
                                            let release = release.clone();
                                            let first = calls.fetch_add(1, Ordering::SeqCst) == 0;
                                            async move {
                                                if first {
                                                    started.notify_one();
                                                    release.notified().await;
                                                }
                                                if mode == "reject" {
                                                    return Err(AuthError::type_error(
                                                        "membership-output-rejected",
                                                    ));
                                                }
                                                Ok(value)
                                            }
                                        }
                                    })),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            },
                        )]
                        .into(),
                    ),
                },
            );
            let task = tokio::spawn({
                let store = store.clone();
                let id = team.id.clone();
                async move { store.add_team_member(&id, "recipient", Some(1)).await }
            });
            started.notified().await;
            assert!(store.lock()?.team_members.snapshot()?.is_empty());
            assert_eq!(store.lock()?.teams.snapshot()?, original);
            if mode == "cancel" {
                task.abort();
                assert!(task.await.is_err_and(|error| error.is_cancelled()));
            } else {
                release.notify_one();
                let result = task
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                if mode == "reject" {
                    assert!(
                        matches!(result, Err(AuthError::TypeError(message)) if message == "membership-output-rejected")
                    );
                } else {
                    assert!(result?.is_some());
                }
            }
            assert_eq!(
                calls.load(Ordering::SeqCst),
                if mode == "reject" { 2 } else { 1 }
            );
            let state = store.lock()?;
            if mode == "commit" {
                assert_eq!(state.team_members.len(), 1);
                assert_eq!(
                    state
                        .teams
                        .get(&team.id)?
                        .ok_or_else(|| AuthError::internal("Team disappeared"))?["memberCount"],
                    Value::Number(1.0)
                );
            } else {
                assert_eq!(state.team_members.len(), 0);
                assert_eq!(state.teams.snapshot()?, original);
            }
        }
        Ok(())
    }
}

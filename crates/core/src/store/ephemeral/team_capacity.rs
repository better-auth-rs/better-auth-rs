use super::fields::PreparedOrganizationFields;
use super::rows::RowRef;
use super::table::TableRef;
use super::*;
use better_auth_schema_registry::EntityRole;

pub(super) struct StagedTeamMember {
    pub(super) member: crate::TeamMember,
    pub(super) created: bool,
    pub(super) base: TableRef<FieldMap>,
    pub(super) working: TableRef<FieldMap>,
}

pub(super) struct TeamMemberLookup {
    key: Vec<(String, Value)>,
    pair: Option<Vec<(String, Value)>>,
}

impl TeamMemberLookup {
    pub(super) fn find(&self, table: &TableRef<FieldMap>) -> AuthResult<Option<RowRef<FieldMap>>> {
        let row = table
            .select_refs(|row| super::organization_rows::matches(row, &self.key))?
            .into_iter()
            .next();
        match (row, &self.pair) {
            (Some(row), _) => Ok(Some(row)),
            (None, Some(pair)) => Ok(table
                .select_refs(|row| super::organization_rows::matches(row, pair))?
                .into_iter()
                .next()),
            (None, None) => Ok(None),
        }
    }
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
    selector: (String, Value),
    count: Option<Value>,
    column: String,
    actual: usize,
    patch: Option<PreparedOrganizationFields>,
    next_count: Option<Value>,
    pub(super) reserved: bool,
}

impl PreparedTeamSeats {
    pub(super) fn same_team(&self, source: &RowRef<FieldMap>) -> bool {
        self.source.same_row(source)
    }

    pub(super) fn pending_write(&self) -> (RowRef<FieldMap>, FieldMap) {
        let mut fields = self
            .patch
            .clone()
            .map(|patch| patch.apply(FieldMap::new()))
            .unwrap_or_default();
        if let Some(count) = &self.next_count {
            let _ = fields.insert(self.column.clone(), count.clone());
        }
        (self.source.clone(), fields)
    }

    fn fields(&self) -> AuthResult<FieldMap> {
        let (source, patch) = self.pending_write();
        super::rows::RecordSource::Live(source)
            .with_patch(patch)
            .shallow_fields()
    }

    pub(super) fn current(&self, teams: &TableRef<FieldMap>) -> AuthResult<FieldMap> {
        if !teams.contains_ref(&self.source)?
            || !super::organization_rows::matches(
                &self.source,
                std::slice::from_ref(&self.selector),
            )?
        {
            return Err(AuthError::conflict(
                "Team changed while field transforms were pending",
            ));
        }
        self.source.shallow_fields()
    }

    pub(super) fn is_current(&self, teams: &TableRef<FieldMap>, actual: usize) -> AuthResult<bool> {
        let team = self.current(teams)?;
        let unchanged = super::rows::same_field_value(team.get(&self.column), self.count.as_ref());
        Ok(actual == self.actual && unchanged)
    }

    pub(super) fn apply(
        &self,
        teams: &TableRef<FieldMap>,
        actual: usize,
    ) -> AuthResult<(RowRef<FieldMap>, FieldMap)> {
        if !self.is_current(teams, actual)? {
            return Err(AuthError::conflict(
                "Team capacity changed while field transforms were pending",
            ));
        }
        let team = self.fields()?;
        Ok((self.source.clone(), team))
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
        values
            .into_iter()
            .map(|(name, value)| self.organization_query_field(EntityRole::TeamMember, name, value))
            .collect()
    }

    pub(super) fn matches_team_member(
        row: &RowRef<FieldMap>,
        selectors: &[(String, Value)],
    ) -> AuthResult<bool> {
        super::organization_rows::matches(row, selectors)
    }

    pub(super) fn team_member_by_key_or_pair(
        &self,
        op: &super::operation::MemoryOperation<'_>,
        team_id: &Value,
        user_id: &Value,
        key: &str,
    ) -> AuthResult<Option<RowRef<FieldMap>>> {
        self.prepare_team_member_lookup(op, team_id, user_id, key)
            .map(|(row, _)| row)
    }

    pub(super) fn prepare_team_member_lookup(
        &self,
        op: &super::operation::MemoryOperation<'_>,
        team_id: &Value,
        user_id: &Value,
        key: &str,
    ) -> AuthResult<(Option<RowRef<FieldMap>>, TeamMemberLookup)> {
        let key = self.team_member_field_selectors(vec![("membershipKey", key.into())])?;
        let row = op
            .capture_table(EntityRole::TeamMember)?
            .select_refs(|row| Self::matches_team_member(row, &key))?
            .into_iter()
            .next();
        if row.is_some() {
            return Ok((row, TeamMemberLookup { key, pair: None }));
        }
        let pair = self.team_member_selectors(team_id, Some(user_id))?;
        let row = op
            .capture_table(EntityRole::TeamMember)?
            .select_refs(|row| Self::matches_team_member(row, &pair))?
            .into_iter()
            .next();
        Ok((
            row,
            TeamMemberLookup {
                key,
                pair: Some(pair),
            },
        ))
    }

    pub(super) async fn find_team_member_by_key_or_pair(
        &self,
        team_id: &Value,
        user_id: &Value,
        key: &str,
    ) -> AuthResult<Option<crate::TeamMember>> {
        let row =
            self.operation(|op| self.team_member_by_key_or_pair(op, team_id, user_id, key))?;
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
        let working = staged.operation(|op| op.capture_table(EntityRole::TeamMember))?;
        Ok(StagedTeamMember {
            member,
            created,
            base: self.snapshot_table(&base, EntityRole::TeamMember)?.clone(),
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
            let fields = self
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
            let row = self.insert_organization_row(EntityRole::TeamMember, fields)?;
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
        let (column, minimum) =
            self.organization_query_field(EntityRole::Team, "memberCount", Value::from(1))?;
        let mut team = prepared.fields()?;
        if count_compare(&team, &column, &minimum)?.is_some_and(|order| !order.is_lt()) {
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
        selector: (String, Value),
        actual: usize,
        maximum: Option<usize>,
    ) -> AuthResult<PreparedTeamSeats> {
        let mut team = source.shallow_fields()?;
        let (column, actual_count) =
            self.organization_query_field(EntityRole::Team, "memberCount", Value::from(actual))?;
        let initial_count = team.get(&column).cloned();
        let patch = self
            .prepare_increment_one_patch(
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
                let (bound_column, bound) = self.organization_query_field(
                    EntityRole::Team,
                    "memberCount",
                    Value::from(maximum),
                )?;
                actual < maximum
                    && count_compare(&team, &bound_column, &bound)?
                        .is_some_and(|order| order.is_lt())
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
            selector,
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
        let team_id = self.organization_query_field(EntityRole::Team, "id", team_id.clone())?;
        let (column, minimum) =
            self.organization_query_field(EntityRole::Team, "memberCount", Value::from(deleted))?;
        let source = self.operation(|op| {
            let selected = op
                .capture_table(EntityRole::Team)?
                .select_refs(|row| {
                    crate::memory_query::matches_all([0, 1], |clause| {
                        if clause == 0 {
                            return super::organization_rows::matches(
                                row,
                                std::slice::from_ref(&team_id),
                            );
                        }
                        Ok(crate::query::field_compare(
                            &row.field(&column)?.unwrap_or_default(),
                            &minimum,
                        )?
                        .is_some_and(|order| !order.is_lt()))
                    })
                })?
                .into_iter()
                .next();
            if let Some(source) = &selected {
                source.increment_number_fields(&[(column, -(deleted as f64))])?;
            }
            Ok(selected)
        })?;
        let _ = self
            .output_record_refs::<FieldMap>(EntityRole::Team, source.into_iter().collect())
            .await?;
        Ok(())
    }
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "Fixture indexing must fail when an expected record or property is missing. Assertions report exact contract mismatches while Result propagates fixture errors."
)]
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
            let original = store
                .operation(|op| op.capture_state())?
                .fixture_table("team")
                .snapshot()?;
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
            assert!(
                store
                    .operation(|op| op.capture_state())?
                    .fixture_table("teamMember")
                    .snapshot()?
                    .is_empty()
            );
            assert_eq!(
                store
                    .operation(|op| op.capture_state())?
                    .fixture_table("team")
                    .snapshot()?,
                original
            );
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
            let state = store.operation(|op| op.capture_state())?;
            if mode == "commit" {
                assert_eq!(state.fixture_table("teamMember").len()?, 1);
                assert_eq!(
                    state
                        .fixture_table("team")
                        .get(&team.id)?
                        .ok_or_else(|| AuthError::internal("Team disappeared"))?["memberCount"],
                    Value::Number(1.0)
                );
            } else {
                assert_eq!(state.fixture_table("teamMember").len()?, 0);
                assert_eq!(state.fixture_table("team").snapshot()?, original);
            }
        }
        Ok(())
    }
}

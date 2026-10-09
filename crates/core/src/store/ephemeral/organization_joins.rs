use super::rows::{RecordSource, RowRef};
use super::*;
use crate::store::{
    JoinValue, MemberUser, OrganizationDetails, OrganizationDetailsQuery, OrganizationKey,
};
use better_auth_schema_registry::EntityRole;

mod details;
mod member_user;
#[cfg(test)]
mod property_tests;
mod team_details;
#[cfg(test)]
mod tests;

struct NativeRelationship {
    parent: FieldMap,
    children: Vec<Vec<RowRef<FieldMap>>>,
    ids: Vec<Vec<Value>>,
}

fn raw_relation<T: AuthRecordFields + Clone + Send + 'static>(
    rows: &[RowRef<T>],
    many: bool,
) -> Value {
    if many {
        JoinValue::Many(rows.to_vec()).raw_value()
    } else {
        JoinValue::One(rows.first().cloned()).raw_value()
    }
}

fn native_relationships(
    parents: Vec<FieldMap>,
    relations: &[(
        &super::rows::Rows<FieldMap>,
        &crate::store::ResolvedJoin,
        f64,
    )],
) -> AuthResult<Vec<NativeRelationship>> {
    let mut groups = indexmap::IndexMap::new();
    for parent in parents {
        let id = parent
            .get("id")
            .unwrap_or(&Value::Undefined)
            .display_utf16()?;
        let values = relations
            .iter()
            .map(|(_, relation, _)| parent.get(&relation.from).cloned().unwrap_or_default())
            .collect::<Vec<_>>();
        let group = groups
            .entry(id.as_utf16().to_vec())
            .or_insert_with(|| NativeRelationship {
                parent,
                children: vec![Vec::new(); relations.len()],
                ids: vec![Vec::new(); relations.len()],
            });
        for ((((children, relation, limit), from), selected), ids) in relations
            .iter()
            .zip(values)
            .zip(&mut group.children)
            .zip(&mut group.ids)
        {
            let matches = children.select_refs(|row| {
                row.get(&relation.to)
                    .unwrap_or(&Value::Undefined)
                    .strict_equals(&from)
            })?;
            if !relation.many {
                *selected = matches.into_iter().take(1).collect();
                continue;
            }
            let mut added = 0_usize;
            for child in matches {
                if added as f64 >= *limit {
                    break;
                }
                let id = child.read(|row| Ok(row.get("id").cloned().unwrap_or_default()))?;
                if !ids.iter().any(|seen| seen.same_value_zero(&id)) {
                    ids.push(id);
                    selected.push(child);
                    added += 1;
                }
            }
        }
    }
    Ok(groups.into_values().collect())
}

impl EphemeralStore {
    pub(super) async fn joined_user_organizations(
        &self,
        user_id: &Value,
    ) -> AuthResult<Vec<Organization>> {
        let schema = self.field_config(EntityRole::Member)?;
        let user_id = self.organization_query(EntityRole::Member, "userId", user_id.clone())?;
        let (members, organizations) = {
            let state = self.lock()?;
            let rows = crate::query::paginate_memory(
                state
                    .members
                    .snapshot()?
                    .into_iter()
                    .filter(|row| {
                        organization_value(row, &schema, "userId")
                            .strict_equals(&user_id.field_value())
                    })
                    .collect(),
                Some(self.config.advanced.database.find_many_limit()),
                None,
            );
            let organizations = rows
                .iter()
                .map(|row| {
                    state.organizations.first_ref(|org| {
                        super::organization_rows::id(org)
                            .field_value()
                            .strict_equals(&organization_value(row, &schema, "organizationId"))
                    })
                })
                .collect::<AuthResult<Vec<_>>>()?;
            let sources = rows
                .into_iter()
                .zip(&organizations)
                .map(|(parent, child)| {
                    RecordSource::joined(
                        parent,
                        [(
                            self.model_fields
                                .storage_model_name(EntityRole::Organization, "organization")
                                .to_owned(),
                            JoinValue::One(child.clone()).raw_value(),
                        )],
                    )
                })
                .collect();
            (sources, organizations)
        };
        self.project_record_sources_batches_then(
            EntityRole::Member,
            &schema,
            members,
            |ready: Vec<(usize, FieldMap)>| {
                let organizations = &organizations;
                async move {
                    let mut indices = Vec::new();
                    let mut sources = Vec::new();
                    for (index, _) in ready {
                        if let Some(row) = organizations.get(index).ok_or_else(|| {
                            AuthError::internal("Member projection lost its stored join index")
                        })? {
                            indices.push(index);
                            sources.push(row.clone());
                        }
                    }
                    Ok(indices
                        .into_iter()
                        .zip(
                            self.output_record_refs(EntityRole::Organization, sources)
                                .await?,
                        )
                        .collect())
                }
            },
        )
        .await
    }

    pub(super) async fn joined_user_teams(&self, user_id: &Value) -> AuthResult<Vec<crate::Team>> {
        let member_schema = self.field_config(EntityRole::TeamMember)?;
        let team_schema = self.field_config(EntityRole::Team)?;
        let user_id = self.organization_query(EntityRole::TeamMember, "userId", user_id.clone())?;
        let runtime = self.model_fields.organization_join_schema(&self.config);
        let join = crate::store::ResolvedJoin::resolve(
            (EntityRole::TeamMember, "teamMember", &member_schema),
            (EntityRole::Team, "team", &team_schema),
            &runtime,
            |_, _| false,
        )?;
        let limit = self.config.advanced.database.find_many_limit();
        let (members, teams) = {
            let state = self.lock()?;
            let rows = state
                .team_members
                .snapshot()?
                .into_iter()
                .filter(|row| {
                    organization_value(row, &member_schema, "userId")
                        .strict_equals(&user_id.field_value())
                })
                .collect();
            let groups = native_relationships(rows, &[(&state.teams, &join, limit)])?;
            crate::query::paginate_memory(groups, Some(limit), None)
                .into_iter()
                .map(|mut group| {
                    let children = group.children.remove(0);
                    let source = RecordSource::joined(
                        group.parent,
                        [(
                            self.model_fields
                                .storage_model_name(EntityRole::Team, "team")
                                .to_owned(),
                            raw_relation(&children, join.many),
                        )],
                    );
                    (source, children)
                })
                .unzip::<_, _, Vec<_>, Vec<_>>()
        };
        let projected = self
            .project_record_sources_batches_then(
                EntityRole::TeamMember,
                &member_schema,
                members,
                |ready: Vec<(usize, FieldMap)>| {
                    let teams = &teams;
                    async move {
                        let pages = ready
                            .iter()
                            .map(|(index, _)| {
                                teams.get(*index).map(Vec::as_slice).ok_or_else(|| {
                                    AuthError::internal(
                                        "Team membership projection lost its stored join index",
                                    )
                                })
                            })
                            .collect::<AuthResult<Vec<_>>>()?;
                        let output = self.output_record_pages(EntityRole::Team, pages).await?;
                        Ok(ready
                            .into_iter()
                            .zip(output)
                            .map(|((index, _), rows)| (index, rows))
                            .collect())
                    }
                },
            )
            .await?;
        projected
            .into_iter()
            .map(|rows| crate::Team::from_membership_join(rows, join.many))
            .collect()
    }

    pub(super) async fn joined_user_invitations(
        &self,
        email: &str,
    ) -> AuthResult<Vec<crate::store::InvitationOrganization>> {
        let schema = self.field_config(EntityRole::Invitation)?;
        let email = self.organization_query(
            EntityRole::Invitation,
            "email",
            Value::from(email.to_lowercase()),
        )?;
        let (invitations, organizations) = {
            let state = self.lock()?;
            let rows = crate::query::paginate_memory(
                state
                    .invitations
                    .snapshot()?
                    .into_iter()
                    .filter(|row| {
                        organization_value(row, &schema, "email")
                            .strict_equals(&email.field_value())
                    })
                    .collect(),
                Some(self.config.advanced.database.find_many_limit()),
                None,
            );
            let organizations = rows
                .iter()
                .map(|row| {
                    state.organizations.first_ref(|org| {
                        super::organization_rows::id(org)
                            .field_value()
                            .strict_equals(&organization_value(row, &schema, "organizationId"))
                    })
                })
                .collect::<AuthResult<Vec<_>>>()?;
            let sources = rows
                .into_iter()
                .zip(&organizations)
                .map(|(parent, child)| {
                    RecordSource::joined(
                        parent,
                        [(
                            self.model_fields
                                .storage_model_name(EntityRole::Organization, "organization")
                                .to_owned(),
                            JoinValue::One(child.clone()).raw_value(),
                        )],
                    )
                })
                .collect();
            (sources, organizations)
        };
        self.project_record_sources_batches_then(
            EntityRole::Invitation,
            &schema,
            invitations,
            |ready: Vec<(usize, FieldMap)>| {
                let organizations = &organizations;
                async move {
                    let mut pending = Vec::new();
                    let mut sources = Vec::new();
                    for (index, invitation) in ready {
                        let row = organizations.get(index).ok_or_else(|| {
                            AuthError::internal("Invitation projection lost its stored join index")
                        })?;
                        sources.extend(row.clone());
                        pending.push((index, invitation, row.is_some()));
                    }
                    let mut projected = self
                        .output_record_refs(EntityRole::Organization, sources)
                        .await?
                        .into_iter();
                    Ok(pending
                        .into_iter()
                        .map(|(index, mut invitation, present)| {
                            let _ = invitation.shift_remove("organization");
                            Ok((
                                index,
                                crate::store::InvitationOrganization {
                                    invitation: Invitation::from_field_values(invitation)?,
                                    organization: if present { projected.next() } else { None },
                                },
                            ))
                        })
                        .collect::<AuthResult<Vec<_>>>()?)
                }
            },
        )
        .await
    }
}

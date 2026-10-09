use super::rows::RowRef;
use super::*;
use crate::store::{MemberUser, OrganizationDetails, OrganizationDetailsQuery, OrganizationKey};
use better_auth_schema_registry::EntityRole;

mod member_user;

struct OrganizationChildren {
    invitations: Vec<RowRef<FieldMap>>,
    members: Vec<RowRef<FieldMap>>,
    teams: Option<Vec<RowRef<FieldMap>>>,
}

fn child_page(rows: Vec<RowRef<FieldMap>>, limit: f64) -> AuthResult<Vec<RowRef<FieldMap>>> {
    let mut result = Vec::new();
    let mut ids = Vec::new();
    for row in rows {
        if result.len() as f64 >= limit {
            break;
        }
        let id = row.read(|row| Ok(super::organization_rows::id(row)))?;
        if !ids.contains(&id) {
            ids.push(id);
            result.push(row);
        }
    }
    Ok(result)
}

impl EphemeralStore {
    pub(super) async fn read_organization_details(
        &self,
        query: OrganizationDetailsQuery<'_>,
    ) -> AuthResult<Option<OrganizationDetails>> {
        let organization_schema = self.field_config(EntityRole::Organization)?;
        let member_schema = self.field_config(EntityRole::Member)?;
        let invitation_schema = self.field_config(EntityRole::Invitation)?;
        let team_schema = self.field_config(EntityRole::Team)?;
        let (field, value) = match query.organization {
            OrganizationKey::Id(id) => ("id", Value::from(id)),
            OrganizationKey::IdValue(id) => ("id", id.clone()),
            OrganizationKey::Slug(slug) => ("slug", Value::from(slug)),
        };
        let value = self.organization_query(EntityRole::Organization, field, value)?;
        let default_limit = self.config.advanced.database.find_many_limit();
        let members_limit = query.members_limit.unwrap_or(default_limit);
        let native = self.config.advanced.database.joins == Some(true);
        let (organization, native_organization, (member_org, invitation_org, team_org), children) = {
            let state = self.lock()?;
            let organization = state
                .organizations
                .first_ref(|row| match query.organization {
                    OrganizationKey::Id(_) | OrganizationKey::IdValue(_) => {
                        super::organization_rows::id(row) == value
                    }
                    OrganizationKey::Slug(_) => {
                        organization_value(row, &organization_schema, "slug")
                            .strict_equals(&value.field_value())
                    }
                })?;
            let Some(organization) = organization else {
                return Ok(None);
            };
            let organization_id = organization.read(|row| Ok(super::organization_rows::id(row)))?;
            let member_org = self.organization_reference_query(
                EntityRole::Member,
                "organizationId",
                &organization_id,
            )?;
            let invitation_org = self.organization_reference_query(
                EntityRole::Invitation,
                "organizationId",
                &organization_id,
            )?;
            let team_org = self.organization_reference_query(
                EntityRole::Team,
                "organizationId",
                &organization_id,
            )?;
            let native_organization = native
                .then(|| organization.read(|row| Ok(row.clone())))
                .transpose()?;
            let children = if native {
                let invitations = child_page(
                    state.invitations.select_refs(|row| {
                        organization_value(row, &invitation_schema, "organizationId")
                            .strict_equals(&invitation_org.field_value())
                    })?,
                    default_limit,
                )?;
                let members = child_page(
                    state.members.select_refs(|row| {
                        organization_value(row, &member_schema, "organizationId")
                            .strict_equals(&member_org.field_value())
                    })?,
                    members_limit,
                )?;
                let teams = if query.include_teams {
                    Some(child_page(
                        state.teams.select_refs(|row| {
                            organization_value(row, &team_schema, "organizationId")
                                .strict_equals(&team_org.field_value())
                        })?,
                        default_limit,
                    )?)
                } else {
                    None
                };
                Some(OrganizationChildren {
                    invitations,
                    members,
                    teams,
                })
            } else {
                None
            };
            (
                organization,
                native_organization,
                (member_org, invitation_org, team_org),
                children,
            )
        };
        let organization: Organization = match native_organization {
            Some(organization) => self.output_organization(organization).await?,
            None => self
                .output_record_refs(EntityRole::Organization, vec![organization])
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| {
                    AuthError::internal("Organization projection lost its selected row")
                })?,
        };
        let (invitations, members, teams): (
            Vec<Invitation>,
            Vec<Member>,
            Option<Vec<crate::Team>>,
        ) = if let Some(children) = children {
            let mut invitations = Vec::with_capacity(children.invitations.len());
            for row in children.invitations {
                invitations.extend(
                    self.output_record_refs(EntityRole::Invitation, vec![row])
                        .await?,
                );
            }
            let mut members = Vec::with_capacity(children.members.len());
            for row in children.members {
                members.extend(
                    self.output_record_refs(EntityRole::Member, vec![row])
                        .await?,
                );
            }
            let teams = if let Some(rows) = children.teams {
                let mut teams = Vec::with_capacity(rows.len());
                for row in rows {
                    teams.extend(self.output_record_refs(EntityRole::Team, vec![row]).await?);
                }
                Some(teams)
            } else {
                None
            };
            (invitations, members, teams)
        } else {
            let rows = crate::query::paginate_memory(
                self.lock()?.invitations.select_refs(|row| {
                    organization_value(row, &invitation_schema, "organizationId")
                        .strict_equals(&invitation_org.field_value())
                })?,
                Some(default_limit),
                None,
            );
            let mut invitations = Vec::with_capacity(rows.len());
            for row in rows {
                invitations.extend(
                    self.output_record_refs(EntityRole::Invitation, vec![row])
                        .await?,
                );
            }
            let rows = crate::query::paginate_memory(
                self.lock()?.members.select_refs(|row| {
                    organization_value(row, &member_schema, "organizationId")
                        .strict_equals(&member_org.field_value())
                })?,
                Some(members_limit),
                None,
            );
            let mut members = Vec::with_capacity(rows.len());
            for row in rows {
                members.extend(
                    self.output_record_refs(EntityRole::Member, vec![row])
                        .await?,
                );
            }
            let teams = if query.include_teams {
                let rows = crate::query::paginate_memory(
                    self.lock()?.teams.select_refs(|row| {
                        organization_value(row, &team_schema, "organizationId")
                            .strict_equals(&team_org.field_value())
                    })?,
                    Some(default_limit),
                    None,
                );
                let mut teams = Vec::with_capacity(rows.len());
                for row in rows {
                    teams.extend(self.output_record_refs(EntityRole::Team, vec![row]).await?);
                }
                Some(teams)
            } else {
                None
            };
            (invitations, members, teams)
        };
        let owners = members
            .iter()
            .map(|member| member.user_id.field_value())
            .collect::<Vec<_>>();
        let user_rows = if owners.is_empty() {
            Vec::new()
        } else {
            self.model_fields
                .begin_id_query(crate::store::schema::EntityRole::User)?;
            let owners = self
                .memory_primary_id_query(&owners.into())?
                .decode::<Vec<Value>>()?;
            self.raw("user", "findMany", |state| {
                Ok(crate::query::paginate_memory(
                    state
                        .users
                        .snapshot()?
                        .into_iter()
                        .filter(|user| {
                            owners
                                .iter()
                                .any(|owner| user.id.field_value().same_value_zero(owner))
                        })
                        .collect(),
                    Some(query.users_limit),
                    None,
                ))
            })
            .await?
        };
        let users = self.output_users(user_rows).await?;
        let members = members
            .into_iter()
            .map(|member| {
                let user = users
                    .iter()
                    .rev()
                    .find(|user| {
                        user.id
                            .field_value()
                            .same_value_zero(&member.user_id.field_value())
                    })
                    .cloned()
                    .ok_or_else(|| {
                        AuthError::internal("Unexpected error: User not found for member")
                    })?;
                Ok(MemberUser {
                    member,
                    user: crate::MemberUserView::from_user(&user),
                })
            })
            .collect::<AuthResult<Vec<_>>>()?;
        Ok(Some(OrganizationDetails {
            organization,
            invitations,
            members,
            teams,
        }))
    }

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
            (rows, organizations)
        };
        self.output_records_batches_then(
            EntityRole::Member,
            members,
            |ready: Vec<(usize, Member)>| {
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
            let rows = crate::query::paginate_memory(
                state
                    .team_members
                    .snapshot()?
                    .into_iter()
                    .filter(|row| {
                        organization_value(row, &member_schema, "userId")
                            .strict_equals(&user_id.field_value())
                    })
                    .collect(),
                Some(limit),
                None,
            );
            let teams = rows
                .iter()
                .map(|member| {
                    let from = member.get(&join.from).unwrap_or(&Value::Undefined);
                    let matched = state.teams.select_refs(|team| {
                        team.get(&join.to)
                            .unwrap_or(&Value::Undefined)
                            .strict_equals(from)
                    })?;
                    if join.many {
                        child_page(matched, limit)
                    } else {
                        Ok(matched.into_iter().take(1).collect())
                    }
                })
                .collect::<AuthResult<Vec<_>>>()?;
            (rows, teams)
        };
        let projected = self
            .output_records_batches_then(
                EntityRole::TeamMember,
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
            (rows, organizations)
        };
        self.output_records_batches_then(
            EntityRole::Invitation,
            invitations,
            |ready: Vec<(usize, Invitation)>| {
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
                        .map(|(index, invitation, present)| {
                            (
                                index,
                                crate::store::InvitationOrganization {
                                    invitation,
                                    organization: if present { projected.next() } else { None },
                                },
                            )
                        })
                        .collect())
                }
            },
        )
        .await
    }
}

use super::rows::{MemoryRow, RowRef};
use super::*;
use crate::store::{MemberUser, OrganizationDetails, OrganizationDetailsQuery, OrganizationKey};
use better_auth_schema_registry::EntityRole;

struct OrganizationChildren {
    invitations: Vec<RowRef<Invitation>>,
    members: Vec<RowRef<Member>>,
    teams: Option<Vec<RowRef<crate::Team>>>,
}

fn child_page<T: Clone + MemoryRow>(
    rows: Vec<RowRef<T>>,
    limit: f64,
) -> AuthResult<Vec<RowRef<T>>> {
    let mut result = Vec::new();
    let mut ids = Vec::new();
    for row in rows {
        if result.len() as f64 >= limit {
            break;
        }
        let id = row.read(|row| Ok(row.id().clone()))?;
        if !ids.contains(&id) {
            ids.push(id);
            result.push(row);
        }
    }
    Ok(result)
}

impl EphemeralStore {
    pub(super) async fn read_member_user(
        &self,
        predicate: impl Fn(&Member) -> AuthResult<bool> + Send,
        require_user: bool,
    ) -> AuthResult<Option<MemberUser>> {
        let native = self.config.advanced.database.joins == Some(true);
        let (member, native_member, native_user) = {
            let state = self.lock()?;
            let mut selected = None;
            for row in state.members.select_refs(|_| true)? {
                if row.read(&predicate)? {
                    selected = Some(row);
                    break;
                }
            }
            let Some(member) = selected else {
                return Ok(None);
            };
            let owner_id = member.read(|row| Ok(row.user_id.field_value()))?;
            let native_member = native
                .then(|| member.read(|row| Ok(row.clone())))
                .transpose()?;
            let native_user = if native {
                Some(
                    state
                        .users
                        .first_ref(|user| user.id.field_value().strict_equals(&owner_id))?,
                )
            } else {
                None
            };
            (member, native_member, native_user)
        };
        let member = match native_member {
            Some(member) => self.output_member(member).await?,
            None => self
                .output_record_refs(EntityRole::Member, vec![member])
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| AuthError::internal("Member projection lost its selected row"))?,
        };
        let user = match native_user {
            Some(user) => user,
            None => {
                let owner = member.user_id.field_value();
                if owner.is_null() || owner.is_undefined() {
                    None
                } else {
                    let owner = self.memory_primary_id_query(&owner)?;
                    self.lock()?
                        .users
                        .first_ref(|user| user.id.field_value().strict_equals(&owner))?
                }
            }
        };
        let user = self
            .output_user_refs(user.into_iter().collect())
            .await?
            .into_iter()
            .next();
        match user {
            Some(user) => Ok(Some(MemberUser { member, user })),
            // The by-ID adapter requires a child; the organization/user lookup permits an absent child.
            None if require_user => Err(AuthError::internal("User not found for member")),
            None => Ok(None),
        }
    }

    pub(super) async fn read_organization_details(
        &self,
        query: OrganizationDetailsQuery<'_>,
    ) -> AuthResult<Option<OrganizationDetails>> {
        let (field, value) = match query.organization {
            OrganizationKey::Id(id) => ("id", Value::from(id)),
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
                    OrganizationKey::Id(_) => row.id == value,
                    OrganizationKey::Slug(_) => {
                        row.slug.field_value().strict_equals(&value.field_value())
                    }
                })?;
            let Some(organization) = organization else {
                return Ok(None);
            };
            let organization_id = organization.read(|row| Ok(row.id.clone()))?;
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
                        row.organization_id
                            .field_value()
                            .strict_equals(&invitation_org.field_value())
                    })?,
                    default_limit,
                )?;
                let members = child_page(
                    state.members.select_refs(|row| {
                        row.organization_id
                            .field_value()
                            .strict_equals(&member_org.field_value())
                    })?,
                    members_limit,
                )?;
                let teams = if query.include_teams {
                    Some(child_page(
                        state.teams.select_refs(|row| {
                            row.organization_id
                                .field_value()
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
        let organization = match native_organization {
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
        let (invitations, members, teams) = if let Some(children) = children {
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
                    row.organization_id
                        .field_value()
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
                    row.organization_id
                        .field_value()
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
                        row.organization_id
                            .field_value()
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
                .canonicalize_id(crate::store::schema::EntityRole::User)?;
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
                Ok(MemberUser { member, user })
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
        user_id: &str,
    ) -> AuthResult<Vec<Organization>> {
        let user_id =
            self.organization_query(EntityRole::Member, "userId", Value::from(user_id))?;
        let (members, organizations) = {
            let state = self.lock()?;
            let rows = crate::query::paginate_memory(
                state
                    .members
                    .snapshot()?
                    .into_iter()
                    .filter(|row| row.user_id == user_id)
                    .collect(),
                Some(self.config.advanced.database.find_many_limit()),
                None,
            );
            let organizations = rows
                .iter()
                .map(|row| {
                    state.organizations.first_ref(|org| {
                        org.id
                            .field_value()
                            .strict_equals(&row.organization_id.field_value())
                    })
                })
                .collect::<AuthResult<Vec<_>>>()?;
            (rows, organizations)
        };
        self.output_records_batches_then(EntityRole::Member, members, |ready| {
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
        })
        .await
    }

    pub(super) async fn joined_user_teams(&self, user_id: &str) -> AuthResult<Vec<crate::Team>> {
        let user_id = self
            .config
            .advanced
            .database
            .generate_id()
            .coerce_id(user_id)?;
        let user_id = user_id.as_ref();
        let teams = {
            let state = self.lock()?;
            let rows = crate::query::paginate_memory(
                state
                    .team_members
                    .snapshot()?
                    .into_iter()
                    .filter(|row| row.user_id == user_id)
                    .collect(),
                Some(self.config.advanced.database.find_many_limit()),
                None,
            );
            rows.iter()
                .map(|row| state.teams.first_ref(|team| team.id == row.team_id))
                .collect::<AuthResult<Vec<_>>>()?
                .into_iter()
                .flatten()
                .collect()
        };
        self.output_record_refs(EntityRole::Team, teams).await
    }

    pub(super) async fn joined_user_invitations(
        &self,
        email: &str,
    ) -> AuthResult<Vec<crate::store::InvitationOrganization>> {
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
                    .filter(|row| row.email.field_value().strict_equals(&email.field_value()))
                    .collect(),
                Some(self.config.advanced.database.find_many_limit()),
                None,
            );
            let organizations = rows
                .iter()
                .map(|row| {
                    state.organizations.first_ref(|org| {
                        org.id
                            .field_value()
                            .strict_equals(&row.organization_id.field_value())
                    })
                })
                .collect::<AuthResult<Vec<_>>>()?;
            (rows, organizations)
        };
        self.output_records_batches_then(EntityRole::Invitation, invitations, |ready| {
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
        })
        .await
    }
}

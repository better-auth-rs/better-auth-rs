use super::{
    SeaOrmStore,
    id_filter::IdColumn,
    map_db_err,
    organization_models::{self as models, Entity},
};
use crate::schema::AuthSchema;
use crate::{
    SeaOrmOrganizationModel, SeaOrmOrganizationSchema, SeaOrmPluginSchema, SeaOrmUserModel,
};
use better_auth_core::{
    AuthError, AuthResult,
    store::{MemberUser, OrganizationDetails, OrganizationDetailsQuery, OrganizationKey},
    user_fields::UserConfig,
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityName, EntityTrait, FromQueryResult,
    IntoActiveModel, Iterable, QueryFilter, QuerySelect, QueryTrait, Select, Value,
    sea_query::{Expr, ExprTrait, JoinType, Query},
};

struct OrganizationChildren<O: SeaOrmOrganizationSchema> {
    invitations: Vec<O::Invitation>,
    members: Vec<O::Member>,
    teams: Option<Vec<O::Team>>,
}

async fn project_sequential<M: SeaOrmOrganizationModel>(
    rows: Vec<M>,
    config: &UserConfig,
    native_json: bool,
) -> AuthResult<Vec<M::Record>> {
    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        result.push(row.record(config, native_json).await?);
    }
    Ok(result)
}

impl<S: AuthSchema, O: SeaOrmOrganizationSchema, P: SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S::User: SeaOrmUserModel,
{
    pub(super) async fn read_member_user(
        &self,
        query: Select<Entity<O::Member>>,
        require_user: bool,
    ) -> AuthResult<Option<MemberUser>> {
        let (member, selected_user) = if self.config().advanced.database.joins == Some(true) {
            let query = super::joins::joined_query::<
                Entity<O::Member>,
                <S::User as SeaOrmUserModel>::Entity,
            >(
                query.limit(1),
                (O::Member::column("user_id")?, S::User::id_column()),
                S::User::id_column(),
            );
            let Some((member, user)) = super::joins::joined_rows::<
                Entity<O::Member>,
                <S::User as SeaOrmUserModel>::Entity,
            >(self.connection(), &query)
            .await?
            .into_iter()
            .next() else {
                return Ok(None);
            };
            (member, Some(user))
        } else {
            let Some(member) = query.one(self.connection()).await.map_err(map_db_err)? else {
                return Ok(None);
            };
            (member, None)
        };
        let owner_id = models::join_value(&member, "user_id")?;
        let member = member
            .record(
                &self.organization_fields()?.member,
                self.connection().get_database_backend() == sea_orm::DbBackend::Postgres,
            )
            .await?;
        let user = match selected_user {
            Some(user) => user,
            None => <S::User as SeaOrmUserModel>::Entity::find()
                .filter(S::User::id_column().eq(owner_id))
                .one(self.connection())
                .await
                .map_err(map_db_err)?,
        };
        match user {
            Some(user) => Ok(Some(MemberUser {
                member,
                user: self.output_user(&user, self.connection()).await?,
            })),
            // The by-ID adapter requires a child; the organization/user lookup permits an absent child.
            None if require_user => Err(AuthError::internal("User not found for member")),
            None => Ok(None),
        }
    }

    async fn organization_snapshot(
        &self,
        query: Select<Entity<O::Organization>>,
        include_teams: bool,
        member_limit: f64,
    ) -> AuthResult<Option<(O::Organization, OrganizationChildren<O>)>> {
        let mut parent = query.into_query();
        let _ = parent.clear_selects();
        for column in <Entity<O::Organization> as EntityTrait>::Column::iter() {
            let _ = parent.expr(Expr::col(column.as_column_ref()));
        }
        let mut query = Query::select();
        let _ = query.from_subquery(parent, "organization");
        super::joins::select_model::<Entity<O::Organization>>(&mut query, "organization", "O_");
        let _ = query.join_as(
            JoinType::LeftJoin,
            Entity::<O::Invitation>::default().table_ref(),
            "invitation",
            Expr::col(("organization", O::Organization::column("id")?))
                .equals(("invitation", O::Invitation::column("organization_id")?)),
        );
        super::joins::select_model::<Entity<O::Invitation>>(&mut query, "invitation", "I_");
        let _ = query.expr_as(
            Expr::col(("invitation", O::Invitation::column("id")?)).is_not_null(),
            "invitation_present",
        );
        let _ = query.join_as(
            JoinType::LeftJoin,
            Entity::<O::Member>::default().table_ref(),
            "member",
            Expr::col(("organization", O::Organization::column("id")?))
                .equals(("member", O::Member::column("organization_id")?)),
        );
        super::joins::select_model::<Entity<O::Member>>(&mut query, "member", "M_");
        let _ = query.expr_as(
            Expr::col(("member", O::Member::column("id")?)).is_not_null(),
            "member_present",
        );
        if include_teams {
            let _ = query.join_as(
                JoinType::LeftJoin,
                Entity::<O::Team>::default().table_ref(),
                "team",
                Expr::col(("organization", O::Organization::column("id")?))
                    .equals(("team", O::Team::column("organization_id")?)),
            );
            super::joins::select_model::<Entity<O::Team>>(&mut query, "team", "T_");
            let _ = query.expr_as(
                Expr::col(("team", O::Team::column("id")?)).is_not_null(),
                "team_present",
            );
        }
        let rows = self
            .connection()
            .query_all(&query)
            .await
            .map_err(map_db_err)?;
        let Some(first) = rows.first() else {
            return Ok(None);
        };
        let organization = O::Organization::from_query_result(first, "O_").map_err(map_db_err)?;
        let default_limit = self.config().advanced.database.find_many_limit();
        let mut children = OrganizationChildren {
            invitations: Vec::new(),
            members: Vec::new(),
            teams: include_teams.then(Vec::new),
        };
        for row in rows {
            children
                .invitations
                .extend(super::joins::optional_model::<O::Invitation>(
                    &row,
                    "I_",
                    "invitation_present",
                )?);
            children
                .members
                .extend(super::joins::optional_model::<O::Member>(
                    &row,
                    "M_",
                    "member_present",
                )?);
            if let Some(teams) = &mut children.teams {
                teams.extend(super::joins::optional_model::<O::Team>(
                    &row,
                    "T_",
                    "team_present",
                )?);
            }
        }
        children.invitations = super::joins::limited_children::<Entity<O::Invitation>>(
            children.invitations.into_iter(),
            O::Invitation::column("id")?,
            default_limit,
        );
        children.members = super::joins::limited_children::<Entity<O::Member>>(
            children.members.into_iter(),
            O::Member::column("id")?,
            member_limit,
        );
        children.teams = children
            .teams
            .map(|rows| -> AuthResult<_> {
                Ok(super::joins::limited_children::<Entity<O::Team>>(
                    rows.into_iter(),
                    O::Team::column("id")?,
                    default_limit,
                ))
            })
            .transpose()?;
        Ok(Some((organization, children)))
    }

    pub(super) async fn read_organization_details(
        &self,
        input: OrganizationDetailsQuery<'_>,
    ) -> AuthResult<Option<OrganizationDetails>> {
        let fields = self.organization_fields()?;
        let native_json = self.connection().get_database_backend() == sea_orm::DbBackend::Postgres;
        let predicate = match input.organization {
            OrganizationKey::Id(id) => O::Organization::column("id")?
                .eq_id(id, self.config().advanced.database.generate_id())?,
            OrganizationKey::Slug(slug) => O::Organization::column("slug")?.eq(slug),
        };
        let query = Entity::<O::Organization>::find().filter(predicate).limit(1);
        let member_limit = input
            .members_limit
            .unwrap_or(self.config().advanced.database.find_many_limit());
        let (organization, children) = if self.config().advanced.database.joins == Some(true) {
            let Some((organization, children)) = self
                .organization_snapshot(query, input.include_teams, member_limit)
                .await?
            else {
                return Ok(None);
            };
            (organization, Some(children))
        } else {
            let Some(organization) = query.one(self.connection()).await.map_err(map_db_err)? else {
                return Ok(None);
            };
            (organization, None)
        };
        let organization_id = models::join_value(&organization, "id")?;
        let organization = organization
            .record(&fields.organization, native_json)
            .await?;
        let (invitations, members, teams) = if let Some(children) = children {
            let invitations =
                project_sequential(children.invitations, &fields.invitation, native_json).await?;
            let members = self
                .project_members_with_owners(children.members, &fields.member, native_json)
                .await?;
            let teams = match children.teams {
                Some(rows) => Some(project_sequential(rows, &fields.team, native_json).await?),
                None => None,
            };
            (invitations, members, teams)
        } else {
            let limit = super::pagination::default_limit(
                self.config(),
                self.connection().get_database_backend(),
            )?;
            let rows = Entity::<O::Invitation>::find()
                .filter(O::Invitation::column("organization_id")?.eq(organization_id.clone()))
                .limit(limit)
                .all(self.connection())
                .await
                .map_err(map_db_err)?;
            let invitations = project_sequential(rows, &fields.invitation, native_json).await?;
            let (member_limit, _) = super::pagination::sql_pagination(
                self.connection().get_database_backend(),
                Some(member_limit),
                None,
            )?;
            let rows = Entity::<O::Member>::find()
                .filter(O::Member::column("organization_id")?.eq(organization_id.clone()))
                .limit(member_limit)
                .all(self.connection())
                .await
                .map_err(map_db_err)?;
            let members = self
                .project_members_with_owners(rows, &fields.member, native_json)
                .await?;
            let teams = if input.include_teams {
                let rows = Entity::<O::Team>::find()
                    .filter(O::Team::column("organization_id")?.eq(organization_id))
                    .limit(limit)
                    .all(self.connection())
                    .await
                    .map_err(map_db_err)?;
                Some(project_sequential(rows, &fields.team, native_json).await?)
            } else {
                None
            };
            (invitations, members, teams)
        };
        let user_rows = if members.is_empty() {
            Vec::new()
        } else {
            let (limit, _) = super::pagination::sql_pagination(
                self.connection().get_database_backend(),
                Some(input.users_limit),
                None,
            )?;
            <S::User as SeaOrmUserModel>::Entity::find()
                .filter(S::User::id_column().is_in(members.iter().map(|(_, owner)| owner.clone())))
                .limit(limit)
                .all(self.connection())
                .await
                .map_err(map_db_err)?
        };
        let ids = user_rows
            .iter()
            .map(|user| {
                user.clone()
                    .into_active_model()
                    .get(S::User::id_column())
                    .into_value()
                    .ok_or_else(|| AuthError::internal("Stored member user ID is unavailable"))
            })
            .collect::<AuthResult<Vec<_>>>()?;
        let users = self.output_users(&user_rows, self.connection()).await?;
        let members = members
            .into_iter()
            .map(|(member, owner)| {
                let index = ids.iter().position(|id| *id == owner).ok_or_else(|| {
                    AuthError::internal("Unexpected error: User not found for member")
                })?;
                Ok(MemberUser {
                    member,
                    user: users.get(index).cloned().ok_or_else(|| {
                        AuthError::internal("Member projection lost its stored user index")
                    })?,
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

    async fn project_members_with_owners(
        &self,
        rows: Vec<O::Member>,
        fields: &UserConfig,
        native_json: bool,
    ) -> AuthResult<Vec<(better_auth_core::Member, Value)>> {
        let mut members = Vec::with_capacity(rows.len());
        for row in rows {
            let owner = models::join_value(&row, "user_id")?;
            members.push((row.record(fields, native_json).await?, owner));
        }
        Ok(members)
    }
}

impl<S: AuthSchema, O: SeaOrmOrganizationSchema, P: SeaOrmPluginSchema> SeaOrmStore<S, O, P> {
    pub(super) async fn joined_user_organizations(
        &self,
        user_id: &str,
    ) -> AuthResult<Vec<better_auth_core::Organization>> {
        let fields = self.organization_fields()?;
        let native_json = self.connection().get_database_backend() == sea_orm::DbBackend::Postgres;
        let parent = Entity::<O::Member>::find()
            .filter(
                O::Member::column("user_id")?
                    .eq_id(user_id, self.config().advanced.database.generate_id())?,
            )
            .limit(super::pagination::default_limit(
                self.config(),
                self.connection().get_database_backend(),
            )?);
        let query = super::joins::joined_query::<Entity<O::Member>, Entity<O::Organization>>(
            parent,
            (
                O::Member::column("organization_id")?,
                O::Organization::column("id")?,
            ),
            O::Organization::column("id")?,
        );
        let rows = super::joins::joined_rows::<Entity<O::Member>, Entity<O::Organization>>(
            self.connection(),
            &query,
        )
        .await?;
        let members = rows.iter().map(|(row, _)| row.clone()).collect::<Vec<_>>();
        models::project_batches_then::<O::Member, _, _>(
            &members,
            &fields.member,
            native_json,
            |ready| {
                let rows = &rows;
                let fields = &fields;
                async move {
                    let mut indices = Vec::new();
                    let mut organizations = Vec::new();
                    for (index, _) in ready {
                        if let Some(row) = &rows
                            .get(index)
                            .ok_or_else(|| {
                                AuthError::internal("Member projection lost its stored join index")
                            })?
                            .1
                        {
                            indices.push(index);
                            organizations.push(row.clone());
                        }
                    }
                    Ok(indices
                        .into_iter()
                        .zip(
                            models::project::<O::Organization>(
                                organizations,
                                &fields.organization,
                                native_json,
                            )
                            .await?,
                        )
                        .collect())
                }
            },
        )
        .await
    }

    pub(super) async fn joined_user_teams(
        &self,
        user_id: &str,
    ) -> AuthResult<Vec<better_auth_core::Team>> {
        let parent = Entity::<O::TeamMember>::find()
            .filter(
                O::TeamMember::column("user_id")?
                    .eq_id(user_id, self.config().advanced.database.generate_id())?,
            )
            .limit(super::pagination::default_limit(
                self.config(),
                self.connection().get_database_backend(),
            )?);
        let query = super::joins::joined_query::<Entity<O::TeamMember>, Entity<O::Team>>(
            parent,
            (O::TeamMember::column("team_id")?, O::Team::column("id")?),
            O::Team::column("id")?,
        );
        let rows = super::joins::joined_rows::<Entity<O::TeamMember>, Entity<O::Team>>(
            self.connection(),
            &query,
        )
        .await?;
        let teams = rows.into_iter().filter_map(|(_, team)| team).collect();
        models::project::<O::Team>(
            teams,
            &self.organization_fields()?.team,
            self.connection().get_database_backend() == sea_orm::DbBackend::Postgres,
        )
        .await
    }

    pub(super) async fn joined_user_invitations(
        &self,
        email: &str,
    ) -> AuthResult<Vec<better_auth_core::store::InvitationOrganization>> {
        let fields = self.organization_fields()?;
        let native_json = self.connection().get_database_backend() == sea_orm::DbBackend::Postgres;
        let parent = Entity::<O::Invitation>::find()
            .filter(O::Invitation::column("email")?.eq(email.to_lowercase()))
            .limit(super::pagination::default_limit(
                self.config(),
                self.connection().get_database_backend(),
            )?);
        let query = super::joins::joined_query::<Entity<O::Invitation>, Entity<O::Organization>>(
            parent,
            (
                O::Invitation::column("organization_id")?,
                O::Organization::column("id")?,
            ),
            O::Organization::column("id")?,
        );
        let rows = super::joins::joined_rows::<Entity<O::Invitation>, Entity<O::Organization>>(
            self.connection(),
            &query,
        )
        .await?;
        let invitations = rows.iter().map(|(row, _)| row.clone()).collect::<Vec<_>>();
        models::project_batches_then::<O::Invitation, _, _>(
            &invitations,
            &fields.invitation,
            native_json,
            |ready| {
                let rows = &rows;
                let fields = &fields;
                async move {
                    let mut pending = Vec::new();
                    let mut organizations = Vec::new();
                    for (index, invitation) in ready {
                        let organization = &rows
                            .get(index)
                            .ok_or_else(|| {
                                AuthError::internal(
                                    "Invitation projection lost its stored join index",
                                )
                            })?
                            .1;
                        organizations.extend(organization.clone());
                        pending.push((index, invitation, organization.is_some()));
                    }
                    let mut projected = models::project::<O::Organization>(
                        organizations,
                        &fields.organization,
                        native_json,
                    )
                    .await?
                    .into_iter();
                    Ok(pending
                        .into_iter()
                        .map(|(index, invitation, present)| {
                            (
                                index,
                                better_auth_core::store::InvitationOrganization {
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

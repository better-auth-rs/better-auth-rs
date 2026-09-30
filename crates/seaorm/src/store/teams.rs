use super::{
    SeaOrmStore, map_db_err,
    organization_models::{self as models, Entity, values},
};
use crate::SeaOrmOrganizationModel;
use async_trait::async_trait;
use better_auth_core::{
    AuthError, AuthResult, CreateTeam, Team, TeamMember, UpdateTeam, store::TeamStore,
};
use chrono::Utc;
use sea_orm::{
    ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, TransactionTrait,
    sea_query::Expr,
};
use serde_json::json;

#[async_trait]
impl<
    S: better_auth_core::AuthSchema,
    O: crate::SeaOrmOrganizationSchema,
    P: crate::SeaOrmPluginSchema,
> TeamStore for SeaOrmStore<S, O, P>
{
    async fn create_team(&self, mut input: CreateTeam) -> AuthResult<Team> {
        let mut core = values([
            (
                "id",
                json!(input.id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string())),
            ),
            ("organization_id", json!(input.organization_id)),
            (
                "created_at",
                json!(input.created_at.unwrap_or_else(Utc::now)),
            ),
            ("member_count", json!(0)),
        ]);
        if let Some(name) = input.name.json()? {
            let _ = core.insert("name".into(), name);
        }
        if let Some(updated_at) = input.updated_at {
            let _ = core.insert("updated_at".into(), json!(updated_at));
        }
        for (public, stored) in [("createdAt", "created_at"), ("updatedAt", "updated_at")] {
            if let Some(value) = input.additional_fields.remove(public) {
                let _ = core.insert(stored.into(), value);
            }
        }
        models::insert::<O::Team, _>(
            self.connection(),
            core,
            input.additional_fields,
            &self.organization_fields()?.team,
        )
        .await
    }
    async fn get_team(&self, id: &str) -> AuthResult<Option<Team>> {
        let config = self.organization_fields()?.team;
        models::find::<O::Team, _>(self.connection(), id)
            .await?
            .map(|row| row.record(&config))
            .transpose()
    }
    async fn get_team_value(&self, id: &serde_json::Value) -> AuthResult<Option<Team>> {
        let config = self.organization_fields()?.team;
        Entity::<O::Team>::find()
            .filter(super::value_filter::equals(O::Team::column("id")?, id))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
            .map(|row| row.record(&config))
            .transpose()
    }
    async fn update_team(&self, id: &str, update: UpdateTeam) -> AuthResult<Team> {
        let config = self.organization_fields()?.team;
        let mut core = Default::default();
        if let Some(updated_at) = update.updated_at {
            core = values([("updated_at", json!(updated_at))]);
        } else if !config.additional_fields.contains_key("updatedAt") {
            core = values([("updated_at", json!(Utc::now()))]);
        }
        for (name, value) in [
            ("name", update.name.map(|v| json!(v))),
            ("organization_id", update.organization_id.map(|v| json!(v))),
            ("created_at", update.created_at.map(|v| json!(v))),
        ] {
            if let Some(value) = value {
                let _ = core.insert(name.into(), value);
            }
        }
        models::update::<O::Team, _>(
            self.connection(),
            id,
            core,
            update.additional_fields,
            &config,
        )
        .await
    }
    async fn delete_team(&self, id: &str) -> AuthResult<()> {
        let tx = self.connection().begin().await.map_err(map_db_err)?;
        let team = models::find::<O::Team, _>(&tx, id)
            .await?
            .ok_or_else(|| AuthError::not_found("Team not found"))?
            .record(&Default::default())?;
        let _ = Entity::<O::TeamMember>::delete_many()
            .filter(O::TeamMember::column("team_id")?.eq(id))
            .exec(&tx)
            .await
            .map_err(map_db_err)?;
        let _ = Entity::<O::Team>::delete_many()
            .filter(O::Team::column("id")?.eq(id))
            .exec(&tx)
            .await
            .map_err(map_db_err)?;
        let config = self.organization_fields()?.invitation;
        let pending = Entity::<O::Invitation>::find()
            .filter(
                O::Invitation::column("organization_id")?.eq(team.organization_id.typed()?.clone()),
            )
            .filter(O::Invitation::column("status")?.eq("pending"))
            .all(&tx)
            .await
            .map_err(map_db_err)?;
        // Upstream projects every pending row before filtering expiration or updating team IDs.
        let pending = models::project::<O::Invitation>(pending, &config)?;
        for row in pending {
            if *row.expires_at.typed()? <= Utc::now() {
                continue;
            }
            if let Some(ids) = row.team_id.typed()? {
                let retained: Vec<_> = ids.split(',').filter(|team_id| *team_id != id).collect();
                if retained.len() != ids.split(',').count() {
                    let _ = models::update::<O::Invitation, _>(
                        &tx,
                        &row.id,
                        values([(
                            "team_id",
                            json!((!retained.is_empty()).then(|| retained.join(","))),
                        )]),
                        Default::default(),
                        &config,
                    )
                    .await?;
                }
            }
        }
        tx.commit().await.map_err(map_db_err)
    }
    async fn list_organization_teams(&self, organization_id: &str) -> AuthResult<Vec<Team>> {
        Entity::<O::Team>::find()
            .filter(O::Team::column("organization_id")?.eq(organization_id))
            .order_by_asc(O::Team::column("created_at")?)
            .all(self.connection())
            .await
            .map_err(map_db_err)
            .and_then(|rows| models::project::<O::Team>(rows, &self.organization_fields()?.team))
    }
    async fn list_user_teams(&self, user_id: &str) -> AuthResult<Vec<Team>> {
        let ids: Vec<_> = Entity::<O::TeamMember>::find()
            .filter(O::TeamMember::column("user_id")?.eq(user_id))
            .all(self.connection())
            .await
            .map_err(map_db_err)?
            .into_iter()
            .map(|row| row.record(&Default::default()).map(|member| member.team_id))
            .collect::<AuthResult<Vec<_>>>()?;
        Entity::<O::Team>::find()
            .filter(O::Team::column("id")?.is_in(ids))
            .order_by_asc(O::Team::column("created_at")?)
            .all(self.connection())
            .await
            .map_err(map_db_err)
            .and_then(|rows| models::project::<O::Team>(rows, &self.organization_fields()?.team))
    }
    async fn get_team_member(
        &self,
        team_id: &str,
        user_id: &str,
    ) -> AuthResult<Option<TeamMember>> {
        Entity::<O::TeamMember>::find()
            .filter(O::TeamMember::column("team_id")?.eq(team_id))
            .filter(O::TeamMember::column("user_id")?.eq(user_id))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
            .map(|row| row.record(&Default::default()))
            .transpose()
    }
    async fn list_team_members(&self, team_id: &str) -> AuthResult<Vec<TeamMember>> {
        Entity::<O::TeamMember>::find()
            .filter(O::TeamMember::column("team_id")?.eq(team_id))
            .order_by_asc(O::TeamMember::column("created_at")?)
            .all(self.connection())
            .await
            .map_err(map_db_err)
            .and_then(|rows| models::project::<O::TeamMember>(rows, &Default::default()))
    }
    async fn add_team_member(
        &self,
        team_id: &str,
        user_id: &str,
        maximum: Option<usize>,
    ) -> AuthResult<Option<TeamMember>> {
        let tx = self.connection().begin().await.map_err(map_db_err)?;
        // Lock the aggregate before reading membership or capacity, including on SQLite.
        let locked = Entity::<O::Team>::update_many()
            .col_expr(
                O::Team::column("member_count")?,
                Expr::col(O::Team::column("member_count")?),
            )
            .filter(O::Team::column("id")?.eq(team_id))
            .exec(&tx)
            .await
            .map_err(map_db_err)?;
        if locked.rows_affected == 0 {
            return Err(AuthError::not_found("Team not found"));
        }
        if let Some(member) = Entity::<O::TeamMember>::find()
            .filter(O::TeamMember::column("team_id")?.eq(team_id))
            .filter(O::TeamMember::column("user_id")?.eq(user_id))
            .one(&tx)
            .await
            .map_err(map_db_err)?
        {
            tx.commit().await.map_err(map_db_err)?;
            return Ok(Some(member.record(&Default::default())?));
        }
        let count = Entity::<O::TeamMember>::find()
            .filter(O::TeamMember::column("team_id")?.eq(team_id))
            .count(&tx)
            .await
            .map_err(map_db_err)?;
        if !super::team_capacity::reserve::<O::Team, _>(
            &tx,
            team_id,
            count,
            maximum,
            &self.organization_fields()?.team,
        )
        .await?
        {
            tx.commit().await.map_err(map_db_err)?;
            return Ok(None);
        }
        let member = models::insert::<O::TeamMember, _>(
            &tx,
            values([
                ("id", json!(uuid::Uuid::new_v4().to_string())),
                ("team_id", json!(team_id)),
                ("user_id", json!(user_id)),
                (
                    "membership_key",
                    json!(better_auth_core::organization_fields::team_membership_key(
                        team_id, user_id
                    )?),
                ),
                ("created_at", json!(Utc::now())),
            ]),
            Default::default(),
            &Default::default(),
        )
        .await?;
        tx.commit().await.map_err(map_db_err)?;
        Ok(Some(member))
    }
    async fn remove_team_member(&self, team_id: &str, user_id: &str) -> AuthResult<()> {
        let tx = self.connection().begin().await.map_err(map_db_err)?;
        let _ = Entity::<O::Team>::update_many()
            .col_expr(
                O::Team::column("member_count")?,
                Expr::col(O::Team::column("member_count")?),
            )
            .filter(O::Team::column("id")?.eq(team_id))
            .exec(&tx)
            .await
            .map_err(map_db_err)?;
        let deleted = Entity::<O::TeamMember>::delete_many()
            .filter(O::TeamMember::column("team_id")?.eq(team_id))
            .filter(O::TeamMember::column("user_id")?.eq(user_id))
            .exec(&tx)
            .await
            .map_err(map_db_err)?;
        super::team_capacity::release::<O::Team, _>(
            &tx,
            team_id,
            deleted.rows_affected,
            &self.organization_fields()?.team,
        )
        .await?;
        tx.commit().await.map_err(map_db_err)
    }
}

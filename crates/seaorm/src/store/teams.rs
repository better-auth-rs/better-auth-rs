use super::id_filter::IdColumn;
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
    ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QuerySelect, TransactionTrait,
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
        let mut core = self.create_fields(
            "team",
            input.id,
            values([
                ("organization_id", json!(input.organization_id)),
                (
                    "created_at",
                    json!(input.created_at.unwrap_or_else(Utc::now)),
                ),
                ("member_count", json!(0)),
            ]),
        )?;
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
            self.config().advanced.database.generate_id(),
        )
        .await
    }
    async fn get_team(&self, id: &str) -> AuthResult<Option<Team>> {
        let config = self.organization_fields()?.team;
        let row = models::find::<O::Team, _>(
            self.connection(),
            id,
            self.config().advanced.database.generate_id(),
        )
        .await?;
        match row {
            Some(row) => row
                .record(
                    &config,
                    self.connection().get_database_backend() == sea_orm::DbBackend::Postgres,
                )
                .await
                .map(Some),
            None => Ok(None),
        }
    }
    async fn get_team_value(&self, id: &serde_json::Value) -> AuthResult<Option<Team>> {
        self.get_team_value_with_connection(self.connection(), id)
            .await
    }
    async fn update_team(&self, id: &str, update: UpdateTeam) -> AuthResult<Team> {
        let config = self.organization_fields()?.team;
        let mut core = Default::default();
        if let Some(updated_at) = update.updated_at {
            core = values([("updated_at", json!(updated_at))]);
        } else if !config.fields().contains_key("updatedAt") {
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
            self.config().advanced.database.generate_id(),
        )
        .await
    }
    async fn delete_team(&self, id: &str) -> AuthResult<()> {
        let tx = self.connection().begin().await.map_err(map_db_err)?;
        let team =
            models::find::<O::Team, _>(&tx, id, self.config().advanced.database.generate_id())
                .await?
                .ok_or_else(|| AuthError::not_found("Team not found"))?
                .record(
                    &Default::default(),
                    self.connection().get_database_backend() == sea_orm::DbBackend::Postgres,
                )
                .await?;
        let _ = Entity::<O::TeamMember>::delete_many()
            .filter(
                O::TeamMember::column("team_id")?
                    .eq_id(id, self.config().advanced.database.generate_id())?,
            )
            .exec(&tx)
            .await
            .map_err(map_db_err)?;
        let _ = Entity::<O::Team>::delete_many()
            .filter(
                O::Team::column("id")?.eq_id(id, self.config().advanced.database.generate_id())?,
            )
            .exec(&tx)
            .await
            .map_err(map_db_err)?;
        let config = self.organization_fields()?.invitation;
        let pending = Entity::<O::Invitation>::find()
            .filter(O::Invitation::column("organization_id")?.eq_id(
                team.organization_id.typed()?.clone(),
                self.config().advanced.database.generate_id(),
            )?)
            .filter(O::Invitation::column("status")?.eq("pending"))
            .all(&tx)
            .await
            .map_err(map_db_err)?;
        // Upstream projects every pending row before filtering expiration or updating team IDs.
        let pending = models::project::<O::Invitation>(
            pending,
            &config,
            self.connection().get_database_backend() == sea_orm::DbBackend::Postgres,
        )
        .await?;
        for row in pending {
            if *row.expires_at.typed()? <= Utc::now() {
                continue;
            }
            if let Some(ids) = row.team_id.typed()? {
                let retained: Vec<_> = ids.split(',').filter(|team_id| *team_id != id).collect();
                if retained.len() != ids.split(',').count() {
                    let _ = models::update::<O::Invitation, _>(
                        &tx,
                        row.id.typed()?,
                        values([(
                            "team_id",
                            json!((!retained.is_empty()).then(|| retained.join(","))),
                        )]),
                        Default::default(),
                        &config,
                        self.config().advanced.database.generate_id(),
                    )
                    .await?;
                }
            }
        }
        tx.commit().await.map_err(map_db_err)
    }
    async fn list_organization_teams(&self, organization_id: &str) -> AuthResult<Vec<Team>> {
        let rows = Entity::<O::Team>::find()
            .filter(O::Team::column("organization_id")?.eq_id(
                organization_id,
                self.config().advanced.database.generate_id(),
            )?)
            .limit(super::pagination::default_limit(
                self.config(),
                self.connection().get_database_backend(),
            )?)
            .all(self.connection())
            .await
            .map_err(map_db_err)?;
        models::project::<O::Team>(
            rows,
            &self.organization_fields()?.team,
            self.connection().get_database_backend() == sea_orm::DbBackend::Postgres,
        )
        .await
    }
    async fn count_organization_teams(&self, organization_id: &str) -> AuthResult<u64> {
        Entity::<O::Team>::find()
            .filter(O::Team::column("organization_id")?.eq_id(
                organization_id,
                self.config().advanced.database.generate_id(),
            )?)
            .count(self.connection())
            .await
            .map_err(map_db_err)
    }
    async fn list_user_teams(&self, user_id: &str) -> AuthResult<Vec<Team>> {
        let rows = Entity::<O::TeamMember>::find()
            .filter(
                O::TeamMember::column("user_id")?
                    .eq_id(user_id, self.config().advanced.database.generate_id())?,
            )
            .limit(super::pagination::default_limit(
                self.config(),
                self.connection().get_database_backend(),
            )?)
            .all(self.connection())
            .await
            .map_err(map_db_err)?;
        let config = self.organization_fields()?.team;
        let teams = models::project_then::<O::TeamMember, _, _>(
            &rows,
            &better_auth_core::user_fields::UserConfig::default(),
            self.connection().get_database_backend() == sea_orm::DbBackend::Postgres,
            |index, _| {
                let rows = &rows;
                let config = &config;
                async move {
                    let member = rows.get(index).ok_or_else(|| {
                        better_auth_core::AuthError::internal(
                            "Team member projection lost its stored join index",
                        )
                    })?;
                    let row = Entity::<O::Team>::find()
                        .filter(O::Team::column("id")?.eq(models::join_value(member, "team_id")?))
                        .one(self.connection())
                        .await
                        .map_err(map_db_err)?;
                    match row {
                        Some(row) => row
                            .record(
                                config,
                                self.connection().get_database_backend()
                                    == sea_orm::DbBackend::Postgres,
                            )
                            .await
                            .map(Some),
                        None => Ok(None),
                    }
                }
            },
        )
        .await?;
        Ok(teams.into_iter().flatten().collect())
    }
    async fn get_team_member(
        &self,
        team_id: &str,
        user_id: &str,
    ) -> AuthResult<Option<TeamMember>> {
        let row = Entity::<O::TeamMember>::find()
            .filter(
                O::TeamMember::column("team_id")?
                    .eq_id(team_id, self.config().advanced.database.generate_id())?,
            )
            .filter(
                O::TeamMember::column("user_id")?
                    .eq_id(user_id, self.config().advanced.database.generate_id())?,
            )
            .one(self.connection())
            .await
            .map_err(map_db_err)?;
        match row {
            Some(row) => row
                .record(
                    &Default::default(),
                    self.connection().get_database_backend() == sea_orm::DbBackend::Postgres,
                )
                .await
                .map(Some),
            None => Ok(None),
        }
    }
    async fn list_team_members(&self, team_id: &str) -> AuthResult<Vec<TeamMember>> {
        let rows = Entity::<O::TeamMember>::find()
            .filter(
                O::TeamMember::column("team_id")?
                    .eq_id(team_id, self.config().advanced.database.generate_id())?,
            )
            .limit(super::pagination::default_limit(
                self.config(),
                self.connection().get_database_backend(),
            )?)
            .all(self.connection())
            .await
            .map_err(map_db_err)?;
        models::project::<O::TeamMember>(
            rows,
            &Default::default(),
            self.connection().get_database_backend() == sea_orm::DbBackend::Postgres,
        )
        .await
    }
    async fn count_team_members(&self, team_id: &str) -> AuthResult<u64> {
        Entity::<O::TeamMember>::find()
            .filter(
                O::TeamMember::column("team_id")?
                    .eq_id(team_id, self.config().advanced.database.generate_id())?,
            )
            .count(self.connection())
            .await
            .map_err(map_db_err)
    }
    async fn add_team_member(
        &self,
        team_id: &better_auth_core::SchemaValue<String>,
        user_id: &str,
        maximum: Option<usize>,
    ) -> AuthResult<Option<TeamMember>> {
        use sea_orm::TransactionTrait;
        let tx = self.connection().begin().await.map_err(map_db_err)?;
        let result = self
            .add_team_member_with_connection(&tx, team_id, user_id, maximum)
            .await?;
        tx.commit().await.map_err(map_db_err)?;
        Ok(result)
    }
    async fn remove_team_member(&self, team_id: &str, user_id: &str) -> AuthResult<()> {
        let tx = self.connection().begin().await.map_err(map_db_err)?;
        let _ = Entity::<O::Team>::update_many()
            .col_expr(
                O::Team::column("member_count")?,
                Expr::col(O::Team::column("member_count")?),
            )
            .filter(
                O::Team::column("id")?
                    .eq_id(team_id, self.config().advanced.database.generate_id())?,
            )
            .exec(&tx)
            .await
            .map_err(map_db_err)?;
        let deleted = Entity::<O::TeamMember>::delete_many()
            .filter(
                O::TeamMember::column("team_id")?
                    .eq_id(team_id, self.config().advanced.database.generate_id())?,
            )
            .filter(
                O::TeamMember::column("user_id")?
                    .eq_id(user_id, self.config().advanced.database.generate_id())?,
            )
            .exec(&tx)
            .await
            .map_err(map_db_err)?;
        super::team_capacity::release::<O::Team, _>(
            &tx,
            team_id,
            deleted.rows_affected,
            &self.organization_fields()?.team,
            self.config().advanced.database.generate_id(),
        )
        .await?;
        tx.commit().await.map_err(map_db_err)
    }
}

impl<
    S: better_auth_core::AuthSchema,
    O: crate::SeaOrmOrganizationSchema,
    P: crate::SeaOrmPluginSchema,
> SeaOrmStore<S, O, P>
{
    pub(super) async fn get_team_value_with_connection<C: sea_orm::ConnectionTrait>(
        &self,
        db: &C,
        id: &serde_json::Value,
    ) -> AuthResult<Option<Team>> {
        let config = self.organization_fields()?.team;
        let row = Entity::<O::Team>::find()
            .filter(super::value_filter::equals_id(
                O::Team::column("id")?,
                id,
                self.config().advanced.database.generate_id(),
            )?)
            .one(db)
            .await
            .map_err(map_db_err)?;
        match row {
            Some(row) => row
                .record(
                    &config,
                    db.get_database_backend() == sea_orm::DbBackend::Postgres,
                )
                .await
                .map(Some),
            None => Ok(None),
        }
    }

    pub(super) async fn add_team_member_with_connection<C: sea_orm::ConnectionTrait>(
        &self,
        db: &C,
        team_id: &better_auth_core::SchemaValue<String>,
        user_id: &str,
        maximum: Option<usize>,
    ) -> AuthResult<Option<TeamMember>> {
        let team_id = team_id.typed()?;
        // Lock the aggregate before reading membership or capacity, including on SQLite.
        let locked = Entity::<O::Team>::update_many()
            .col_expr(
                O::Team::column("member_count")?,
                Expr::col(O::Team::column("member_count")?),
            )
            .filter(
                O::Team::column("id")?
                    .eq_id(team_id, self.config().advanced.database.generate_id())?,
            )
            .exec(db)
            .await
            .map_err(map_db_err)?;
        if locked.rows_affected == 0 {
            return Err(AuthError::not_found("Team not found"));
        }
        if let Some(member) = Entity::<O::TeamMember>::find()
            .filter(
                O::TeamMember::column("team_id")?
                    .eq_id(team_id, self.config().advanced.database.generate_id())?,
            )
            .filter(
                O::TeamMember::column("user_id")?
                    .eq_id(user_id, self.config().advanced.database.generate_id())?,
            )
            .one(db)
            .await
            .map_err(map_db_err)?
        {
            return Ok(Some(
                member
                    .record(
                        &Default::default(),
                        db.get_database_backend() == sea_orm::DbBackend::Postgres,
                    )
                    .await?,
            ));
        }
        let count = Entity::<O::TeamMember>::find()
            .filter(
                O::TeamMember::column("team_id")?
                    .eq_id(team_id, self.config().advanced.database.generate_id())?,
            )
            .count(db)
            .await
            .map_err(map_db_err)?;
        if !super::team_capacity::reserve::<O::Team, _>(
            db,
            team_id,
            count,
            maximum,
            &self.organization_fields()?.team,
            self.config().advanced.database.generate_id(),
        )
        .await?
        {
            return Ok(None);
        }
        let member = models::insert::<O::TeamMember, _>(
            db,
            self.create_fields(
                "teamMember",
                None,
                values([
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
            )?,
            Default::default(),
            &Default::default(),
            self.config().advanced.database.generate_id(),
        )
        .await?;
        Ok(Some(member))
    }
}

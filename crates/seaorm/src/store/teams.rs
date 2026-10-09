use super::{
    SeaOrmStore, map_db_err,
    organization_models::{self as models, Entity, values},
};
use crate::SeaOrmOrganizationModel;
use async_trait::async_trait;
use better_auth_core::{
    AuthError, AuthResult, CreateTeam, Team, TeamMember, UpdateTeam,
    store::{TeamStore, schema::EntityRole},
};
use better_auth_core::{FieldValue, SchemaField};
use chrono::Utc;
use sea_orm::{
    EntityTrait, PaginatorTrait, QueryFilter, QuerySelect, TransactionTrait, sea_query::Expr,
};

#[async_trait]
impl<
    S: better_auth_core::AuthSchema,
    O: crate::SeaOrmOrganizationSchema,
    P: crate::SeaOrmPluginSchema,
> TeamStore for SeaOrmStore<S, O, P>
{
    async fn create_team(&self, mut input: CreateTeam) -> AuthResult<Team> {
        let mut core = models::with_id(
            values([
                ("organization_id", (input.organization_id).into_field()),
                (
                    "created_at",
                    input
                        .created_at
                        .unwrap_or_else(|| Utc::now().into())
                        .into_field(),
                ),
                ("member_count", (0).into_field()),
            ]),
            input.id.map(FieldValue::from),
        );
        if let Some(name) = Some(input.name.field_value()).filter(|value| !value.is_undefined()) {
            let _ = core.insert("name".into(), name);
        }
        if let Some(updated_at) = input.updated_at {
            let _ = core.insert("updated_at".into(), (updated_at).into_field());
        }
        for (public, stored) in [("createdAt", "created_at"), ("updatedAt", "updated_at")] {
            if let Some(value) = input.additional_fields.remove(public) {
                let _ = core.insert(stored.into(), value);
            }
        }
        models::insert::<O::Team, _>(
            self.connection(),
            super::create_readback::ReadbackScope::Direct(self.connection()),
            core,
            input.additional_fields,
            &self.organization_fields()?.team,
            self.config().advanced.database.generate_id(),
            (
                &self.model_fields,
                better_auth_core::store::schema::EntityRole::Team,
                "team",
            ),
        )
        .await
    }
    async fn get_team(&self, id: &str) -> AuthResult<Option<Team>> {
        self.get_team_value(&id.into()).await
    }
    async fn get_team_value(&self, id: &FieldValue) -> AuthResult<Option<Team>> {
        self.get_team_value_with_connection(self.connection(), id)
            .await
    }
    async fn update_team(&self, id: &str, update: UpdateTeam) -> AuthResult<Team> {
        self.update_team_value(&id.into(), update).await
    }

    async fn update_team_value(&self, id: &FieldValue, update: UpdateTeam) -> AuthResult<Team> {
        let config = self.organization_fields()?.team;
        let mut core = Default::default();
        if let Some(updated_at) = update.updated_at {
            core = values([("updated_at", (updated_at).into_field())]);
        }
        for (name, value) in [
            ("name", update.name.map(|v| v.to_owned().into_field())),
            (
                "organization_id",
                update.organization_id.map(|v| v.to_owned().into_field()),
            ),
            (
                "created_at",
                update.created_at.map(|v| v.to_owned().into_field()),
            ),
        ] {
            if let Some(value) = value {
                let _ = core.insert(name.into(), value);
            }
        }
        self.update_organization_model::<O::Team>(
            self.connection(),
            better_auth_core::store::schema::EntityRole::Team,
            id,
            core,
            update.additional_fields,
            &config,
        )
        .await
    }
    async fn delete_team(&self, id: &str) -> AuthResult<()> {
        self.delete_team_value(&id.into()).await
    }

    async fn delete_team_value(&self, id: &FieldValue) -> AuthResult<()> {
        let tx = self.connection().begin().await.map_err(map_db_err)?;
        let team = self
            .find_organization_model::<O::Team>(
                &tx,
                better_auth_core::store::schema::EntityRole::Team,
                id,
            )
            .await?
            .ok_or_else(|| AuthError::not_found("Team not found"))?;
        let team = models::record(
            &team,
            &Default::default(),
            self.connection().get_database_backend(),
            (&self.model_fields, EntityRole::Team),
        )
        .await?;
        let public_id = team.id.field_value();
        let _ = Entity::<O::TeamMember>::delete_many()
            .filter(self.organization_field_equals::<O::TeamMember>(
                better_auth_core::store::schema::EntityRole::TeamMember,
                "teamId",
                id,
            )?)
            .exec(&tx)
            .await
            .map_err(map_db_err)?;
        let _ = Entity::<O::Team>::delete_many()
            .filter(self.organization_field_equals::<O::Team>(
                better_auth_core::store::schema::EntityRole::Team,
                "id",
                id,
            )?)
            .exec(&tx)
            .await
            .map_err(map_db_err)?;
        let config = self.organization_fields()?.invitation;
        let pending = self
            .pending_invitation_rows(&tx, &team.organization_id.field_value(), None)
            .await?;
        for row in pending {
            if let Some(ids) = row.team_id.typed()? {
                let retained: Vec<_> = ids
                    .split(',')
                    .filter(|team_id| Some(*team_id) != public_id.as_str())
                    .collect();
                if retained.len() != ids.split(',').count() {
                    let _ = self
                        .update_organization_model::<O::Invitation>(
                            &tx,
                            better_auth_core::store::schema::EntityRole::Invitation,
                            &row.id.field_value(),
                            values([(
                                "team_id",
                                ((!retained.is_empty()).then(|| retained.join(","))).into_field(),
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
        self.list_organization_teams_value(&organization_id.into())
            .await
    }

    async fn list_organization_teams_value(
        &self,
        organization_id: &better_auth_core::FieldValue,
    ) -> AuthResult<Vec<Team>> {
        let rows = Entity::<O::Team>::find()
            .filter(self.organization_field_equals::<O::Team>(
                EntityRole::Team,
                "organizationId",
                organization_id,
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
            self.connection().get_database_backend(),
            (
                &self.model_fields,
                better_auth_core::store::schema::EntityRole::Team,
            ),
        )
        .await
    }
    async fn count_organization_teams(&self, organization_id: &str) -> AuthResult<u64> {
        self.count_organization_teams_value(&organization_id.into())
            .await
    }

    async fn count_organization_teams_value(
        &self,
        organization_id: &better_auth_core::FieldValue,
    ) -> AuthResult<u64> {
        Entity::<O::Team>::find()
            .filter(self.organization_field_equals::<O::Team>(
                EntityRole::Team,
                "organizationId",
                organization_id,
            )?)
            .count(self.connection())
            .await
            .map_err(map_db_err)
    }
    async fn list_user_teams(&self, user_id: &str) -> AuthResult<Vec<Team>> {
        self.list_user_teams_value(&user_id.into()).await
    }

    async fn list_user_teams_value(&self, user_id: &FieldValue) -> AuthResult<Vec<Team>> {
        if self.config().advanced.database.joins == Some(true) {
            return self.joined_user_teams(user_id).await;
        }
        let rows = Entity::<O::TeamMember>::find()
            .filter(self.organization_field_equals::<O::TeamMember>(
                better_auth_core::store::schema::EntityRole::TeamMember,
                "userId",
                user_id,
            )?)
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
            self.connection().get_database_backend(),
            (
                &self.model_fields,
                better_auth_core::store::schema::EntityRole::TeamMember,
            ),
            |index, _| {
                let rows = &rows;
                let config = &config;
                async move {
                    let member = rows.get(index).ok_or_else(|| {
                        better_auth_core::AuthError::internal(
                            "Team member projection lost its stored join index",
                        )
                    })?;
                    self.model_fields
                        .begin_id_query(better_auth_core::store::schema::EntityRole::Team)?;
                    let row = Entity::<O::Team>::find()
                        .filter(super::value_filter::equals_native(
                            O::Team::column("id")?,
                            models::join_value(member, "team_id")?,
                            self.connection().get_database_backend(),
                        )?)
                        .one(self.connection())
                        .await
                        .map_err(map_db_err)?;
                    match row {
                        Some(row) => models::record(
                            &row,
                            config,
                            self.connection().get_database_backend(),
                            (
                                &self.model_fields,
                                better_auth_core::store::schema::EntityRole::Team,
                            ),
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
        self.get_team_member_value(&team_id.into(), &user_id.into())
            .await
    }

    async fn get_team_member_value(
        &self,
        team_id: &better_auth_core::FieldValue,
        user_id: &better_auth_core::FieldValue,
    ) -> AuthResult<Option<TeamMember>> {
        let row = Entity::<O::TeamMember>::find()
            .filter(self.organization_fields_equal::<O::TeamMember>(
                better_auth_core::store::schema::EntityRole::TeamMember,
                [("teamId", team_id), ("userId", user_id)],
            )?)
            .one(self.connection())
            .await
            .map_err(map_db_err)?;
        match row {
            Some(row) => models::record(
                &row,
                &Default::default(),
                self.connection().get_database_backend(),
                (
                    &self.model_fields,
                    better_auth_core::store::schema::EntityRole::TeamMember,
                ),
            )
            .await
            .map(Some),
            None => Ok(None),
        }
    }
    async fn list_team_members(&self, team_id: &str) -> AuthResult<Vec<TeamMember>> {
        self.list_team_members_value(&team_id.into()).await
    }

    async fn list_team_members_value(
        &self,
        team_id: &better_auth_core::FieldValue,
    ) -> AuthResult<Vec<TeamMember>> {
        let rows = Entity::<O::TeamMember>::find()
            .filter(self.organization_field_equals::<O::TeamMember>(
                better_auth_core::store::schema::EntityRole::TeamMember,
                "teamId",
                team_id,
            )?)
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
            self.connection().get_database_backend(),
            (
                &self.model_fields,
                better_auth_core::store::schema::EntityRole::TeamMember,
            ),
        )
        .await
    }
    async fn count_team_members(&self, team_id: &str) -> AuthResult<u64> {
        self.count_team_members_value(&team_id.into()).await
    }

    async fn count_team_members_value(&self, team_id: &FieldValue) -> AuthResult<u64> {
        Entity::<O::TeamMember>::find()
            .filter(self.organization_field_equals::<O::TeamMember>(
                better_auth_core::store::schema::EntityRole::TeamMember,
                "teamId",
                team_id,
            )?)
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
        self.add_team_member_value(&team_id.field_value(), &user_id.into(), maximum)
            .await
    }

    async fn add_team_member_value(
        &self,
        team_id: &FieldValue,
        user_id: &FieldValue,
        maximum: Option<usize>,
    ) -> AuthResult<Option<TeamMember>> {
        let tx = self.connection().begin().await.map_err(map_db_err)?;
        let result = self
            .add_team_member_with_connection(&tx, team_id, user_id, maximum)
            .await?;
        tx.commit().await.map_err(map_db_err)?;
        Ok(result)
    }
    async fn remove_team_member(&self, team_id: &str, user_id: &str) -> AuthResult<()> {
        self.remove_team_member_value(&team_id.into(), &user_id.into())
            .await
    }

    async fn remove_team_member_value(
        &self,
        team_id: &FieldValue,
        user_id: &FieldValue,
    ) -> AuthResult<()> {
        let tx = self.connection().begin().await.map_err(map_db_err)?;
        self.model_fields
            .begin_id_query(better_auth_core::store::schema::EntityRole::Team)?;
        let _ = Entity::<O::Team>::update_many()
            .col_expr(
                O::Team::column("member_count")?,
                Expr::col(O::Team::column("member_count")?),
            )
            .filter(super::value_filter::equals_id(
                O::Team::column("id")?,
                team_id,
                self.config().advanced.database.generate_id(),
                self.connection().get_database_backend(),
            )?)
            .exec(&tx)
            .await
            .map_err(map_db_err)?;
        let deleted = Entity::<O::TeamMember>::delete_many()
            .filter(self.organization_fields_equal::<O::TeamMember>(
                better_auth_core::store::schema::EntityRole::TeamMember,
                [("teamId", team_id), ("userId", user_id)],
            )?)
            .exec(&tx)
            .await
            .map_err(map_db_err)?;
        super::team_capacity::release::<O::Team, _>(
            &tx,
            team_id,
            deleted.rows_affected,
            &self.organization_fields()?.team,
            self.config().advanced.database.generate_id(),
            (
                &self.model_fields,
                better_auth_core::store::schema::EntityRole::Team,
            ),
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
        id: &FieldValue,
    ) -> AuthResult<Option<Team>> {
        let config = self.organization_fields()?.team;
        let row = self
            .find_organization_model::<O::Team>(
                db,
                better_auth_core::store::schema::EntityRole::Team,
                id,
            )
            .await?;
        match row {
            Some(row) => models::record(
                &row,
                &config,
                db.get_database_backend(),
                (
                    &self.model_fields,
                    better_auth_core::store::schema::EntityRole::Team,
                ),
            )
            .await
            .map(Some),
            None => Ok(None),
        }
    }

    pub(super) async fn add_team_member_with_connection<C: sea_orm::ConnectionTrait>(
        &self,
        db: &C,
        team_id: &FieldValue,
        user_id: &FieldValue,
        maximum: Option<usize>,
    ) -> AuthResult<Option<TeamMember>> {
        // Lock the aggregate before reading membership or capacity, including on SQLite.
        self.model_fields
            .begin_id_query(better_auth_core::store::schema::EntityRole::Team)?;
        let locked = Entity::<O::Team>::update_many()
            .col_expr(
                O::Team::column("member_count")?,
                Expr::col(O::Team::column("member_count")?),
            )
            .filter(super::value_filter::equals_id(
                O::Team::column("id")?,
                team_id,
                self.config().advanced.database.generate_id(),
                self.connection().get_database_backend(),
            )?)
            .exec(db)
            .await
            .map_err(map_db_err)?;
        if locked.rows_affected == 0 {
            return Err(AuthError::not_found("Team not found"));
        }
        if let Some(member) = Entity::<O::TeamMember>::find()
            .filter(self.organization_fields_equal::<O::TeamMember>(
                better_auth_core::store::schema::EntityRole::TeamMember,
                [("teamId", team_id), ("userId", user_id)],
            )?)
            .one(db)
            .await
            .map_err(map_db_err)?
        {
            return Ok(Some(
                models::record(
                    &member,
                    &Default::default(),
                    db.get_database_backend(),
                    (
                        &self.model_fields,
                        better_auth_core::store::schema::EntityRole::TeamMember,
                    ),
                )
                .await?,
            ));
        }
        let count = Entity::<O::TeamMember>::find()
            .filter(self.organization_field_equals::<O::TeamMember>(
                better_auth_core::store::schema::EntityRole::TeamMember,
                "teamId",
                team_id,
            )?)
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
            (
                &self.model_fields,
                better_auth_core::store::schema::EntityRole::Team,
            ),
        )
        .await?
        {
            return Ok(None);
        }
        let member = models::insert::<O::TeamMember, _>(
            db,
            super::create_readback::ReadbackScope::Transaction,
            values([
                ("team_id", team_id.clone()),
                ("user_id", user_id.clone()),
                (
                    "membership_key",
                    (better_auth_core::organization_fields::team_membership_key_values(
                        team_id, user_id,
                    )?)
                    .into_field(),
                ),
                ("created_at", FieldValue::Date((Utc::now()).into())),
            ]),
            Default::default(),
            &Default::default(),
            self.config().advanced.database.generate_id(),
            (
                &self.model_fields,
                better_auth_core::store::schema::EntityRole::TeamMember,
                "teamMember",
            ),
        )
        .await?;
        Ok(Some(member))
    }
}

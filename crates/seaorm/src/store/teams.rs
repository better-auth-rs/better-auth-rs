use super::{
    SeaOrmStore, map_db_err,
    organization_models::{self as models, Entity, values},
};
use crate::SeaOrmOrganizationModel;
use crate::store::query_compile::Execute;
use async_trait::async_trait;
use better_auth_core::{
    AuthError, AuthResult, CreateTeam, Team, TeamMember, UpdateTeam,
    store::{TeamStore, schema::EntityRole},
};
use better_auth_core::{FieldValue, SchemaField};
use chrono::Utc;
use sea_orm::{EntityTrait, QueryFilter, QuerySelect, TransactionTrait, sea_query::Expr};

mod deletion;

#[async_trait]
impl<
    S: better_auth_core::AuthSchema,
    O: crate::SeaOrmOrganizationSchema,
    P: crate::SeaOrmPluginSchema,
> TeamStore for SeaOrmStore<S, O, P>
where
    S::User: crate::SeaOrmUserModel,
    S::Session: crate::SeaOrmSessionModel,
    S::Account: crate::SeaOrmAccountModel,
    S::Verification: crate::SeaOrmVerificationModel,
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
    async fn get_team_details_value(
        &self,
        team_id: &FieldValue,
        organization_id: Option<&FieldValue>,
        include_members: bool,
    ) -> AuthResult<Option<better_auth_core::store::TeamDetails>> {
        self.read_team_details(self.connection(), team_id, organization_id, include_members)
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
        self.delete_team_with_context(id, None).await
    }

    async fn delete_team_for_organization_value(
        &self,
        id: &FieldValue,
        organization_id: &FieldValue,
    ) -> AuthResult<()> {
        self.delete_team_with_context(id, Some(organization_id))
            .await
    }
    async fn list_organization_teams(&self, organization_id: &str) -> AuthResult<Vec<Team>> {
        self.list_organization_teams_value(&organization_id.into())
            .await
    }

    async fn list_organization_teams_value(
        &self,
        organization_id: &better_auth_core::FieldValue,
    ) -> AuthResult<Vec<Team>> {
        let rows = super::plugin_rows::all(
            self.connection(),
            super::plugin_rows::select_all::<Entity<O::Team>>()
                .filter(self.organization_field_equals::<O::Team>(
                    EntityRole::Team,
                    "organizationId",
                    organization_id,
                )?)
                .limit(super::pagination::default_limit(
                    self.config(),
                    self.connection().get_database_backend(),
                )?),
        )
        .await?;
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
        let query = Entity::<O::Team>::find().filter(self.organization_field_equals::<O::Team>(
            EntityRole::Team,
            "organizationId",
            organization_id,
        )?);
        super::plugin_rows::count(self.connection(), query).await
    }
    async fn list_user_teams(&self, user_id: &str) -> AuthResult<Vec<Team>> {
        self.list_user_teams_value(&user_id.into()).await
    }

    async fn list_user_teams_value(&self, user_id: &FieldValue) -> AuthResult<Vec<Team>> {
        self.list_user_teams_with_schema(user_id).await
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
        self.find_team_member_with_connection(
            self.connection(),
            [("teamId", team_id), ("userId", user_id)],
        )
        .await
    }
    async fn list_team_members(&self, team_id: &str) -> AuthResult<Vec<TeamMember>> {
        self.list_team_members_value(&team_id.into()).await
    }

    async fn list_team_members_value(
        &self,
        team_id: &better_auth_core::FieldValue,
    ) -> AuthResult<Vec<TeamMember>> {
        let query = super::plugin_rows::select_all::<Entity<O::TeamMember>>()
            .filter(self.organization_field_equals::<O::TeamMember>(
                better_auth_core::store::schema::EntityRole::TeamMember,
                "teamId",
                team_id,
            )?)
            .limit(super::pagination::default_limit(
                self.config(),
                self.connection().get_database_backend(),
            )?);
        let rows = super::plugin_rows::all(self.connection(), query).await?;
        self.project_team_member_rows(&rows, self.connection().get_database_backend())
            .await
    }
    async fn count_team_members(&self, team_id: &str) -> AuthResult<u64> {
        self.count_team_members_value(&team_id.into()).await
    }

    async fn count_team_members_value(&self, team_id: &FieldValue) -> AuthResult<u64> {
        let query = Entity::<O::TeamMember>::find().filter(
            self.organization_field_equals::<O::TeamMember>(
                better_auth_core::store::schema::EntityRole::TeamMember,
                "teamId",
                team_id,
            )?,
        );
        super::plugin_rows::count(self.connection(), query).await
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
        let deleted = Entity::<O::TeamMember>::delete_many()
            .filter(self.organization_fields_equal::<O::TeamMember>(
                better_auth_core::store::schema::EntityRole::TeamMember,
                [("teamId", team_id), ("userId", user_id)],
            )?)
            .exec_native(self.connection())
            .await?;
        super::team_capacity::release::<O::Team, _>(
            self.connection(),
            super::create_readback::ReadbackScope::Direct(self.connection()),
            team_id,
            deleted.rows_affected,
            &self.organization_fields()?.team,
            self.config(),
            (
                &self.model_fields,
                better_auth_core::store::schema::EntityRole::Team,
            ),
        )
        .await
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
            Some(row) => models::record::<O::Team>(
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
        let membership_key =
            better_auth_core::organization_fields::team_membership_key_values(team_id, user_id)?
                .into();
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
            .exec_native(db)
            .await?;
        if locked.rows_affected == 0 {
            return Err(AuthError::not_found("Team not found"));
        }
        if let Some(member) = self
            .find_team_member_by_key_or_pair(db, team_id, user_id, &membership_key)
            .await?
        {
            return Ok(Some(member));
        }
        let query = Entity::<O::TeamMember>::find().filter(
            self.organization_field_equals::<O::TeamMember>(
                better_auth_core::store::schema::EntityRole::TeamMember,
                "teamId",
                team_id,
            )?,
        );
        let count = super::plugin_rows::count(db, query).await?;
        let fields = self.organization_fields()?.team;
        super::team_capacity::sync::<O::Team, _>(
            db,
            team_id,
            count,
            &fields,
            self.config(),
            (&self.model_fields, EntityRole::Team),
        )
        .await?;
        let member = if let Some(maximum) = maximum {
            if !super::team_capacity::reserve::<O::Team, _>(
                db,
                team_id,
                maximum,
                &fields,
                self.config(),
                (&self.model_fields, EntityRole::Team),
            )
            .await?
            {
                return Ok(None);
            }
            self.create_reserved_team_member(db, team_id, user_id, &membership_key)
                .await?
        } else {
            self.create_unlimited_team_member(db, team_id, user_id, &membership_key)
                .await?
        };
        Ok(Some(member))
    }
}

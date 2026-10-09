use super::{
    SeaOrmStore,
    organization_models::{self as models, Entity, values},
    plugin_rows::{self, SqlRow},
};
use crate::SeaOrmOrganizationModel;
use better_auth_core::{
    AuthError, AuthResult, FieldValue, TeamMember, entity::FromFieldMap, store::schema::EntityRole,
    user_fields::AdapterRecord,
};
use sea_orm::{ConnectionTrait, DbBackend, EntityTrait, QueryFilter};

impl<S: crate::schema::AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    SeaOrmStore<S, O, P>
{
    pub(super) fn team_member_records(
        &self,
        rows: &[SqlRow],
        backend: DbBackend,
    ) -> AuthResult<Vec<AdapterRecord>> {
        let fields = self.model_fields.plugin_fields(EntityRole::TeamMember);
        rows.iter()
            .map(|row| {
                models::raw_record::<O::TeamMember>(
                    row,
                    &fields,
                    backend,
                    (&self.model_fields, EntityRole::TeamMember),
                )
            })
            .collect()
    }

    pub(super) async fn project_team_member_rows(
        &self,
        rows: &[SqlRow],
        backend: DbBackend,
    ) -> AuthResult<Vec<TeamMember>> {
        self.model_fields
            .plugin_fields(EntityRole::TeamMember)
            .organization_output_records(
                self.team_member_records(rows, backend)?,
                backend == DbBackend::Postgres,
            )
            .await?
            .into_iter()
            .map(TeamMember::from_field_values)
            .collect()
    }

    pub(super) async fn find_team_member_with_connection<'a>(
        &self,
        db: &impl ConnectionTrait,
        selectors: impl IntoIterator<Item = (&'a str, &'a FieldValue)> + Send,
    ) -> AuthResult<Option<TeamMember>> {
        let row = plugin_rows::one(
            db,
            Entity::<O::TeamMember>::find().filter(
                self.organization_fields_equal::<O::TeamMember>(EntityRole::TeamMember, selectors)?,
            ),
        )
        .await?;
        self.project_team_member_rows(
            &row.into_iter().collect::<Vec<_>>(),
            db.get_database_backend(),
        )
        .await
        .map(|mut rows| rows.pop())
    }

    pub(super) async fn find_team_member_by_key_or_pair(
        &self,
        db: &impl ConnectionTrait,
        team_id: &FieldValue,
        user_id: &FieldValue,
        membership_key: &FieldValue,
    ) -> AuthResult<Option<TeamMember>> {
        if let Some(member) = self
            .find_team_member_with_connection(db, [("membershipKey", membership_key)])
            .await?
        {
            return Ok(Some(member));
        }
        self.find_team_member_with_connection(db, [("teamId", team_id), ("userId", user_id)])
            .await
    }

    async fn create_team_member_with_key(
        &self,
        db: &impl ConnectionTrait,
        team_id: &FieldValue,
        user_id: &FieldValue,
        membership_key: &FieldValue,
    ) -> AuthResult<(TeamMember, bool)> {
        let result = async {
            let fields = self.model_fields.plugin_fields(EntityRole::TeamMember);
            let row = models::active::<O::TeamMember>(
                values([
                    ("team_id", team_id.clone()),
                    ("user_id", user_id.clone()),
                    ("membership_key", membership_key.clone()),
                    ("created_at", chrono::Utc::now().into()),
                ]),
                Default::default(),
                &fields,
                Some("teamMember"),
                db.get_database_backend(),
                self.config().advanced.database.generate_id(),
                (&self.model_fields, EntityRole::TeamMember),
            )
            .await?
            .insert_raw(
                db,
                super::create_readback::CreateReadback {
                    schema: &fields,
                    policy: self.config().advanced.database.generate_id(),
                    scope: super::create_readback::ReadbackScope::Transaction,
                    column: O::TeamMember::column,
                },
            )
            .await?
            .ok_or_else(|| AuthError::internal("Team member creation returned no record"))?;
            self.project_team_member_rows(&[SqlRow::from(row)], db.get_database_backend())
                .await?
                .pop()
                .ok_or_else(|| AuthError::internal("Team member projection returned no record"))
        }
        .await;
        match result {
            Ok(member) => Ok((member, true)),
            Err(error) => self
                .find_team_member_by_key_or_pair(db, team_id, user_id, membership_key)
                .await?
                .map(|member| (member, false))
                .ok_or(error),
        }
    }

    pub(super) async fn create_reserved_team_member(
        &self,
        db: &impl ConnectionTrait,
        team_id: &FieldValue,
        user_id: &FieldValue,
        membership_key: &FieldValue,
    ) -> AuthResult<TeamMember> {
        let result = self
            .create_team_member_with_key(db, team_id, user_id, membership_key)
            .await;
        if !matches!(result, Ok((_, true))) {
            super::team_capacity::release::<O::Team, _>(
                db,
                super::create_readback::ReadbackScope::Transaction,
                team_id,
                1,
                &self.organization_fields()?.team,
                self.config().advanced.database.generate_id(),
                (&self.model_fields, EntityRole::Team),
            )
            .await?;
        }
        result.map(|(member, _)| member)
    }

    pub(super) async fn create_unlimited_team_member(
        &self,
        db: &impl ConnectionTrait,
        team_id: &FieldValue,
        user_id: &FieldValue,
        membership_key: &FieldValue,
    ) -> AuthResult<TeamMember> {
        let (member, created) = self
            .create_team_member_with_key(db, team_id, user_id, membership_key)
            .await?;
        if created {
            super::team_capacity::increment::<O::Team, _>(
                db,
                team_id,
                &self.organization_fields()?.team,
                self.config().advanced.database.generate_id(),
                (&self.model_fields, EntityRole::Team),
            )
            .await?;
        }
        Ok(member)
    }
}

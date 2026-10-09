use super::{
    SeaOrmStore, map_db_err,
    organization_models::{self as models, Entity, values},
};
use crate::SeaOrmOrganizationModel;
use crate::schema::{AuthSchema, SeaOrmSessionModel};
use better_auth_core::{AuthError, AuthResult, Invitation, Member, store::schema::EntityRole};
use better_auth_core::{FieldValue, SchemaField};
use chrono::Utc;
use sea_orm::{
    EntityTrait, FromQueryResult, PaginatorTrait, QueryFilter, TransactionTrait,
    sea_query::{Expr, ExprTrait},
};

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S: AuthSchema,
    S::Session: SeaOrmSessionModel,
{
    pub(super) async fn accept_team_invitation(
        &self,
        invitation_id: &FieldValue,
        user_id: &FieldValue,
        session_token: Option<&FieldValue>,
        teams_enabled: bool,
        maximum: better_auth_core::store::TeamMemberLimits<'_>,
    ) -> AuthResult<(
        Member,
        better_auth_core::Invitation,
        Option<better_auth_core::wire::SessionView>,
    )> {
        let invitation = self
            .transition_invitation(invitation_id, "pending", "accepted")
            .await?
            .ok_or_else(|| AuthError::bad_request("Invitation not found"))?;
        match self
            .accept_claimed_invitation(&invitation, user_id, session_token, teams_enabled, maximum)
            .await
        {
            Ok((member, session)) => Ok((member, invitation, session)),
            Err(error) => {
                let _ = self
                    .transition_invitation(invitation_id, "accepted", "pending")
                    .await?;
                Err(error)
            }
        }
    }

    async fn transition_invitation(
        &self,
        id: &FieldValue,
        from: &str,
        status: &str,
    ) -> AuthResult<Option<Invitation>> {
        let config = self.organization_fields()?.invitation;
        let id = self.bind_organization_query_field(EntityRole::Invitation, "id", id)?;
        let from =
            self.bind_organization_query_field(EntityRole::Invitation, "status", &from.into())?;
        let active = models::active::<O::Invitation>(
            values([("status", status.to_owned().into_field())]),
            Default::default(),
            &config,
            None,
            self.connection().get_database_backend(),
            self.config().advanced.database.generate_id(),
            (
                &self.model_fields,
                better_auth_core::store::schema::EntityRole::Invitation,
            ),
        )
        .await?;
        let backend = self.connection().get_database_backend();
        let (id_column, id) =
            self.resolve_organization_query_field::<O::Invitation>(EntityRole::Invitation, id)?;
        let (status_column, from) =
            self.resolve_organization_query_field::<O::Invitation>(EntityRole::Invitation, from)?;
        let id = super::value_filter::equals(id_column, &id, backend)?;
        let condition = id
            .clone()
            .and(super::value_filter::equals(status_column, &from, backend)?);
        let tx = self.connection().begin().await.map_err(map_db_err)?;
        let row =
            super::updates::increment_returning_raw_with_connection::<Entity<O::Invitation>, _>(
                &tx,
                active.update(backend)?.filter(condition.clone()),
                condition,
                id,
            )
            .await?;
        let row = row
            .map(|row| O::Invitation::from_query_result(&row, "").map_err(map_db_err))
            .transpose()?;
        tx.commit().await.map_err(map_db_err)?;
        // Output transforms run after the claim is committed, before the member transaction starts.
        match row {
            Some(row) => models::record(
                &row,
                &config,
                self.connection().get_database_backend(),
                (
                    &self.model_fields,
                    better_auth_core::store::schema::EntityRole::Invitation,
                ),
            )
            .await
            .map(Some),
            None => Ok(None),
        }
    }

    async fn accept_claimed_invitation(
        &self,
        invitation: &Invitation,
        user_id: &FieldValue,
        session_token: Option<&FieldValue>,
        teams_enabled: bool,
        maximum: better_auth_core::store::TeamMemberLimits<'_>,
    ) -> AuthResult<(Member, Option<better_auth_core::wire::SessionView>)> {
        let config = self.organization_fields()?;
        let tx = self.connection().begin().await.map_err(map_db_err)?;
        let result = async {
            let team_id = invitation.team_id.field_value();
            let team_ids: Vec<_> = if teams_enabled && team_id.is_truthy() {
                team_id
                    .as_str()
                    .ok_or_else(|| {
                        AuthError::type_error("acceptedI.teamId.split is not a function")
                    })?
                    .split(',')
                    .collect()
            } else {
                Vec::new()
            };
            for team_id in &team_ids {
                let team_value = FieldValue::from(*team_id);
                self.model_fields
                    .begin_id_query(better_auth_core::store::schema::EntityRole::Team)?;
                let locked = Entity::<O::Team>::update_many()
                    .col_expr(
                        O::Team::column("member_count")?,
                        Expr::col(O::Team::column("member_count")?),
                    )
                    .filter(super::value_filter::equals_id(
                        O::Team::column("id")?,
                        &team_value,
                        self.config().advanced.database.generate_id(),
                        self.connection().get_database_backend(),
                    )?)
                    .filter(self.organization_field_equals::<O::Team>(
                        EntityRole::Team,
                        "organizationId",
                        &invitation.organization_id.field_value(),
                    )?)
                    .exec(&tx)
                    .await
                    .map_err(map_db_err)?;
                if locked.rows_affected == 0 {
                    return Err(AuthError::bad_request("Team not found"));
                }
                let maximum = maximum
                    .maximum(team_id, &invitation.organization_id.field_value())
                    .await?;
                let membership_key =
                    better_auth_core::organization_fields::team_membership_key_values(
                        &team_value,
                        user_id,
                    )?
                    .into();
                let existing = self
                    .find_team_member_by_key_or_pair(&tx, &team_value, user_id, &membership_key)
                    .await?;
                if existing.is_none() {
                    let count = Entity::<O::TeamMember>::find()
                        .filter(self.organization_field_equals::<O::TeamMember>(
                            better_auth_core::store::schema::EntityRole::TeamMember,
                            "teamId",
                            &team_value,
                        )?)
                        .count(&tx)
                        .await
                        .map_err(map_db_err)?;
                    super::team_capacity::sync::<O::Team, _>(
                        &tx,
                        &team_value,
                        count,
                        &config.team,
                        self.config().advanced.database.generate_id(),
                        (&self.model_fields, EntityRole::Team),
                    )
                    .await?;
                    if let Some(maximum) = maximum {
                        if !super::team_capacity::reserve::<O::Team, _>(
                            &tx,
                            &team_value,
                            maximum,
                            &config.team,
                            self.config().advanced.database.generate_id(),
                            (&self.model_fields, EntityRole::Team),
                        )
                        .await?
                        {
                            return Err(AuthError::forbidden("Team member limit reached"));
                        }
                        let _ = self
                            .create_reserved_team_member(&tx, &team_value, user_id, &membership_key)
                            .await?;
                    } else {
                        let _ = self
                            .create_unlimited_team_member(
                                &tx,
                                &team_value,
                                user_id,
                                &membership_key,
                            )
                            .await?;
                    }
                }
            }
            let member = models::insert::<O::Member, _>(
                &tx,
                super::create_readback::ReadbackScope::Transaction,
                values([
                    ("organization_id", invitation.organization_id.field_value()),
                    ("user_id", user_id.clone()),
                    ("role", invitation.role.field_value()),
                    ("created_at", FieldValue::Date((Utc::now()).into())),
                ]),
                Default::default(),
                &config.member,
                self.config().advanced.database.generate_id(),
                (
                    &self.model_fields,
                    better_auth_core::store::schema::EntityRole::Member,
                    "member",
                ),
            )
            .await?;
            let Some(session_token) = session_token else {
                return Ok((member, None));
            };
            let cookie_session = if let [team_id] = team_ids.as_slice() {
                Some(
                    self.write_session_update(
                        &tx,
                        session_token,
                        [("activeTeamId".into(), (*team_id).into())].into(),
                    )
                    .await?
                    .ok_or(AuthError::SessionNotFound)?,
                )
            } else {
                None
            };
            let _ = self
                .write_session_update(
                    &tx,
                    session_token,
                    [(
                        "activeOrganizationId".into(),
                        invitation.organization_id.field_value(),
                    )]
                    .into(),
                )
                .await?
                .ok_or(AuthError::SessionNotFound)?;
            Ok((member, cookie_session))
        }
        .await;
        match result {
            Ok(value) => {
                tx.commit().await.map_err(map_db_err)?;
                Ok(value)
            }
            Err(error) => {
                tx.rollback().await.map_err(map_db_err)?;
                Err(error)
            }
        }
    }
}

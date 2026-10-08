use super::id_filter::IdColumn;
use super::{
    SeaOrmStore, map_db_err,
    organization_models::{self as models, Entity, values},
};
use crate::SeaOrmOrganizationModel;
use crate::schema::{AuthSchema, SeaOrmSessionModel};
use better_auth_core::{AuthError, AuthResult, Invitation, Member};
use better_auth_core::{FieldValue, SchemaField};
use chrono::Utc;
use sea_orm::{
    ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, TransactionTrait, sea_query::Expr,
};

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S: AuthSchema,
    S::Session: SeaOrmSessionModel,
{
    pub(super) async fn accept_team_invitation(
        &self,
        invitation_id: &str,
        user_id: &str,
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
        id: &str,
        from: &str,
        status: &str,
    ) -> AuthResult<Option<Invitation>> {
        let config = self.organization_fields()?.invitation;
        let active = models::active::<O::Invitation>(
            values([("status", status.to_owned().into_field())]),
            Default::default(),
            &config,
            false,
            self.connection().get_database_backend(),
            self.config().advanced.database.generate_id(),
        )
        .await?;
        let tx = self.connection().begin().await.map_err(map_db_err)?;
        let changed = active
            .update(self.connection().get_database_backend())?
            .filter(
                O::Invitation::column("id")?
                    .eq_id(id, self.config().advanced.database.generate_id())?,
            )
            .filter(O::Invitation::column("status")?.eq(from))
            .exec(&tx)
            .await
            .map_err(map_db_err)?;
        let row = if changed.rows_affected == 0 {
            None
        } else {
            models::find::<O::Invitation, _>(&tx, id, self.config().advanced.database.generate_id())
                .await?
        };
        tx.commit().await.map_err(map_db_err)?;
        // Output transforms run after the claim is committed, before the member transaction starts.
        match row {
            Some(row) => row
                .record(&config, self.connection().get_database_backend())
                .await
                .map(Some),
            None => Ok(None),
        }
    }

    async fn accept_claimed_invitation(
        &self,
        invitation: &Invitation,
        user_id: &str,
        session_token: Option<&FieldValue>,
        teams_enabled: bool,
        maximum: better_auth_core::store::TeamMemberLimits<'_>,
    ) -> AuthResult<(Member, Option<better_auth_core::wire::SessionView>)> {
        let config = self.organization_fields()?;
        let tx = self.connection().begin().await.map_err(map_db_err)?;
        let result = async {
            let team_ids: Vec<_> = invitation
                .team_id
                .typed()?
                .as_deref()
                .filter(|_| teams_enabled)
                .unwrap_or("")
                .split(',')
                .filter(|id| !id.is_empty())
                .collect();
            for team_id in &team_ids {
                let locked = Entity::<O::Team>::update_many()
                    .col_expr(
                        O::Team::column("member_count")?,
                        Expr::col(O::Team::column("member_count")?),
                    )
                    .filter(
                        O::Team::column("id")?
                            .eq_id(*team_id, self.config().advanced.database.generate_id())?,
                    )
                    .filter(O::Team::column("organization_id")?.eq_id(
                        invitation.organization_id.typed()?.clone(),
                        self.config().advanced.database.generate_id(),
                    )?)
                    .exec(&tx)
                    .await
                    .map_err(map_db_err)?;
                if locked.rows_affected == 0 {
                    return Err(AuthError::bad_request("Team not found"));
                }
                let maximum = maximum.maximum(team_id).await?;
                let existing = Entity::<O::TeamMember>::find()
                    .filter(
                        O::TeamMember::column("team_id")?
                            .eq_id(*team_id, self.config().advanced.database.generate_id())?,
                    )
                    .filter(
                        O::TeamMember::column("user_id")?
                            .eq_id(user_id, self.config().advanced.database.generate_id())?,
                    )
                    .one(&tx)
                    .await
                    .map_err(map_db_err)?;
                if existing.is_none() {
                    let count = Entity::<O::TeamMember>::find()
                        .filter(
                            O::TeamMember::column("team_id")?
                                .eq_id(*team_id, self.config().advanced.database.generate_id())?,
                        )
                        .count(&tx)
                        .await
                        .map_err(map_db_err)?;
                    if !super::team_capacity::reserve::<O::Team, _>(
                        &tx,
                        team_id,
                        count,
                        maximum,
                        &config.team,
                        self.config().advanced.database.generate_id(),
                    )
                    .await?
                    {
                        return Err(AuthError::forbidden("Team member limit reached"));
                    }
                    let _ = models::insert::<O::TeamMember, _>(
                        &tx,
                        super::create_readback::ReadbackScope::Transaction,
                        self.create_fields(
                            "teamMember",
                            None,
                            values([
                                ("team_id", (*team_id).to_owned().into_field()),
                                ("user_id", (user_id).to_owned().into_field()),
                                (
                                    "membership_key",
                                    (better_auth_core::organization_fields::team_membership_key(
                                        team_id, user_id,
                                    )?)
                                    .into_field(),
                                ),
                                ("created_at", FieldValue::Date((Utc::now()).into())),
                            ]),
                        )?,
                        Default::default(),
                        &Default::default(),
                        self.config().advanced.database.generate_id(),
                    )
                    .await?;
                }
            }
            let member = models::insert::<O::Member, _>(
                &tx,
                super::create_readback::ReadbackScope::Transaction,
                self.create_fields(
                    "member",
                    None,
                    values([
                        ("organization_id", invitation.organization_id.field_value()),
                        ("user_id", (user_id).to_owned().into_field()),
                        ("role", invitation.role.field_value()),
                        ("created_at", FieldValue::Date((Utc::now()).into())),
                    ]),
                )?,
                Default::default(),
                &config.member,
                self.config().advanced.database.generate_id(),
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
                        better_auth_core::hooks::SessionUpdate {
                            additional_fields: [("activeTeamId".into(), (*team_id).into())].into(),
                            ..Default::default()
                        },
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
                    better_auth_core::hooks::SessionUpdate {
                        additional_fields: [(
                            "activeOrganizationId".into(),
                            invitation.organization_id.field_value(),
                        )]
                        .into(),
                        ..Default::default()
                    },
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

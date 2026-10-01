use super::{
    SeaOrmStore, map_db_err,
    organization_models::{self as models, Entity, values},
};
use crate::SeaOrmOrganizationModel;
use crate::schema::{AuthSchema, SeaOrmSessionModel};
use better_auth_core::{AuthError, AuthResult, Invitation, Member};
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, PaginatorTrait, QueryFilter,
    TransactionTrait, sea_query::Expr,
};
use serde_json::json;

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S: AuthSchema,
    S::Session: SeaOrmSessionModel,
{
    pub(super) async fn accept_team_invitation(
        &self,
        invitation_id: &str,
        user_id: &str,
        session_token: Option<&str>,
        teams_enabled: bool,
        maximum: better_auth_core::store::TeamMemberLimits<'_>,
    ) -> AuthResult<(Member, better_auth_core::Invitation, Option<S::Session>)> {
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
            values([("status", json!(status))]),
            Default::default(),
            &config,
            false,
            self.connection().get_database_backend(),
        )?;
        let tx = self.connection().begin().await.map_err(map_db_err)?;
        let changed = Entity::<O::Invitation>::update_many()
            .set(active)
            .filter(O::Invitation::column("id")?.eq(id))
            .filter(O::Invitation::column("status")?.eq(from))
            .exec(&tx)
            .await
            .map_err(map_db_err)?;
        let row = if changed.rows_affected == 0 {
            None
        } else {
            models::find::<O::Invitation, _>(&tx, id).await?
        };
        tx.commit().await.map_err(map_db_err)?;
        // Output transforms run after the claim is committed, before the member transaction starts.
        row.map(|row| row.record(&config)).transpose()
    }

    async fn accept_claimed_invitation(
        &self,
        invitation: &Invitation,
        user_id: &str,
        session_token: Option<&str>,
        teams_enabled: bool,
        maximum: better_auth_core::store::TeamMemberLimits<'_>,
    ) -> AuthResult<(Member, Option<S::Session>)> {
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
                    .filter(O::Team::column("id")?.eq(*team_id))
                    .filter(
                        O::Team::column("organization_id")?
                            .eq(invitation.organization_id.typed()?.clone()),
                    )
                    .exec(&tx)
                    .await
                    .map_err(map_db_err)?;
                if locked.rows_affected == 0 {
                    return Err(AuthError::bad_request("Team not found"));
                }
                let maximum = maximum.maximum(team_id).await?;
                let existing = Entity::<O::TeamMember>::find()
                    .filter(O::TeamMember::column("team_id")?.eq(*team_id))
                    .filter(O::TeamMember::column("user_id")?.eq(user_id))
                    .one(&tx)
                    .await
                    .map_err(map_db_err)?;
                if existing.is_none() {
                    let count = Entity::<O::TeamMember>::find()
                        .filter(O::TeamMember::column("team_id")?.eq(*team_id))
                        .count(&tx)
                        .await
                        .map_err(map_db_err)?;
                    if !super::team_capacity::reserve::<O::Team, _>(
                        &tx,
                        team_id,
                        count,
                        maximum,
                        &config.team,
                    )
                    .await?
                    {
                        return Err(AuthError::forbidden("Team member limit reached"));
                    }
                    let _ = models::insert::<O::TeamMember, _>(
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
                }
            }
            let member = models::insert::<O::Member, _>(
                &tx,
                values([
                    ("id", json!(uuid::Uuid::new_v4().to_string())),
                    ("organization_id", json!(invitation.organization_id)),
                    ("user_id", json!(user_id)),
                    ("role", json!(invitation.role)),
                    ("created_at", json!(Utc::now())),
                ]),
                Default::default(),
                &config.member,
            )
            .await?;
            let Some(session_token) = session_token else {
                return Ok((member, None));
            };
            let session = <S::Session as SeaOrmSessionModel>::Entity::find()
                .filter(S::Session::token_column().eq(session_token))
                .one(&tx)
                .await
                .map_err(map_db_err)?
                .ok_or(AuthError::SessionNotFound)?;
            let mut active = session.into_active_model();
            let cookie_session = if let [team_id] = team_ids.as_slice() {
                S::Session::set_active_team_id(&mut active, Some((*team_id).to_owned()));
                self.apply_session_field_updates(&mut active)?;
                S::Session::set_updated_at(&mut active, Utc::now());
                let updated = active.update(&tx).await.map_err(map_db_err)?;
                active = updated.clone().into_active_model();
                Some(updated)
            } else {
                None
            };
            S::Session::set_active_organization_id(
                &mut active,
                Some(invitation.organization_id.typed()?.clone()),
            );
            self.apply_session_field_updates(&mut active)?;
            S::Session::set_updated_at(&mut active, Utc::now());
            let _ = active.update(&tx).await.map_err(map_db_err)?;
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

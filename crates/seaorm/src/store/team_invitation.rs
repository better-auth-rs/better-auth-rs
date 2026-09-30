use super::{
    SeaOrmStore,
    entities::{invitation, member, team, team_member},
    map_db_err,
};
use crate::schema::{AuthSchema, SeaOrmSessionModel};
use better_auth_core::{AuthError, AuthResult, Member};
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, PaginatorTrait, QueryFilter, Set,
    TransactionTrait, sea_query::Expr,
};

impl<S> SeaOrmStore<S>
where
    S: AuthSchema,
    S::Session: SeaOrmSessionModel,
{
    pub(super) async fn accept_team_invitation(
        &self,
        invitation_id: &str,
        user_id: &str,
        session_token: &str,
        maximum: Option<usize>,
    ) -> AuthResult<(Member, Option<S::Session>)> {
        let tx = self.connection().begin().await.map_err(map_db_err)?;
        let claimed = invitation::Entity::update_many()
            .col_expr(invitation::Column::Status, Expr::value("accepted"))
            .filter(invitation::Column::Id.eq(invitation_id))
            .filter(invitation::Column::Status.eq("pending"))
            .exec(&tx)
            .await
            .map_err(map_db_err)?;
        if claimed.rows_affected == 0 {
            return Err(AuthError::bad_request("Invitation not found"));
        }
        let invitation = invitation::Entity::find_by_id(invitation_id)
            .one(&tx)
            .await
            .map_err(map_db_err)?
            .ok_or_else(|| AuthError::bad_request("Invitation not found"))?;
        let team_ids: Vec<_> = invitation
            .team_id
            .as_deref()
            .unwrap_or("")
            .split(',')
            .filter(|id| !id.is_empty())
            .collect();
        for team_id in &team_ids {
            let locked = team::Entity::update_many()
                .col_expr(
                    team::Column::MemberCount,
                    Expr::col(team::Column::MemberCount),
                )
                .filter(team::Column::Id.eq(*team_id))
                .filter(team::Column::OrganizationId.eq(&invitation.organization_id))
                .exec(&tx)
                .await
                .map_err(map_db_err)?;
            if locked.rows_affected == 0 {
                return Err(AuthError::bad_request("Team not found"));
            }
            let existing = team_member::Entity::find()
                .filter(team_member::Column::TeamId.eq(*team_id))
                .filter(team_member::Column::UserId.eq(user_id))
                .one(&tx)
                .await
                .map_err(map_db_err)?;
            if existing.is_none() {
                let count = team_member::Entity::find()
                    .filter(team_member::Column::TeamId.eq(*team_id))
                    .count(&tx)
                    .await
                    .map_err(map_db_err)?;
                if maximum.is_some_and(|maximum| count >= maximum as u64) {
                    return Err(AuthError::forbidden("Team member limit reached"));
                }
                let _ = team_member::ActiveModel {
                    id: Set(uuid::Uuid::new_v4().to_string()),
                    team_id: Set((*team_id).to_owned()),
                    user_id: Set(user_id.to_owned()),
                    created_at: Set(Utc::now()),
                }
                .insert(&tx)
                .await
                .map_err(map_db_err)?;
                let _ = team::Entity::update_many()
                    .col_expr(team::Column::MemberCount, Expr::value((count + 1) as i64))
                    .filter(team::Column::Id.eq(*team_id))
                    .exec(&tx)
                    .await
                    .map_err(map_db_err)?;
            }
        }
        let member = member::ActiveModel {
            id: Set(uuid::Uuid::new_v4().to_string()),
            organization_id: Set(invitation.organization_id.clone()),
            user_id: Set(user_id.to_owned()),
            role: Set(invitation.role),
            created_at: Set(Utc::now()),
        }
        .insert(&tx)
        .await
        .map_err(map_db_err)?;
        let session = <S::Session as SeaOrmSessionModel>::Entity::find()
            .filter(S::Session::token_column().eq(session_token))
            .one(&tx)
            .await
            .map_err(map_db_err)?
            .ok_or(AuthError::SessionNotFound)?;
        let mut active = session.into_active_model();
        let cookie_session = if let [team_id] = team_ids.as_slice() {
            S::Session::set_active_team_id(&mut active, Some((*team_id).to_owned()));
            S::Session::set_updated_at(&mut active, Utc::now());
            let updated = active.update(&tx).await.map_err(map_db_err)?;
            active = updated.clone().into_active_model();
            Some(updated)
        } else {
            None
        };
        S::Session::set_active_organization_id(&mut active, Some(invitation.organization_id));
        S::Session::set_updated_at(&mut active, Utc::now());
        let _ = active.update(&tx).await.map_err(map_db_err)?;
        tx.commit().await.map_err(map_db_err)?;
        Ok((Member::from(&member), cookie_session))
    }
}

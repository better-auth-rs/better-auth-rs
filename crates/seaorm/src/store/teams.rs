use super::{
    SeaOrmStore,
    entities::{invitation, team, team_member},
    map_db_err,
};
use async_trait::async_trait;
use better_auth_core::{AuthError, AuthResult, CreateTeam, Team, TeamMember, store::TeamStore};
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, Set,
    TransactionTrait, sea_query::Expr,
};

#[async_trait]
impl<S: better_auth_core::AuthSchema> TeamStore for SeaOrmStore<S> {
    async fn create_team(&self, input: CreateTeam) -> AuthResult<Team> {
        team::ActiveModel {
            id: Set(uuid::Uuid::new_v4().to_string()),
            name: Set(input.name),
            organization_id: Set(input.organization_id),
            created_at: Set(Utc::now()),
            updated_at: Set(input.updated_at),
            member_count: Set(0),
        }
        .insert(self.connection())
        .await
        .map(Into::into)
        .map_err(map_db_err)
    }
    async fn get_team(&self, id: &str) -> AuthResult<Option<Team>> {
        team::Entity::find_by_id(id)
            .one(self.connection())
            .await
            .map(|row| row.map(Into::into))
            .map_err(map_db_err)
    }
    async fn update_team(&self, id: &str, name: &str) -> AuthResult<Team> {
        team::ActiveModel {
            id: Set(id.to_owned()),
            name: Set(name.to_owned()),
            ..Default::default()
        }
        .update(self.connection())
        .await
        .map(Into::into)
        .map_err(map_db_err)
    }
    async fn delete_team(&self, id: &str) -> AuthResult<()> {
        let tx = self.connection().begin().await.map_err(map_db_err)?;
        for row in invitation::Entity::find()
            .filter(invitation::Column::Status.eq("pending"))
            .filter(invitation::Column::TeamId.is_not_null())
            .all(&tx)
            .await
            .map_err(map_db_err)?
        {
            if let Some(ids) = row.team_id.as_ref() {
                let retained: Vec<_> = ids.split(',').filter(|team_id| *team_id != id).collect();
                if retained.len() != ids.split(',').count() {
                    let _ = invitation::ActiveModel {
                        id: Set(row.id),
                        team_id: Set((!retained.is_empty()).then(|| retained.join(","))),
                        ..Default::default()
                    }
                    .update(&tx)
                    .await
                    .map_err(map_db_err)?;
                }
            }
        }
        let _ = team_member::Entity::delete_many()
            .filter(team_member::Column::TeamId.eq(id))
            .exec(&tx)
            .await
            .map_err(map_db_err)?;
        let _ = team::Entity::delete_by_id(id)
            .exec(&tx)
            .await
            .map_err(map_db_err)?;
        tx.commit().await.map_err(map_db_err)
    }
    async fn list_organization_teams(&self, organization_id: &str) -> AuthResult<Vec<Team>> {
        team::Entity::find()
            .filter(team::Column::OrganizationId.eq(organization_id))
            .order_by_asc(team::Column::CreatedAt)
            .all(self.connection())
            .await
            .map(|rows| rows.into_iter().map(Into::into).collect())
            .map_err(map_db_err)
    }
    async fn list_user_teams(&self, user_id: &str) -> AuthResult<Vec<Team>> {
        let ids: Vec<_> = team_member::Entity::find()
            .filter(team_member::Column::UserId.eq(user_id))
            .all(self.connection())
            .await
            .map_err(map_db_err)?
            .into_iter()
            .map(|row| row.team_id)
            .collect();
        team::Entity::find()
            .filter(team::Column::Id.is_in(ids))
            .order_by_asc(team::Column::CreatedAt)
            .all(self.connection())
            .await
            .map(|rows| rows.into_iter().map(Into::into).collect())
            .map_err(map_db_err)
    }
    async fn get_team_member(
        &self,
        team_id: &str,
        user_id: &str,
    ) -> AuthResult<Option<TeamMember>> {
        team_member::Entity::find()
            .filter(team_member::Column::TeamId.eq(team_id))
            .filter(team_member::Column::UserId.eq(user_id))
            .one(self.connection())
            .await
            .map(|row| row.map(Into::into))
            .map_err(map_db_err)
    }
    async fn list_team_members(&self, team_id: &str) -> AuthResult<Vec<TeamMember>> {
        team_member::Entity::find()
            .filter(team_member::Column::TeamId.eq(team_id))
            .order_by_asc(team_member::Column::CreatedAt)
            .all(self.connection())
            .await
            .map(|rows| rows.into_iter().map(Into::into).collect())
            .map_err(map_db_err)
    }
    async fn add_team_member(
        &self,
        team_id: &str,
        user_id: &str,
        maximum: Option<usize>,
    ) -> AuthResult<Option<TeamMember>> {
        let tx = self.connection().begin().await.map_err(map_db_err)?;
        // Lock the aggregate before reading membership or capacity, including on SQLite.
        let locked = team::Entity::update_many()
            .col_expr(
                team::Column::MemberCount,
                Expr::col(team::Column::MemberCount),
            )
            .filter(team::Column::Id.eq(team_id))
            .exec(&tx)
            .await
            .map_err(map_db_err)?;
        if locked.rows_affected == 0 {
            return Err(AuthError::not_found("Team not found"));
        }
        if let Some(member) = team_member::Entity::find()
            .filter(team_member::Column::TeamId.eq(team_id))
            .filter(team_member::Column::UserId.eq(user_id))
            .one(&tx)
            .await
            .map_err(map_db_err)?
        {
            tx.commit().await.map_err(map_db_err)?;
            return Ok(Some(member.into()));
        }
        let count = team_member::Entity::find()
            .filter(team_member::Column::TeamId.eq(team_id))
            .count(&tx)
            .await
            .map_err(map_db_err)?;
        if maximum.is_some_and(|limit| count >= limit as u64) {
            tx.rollback().await.map_err(map_db_err)?;
            return Ok(None);
        }
        let member = team_member::ActiveModel {
            id: Set(uuid::Uuid::new_v4().to_string()),
            team_id: Set(team_id.to_owned()),
            user_id: Set(user_id.to_owned()),
            created_at: Set(Utc::now()),
        }
        .insert(&tx)
        .await
        .map_err(map_db_err)?;
        let _ = team::Entity::update_many()
            .col_expr(team::Column::MemberCount, Expr::value((count + 1) as i64))
            .filter(team::Column::Id.eq(team_id))
            .exec(&tx)
            .await
            .map_err(map_db_err)?;
        tx.commit().await.map_err(map_db_err)?;
        Ok(Some(member.into()))
    }
    async fn remove_team_member(&self, team_id: &str, user_id: &str) -> AuthResult<()> {
        let tx = self.connection().begin().await.map_err(map_db_err)?;
        let _ = team::Entity::update_many()
            .col_expr(
                team::Column::MemberCount,
                Expr::col(team::Column::MemberCount),
            )
            .filter(team::Column::Id.eq(team_id))
            .exec(&tx)
            .await
            .map_err(map_db_err)?;
        let _ = team_member::Entity::delete_many()
            .filter(team_member::Column::TeamId.eq(team_id))
            .filter(team_member::Column::UserId.eq(user_id))
            .exec(&tx)
            .await
            .map_err(map_db_err)?;
        let count = team_member::Entity::find()
            .filter(team_member::Column::TeamId.eq(team_id))
            .count(&tx)
            .await
            .map_err(map_db_err)?;
        let _ = team::Entity::update_many()
            .col_expr(team::Column::MemberCount, Expr::value(count as i64))
            .filter(team::Column::Id.eq(team_id))
            .exec(&tx)
            .await
            .map_err(map_db_err)?;
        tx.commit().await.map_err(map_db_err)
    }
}

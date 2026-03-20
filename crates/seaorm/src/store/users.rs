use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait,
    IntoActiveModel, QueryFilter, QueryOrder, QuerySelect,
};

use better_auth_core::store::UserStore;

use crate::error::{AuthError, AuthResult};
use crate::schema::{AuthSchema, SeaOrmUserModel};
use crate::types::{CreateUser, ListUsersParams, UpdateUser};
use crate::utils::email::{normalize_optional_user_email, normalize_user_email};

use super::{SeaOrmStore, cancelled_by_hook, map_db_err};

impl<S> SeaOrmStore<S>
where
    S: AuthSchema,
    S::User: SeaOrmUserModel,
{
    async fn create_user_with_connection<C>(
        &self,
        db: &C,
        tx: Option<&DatabaseTransaction>,
        mut create_user: CreateUser,
    ) -> AuthResult<S::User>
    where
        C: ConnectionTrait,
    {
        create_user.email = normalize_optional_user_email(create_user.email);
        let hook_context = self.hook_context(tx);
        for hook in self.hooks() {
            if hook
                .before_create_user(&mut create_user, &hook_context)
                .await?
                .is_cancelled()
            {
                return Err(cancelled_by_hook("user creation"));
            }
        }
        let now = Utc::now();
        let user_id = create_user
            .id
            .as_deref()
            .map(S::User::parse_id)
            .transpose()?;
        let model = S::User::new_active(user_id, create_user, now);

        let user = model.insert(db).await.map_err(map_db_err)?;
        for hook in self.hooks() {
            hook.after_create_user(&user, &hook_context).await?;
        }
        Ok(user)
    }

    pub(crate) async fn create_user_in_tx(
        &self,
        tx: &DatabaseTransaction,
        create_user: CreateUser,
    ) -> AuthResult<S::User> {
        self.create_user_with_connection(tx, Some(tx), create_user)
            .await
    }
}

#[async_trait]
impl<S> UserStore<S> for SeaOrmStore<S>
where
    S: AuthSchema + Send + Sync,
    S::User: SeaOrmUserModel,
{
    async fn create_user(&self, create_user: CreateUser) -> AuthResult<S::User> {
        self.create_user_with_connection(self.connection(), None, create_user)
            .await
    }

    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<S::User>> {
        let user_id = S::User::parse_id(id)?;
        <S::User as SeaOrmUserModel>::Entity::find()
            .filter(<S::User as SeaOrmUserModel>::id_column().eq(user_id))
            .one(self.connection())
            .await
            .map_err(map_db_err)
    }

    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<S::User>> {
        let email = normalize_user_email(email);
        <S::User as SeaOrmUserModel>::Entity::find()
            .filter(<S::User as SeaOrmUserModel>::email_column().eq(email))
            .one(self.connection())
            .await
            .map_err(map_db_err)
    }

    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<S::User>> {
        <S::User as SeaOrmUserModel>::Entity::find()
            .filter(<S::User as SeaOrmUserModel>::username_column().eq(username))
            .one(self.connection())
            .await
            .map_err(map_db_err)
    }

    async fn update_user(&self, id: &str, mut update: UpdateUser) -> AuthResult<S::User> {
        update.email = normalize_optional_user_email(update.email);
        let user_id = S::User::parse_id(id)?;
        let hook_context = self.hook_context(None);
        for hook in self.hooks() {
            if hook
                .before_update_user(id, &mut update, &hook_context)
                .await?
                .is_cancelled()
            {
                return Err(cancelled_by_hook("user update"));
            }
        }
        let Some(model) = <S::User as SeaOrmUserModel>::Entity::find()
            .filter(<S::User as SeaOrmUserModel>::id_column().eq(user_id))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(AuthError::UserNotFound);
        };

        let mut active = model.into_active_model();
        S::User::apply_update(&mut active, update, Utc::now());

        let user = active.update(self.connection()).await.map_err(map_db_err)?;
        for hook in self.hooks() {
            hook.after_update_user(&user, &hook_context).await?;
        }
        Ok(user)
    }

    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        let user_id = S::User::parse_id(id)?;
        let Some(user) = self.get_user_by_id(id).await? else {
            return Err(AuthError::UserNotFound);
        };
        let hook_context = self.hook_context(None);
        for hook in self.hooks() {
            if hook
                .before_delete_user(&user, &hook_context)
                .await?
                .is_cancelled()
            {
                return Err(cancelled_by_hook("user deletion"));
            }
        }
        let _ = <S::User as SeaOrmUserModel>::Entity::delete_many()
            .filter(<S::User as SeaOrmUserModel>::id_column().eq(user_id))
            .exec(self.connection())
            .await
            .map_err(map_db_err)?;
        for hook in self.hooks() {
            hook.after_delete_user(&user, &hook_context).await?;
        }
        Ok(())
    }

    async fn list_users(&self, params: ListUsersParams) -> AuthResult<(Vec<S::User>, usize)> {
        let limit = params.limit.unwrap_or(100);
        let offset = params.offset.unwrap_or(0);
        let mut count_query = <S::User as SeaOrmUserModel>::Entity::find();
        let mut query = <S::User as SeaOrmUserModel>::Entity::find();

        if let (Some(field), Some(value)) = (
            params.search_field.as_deref(),
            params.search_value.as_deref(),
        ) {
            let predicate = match field {
                "email" => <S::User as SeaOrmUserModel>::email_column().contains(value),
                "name" => <S::User as SeaOrmUserModel>::name_column().contains(value),
                "username" => <S::User as SeaOrmUserModel>::username_column().contains(value),
                _ => <S::User as SeaOrmUserModel>::email_column().contains(value),
            };
            count_query = count_query.filter(predicate.clone());
            query = query.filter(predicate);
        }

        let total = count_query
            .all(self.connection())
            .await
            .map_err(map_db_err)?
            .len();
        let query = match (params.sort_by.as_deref(), params.sort_direction.as_deref()) {
            (Some("email"), Some("asc")) => {
                query.order_by_asc(<S::User as SeaOrmUserModel>::email_column())
            }
            (Some("email"), _) => query.order_by_desc(<S::User as SeaOrmUserModel>::email_column()),
            (Some("name"), Some("asc")) => {
                query.order_by_asc(<S::User as SeaOrmUserModel>::name_column())
            }
            (Some("name"), _) => query.order_by_desc(<S::User as SeaOrmUserModel>::name_column()),
            (Some("username"), Some("asc")) => {
                query.order_by_asc(<S::User as SeaOrmUserModel>::username_column())
            }
            (Some("username"), _) => {
                query.order_by_desc(<S::User as SeaOrmUserModel>::username_column())
            }
            (_, Some("asc")) => {
                query.order_by_asc(<S::User as SeaOrmUserModel>::created_at_column())
            }
            _ => query.order_by_desc(<S::User as SeaOrmUserModel>::created_at_column()),
        };
        let models = query
            .offset(offset as u64)
            .limit(limit as u64)
            .all(self.connection())
            .await
            .map_err(map_db_err)?;

        Ok((models, total))
    }
}

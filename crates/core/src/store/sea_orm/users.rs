use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait,
    IntoActiveModel, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, Set,
};
use uuid::Uuid;

use crate::error::{AuthError, AuthResult};
use crate::types::{CreateUser, ListUsersParams, UpdateUser, User};
use crate::utils::email::{normalize_optional_user_email, normalize_user_email};

use super::entities::user::{ActiveModel, Column, Entity};
use super::{AuthStore, cancelled_by_hook, map_db_err};

impl AuthStore {
    async fn create_user_with_connection<C>(
        &self,
        db: &C,
        tx: Option<&DatabaseTransaction>,
        mut create_user: CreateUser,
    ) -> AuthResult<User>
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
        let model = ActiveModel {
            id: Set(create_user.id.unwrap_or_else(|| Uuid::new_v4().to_string())),
            email: Set(create_user.email),
            name: Set(create_user.name),
            image: Set(create_user.image),
            email_verified: Set(create_user.email_verified.unwrap_or(false)),
            username: Set(create_user.username),
            display_username: Set(create_user.display_username),
            two_factor_enabled: Set(false),
            role: Set(create_user.role),
            banned: Set(false),
            ban_reason: Set(None),
            ban_expires: Set(None),
            metadata: Set(create_user.metadata.unwrap_or(serde_json::json!({}))),
            created_at: Set(now),
            updated_at: Set(now),
        };

        let user = model.insert(db).await.map(User::from).map_err(map_db_err)?;
        for hook in self.hooks() {
            hook.after_create_user(&user, &hook_context).await?;
        }
        Ok(user)
    }

    pub async fn create_user(&self, create_user: CreateUser) -> AuthResult<User> {
        self.create_user_with_connection(self.connection(), None, create_user)
            .await
    }

    /// Create a user inside an existing transaction.
    #[doc(hidden)]
    pub async fn create_user_in_tx(
        &self,
        tx: &DatabaseTransaction,
        create_user: CreateUser,
    ) -> AuthResult<User> {
        self.create_user_with_connection(tx, Some(tx), create_user)
            .await
    }

    pub async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<User>> {
        Entity::find_by_id(id.to_owned())
            .one(self.connection())
            .await
            .map(|model| model.map(User::from))
            .map_err(map_db_err)
    }

    pub async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<User>> {
        let email = normalize_user_email(email);
        Entity::find()
            .filter(Column::Email.eq(email))
            .one(self.connection())
            .await
            .map(|model| model.map(User::from))
            .map_err(map_db_err)
    }

    pub async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<User>> {
        Entity::find()
            .filter(Column::Username.eq(username))
            .one(self.connection())
            .await
            .map(|model| model.map(User::from))
            .map_err(map_db_err)
    }

    pub async fn update_user(&self, id: &str, mut update: UpdateUser) -> AuthResult<User> {
        update.email = normalize_optional_user_email(update.email);
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
        let Some(model) = Entity::find_by_id(id.to_owned())
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(AuthError::UserNotFound);
        };

        let mut active = model.into_active_model();
        if let Some(email) = update.email {
            active.email = Set(Some(email));
        }
        if let Some(name) = update.name {
            active.name = Set(Some(name));
        }
        if let Some(image) = update.image {
            active.image = Set(Some(image));
        }
        if let Some(email_verified) = update.email_verified {
            active.email_verified = Set(email_verified);
        }
        if let Some(username) = update.username {
            active.username = Set(Some(username));
        }
        if let Some(display_username) = update.display_username {
            active.display_username = Set(Some(display_username));
        }
        if let Some(role) = update.role {
            active.role = Set(Some(role));
        }
        if let Some(two_factor_enabled) = update.two_factor_enabled {
            active.two_factor_enabled = Set(two_factor_enabled);
        }
        if let Some(metadata) = update.metadata {
            active.metadata = Set(metadata);
        }
        if let Some(banned) = update.banned {
            active.banned = Set(banned);
            if !banned {
                active.ban_reason = Set(None);
                active.ban_expires = Set(None);
            }
        }
        if update.banned != Some(false) {
            if let Some(ban_reason) = update.ban_reason {
                active.ban_reason = Set(Some(ban_reason));
            }
            if let Some(ban_expires) = update.ban_expires {
                active.ban_expires = Set(Some(ban_expires));
            }
        }
        active.updated_at = Set(Utc::now());

        let user = active
            .update(self.connection())
            .await
            .map(User::from)
            .map_err(map_db_err)?;
        for hook in self.hooks() {
            hook.after_update_user(&user, &hook_context).await?;
        }
        Ok(user)
    }

    pub async fn delete_user(&self, id: &str) -> AuthResult<()> {
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
        let _ = Entity::delete_by_id(id.to_owned())
            .exec(self.connection())
            .await
            .map_err(map_db_err)?;
        for hook in self.hooks() {
            hook.after_delete_user(&user, &hook_context).await?;
        }
        Ok(())
    }

    pub async fn list_users(&self, params: ListUsersParams) -> AuthResult<(Vec<User>, usize)> {
        let limit = params.limit.unwrap_or(100);
        let offset = params.offset.unwrap_or(0);
        let mut count_query = Entity::find();
        let mut query = Entity::find();

        if let (Some(field), Some(value)) = (
            params.search_field.as_deref(),
            params.search_value.as_deref(),
        ) {
            let predicate = match field {
                "email" => Column::Email.contains(value),
                "name" => Column::Name.contains(value),
                "username" => Column::Username.contains(value),
                _ => Column::Email.contains(value),
            };
            count_query = count_query.filter(predicate.clone());
            query = query.filter(predicate);
        }

        let total = count_query
            .count(self.connection())
            .await
            .map_err(map_db_err)? as usize;
        let query = match (params.sort_by.as_deref(), params.sort_direction.as_deref()) {
            (Some("email"), Some("asc")) => query.order_by_asc(Column::Email),
            (Some("email"), _) => query.order_by_desc(Column::Email),
            (Some("name"), Some("asc")) => query.order_by_asc(Column::Name),
            (Some("name"), _) => query.order_by_desc(Column::Name),
            (Some("username"), Some("asc")) => query.order_by_asc(Column::Username),
            (Some("username"), _) => query.order_by_desc(Column::Username),
            (_, Some("asc")) => query.order_by_asc(Column::CreatedAt),
            _ => query.order_by_desc(Column::CreatedAt),
        };
        let models = query
            .offset(offset as u64)
            .limit(limit as u64)
            .all(self.connection())
            .await
            .map_err(map_db_err)?;

        Ok((models.into_iter().map(User::from).collect(), total))
    }
}

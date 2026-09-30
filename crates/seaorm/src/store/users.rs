use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait,
    IntoActiveModel, QueryFilter,
};

use better_auth_core::store::UserStore;

use crate::error::{AuthError, AuthResult};
use crate::schema::{AuthSchema, SeaOrmUserModel};
use crate::types::{CreateUser, ListUsersParams, UpdateUser};
use crate::utils::email::{normalize_optional_user_email, normalize_user_email};

use super::{SeaOrmStore, cancelled_by_hook, map_db_err};

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SeaOrmStore<S, O, P>
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
        if let Some(username) = create_user.username.as_mut() {
            *username = username.to_lowercase();
        }
        let now = Utc::now();
        let user_id = create_user
            .id
            .as_deref()
            .map(S::User::parse_id)
            .transpose()?;
        let fields = self.config().user.storage_fields_for_adapter(
            std::mem::take(&mut create_user.additional_fields),
            true,
            db.get_database_backend() == sea_orm::DbBackend::Postgres,
            S::User::native_json_field,
        )?;
        let mut model = S::User::new_active(user_id, create_user, now);
        S::User::apply_fields(&mut model, fields)?;

        let user = model.insert(db).await.map_err(map_db_err)?;
        for hook in self.hooks() {
            hook.after_create_user(&user, &hook_context).await?;
        }
        Ok(user)
    }

    pub(super) async fn update_user_with_connection(
        &self,
        db: &impl ConnectionTrait,
        tx: Option<&DatabaseTransaction>,
        id: &str,
        mut update: UpdateUser,
    ) -> AuthResult<S::User> {
        update.email = normalize_optional_user_email(update.email);
        if update.phone_number == Some(None) {
            update.phone_number_verified = Some(false);
        }
        let user_id = S::User::parse_id(id)?;
        let hook_context = self.hook_context(tx);
        for hook in self.hooks() {
            if hook
                .before_update_user(id, &mut update, &hook_context)
                .await?
                .is_cancelled()
            {
                return Err(cancelled_by_hook("user update"));
            }
        }
        if let Some(username) = update.username.as_mut() {
            *username = username.to_lowercase();
        }
        let Some(model) = <S::User as SeaOrmUserModel>::Entity::find()
            .filter(<S::User as SeaOrmUserModel>::id_column().eq(user_id))
            .one(db)
            .await
            .map_err(map_db_err)?
        else {
            return Err(AuthError::UserNotFound);
        };

        let mut active = model.into_active_model();
        let fields = self.config().user.storage_fields_for_adapter(
            std::mem::take(&mut update.additional_fields),
            false,
            db.get_database_backend() == sea_orm::DbBackend::Postgres,
            S::User::native_json_field,
        )?;
        S::User::apply_update(&mut active, update, Utc::now());
        S::User::apply_fields(&mut active, fields)?;

        let user = active.update(db).await.map_err(map_db_err)?;
        for hook in self.hooks() {
            hook.after_update_user(&user, &hook_context).await?;
        }
        Ok(user)
    }
    pub(super) async fn delete_user_with_connection(
        &self,
        db: &impl ConnectionTrait,
        tx: Option<&DatabaseTransaction>,
        id: &str,
    ) -> AuthResult<()> {
        let user_id = S::User::parse_id(id)?;
        let Some(user) = <S::User as SeaOrmUserModel>::Entity::find()
            .filter(<S::User as SeaOrmUserModel>::id_column().eq(user_id.clone()))
            .one(db)
            .await
            .map_err(map_db_err)?
        else {
            return Err(AuthError::UserNotFound);
        };
        let hook_context = self.hook_context(tx);
        for hook in self.hooks() {
            if hook
                .before_delete_user(&user, &hook_context)
                .await?
                .is_cancelled()
            {
                return Err(cancelled_by_hook("user deletion"));
            }
        }
        // API keys reference their owner polymorphically, so they carry no
        // foreign key to cascade from. Without this, a deleted user's keys
        // would outlive them and start working again if the id were reused.
        let _ = <P::ApiKey as crate::SeaOrmPluginModel>::Entity::delete_many()
            .filter(<P::ApiKey as crate::SeaOrmPluginModel>::column("reference_id")?.eq(id))
            .exec(db)
            .await
            .map_err(map_db_err)?;

        let _ = <S::User as SeaOrmUserModel>::Entity::delete_many()
            .filter(<S::User as SeaOrmUserModel>::id_column().eq(user_id))
            .exec(db)
            .await
            .map_err(map_db_err)?;
        for hook in self.hooks() {
            hook.after_delete_user(&user, &hook_context).await?;
        }
        Ok(())
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
impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> UserStore<S>
    for SeaOrmStore<S, O, P>
where
    S: AuthSchema + Send + Sync,
    S::User: SeaOrmUserModel,
    S::Account: crate::schema::SeaOrmAccountModel,
    S::Session: crate::schema::SeaOrmSessionModel,
{
    fn supports_native_json(&self) -> bool {
        self.connection().get_database_backend() == sea_orm::DbBackend::Postgres
    }

    async fn verify_user_with_cleanup(
        &self,
        user_id: &str,
        cleanup: better_auth_core::store::VerificationCleanup,
        sessions: Option<&dyn better_auth_core::store::VerificationSessionCleanup>,
    ) -> AuthResult<Option<S::User>> {
        self.verify_unproven_user(
            user_id,
            matches!(
                cleanup,
                better_auth_core::store::VerificationCleanup::AccountsAndSessions
            ),
            sessions,
        )
        .await
    }

    async fn verify_user_and_revoke_unproven_access(
        &self,
        user_id: &str,
    ) -> AuthResult<Option<S::User>> {
        self.verify_unproven_user(user_id, true, None).await
    }
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

    async fn get_user_by_id_value(&self, id: &serde_json::Value) -> AuthResult<Option<S::User>> {
        if let Some(id) = id.as_str() {
            return self.get_user_by_id(id).await;
        }
        <S::User as SeaOrmUserModel>::Entity::find()
            .filter(super::value_filter::equals(
                <S::User as SeaOrmUserModel>::id_column(),
                id,
            ))
            .one(self.connection())
            .await
            .map_err(map_db_err)
    }

    async fn list_users_by_ids(&self, ids: &[String]) -> AuthResult<Vec<S::User>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }

        let user_ids = ids
            .iter()
            .map(|id| S::User::parse_id(id))
            .collect::<AuthResult<Vec<_>>>()?;

        <S::User as SeaOrmUserModel>::Entity::find()
            .filter(<S::User as SeaOrmUserModel>::id_column().is_in(user_ids))
            .all(self.connection())
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
        let Some(col) = <S::User as SeaOrmUserModel>::username_column() else {
            return Ok(None);
        };
        <S::User as SeaOrmUserModel>::Entity::find()
            .filter(col.eq(username.to_lowercase()))
            .one(self.connection())
            .await
            .map_err(map_db_err)
    }

    async fn get_user_by_phone_number(&self, phone_number: &str) -> AuthResult<Option<S::User>> {
        let column = S::User::phone_number_column()
            .ok_or_else(|| AuthError::config("The user entity requires phone_number"))?;
        <S::User as SeaOrmUserModel>::Entity::find()
            .filter(column.eq(phone_number))
            .one(self.connection())
            .await
            .map_err(map_db_err)
    }

    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<S::User> {
        self.update_user_with_connection(self.connection(), None, id, update)
            .await
    }

    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        self.delete_user_with_connection(self.connection(), None, id)
            .await
    }

    async fn list_users(&self, params: ListUsersParams) -> AuthResult<(Vec<S::User>, usize)> {
        let models = <S::User as SeaOrmUserModel>::Entity::find()
            .all(self.connection())
            .await
            .map_err(map_db_err)?;

        Ok(better_auth_core::user_query::apply_list_users(
            models, &params,
        ))
    }
}

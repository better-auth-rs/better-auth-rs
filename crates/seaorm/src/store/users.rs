use super::instrumentation::database_operation;
use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, IntoActiveModel, QueryFilter,
    QuerySelect,
};

use better_auth_core::store::UserStore;

use crate::error::{AuthError, AuthResult};
use crate::hooks::DatabaseHookUpdate;
use crate::schema::{AuthSchema, SeaOrmUserModel};
use crate::types::{CreateUser, ListUsersParams, UpdateUser};
use crate::utils::email::{normalize_optional_user_email, normalize_user_email};

use super::{SeaOrmStore, cancelled_by_hook, map_db_err};

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S: AuthSchema,
    S::User: SeaOrmUserModel,
{
    pub(super) fn output_user(
        &self,
        row: &S::User,
        db: &impl ConnectionTrait,
    ) -> AuthResult<better_auth_core::wire::UserView> {
        use better_auth_core::AuthUser;
        let mut output = better_auth_core::wire::UserView::with_internal_fields_for_adapter(
            row,
            &self.config().user,
            &Default::default(),
            db.get_database_backend() == sea_orm::DbBackend::Postgres,
        )?;
        output.visible_fields = row.field_presence().cloned();
        Ok(output)
    }

    pub(super) async fn find_user_by_username(
        &self,
        db: &impl ConnectionTrait,
        username: &str,
    ) -> AuthResult<Option<better_auth_core::wire::UserView>> {
        let Some(column) = S::User::username_column() else {
            return Ok(None);
        };
        database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
            self.config(),
            "findOne",
            async {
                <S::User as SeaOrmUserModel>::Entity::find()
                    .filter(column.eq(username))
                    .one(db)
                    .await
                    .map_err(map_db_err)
            },
        )
        .await?
        .as_ref()
        .map(|row| self.output_user(row, db))
        .transpose()
    }

    pub(crate) async fn create_user_with_connection<C>(
        &self,
        db: &C,
        tx: Option<super::HookTransaction<'_, S>>,
        mut create_user: CreateUser,
    ) -> AuthResult<Option<better_auth_core::wire::UserView>>
    where
        C: ConnectionTrait,
    {
        create_user.prepare_user_fields(&self.config().user)?;
        create_user.email = normalize_optional_user_email(create_user.email);
        let hook_context = self.hook_context(tx);
        for hook in self.hooks() {
            if better_auth_core::observability::database::with_database_hook(
                hook_context.config,
                hook.hook_metadata(),
                better_auth_core::observability::database::DatabaseHook::BeforeCreateUser,
                hook.before_create_user(&mut create_user, &hook_context),
            )
            .await?
            .is_cancelled()
            {
                return Ok(None);
            }
            create_user.prepare_user_fields(&self.config().user)?;
        }
        let now = Utc::now();
        let generated_id = self.generated_id("user", create_user.id.take())?;
        let user_id = generated_id.as_deref().map(S::User::parse_id).transpose()?;
        let fields = self.config().user.storage_fields_for_adapter(
            create_user.take_user_field_input(&self.config().user),
            true,
            db.get_database_backend() == sea_orm::DbBackend::Postgres,
            S::User::native_json_field,
        )?;
        let created_at = create_user.created_at;
        let updated_at = create_user.updated_at;
        let mut model = S::User::new_active(user_id, create_user, now);
        if let Some(value) = created_at {
            model.set(S::User::created_at_column(), value.into());
        }
        if let Some(value) = updated_at {
            model.set(S::User::field_column("updatedAt")?, value.into());
        }
        if generated_id.is_none() {
            model.not_set(S::User::id_column());
        }
        S::User::apply_fields(&mut model, fields)?;
        crate::reference_id::apply_bindings(
            &mut model,
            &self.config().user,
            db.get_database_backend(),
            S::User::field_column,
        )?;

        let user = database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
            self.config(),
            "create",
            async { model.insert(db).await.map_err(map_db_err) },
        )
        .await?;
        let user = self.output_user(&user, db)?;
        if tx.is_none() {
            for hook in self.hooks() {
                better_auth_core::observability::database::with_database_hook(
                    hook_context.config,
                    hook.hook_metadata(),
                    better_auth_core::observability::database::DatabaseHook::AfterCreateUser,
                    hook.after_create_user(&user, &hook_context),
                )
                .await?;
            }
        }
        Ok(Some(user))
    }

    pub(super) async fn update_user_with_connection(
        &self,
        db: &impl ConnectionTrait,
        tx: Option<super::HookTransaction<'_, S>>,
        id: &str,
        update: UpdateUser,
    ) -> AuthResult<better_auth_core::UserView> {
        match self
            .update_user_outcome_with_connection(db, tx, id, update)
            .await?
        {
            std::ops::ControlFlow::Break(()) => Err(cancelled_by_hook("user update")),
            std::ops::ControlFlow::Continue(user) => user.ok_or(AuthError::UserNotFound),
        }
    }

    pub(super) async fn update_user_outcome_with_connection(
        &self,
        db: &impl ConnectionTrait,
        tx: Option<super::HookTransaction<'_, S>>,
        id: &str,
        mut update: UpdateUser,
    ) -> AuthResult<std::ops::ControlFlow<(), Option<better_auth_core::UserView>>> {
        update.prepare_user_fields(&self.config().user)?;
        update.email = normalize_optional_user_email(update.email);
        if update.phone_number == Some(None) {
            update.phone_number_verified = Some(false);
        }
        let user_id = S::User::parse_id(id)?;
        let hook_context = self.hook_context(tx);
        let original = update.clone();
        for hook in self.hooks() {
            match better_auth_core::observability::database::with_database_hook(
                hook_context.config,
                hook.hook_metadata(),
                better_auth_core::observability::database::DatabaseHook::BeforeUpdateUser,
                hook.before_update_user(id, &original, &hook_context),
            )
            .await?
            {
                DatabaseHookUpdate::Continue => {}
                DatabaseHookUpdate::Cancel => return Ok(std::ops::ControlFlow::Break(())),
                DatabaseHookUpdate::Patch(mut patch) => {
                    patch.prepare_user_fields(&self.config().user)?;
                    update.merge(patch);
                }
            }
        }
        let fields = self.config().user.storage_fields_for_adapter(
            update.take_user_field_input(&self.config().user),
            false,
            db.get_database_backend() == sea_orm::DbBackend::Postgres,
            S::User::native_json_field,
        )?;
        let user = database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
            self.config(),
            "update",
            async {
                let Some(model) = <S::User as SeaOrmUserModel>::Entity::find()
                    .filter(<S::User as SeaOrmUserModel>::id_column().eq(user_id))
                    .one(db)
                    .await
                    .map_err(map_db_err)?
                else {
                    return Ok(None);
                };
                let mut active = model.into_active_model();
                S::User::apply_update(&mut active, update, Utc::now());
                S::User::apply_fields(&mut active, fields)?;
                crate::reference_id::apply_bindings(
                    &mut active,
                    &self.config().user,
                    db.get_database_backend(),
                    S::User::field_column,
                )?;

                active.update(db).await.map(Some).map_err(map_db_err)
            },
        )
        .await?;
        let Some(user) = user else {
            let store = self.clone();
            let request = hook_context.request.clone();
            super::transaction_hooks::after_write(
                tx,
                Box::pin(async move {
                    let mut context = store.hook_context(None);
                    context.request = request;
                    for hook in store.hooks() {
                        better_auth_core::observability::database::with_database_hook(context.config, hook.hook_metadata(), better_auth_core::observability::database::DatabaseHook::AfterUpdateUser, hook.after_update_user(None, &context)).await?;
                    }
                    Ok(())
                }),
            )
            .await?;
            return Ok(std::ops::ControlFlow::Continue(None));
        };

        let user = self.output_user(&user, db)?;
        if tx.is_none() {
            for hook in self.hooks() {
                better_auth_core::observability::database::with_database_hook(
                    hook_context.config,
                    hook.hook_metadata(),
                    better_auth_core::observability::database::DatabaseHook::AfterUpdateUser,
                    hook.after_update_user(Some(&user), &hook_context),
                )
                .await?;
            }
        }
        Ok(std::ops::ControlFlow::Continue(Some(user)))
    }

    pub(crate) async fn create_user_in_tx(
        &self,
        tx: super::HookTransaction<'_, S>,
        create_user: CreateUser,
    ) -> AuthResult<better_auth_core::wire::UserView> {
        self.create_user_with_connection(tx.0, Some(tx), create_user)
            .await?
            .ok_or_else(|| cancelled_by_hook("user creation"))
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
    S::Verification: crate::schema::SeaOrmVerificationModel,
{
    fn supports_native_json(&self) -> bool {
        self.connection().get_database_backend() == sea_orm::DbBackend::Postgres
    }

    async fn verify_user_with_cleanup(
        &self,
        user_id: &str,
        cleanup: better_auth_core::store::VerificationCleanup,
        sessions: Option<&dyn better_auth_core::store::VerificationSessionCleanup>,
    ) -> AuthResult<Option<better_auth_core::wire::UserView>> {
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
    ) -> AuthResult<Option<better_auth_core::wire::UserView>> {
        self.verify_unproven_user(user_id, true, None).await
    }
    async fn create_user(
        &self,
        create_user: CreateUser,
    ) -> AuthResult<better_auth_core::wire::UserView> {
        self.create_user_optional(create_user)
            .await?
            .ok_or_else(|| cancelled_by_hook("user creation"))
    }

    async fn create_user_optional(
        &self,
        create_user: CreateUser,
    ) -> AuthResult<Option<better_auth_core::wire::UserView>> {
        self.create_user_with_connection(self.connection(), None, create_user)
            .await
    }

    async fn get_user_by_id(
        &self,
        id: &str,
    ) -> AuthResult<Option<better_auth_core::wire::UserView>> {
        let user_id = S::User::parse_id(id)?;
        database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
            self.config(),
            "findOne",
            async {
                <S::User as SeaOrmUserModel>::Entity::find()
                    .filter(<S::User as SeaOrmUserModel>::id_column().eq(user_id))
                    .one(self.connection())
                    .await
                    .map_err(map_db_err)
            },
        )
        .await?
        .as_ref()
        .map(|row| self.output_user(row, self.connection()))
        .transpose()
    }

    async fn get_user_by_id_value(
        &self,
        id: &serde_json::Value,
    ) -> AuthResult<Option<better_auth_core::wire::UserView>> {
        if let Some(id) = id.as_str() {
            return self.get_user_by_id(id).await;
        }
        database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
            self.config(),
            "findOne",
            async {
                <S::User as SeaOrmUserModel>::Entity::find()
                    .filter(super::value_filter::equals(
                        <S::User as SeaOrmUserModel>::id_column(),
                        id,
                    ))
                    .one(self.connection())
                    .await
                    .map_err(map_db_err)
            },
        )
        .await?
        .as_ref()
        .map(|row| self.output_user(row, self.connection()))
        .transpose()
    }

    async fn list_users_by_ids(
        &self,
        ids: &[String],
        limit: f64,
    ) -> AuthResult<Vec<better_auth_core::wire::UserView>> {
        let user_ids = ids
            .iter()
            .map(|id| S::User::parse_id(id))
            .collect::<AuthResult<Vec<_>>>()?;

        database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
            self.config(),
            "findMany",
            async {
                <S::User as SeaOrmUserModel>::Entity::find()
                    .filter(<S::User as SeaOrmUserModel>::id_column().is_in(user_ids))
                    .limit(
                        super::pagination::sql_pagination(
                            self.connection().get_database_backend(),
                            Some(limit),
                            None,
                        )?
                        .0,
                    )
                    .all(self.connection())
                    .await
                    .map_err(map_db_err)
            },
        )
        .await?
        .iter()
        .map(|row| self.output_user(row, self.connection()))
        .collect()
    }

    async fn get_user_by_email(
        &self,
        email: &str,
    ) -> AuthResult<Option<better_auth_core::wire::UserView>> {
        let email = normalize_user_email(email);
        database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
            self.config(),
            "findOne",
            async {
                <S::User as SeaOrmUserModel>::Entity::find()
                    .filter(<S::User as SeaOrmUserModel>::email_column().eq(email))
                    .one(self.connection())
                    .await
                    .map_err(map_db_err)
            },
        )
        .await?
        .as_ref()
        .map(|row| self.output_user(row, self.connection()))
        .transpose()
    }

    async fn get_user_by_username(
        &self,
        username: &str,
    ) -> AuthResult<Option<better_auth_core::wire::UserView>> {
        self.find_user_by_username(self.connection(), username)
            .await
    }

    async fn get_user_by_phone_number(
        &self,
        phone_number: &str,
    ) -> AuthResult<Option<better_auth_core::wire::UserView>> {
        let column = S::User::phone_number_column()
            .ok_or_else(|| AuthError::config("The user entity requires phone_number"))?;
        database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
            self.config(),
            "findOne",
            async {
                <S::User as SeaOrmUserModel>::Entity::find()
                    .filter(column.eq(phone_number))
                    .one(self.connection())
                    .await
                    .map_err(map_db_err)
            },
        )
        .await?
        .as_ref()
        .map(|row| self.output_user(row, self.connection()))
        .transpose()
    }

    async fn update_user(
        &self,
        id: &str,
        update: UpdateUser,
    ) -> AuthResult<better_auth_core::wire::UserView> {
        self.update_user_with_connection(self.connection(), None, id, update)
            .await
    }

    async fn update_user_optional(
        &self,
        id: &str,
        update: UpdateUser,
    ) -> AuthResult<Option<better_auth_core::UserView>> {
        Ok(self
            .update_user_outcome_with_connection(self.connection(), None, id, update)
            .await?
            .continue_value()
            .flatten())
    }
    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        self.delete_user_optional(id, true).await.map(|_| ())
    }

    async fn delete_user_optional(
        &self,
        id: &str,
        delete_database_sessions: bool,
    ) -> AuthResult<Option<better_auth_core::wire::UserView>> {
        self.delete_user_with_connection(self.connection(), None, id, delete_database_sessions)
            .await
    }

    async fn list_users(
        &self,
        mut params: ListUsersParams,
    ) -> AuthResult<(Vec<better_auth_core::wire::UserView>, usize)> {
        let _ = params
            .limit
            .get_or_insert(self.config.advanced.database.find_many_limit());
        let (limit, offset) = super::pagination::sql_pagination(
            self.connection().get_database_backend(),
            params.limit,
            params.offset,
        )?;
        params.limit = limit.map(|value| value as f64);
        params.offset = offset.map(|value| value as f64);
        let models = database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
            self.config(),
            "findMany",
            async {
                <S::User as SeaOrmUserModel>::Entity::find()
                    .all(self.connection())
                    .await
                    .map_err(map_db_err)
            },
        )
        .await?;

        let (models, _) = better_auth_core::user_query::apply_list_users(models, &params);
        let users = models
            .iter()
            .map(|row| self.output_user(row, self.connection()))
            .collect::<AuthResult<Vec<_>>>()?;
        let total = database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
            self.config(),
            "count",
            async {
                let rows = <S::User as SeaOrmUserModel>::Entity::find()
                    .all(self.connection())
                    .await
                    .map_err(map_db_err)?;
                Ok(better_auth_core::user_query::count_users(&rows, &params))
            },
        )
        .await?;
        Ok((users, total))
    }
}

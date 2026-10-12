use super::instrumentation::database_operation;
use async_trait::async_trait;
use better_auth_core::store::schema::EntityRole;
use sea_orm::{ConnectionTrait, EntityName, QueryFilter, QuerySelect};

use better_auth_core::store::{ResolvedJoin, UserStore};
use better_auth_core::{FieldMap, FieldValue};

use crate::error::{AuthError, AuthResult};
use crate::schema::{AuthSchema, SeaOrmAccountModel, SeaOrmUserModel};
use crate::types::{CreateUser, ListUsersParams, UpdateUser};
use crate::utils::email::normalize_user_email;

use super::{SeaOrmStore, cancelled_by_hook, plugin_rows::SqlRow};

#[path = "users/query.rs"]
mod query;

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S: AuthSchema,
    S::User: SeaOrmUserModel,
{
    async fn user_record_by_email(&self, email: &str) -> AuthResult<Option<SqlRow>> {
        self.user_record_by_email_value(&normalize_user_email(email).into())
            .await
    }

    async fn user_record_by_email_value(&self, email: &FieldValue) -> AuthResult<Option<SqlRow>> {
        let query = self.user_field_query(self.connection(), "email", email)?;
        database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
            self.config(),
            "findOne",
            super::plugin_rows::one(self.connection(), query),
        )
        .await
    }

    pub(super) async fn get_user_by_id_with_connection(
        &self,
        db: &impl ConnectionTrait,
        id: &FieldValue,
        trace_query: bool,
    ) -> AuthResult<Option<better_auth_core::wire::UserView>> {
        let selected = self.user_field_query(db, "id", id)?;
        let query = super::plugin_rows::one(db, selected);
        let row = if trace_query {
            database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
                self.config(),
                "findOne",
                query,
            )
            .await?
        } else {
            query.await?
        };
        match row.as_ref() {
            Some(row) => self.output_user(row, db).await.map(Some),
            None => Ok(None),
        }
    }

    pub(super) async fn selected_join_users(
        &self,
        relation: &ResolvedJoin,
        value: FieldValue,
        limit: f64,
    ) -> AuthResult<Vec<SqlRow>> {
        if value.is_null() || value.is_undefined() {
            return Ok(Vec::new());
        }
        let backend = self.connection().get_database_backend();
        let (physical_to, value) = self.query_field_binding(
            EntityRole::User,
            &self.field_policy().user(),
            &relation.to,
            &value,
            backend,
        )?;
        let column = S::User::field_column(&physical_to)?;
        let query = super::plugin_rows::select_all::<<S::User as SeaOrmUserModel>::Entity>()
            .filter(super::value_filter::equals(column, &value, backend)?);
        database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
            self.config(),
            if relation.many { "findMany" } else { "findOne" },
            async {
                if relation.many {
                    super::plugin_rows::all(
                        self.connection(),
                        query.limit(
                            super::pagination::sql_pagination(backend, Some(limit), None)?.0,
                        ),
                    )
                    .await
                } else {
                    super::plugin_rows::one(self.connection(), query)
                        .await
                        .map(|user| user.into_iter().collect())
                }
            },
        )
        .await
    }

    pub(super) async fn find_user_by_username(
        &self,
        db: &impl ConnectionTrait,
        username: &str,
    ) -> AuthResult<Option<better_auth_core::wire::UserView>> {
        let Some(_) = S::User::username_column() else {
            return Ok(None);
        };
        self.find_user_by_field_value(db, "username", &username.into())
            .await
    }

    pub(super) fn user_field_query(
        &self,
        db: &impl ConnectionTrait,
        name: &str,
        value: &FieldValue,
    ) -> AuthResult<sea_orm::Select<<S::User as SeaOrmUserModel>::Entity>> {
        let (physical, bound) = self.user_field_selector(db, name, value)?;
        Ok(
            super::plugin_rows::select_all::<<S::User as SeaOrmUserModel>::Entity>().filter(
                super::value_filter::equals(
                    S::User::field_column(&physical)?,
                    &bound,
                    db.get_database_backend(),
                )?,
            ),
        )
    }

    fn user_field_selector(
        &self,
        db: &impl ConnectionTrait,
        name: &str,
        value: &FieldValue,
    ) -> AuthResult<(String, FieldValue)> {
        self.query_field_binding(
            EntityRole::User,
            &self.field_policy().user(),
            name,
            value,
            db.get_database_backend(),
        )
    }

    pub(super) async fn find_user_by_field_value(
        &self,
        db: &impl ConnectionTrait,
        name: &str,
        value: &FieldValue,
    ) -> AuthResult<Option<better_auth_core::UserView>> {
        let query = self.user_field_query(db, name, value)?;
        let row = database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
            self.config(),
            "findOne",
            super::plugin_rows::one(db, query),
        )
        .await?;
        match row {
            Some(row) => self.output_user(&row, db).await.map(Some),
            None => Ok(None),
        }
    }

    pub(crate) async fn create_user_fields_with_connection<C>(
        &self,
        db: &C,
        tx: Option<super::HookTransaction<'_, S>>,
        fields: FieldMap,
    ) -> AuthResult<Option<better_auth_core::wire::UserView>>
    where
        C: ConnectionTrait,
    {
        let mut prepared =
            better_auth_core::store::database_hooks::PreparedRecordWrite::new(fields);
        let hook_context = self.hook_context(tx);
        for hook in self.hooks() {
            let outcome = better_auth_core::observability::database::with_database_hook(
                hook_context.config,
                hook.hook_metadata(),
                better_auth_core::observability::database::DatabaseHook::BeforeCreateUser,
                hook.before_create_user(prepared.fields_mut(), &hook_context),
            )
            .await?;
            if !prepared.apply(outcome) {
                return Ok(None);
            }
        }
        let input = prepared.into_fields();
        let backend = db.get_database_backend();
        let schema = self.field_policy().user();
        let policy = self.config().advanced.database.generate_id();
        let fields = super::record_write::prepare_fields(
            &schema,
            input,
            Some("user"),
            (&self.model_fields, EntityRole::User),
            policy,
            backend,
            |name, field, value| {
                crate::reference_id::input_binding(
                    name,
                    field,
                    value,
                    policy,
                    S::User::field_column,
                    S::User::native_json_field,
                    backend,
                )
            },
        )
        .await?;
        let active =
            super::record_write::RecordWrite::<<S::User as SeaOrmUserModel>::Entity>::from_fields(
                fields,
                S::User::field_column,
            )?;
        let user = database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
            self.config(),
            "create",
            active.insert_raw(
                db,
                super::create_readback::CreateReadback {
                    schema: &schema,
                    policy: self.config().advanced.database.generate_id(),
                    scope: self.readback_scope(tx),
                    column: S::User::field_column,
                },
            ),
        )
        .await?;
        let user = match user {
            Some(user) => Some(self.output_user(&SqlRow::from(user), db).await?),
            None => None,
        };
        self.after_creation(
            tx,
            super::transaction_hooks::Effect::UserCreated(user.clone()),
            hook_context.request.clone(),
        )
        .await?;
        Ok(user)
    }

    pub(super) async fn update_user_with_connection(
        &self,
        db: &impl ConnectionTrait,
        tx: Option<super::HookTransaction<'_, S>>,
        id: &str,
        update: UpdateUser,
    ) -> AuthResult<better_auth_core::UserView> {
        match self
            .update_user_outcome_with_connection(db, tx, "id", &FieldValue::from(id), update)
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
        field: &str,
        value: &FieldValue,
        update: UpdateUser,
    ) -> AuthResult<std::ops::ControlFlow<(), Option<better_auth_core::UserView>>> {
        let mut prepared = better_auth_core::store::database_hooks::PreparedRecordWrite::new(
            update.into_user_fields()?,
        );
        let hook_context = self.hook_context(tx);
        for hook in self.hooks() {
            let outcome = better_auth_core::observability::database::with_database_hook(
                hook_context.config,
                hook.hook_metadata(),
                better_auth_core::observability::database::DatabaseHook::BeforeUpdateUser,
                hook.before_update_user(
                    field,
                    value,
                    prepared.original_fields_mut(),
                    &hook_context,
                ),
            )
            .await?;
            if !prepared.apply(outcome) {
                return Ok(std::ops::ControlFlow::Break(()));
            }
        }
        let user = self
            .update_user_record(db, field, value, prepared.into_fields())
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

        let user = self.output_user(&user, db).await?;
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

    pub(super) async fn update_user_record(
        &self,
        db: &impl ConnectionTrait,
        field: &str,
        value: &FieldValue,
        input: FieldMap,
    ) -> AuthResult<Option<SqlRow>> {
        let policy = self.config().advanced.database.generate_id();
        let backend = db.get_database_backend();
        let selector = self.bind_query_field(
            EntityRole::User,
            &self.field_policy().user(),
            field,
            value,
            backend,
        )?;
        let schema = self.field_policy().user();
        let fields = super::record_write::prepare_fields(
            &schema,
            input,
            None,
            (&self.model_fields, EntityRole::User),
            policy,
            backend,
            |name, field, value| {
                crate::reference_id::input_binding(
                    name,
                    field,
                    value,
                    policy,
                    S::User::field_column,
                    S::User::native_json_field,
                    backend,
                )
            },
        )
        .await?;
        let active =
            super::record_write::RecordWrite::<<S::User as SeaOrmUserModel>::Entity>::from_fields(
                fields,
                S::User::field_column,
            )?;
        database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
            self.config(),
            "update",
            async {
                let (physical, value) =
                    selector.resolve(EntityRole::User, &self.field_policy().user())?;
                let (query, filter) = active.update_where_returning(
                    backend,
                    [super::value_filter::QueryPredicate::equals(
                        S::User::field_column(&physical)?,
                        value,
                    )],
                )?;
                super::updates::execute_update_returning_raw(db, query, filter).await
            },
        )
        .await
        .map(|row| row.map(SqlRow::from))
    }

    pub(crate) async fn create_user_in_tx(
        &self,
        tx: super::HookTransaction<'_, S>,
        create_user: CreateUser,
    ) -> AuthResult<better_auth_core::wire::UserView> {
        self.create_user_fields_with_connection(tx.0, Some(tx), create_user.into_user_fields()?)
            .await?
            .ok_or_else(|| AuthError::internal("User creation returned no record"))
    }
}

#[async_trait]
impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> UserStore<S>
    for SeaOrmStore<S, O, P>
where
    S: AuthSchema + Send + Sync,
    S::User: SeaOrmUserModel,
    S::Account: SeaOrmAccountModel,
    S::Session: crate::schema::SeaOrmSessionModel,
    S::Verification: crate::schema::SeaOrmVerificationModel,
{
    fn supports_native_json(&self) -> bool {
        self.connection().get_database_backend() == sea_orm::DbBackend::Postgres
    }

    async fn verify_user_and_revoke_unproven_access(
        &self,
        user_id: &str,
    ) -> AuthResult<Option<better_auth_core::wire::UserView>> {
        self.verify_user_and_revoke_unproven_access_value(&user_id.into())
            .await
    }

    async fn verify_user_and_revoke_unproven_access_value(
        &self,
        user_id: &better_auth_core::FieldValue,
    ) -> AuthResult<Option<better_auth_core::wire::UserView>> {
        better_auth_core::store::revoke_unproven_account_access(self, user_id).await
    }
    async fn create_user(
        &self,
        create_user: CreateUser,
    ) -> AuthResult<better_auth_core::wire::UserView> {
        self.create_user_optional(create_user)
            .await?
            .ok_or_else(|| AuthError::internal("User creation returned no record"))
    }

    async fn create_user_fields_optional(
        &self,
        fields: FieldMap,
    ) -> AuthResult<Option<better_auth_core::wire::UserView>> {
        self.create_user_fields_with_connection(self.connection(), None, fields)
            .await
    }

    async fn get_user_by_id(
        &self,
        id: &str,
    ) -> AuthResult<Option<better_auth_core::wire::UserView>> {
        self.get_user_by_id_with_connection(self.connection(), &id.into(), true)
            .await
    }

    async fn get_user_by_id_field(
        &self,
        id: &better_auth_core::SchemaValue<String>,
    ) -> AuthResult<Option<better_auth_core::wire::UserView>> {
        self.get_user_by_id_with_connection(self.connection(), &id.field_value(), true)
            .await
    }

    async fn get_user_by_id_value(
        &self,
        id: &better_auth_core::FieldValue,
    ) -> AuthResult<Option<better_auth_core::wire::UserView>> {
        self.get_user_by_id_with_connection(self.connection(), id, true)
            .await
    }

    async fn list_users_by_ids(
        &self,
        ids: &[String],
        limit: f64,
    ) -> AuthResult<Vec<better_auth_core::wire::UserView>> {
        let ids = ids
            .iter()
            .cloned()
            .map(FieldValue::from)
            .collect::<Vec<_>>();
        self.list_users_by_id_values(&ids, limit).await
    }

    async fn list_users_by_id_values(
        &self,
        ids: &[FieldValue],
        limit: f64,
    ) -> AuthResult<Vec<better_auth_core::wire::UserView>> {
        let backend = self.connection().get_database_backend();
        let (physical, bound) =
            self.user_field_selector(self.connection(), "id", &ids.to_vec().into())?;
        let column = S::User::field_column(&physical)?;
        let filter = super::value_filter::is_in(column, &bound, backend)?;

        match database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
            self.config(),
            "findMany",
            async {
                super::plugin_rows::all(
                    self.connection(),
                    super::plugin_rows::select_all::<<S::User as SeaOrmUserModel>::Entity>()
                        .filter(filter)
                        .limit(
                            super::pagination::sql_pagination(
                                self.connection().get_database_backend(),
                                Some(limit),
                                None,
                            )?
                            .0,
                        ),
                )
                .await
            },
        )
        .await
        {
            Ok(rows) => self.output_users(&rows, self.connection()).await,
            Err(error) => Err(error),
        }
    }

    async fn get_user_with_accounts(
        &self,
        email: &str,
    ) -> AuthResult<Option<better_auth_core::store::UserAccounts>> {
        self.get_user_with_accounts_value(&normalize_user_email(email).into())
            .await
    }

    async fn get_user_with_accounts_value(
        &self,
        email: &FieldValue,
    ) -> AuthResult<Option<better_auth_core::store::UserAccounts>> {
        let relation = better_auth_core::store::UserAccounts::resolve_schema(
            self.config(),
            &self.model_fields,
            super::model_names::table_matches::<S, O, P>,
        )?;
        let native_join = self.config().advanced.database.joins == Some(true);
        let (record, native_accounts) = if native_join {
            self.model_fields.canonicalize_id(EntityRole::Account)?;
            let query = super::joins::joined_query::<
                <S::User as SeaOrmUserModel>::Entity,
                <S::Account as SeaOrmAccountModel>::Entity,
            >(
                self.connection().get_database_backend(),
                (
                    self.user_field_query(self.connection(), "email", email)?
                        .limit(
                            (self.connection().get_database_backend() != sea_orm::DbBackend::MySql)
                                .then_some(1),
                        ),
                    S::User::id_column(),
                ),
                (
                    S::User::field_column(&relation.from)?,
                    S::Account::field_column(&relation.to)?,
                ),
                &self.field_policy().account().adapter_fields(&[]),
                S::Account::field_column,
            )?;
            let rows = database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
                self.config(),
                "findOne",
                super::joins::joined_raw_rows(self.connection(), &query),
            )
            .await?;
            let Some((record, accounts)) =
                super::joins::grouped_raw_rows(rows, S::User::id_column())?
                    .into_iter()
                    .next()
            else {
                return Ok(None);
            };
            let accounts = super::joins::selected_raw_children(
                accounts.into_iter(),
                S::Account::id_column(),
                relation.many,
                self.config().advanced.database.find_many_limit(),
            )?;
            (record, Some(accounts))
        } else {
            let Some(record) = self.user_record_by_email_value(email).await? else {
                return Ok(None);
            };
            (record, None)
        };
        let user = if let Some(accounts) = &native_accounts {
            let entity = <S::Account as SeaOrmAccountModel>::Entity::default();
            let physical = self
                .model_fields
                .storage_model_name(EntityRole::Account, entity.table_name());
            let raw = super::joins::raw_relation_value(
                accounts,
                &self.field_policy().account().adapter_fields(&[]),
                relation.many,
                S::Account::field_column,
            )?;
            let backend = self.connection().get_database_backend();
            let record = self
                .user_record(&record, backend)?
                .with_storage_property(physical, raw);
            self.output_user_records(vec![record], backend)
                .await?
                .remove(0)
        } else {
            self.output_user(&record, self.connection()).await?
        };
        let records = if let Some(records) = native_accounts {
            records
        } else {
            let source = relation.fallback_from(
                (EntityRole::User, "user", &self.config().user),
                &self.model_fields,
            )?;
            let value = FieldMap::from(user.clone())
                .remove(&source)
                .unwrap_or_default();
            self.selected_join_accounts(&relation, value).await?
        };
        let mut accounts = Vec::with_capacity(records.len());
        for record in records {
            accounts.push(if native_join {
                self.output_native_account(&record).await?
            } else {
                self.output_account(&record, self.connection()).await?
            });
        }

        Ok(Some(better_auth_core::store::UserAccounts::new(
            user,
            super::joins::relation_value(relation.many, accounts),
        )))
    }

    async fn get_user_by_email(
        &self,
        email: &str,
    ) -> AuthResult<Option<better_auth_core::wire::UserView>> {
        match self.user_record_by_email(email).await?.as_ref() {
            Some(row) => self.output_user(row, self.connection()).await.map(Some),
            None => Ok(None),
        }
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
        let _ = S::User::phone_number_column()
            .ok_or_else(|| AuthError::config("The user entity requires phone_number"))?;
        self.find_user_by_field_value(self.connection(), "phoneNumber", &phone_number.into())
            .await
    }

    async fn get_user_by_field_value(
        &self,
        field: &str,
        value: &FieldValue,
    ) -> AuthResult<Option<better_auth_core::UserView>> {
        self.find_user_by_field_value(self.connection(), field, value)
            .await
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
        self.update_user_by_id_value(&FieldValue::from(id), update)
            .await
    }
    async fn update_user_by_field_value(
        &self,
        field: &str,
        value: &FieldValue,
        update: UpdateUser,
    ) -> AuthResult<Option<better_auth_core::UserView>> {
        Ok(self
            .update_user_outcome_with_connection(self.connection(), None, field, value, update)
            .await?
            .continue_value()
            .flatten())
    }
    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        self.delete_user_value(&id.into()).await
    }

    async fn delete_user_value(&self, id: &FieldValue) -> AuthResult<()> {
        self.delete_user_optional_value(id, true).await.map(|_| ())
    }

    async fn delete_user_optional(
        &self,
        id: &str,
        delete_database_sessions: bool,
    ) -> AuthResult<Option<better_auth_core::wire::UserView>> {
        self.delete_user_optional_value(&id.into(), delete_database_sessions)
            .await
    }

    async fn delete_user_optional_value(
        &self,
        id: &FieldValue,
        delete_database_sessions: bool,
    ) -> AuthResult<Option<better_auth_core::wire::UserView>> {
        self.delete_user_with_connection(self.connection(), None, id, delete_database_sessions)
            .await
    }

    async fn list_users(
        &self,
        params: ListUsersParams,
    ) -> AuthResult<(Vec<better_auth_core::wire::UserView>, usize)> {
        let selected = self.user_query_page(&params).await?;
        let users = self.output_users(&selected, self.connection()).await?;
        let total = self.user_query_count(&params).await?;
        Ok((users, total))
    }
}

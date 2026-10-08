use super::instrumentation::database_operation;
use async_trait::async_trait;
use better_auth_core::id::AdapterIdInput;
use better_auth_core::store::schema::{EntityRole, resolve_field_name};
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QuerySelect,
};

use better_auth_core::store::{ResolvedJoin, UserStore};
use better_auth_core::user_fields::{
    AdapterRecord, FieldOutputCapabilities, UserConfig, UserFieldType,
};
use better_auth_core::{AuthUser, FieldMap, FieldValue};

use crate::error::{AuthError, AuthResult};
use crate::hooks::DatabaseHookUpdate;
use crate::schema::{AuthSchema, SeaOrmAccountModel, SeaOrmUserModel};
use crate::types::{CreateUser, ListUsersParams, UpdateUser};
use crate::utils::email::{normalize_optional_user_email, normalize_user_email};

use super::{
    SeaOrmStore, cancelled_by_hook,
    field_output::{column_value, sqlite_extra_output},
    map_db_err,
};

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S: AuthSchema,
    S::User: SeaOrmUserModel,
{
    pub(super) async fn output_users(
        &self,
        rows: &[S::User],
        db: &impl ConnectionTrait,
    ) -> AuthResult<Vec<better_auth_core::wire::UserView>> {
        if !rows.is_empty() {
            self.model_fields.begin_id_output(EntityRole::User)?;
        }
        let sqlite = db.get_database_backend() == sea_orm::DbBackend::Sqlite;
        let mut fields = self.config().user.user_adapter_fields();
        // The typed model getter already projects immutable SQL primary keys.
        let _ = fields.fields_mut().shift_remove("id");
        let mut output =
            better_auth_core::wire::UserView::with_internal_fields_many_for_adapter_using(
                rows,
                &fields,
                &Default::default(),
                FieldOutputCapabilities {
                    supports_native_json: db.get_database_backend() == sea_orm::DbBackend::Postgres,
                    supports_arrays: !sqlite,
                    supports_booleans: !sqlite,
                },
                |model, name, field| {
                    if (sqlite || matches!(field.field_type, UserFieldType::String))
                        && field.references.is_none()
                    {
                        let physical = resolve_field_name(field.field_name.as_deref(), name);
                        let column = S::User::field_column(physical)?;
                        let value =
                            column_value::<<S::User as SeaOrmUserModel>::Entity>(model, column);
                        if sqlite {
                            sqlite_extra_output(value, field)
                        } else {
                            crate::__private_field_value(value).map(Some)
                        }
                    } else {
                        Ok(None)
                    }
                },
            )
            .await?;
        let order: Vec<_> = self
            .config()
            .user
            .user_field_schema()
            .adapter_fields(&[])
            .fields()
            .keys()
            .cloned()
            .collect();
        for (view, row) in output.iter_mut().zip(rows) {
            view.field_order.clone_from(&order);
            view.visible_fields = row.field_presence().cloned();
        }
        Ok(output)
    }

    async fn user_record_by_email(&self, email: &str) -> AuthResult<Option<S::User>> {
        self.model_fields.begin_id_query(EntityRole::User)?;
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
        .await
    }

    pub(super) async fn output_user(
        &self,
        row: &S::User,
        db: &impl ConnectionTrait,
    ) -> AuthResult<better_auth_core::wire::UserView> {
        // Projection preserves the one input row.
        Ok(self
            .output_users(std::slice::from_ref(row), db)
            .await?
            .remove(0))
    }

    pub(super) async fn get_user_by_id_with_connection(
        &self,
        db: &impl ConnectionTrait,
        id: &FieldValue,
        trace_query: bool,
    ) -> AuthResult<Option<better_auth_core::wire::UserView>> {
        self.model_fields.begin_id_query(EntityRole::User)?;
        let parsed_id = id
            .as_str()
            .map(|id| self.parse_id(id, S::User::parse_id))
            .transpose()?;
        let query = async {
            let filter = match parsed_id {
                Some(id) => S::User::id_column().eq(id),
                None => super::value_filter::equals(
                    S::User::id_column(),
                    id,
                    db.get_database_backend(),
                )?,
            };
            <S::User as SeaOrmUserModel>::Entity::find()
                .filter(filter)
                .one(db)
                .await
                .map_err(map_db_err)
        };
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

    fn native_user_record(&self, user: &S::User, fields: &UserConfig) -> AuthResult<AdapterRecord> {
        let backend = self.connection().get_database_backend();
        let storage = super::joins::native_child_fields(fields, |name, field| {
            let value = column_value::<<S::User as SeaOrmUserModel>::Entity>(
                user,
                S::User::field_column(name)?,
            );
            super::field_output::raw_field_output(value, field, backend)?.ok_or_else(|| {
                AuthError::internal(format!(
                    "Raw SQL output omitted selected User field: {name}"
                ))
            })
        })?;
        let core = FieldMap::from([("id".into(), user.id().into_owned().into_field_value())]);
        let mut record = AdapterRecord::new(core, FieldMap::new());
        record.map_storage_fields(
            fields,
            super::field_output::capabilities(backend),
            |name, _| Ok(Some(storage.get(name).cloned().unwrap_or_default())),
        )?;
        Ok(record)
    }

    pub(super) async fn output_native_user_pages(
        &self,
        pages: Vec<&[S::User]>,
    ) -> AuthResult<Vec<Vec<FieldMap>>> {
        if pages.iter().any(|page| !page.is_empty()) {
            self.model_fields.begin_id_output(EntityRole::User)?;
        }
        let mut fields = self.config().user.clone();
        for name in [
            "name",
            "email",
            "emailVerified",
            "image",
            "createdAt",
            "updatedAt",
        ]
        .into_iter()
        .chain(self.model_fields.user_plugin_fields().iter().copied())
        {
            let _ = fields
                .fields_mut()
                .entry(name.into())
                .or_insert_with(|| ResolvedJoin::user_field(self.config(), name));
        }
        let mut fields = fields.user_adapter_fields();
        let _ = fields.fields_mut().insert("id".into(), Default::default());
        super::joins::project_child_pages(
            &fields,
            pages,
            self.connection().get_database_backend(),
            &|user| self.native_user_record(user, &fields),
        )
        .await
    }

    pub(super) fn set_join_user_visibility(&self, user: &mut better_auth_core::UserView) {
        user.visible_fields = Some(
            ["name", "email", "image"]
                .into_iter()
                .map(str::to_owned)
                .chain(
                    self.model_fields
                        .user_plugin_fields()
                        .iter()
                        .map(|name| (*name).to_owned()),
                )
                .chain(self.config().user.fields().keys().cloned())
                .collect(),
        );
    }

    pub(super) async fn selected_join_users(
        &self,
        relation: &ResolvedJoin,
        value: FieldValue,
        limit: f64,
    ) -> AuthResult<Vec<S::User>> {
        if value.is_null() || value.is_undefined() {
            return Ok(Vec::new());
        }
        let (logical_to, physical_to) = relation.fallback_target(
            (EntityRole::User, "user", &self.config().user),
            &self.model_fields,
        )?;
        let field = ResolvedJoin::user_field(self.config(), &logical_to);
        let policy = self.config().advanced.database.generate_id();
        let backend = self.connection().get_database_backend();
        let original = value.clone();
        let value = if logical_to == "id" || field.references_id() {
            policy.adapter_id_query(value)?
        } else {
            value
        };
        let value = better_auth_core::user_query::bind_filter(&field, &value)?;
        let value = super::value_filter::adapter_query_value(value, &original, &field, backend)?;
        let column = S::User::field_column(&physical_to)?;
        let query = <S::User as SeaOrmUserModel>::Entity::find()
            .filter(super::value_filter::equals(column, &value, backend)?);
        database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
            self.config(),
            if relation.many { "findMany" } else { "findOne" },
            async {
                if relation.many {
                    query
                        .limit(super::pagination::sql_pagination(backend, Some(limit), None)?.0)
                        .all(self.connection())
                        .await
                        .map_err(map_db_err)
                } else {
                    query
                        .one(self.connection())
                        .await
                        .map(|user| user.into_iter().collect())
                        .map_err(map_db_err)
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
        let Some(column) = S::User::username_column() else {
            return Ok(None);
        };
        self.model_fields.begin_id_query(EntityRole::User)?;
        match database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
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
        {
            Some(row) => self.output_user(row, db).await.map(Some),
            None => Ok(None),
        }
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
        self.model_fields.begin_id_input(
            EntityRole::User,
            AdapterIdInput {
                force_allow_id: create_user.id.is_some(),
                supports_native_uuid: db.get_database_backend() == sea_orm::DbBackend::Postgres,
            },
        )?;
        let now = Utc::now();
        let input = create_user.take_user_field_input(&self.config().user)?;
        let (mut fields, user_id) = self
            .config()
            .user
            .create_user_storage_fields(
                input,
                || {
                    let id = if let Some(policy) =
                        self.model_fields.id_input_policy(EntityRole::User)?
                    {
                        self.generated_id_with_policy("user", create_user.id.take(), policy)?
                    } else {
                        create_user.id.take()
                    };
                    id.as_deref().map(S::User::parse_id).transpose()
                },
                |name, field, value| {
                    crate::reference_id::input_binding(
                        name,
                        field,
                        value,
                        self.config().advanced.database.generate_id(),
                        S::User::field_column,
                        S::User::native_json_field,
                        db.get_database_backend(),
                    )
                },
            )
            .await?;
        let mut name = std::mem::take(&mut create_user.name);
        let mut image = std::mem::take(&mut create_user.image);
        for (key, target) in [("name", &mut name), ("image", &mut image)] {
            if let Some(field) = self.config().user.fields().get(key) {
                *target = better_auth_core::SchemaValue::from_field(
                    fields
                        .remove(resolve_field_name(field.field_name.as_deref(), key))
                        .unwrap_or_default(),
                );
            }
        }
        let ban_expires = create_user.ban_expires.take();
        let created_at = create_user.created_at.take();
        let updated_at = create_user.updated_at.take();
        let database_generated_id = user_id.is_none();
        let mut model = S::User::new_active(user_id, create_user, now)?;
        for (name, value) in [
            ("createdAt", created_at),
            ("updatedAt", updated_at),
            ("banExpires", ban_expires),
        ] {
            if let Some(date) = value {
                let storage = self.config().user.fields().get(name).map_or(name, |field| {
                    resolve_field_name(field.field_name.as_deref(), name)
                });
                if fields.contains_key(storage) {
                    continue;
                }
                let value = if db.get_database_backend() == sea_orm::DbBackend::Sqlite {
                    super::record_bindings::sqlite_date(date)?
                } else {
                    better_auth_core::FieldValue::Date(date)
                };
                let _ = fields.insert(storage.into(), value);
            }
        }
        if database_generated_id {
            model.not_set(S::User::id_column());
        }
        let user = database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
            self.config(),
            "create",
            async {
                super::user_values::insert::<S::User>(
                    db,
                    model,
                    name,
                    image,
                    fields,
                    super::create_readback::CreateReadback {
                        schema: &self.config().user.user_field_schema(),
                        policy: self.config().advanced.database.generate_id(),
                        scope: self.readback_scope(tx),
                        column: S::User::field_column,
                    },
                )
                .await
            },
        )
        .await?;
        let user = match user {
            Some(user) => Some(self.output_user(&user, db).await?),
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
            .update_user_outcome_with_connection(db, tx, &FieldValue::from(id), update)
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
        id: &FieldValue,
        mut update: UpdateUser,
    ) -> AuthResult<std::ops::ControlFlow<(), Option<better_auth_core::UserView>>> {
        update.prepare_user_fields(&self.config().user)?;
        update.email = normalize_optional_user_email(update.email);
        if update.phone_number == Some(None) {
            update.phone_number_verified = Some(false);
        }
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
        let user = self.update_user_record(db, id, update).await?;
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
        user_id: &FieldValue,
        mut update: UpdateUser,
    ) -> AuthResult<Option<S::User>> {
        self.model_fields.canonicalize_id(EntityRole::User)?;
        let user_id = self
            .config()
            .advanced
            .database
            .generate_id()
            .adapter_id_query(user_id.clone())?;
        self.model_fields.begin_id_input(
            EntityRole::User,
            AdapterIdInput {
                force_allow_id: false,
                supports_native_uuid: db.get_database_backend() == sea_orm::DbBackend::Postgres,
            },
        )?;
        let mut fields = self
            .config()
            .user
            .user_adapter_fields()
            .storage_fields_with_binding(
                update.take_user_field_input(&self.config().user)?,
                false,
                |name, field, value| {
                    crate::reference_id::input_binding(
                        name,
                        field,
                        value,
                        self.config().advanced.database.generate_id(),
                        S::User::field_column,
                        S::User::native_json_field,
                        db.get_database_backend(),
                    )
                },
            )
            .await?;
        let mut name = std::mem::take(&mut update.name);
        let mut image = std::mem::take(&mut update.image);
        for (key, target) in [("name", &mut name), ("image", &mut image)] {
            if let Some(field) = self.config().user.fields().get(key) {
                *target = better_auth_core::SchemaValue::from_field(
                    fields
                        .remove(resolve_field_name(field.field_name.as_deref(), key))
                        .unwrap_or_default(),
                );
            }
        }
        if let Some(value) = update.ban_expires.take() {
            let storage = self
                .config()
                .user
                .fields()
                .get("banExpires")
                .map_or("banExpires", |field| {
                    resolve_field_name(field.field_name.as_deref(), "banExpires")
                });
            if !fields.contains_key(storage) {
                let value = match value {
                    Some(date) if db.get_database_backend() == sea_orm::DbBackend::Sqlite => {
                        super::record_bindings::sqlite_date(date)?
                    }
                    Some(date) => better_auth_core::FieldValue::Date(date),
                    None => better_auth_core::FieldValue::Null,
                };
                let _ = fields.insert(storage.into(), value);
            }
        }
        database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
            self.config(),
            "update",
            async {
                let mut active = <S::User as SeaOrmUserModel>::ActiveModel::default();
                S::User::apply_update(&mut active, update, Utc::now())?;
                super::user_values::update::<S::User>(
                    db,
                    active,
                    name,
                    image,
                    fields,
                    user_id,
                    self.config().advanced.database.generate_id(),
                )
                .await
            },
        )
        .await
    }

    pub(crate) async fn create_user_in_tx(
        &self,
        tx: super::HookTransaction<'_, S>,
        create_user: CreateUser,
    ) -> AuthResult<better_auth_core::wire::UserView> {
        self.create_user_with_connection(tx.0, Some(tx), create_user)
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
            .ok_or_else(|| AuthError::internal("User creation returned no record"))
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
        self.model_fields.begin_id_query(EntityRole::User)?;
        let user_ids = ids
            .iter()
            .map(|id| self.parse_id(id, S::User::parse_id))
            .collect::<AuthResult<Vec<_>>>()?;

        match database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
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
                <S::User as SeaOrmUserModel>::Entity::find()
                    .filter(S::User::email_column().eq(normalize_user_email(email)))
                    .limit(1),
                (
                    S::User::field_column(&relation.from)?,
                    S::Account::field_column(&relation.to)?,
                ),
                S::Account::id_column(),
            );
            let rows = database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
                self.config(),
                "findOne",
                super::joins::joined_rows::<
                    <S::User as SeaOrmUserModel>::Entity,
                    <S::Account as SeaOrmAccountModel>::Entity,
                >(self.connection(), &query),
            )
            .await?;
            let mut rows = rows.into_iter();
            let Some((record, first_account)) = rows.next() else {
                return Ok(None);
            };
            let accounts =
                super::joins::selected_children::<<S::Account as SeaOrmAccountModel>::Entity>(
                    std::iter::once(first_account)
                        .chain(rows.map(|(_, account)| account))
                        .flatten(),
                    S::Account::id_column(),
                    relation.many,
                    self.config().advanced.database.find_many_limit(),
                );
            (record, Some(accounts))
        } else {
            let Some(record) = self.user_record_by_email(email).await? else {
                return Ok(None);
            };
            (record, None)
        };
        let mut user = self.output_user(&record, self.connection()).await?;
        self.set_join_user_visibility(&mut user);
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
        let column = S::User::phone_number_column()
            .ok_or_else(|| AuthError::config("The user entity requires phone_number"))?;
        self.model_fields.begin_id_query(EntityRole::User)?;
        match database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
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
        {
            Some(row) => self.output_user(row, self.connection()).await.map(Some),
            None => Ok(None),
        }
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
    async fn update_user_by_id_value(
        &self,
        id: &FieldValue,
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
        let query = better_auth_core::user_query::PreparedUserQuery::for_adapter(
            &params,
            &self.config().user,
            &self.model_fields,
        )?;
        query.validate_sort()?;
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

        let query_record = |model: S::User| {
            let view = better_auth_core::UserView::from_model(&model)?;
            let mut fields = better_auth_core::FieldMap::new();
            for (name, field) in self.config().user.fields() {
                let physical = resolve_field_name(field.field_name.as_deref(), name);
                let column = S::User::field_column(physical)?;
                let value = crate::__private_field_value(column_value::<
                    <S::User as SeaOrmUserModel>::Entity,
                >(&model, column))?;
                let _ = fields.insert(physical.to_owned(), value);
            }
            AuthResult::Ok((view, fields, model))
        };
        let records = models
            .into_iter()
            .map(&query_record)
            .collect::<AuthResult<Vec<_>>>()?;
        let (selected, _) = query.select(records, |(view, fields, _)| (view, fields))?;
        let selected = selected
            .into_iter()
            .map(|(_, _, model)| model)
            .collect::<Vec<_>>();
        let users = self.output_users(&selected, self.connection()).await?;
        query.begin_adapter_count(&self.model_fields)?;
        let total = database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
            self.config(),
            "count",
            async {
                let rows = <S::User as SeaOrmUserModel>::Entity::find()
                    .all(self.connection())
                    .await
                    .map_err(map_db_err)?;
                let records = rows
                    .into_iter()
                    .map(query_record)
                    .collect::<AuthResult<Vec<_>>>()?;
                Ok(query.count(&records, |(view, fields, _)| (view, fields)))
            },
        )
        .await?;
        Ok((users, total))
    }
}

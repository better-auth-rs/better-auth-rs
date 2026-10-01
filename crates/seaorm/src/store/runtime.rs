use std::sync::{Arc, RwLock};

use super::SeaOrmStore;
use crate::hooks::{HookControl, SeaOrmHookContext, SeaOrmHooks};
use crate::schema::{
    SeaOrmAccountModel, SeaOrmSessionModel, SeaOrmUserModel, SeaOrmVerificationModel,
};
use async_trait::async_trait;
use better_auth_core::store::database_hooks::{
    DatabaseHookContext, DatabaseHookControl, DatabaseHookUpdate, DatabaseHooks, SessionUpdate,
    VerificationUpdate,
};
use better_auth_core::store::{AuthStore, RuntimeStore};
use better_auth_core::{
    AuthConfig, AuthResult, AuthSchema, CreateAccount, CreateSession, CreateUser,
    CreateVerification, UpdateAccount, UpdateUser,
};

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> RuntimeStore<S>
    for SeaOrmStore<S, O, P>
where
    S: AuthSchema,
    S::User: SeaOrmUserModel,
    S::Account: SeaOrmAccountModel,
    S::Session: SeaOrmSessionModel,
    S::Verification: SeaOrmVerificationModel,
{
    fn schema_check(
        &self,
        config: &better_auth_core::store::schema::SchemaConfiguration,
    ) -> AuthResult<Option<Arc<better_auth_core::store::schema::SchemaCheck>>> {
        self.create_schema_check(config)
    }

    fn with_runtime(
        &self,
        config: Arc<AuthConfig>,
        hooks: Vec<Arc<dyn DatabaseHooks<S>>>,
    ) -> AuthResult<Arc<dyn AuthStore<S>>> {
        let mut store = self.clone();
        store.config = config;
        store.organization_fields = Arc::new(RwLock::new(self.organization_fields()?));
        store.hooks = hooks
            .into_iter()
            .map(|hook| Arc::new(PluginHook(hook)) as Arc<dyn SeaOrmHooks<S>>)
            .chain(self.hooks.iter().cloned())
            .collect();
        Ok(Arc::new(store))
    }
}

struct PluginHook<S: AuthSchema>(Arc<dyn DatabaseHooks<S>>);

#[async_trait]
impl<S: AuthSchema> SeaOrmHooks<S> for PluginHook<S> {
    fn hook_metadata(&self) -> better_auth_core::observability::database::DatabaseHookMetadata {
        self.0.hook_metadata()
    }

    async fn before_create_user(
        &self,
        _data: &mut CreateUser,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<HookControl> {
        let context = DatabaseHookContext {
            config: ctx.config,
            request: ctx.request.clone(),
            transaction: ctx.transaction,
        };
        Ok(match self.0.before_create_user(_data, &context).await? {
            DatabaseHookControl::Continue => HookControl::Continue,
            DatabaseHookControl::Cancel => HookControl::Cancel,
        })
    }

    async fn after_create_user(
        &self,
        _data: &better_auth_core::wire::UserView,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<()> {
        let context = DatabaseHookContext {
            config: ctx.config,
            request: ctx.request.clone(),
            transaction: ctx.transaction,
        };
        self.0.after_create_user(_data, &context).await
    }

    async fn before_update_user(
        &self,
        _id: &str,
        _data: &UpdateUser,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<UpdateUser>> {
        let context = DatabaseHookContext {
            config: ctx.config,
            request: ctx.request.clone(),
            transaction: ctx.transaction,
        };
        self.0.before_update_user(_data, &context).await
    }

    async fn after_update_user(
        &self,
        _data: Option<&better_auth_core::wire::UserView>,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<()> {
        let context = DatabaseHookContext {
            config: ctx.config,
            request: ctx.request.clone(),
            transaction: ctx.transaction,
        };
        self.0.after_update_user(_data, &context).await
    }

    async fn before_delete_user(
        &self,
        _data: &better_auth_core::wire::UserView,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<HookControl> {
        let context = DatabaseHookContext {
            config: ctx.config,
            request: ctx.request.clone(),
            transaction: ctx.transaction,
        };
        Ok(match self.0.before_delete_user(_data, &context).await? {
            DatabaseHookControl::Continue => HookControl::Continue,
            DatabaseHookControl::Cancel => HookControl::Cancel,
        })
    }

    async fn after_delete_user(
        &self,
        _data: &better_auth_core::wire::UserView,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<()> {
        let context = DatabaseHookContext {
            config: ctx.config,
            request: ctx.request.clone(),
            transaction: ctx.transaction,
        };
        self.0.after_delete_user(_data, &context).await
    }

    async fn before_create_account(
        &self,
        _data: &mut CreateAccount,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<HookControl> {
        let context = DatabaseHookContext {
            config: ctx.config,
            request: ctx.request.clone(),
            transaction: ctx.transaction,
        };
        Ok(match self.0.before_create_account(_data, &context).await? {
            DatabaseHookControl::Continue => HookControl::Continue,
            DatabaseHookControl::Cancel => HookControl::Cancel,
        })
    }

    async fn after_create_account(
        &self,
        _data: &better_auth_core::wire::AccountView,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<()> {
        let context = DatabaseHookContext {
            config: ctx.config,
            request: ctx.request.clone(),
            transaction: ctx.transaction,
        };
        self.0.after_create_account(_data, &context).await
    }

    async fn before_update_account(
        &self,
        _id: &str,
        _data: &UpdateAccount,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<UpdateAccount>> {
        let context = DatabaseHookContext {
            config: ctx.config,
            request: ctx.request.clone(),
            transaction: ctx.transaction,
        };
        self.0.before_update_account(_data, &context).await
    }

    async fn after_update_account(
        &self,
        _data: Option<&better_auth_core::wire::AccountView>,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<()> {
        let context = DatabaseHookContext {
            config: ctx.config,
            request: ctx.request.clone(),
            transaction: ctx.transaction,
        };
        self.0.after_update_account(_data, &context).await
    }

    async fn before_delete_account(
        &self,
        _data: &better_auth_core::wire::AccountView,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<HookControl> {
        let context = DatabaseHookContext {
            config: ctx.config,
            request: ctx.request.clone(),
            transaction: ctx.transaction,
        };
        Ok(match self.0.before_delete_account(_data, &context).await? {
            DatabaseHookControl::Continue => HookControl::Continue,
            DatabaseHookControl::Cancel => HookControl::Cancel,
        })
    }

    async fn after_delete_account(
        &self,
        _data: &better_auth_core::wire::AccountView,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<()> {
        let context = DatabaseHookContext {
            config: ctx.config,
            request: ctx.request.clone(),
            transaction: ctx.transaction,
        };
        self.0.after_delete_account(_data, &context).await
    }

    async fn before_create_session(
        &self,
        _data: &mut CreateSession,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<HookControl> {
        let context = DatabaseHookContext {
            config: ctx.config,
            request: ctx.request.clone(),
            transaction: ctx.transaction,
        };
        Ok(match self.0.before_create_session(_data, &context).await? {
            DatabaseHookControl::Continue => HookControl::Continue,
            DatabaseHookControl::Cancel => HookControl::Cancel,
        })
    }

    async fn after_create_session(
        &self,
        _data: &better_auth_core::wire::SessionView,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<()> {
        let context = DatabaseHookContext {
            config: ctx.config,
            request: ctx.request.clone(),
            transaction: ctx.transaction,
        };
        self.0.after_create_session(_data, &context).await
    }

    async fn before_update_session(
        &self,
        _id: &str,
        _data: &SessionUpdate,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<SessionUpdate>> {
        let context = DatabaseHookContext {
            config: ctx.config,
            request: ctx.request.clone(),
            transaction: ctx.transaction,
        };
        self.0.before_update_session(_data, &context).await
    }

    async fn after_update_session(
        &self,
        _data: Option<&better_auth_core::wire::SessionView>,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<()> {
        let context = DatabaseHookContext {
            config: ctx.config,
            request: ctx.request.clone(),
            transaction: ctx.transaction,
        };
        self.0.after_update_session(_data, &context).await
    }

    async fn before_delete_session(
        &self,
        _data: &better_auth_core::wire::SessionView,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<HookControl> {
        let context = DatabaseHookContext {
            config: ctx.config,
            request: ctx.request.clone(),
            transaction: ctx.transaction,
        };
        Ok(match self.0.before_delete_session(_data, &context).await? {
            DatabaseHookControl::Continue => HookControl::Continue,
            DatabaseHookControl::Cancel => HookControl::Cancel,
        })
    }

    async fn after_delete_session(
        &self,
        _data: &better_auth_core::wire::SessionView,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<()> {
        let context = DatabaseHookContext {
            config: ctx.config,
            request: ctx.request.clone(),
            transaction: ctx.transaction,
        };
        self.0.after_delete_session(_data, &context).await
    }

    async fn before_create_verification(
        &self,
        _data: &mut CreateVerification,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<HookControl> {
        let context = DatabaseHookContext {
            config: ctx.config,
            request: ctx.request.clone(),
            transaction: ctx.transaction,
        };
        Ok(
            match self.0.before_create_verification(_data, &context).await? {
                DatabaseHookControl::Continue => HookControl::Continue,
                DatabaseHookControl::Cancel => HookControl::Cancel,
            },
        )
    }

    async fn after_create_verification(
        &self,
        _data: &better_auth_core::wire::VerificationView,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<()> {
        let context = DatabaseHookContext {
            config: ctx.config,
            request: ctx.request.clone(),
            transaction: ctx.transaction,
        };
        self.0.after_create_verification(_data, &context).await
    }

    async fn before_update_verification(
        &self,
        _id: &str,
        _data: &VerificationUpdate,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<VerificationUpdate>> {
        let context = DatabaseHookContext {
            config: ctx.config,
            request: ctx.request.clone(),
            transaction: ctx.transaction,
        };
        self.0.before_update_verification(_data, &context).await
    }

    async fn after_update_verification(
        &self,
        _data: Option<&better_auth_core::wire::VerificationView>,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<()> {
        let context = DatabaseHookContext {
            config: ctx.config,
            request: ctx.request.clone(),
            transaction: ctx.transaction,
        };
        self.0.after_update_verification(_data, &context).await
    }

    async fn before_delete_verification(
        &self,
        _data: &better_auth_core::wire::VerificationView,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<HookControl> {
        let context = DatabaseHookContext {
            config: ctx.config,
            request: ctx.request.clone(),
            transaction: ctx.transaction,
        };
        Ok(
            match self.0.before_delete_verification(_data, &context).await? {
                DatabaseHookControl::Continue => HookControl::Continue,
                DatabaseHookControl::Cancel => HookControl::Cancel,
            },
        )
    }

    async fn after_delete_verification(
        &self,
        _data: &better_auth_core::wire::VerificationView,
        ctx: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<()> {
        let context = DatabaseHookContext {
            config: ctx.config,
            request: ctx.request.clone(),
            transaction: ctx.transaction,
        };
        self.0.after_delete_verification(_data, &context).await
    }
}

use better_auth_core::{AuthResult, AuthSchema, CreateVerification};

use super::{AuthError, HookTransaction, SeaOrmStore, SeaOrmTransaction};
use crate::schema::SeaOrmVerificationModel;
use better_auth_core::store::TypedTransactionFuture;

pub(super) enum Effect<S: AuthSchema> {
    UserCreated(S::User),
    UserUpdated(Option<S::User>),
    UserDeleted(S::User),
    AccountCreated(Box<better_auth_core::wire::AccountView>),
    SessionCreated(S::Session),
    Created(Box<better_auth_core::wire::VerificationView>),
    Deleted(Box<better_auth_core::wire::VerificationView>),
}

pub(super) enum PendingEffect<S: AuthSchema> {
    Database {
        effect: Box<Effect<S>>,
        request: Option<better_auth_core::hooks::RequestHookContext>,
    },
    External {
        effect: better_auth_core::store::TypedTransactionFuture<'static, ()>,
        request: Option<better_auth_core::hooks::RequestHookContext>,
    },
}

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    SeaOrmTransaction<'_, S, O, P>
where
    S: AuthSchema,
    S::Verification: SeaOrmVerificationModel,
    S::User: crate::schema::SeaOrmUserModel,
    S::Account: crate::schema::SeaOrmAccountModel,
    S::Session: crate::schema::SeaOrmSessionModel,
{
    pub(super) fn queue(&self, effect: Effect<S>) -> AuthResult<()> {
        self.effects
            .lock()
            .map_err(|_| AuthError::internal("Transaction hook queue lock poisoned"))?
            .push(PendingEffect::Database {
                effect: Box::new(effect),
                request: crate::hooks::current_request_hook_context(),
            });
        Ok(())
    }
    pub(super) async fn create_transaction_verification(
        &self,
        input: CreateVerification,
        writer: Option<better_auth_core::store::VerificationCreateWriter>,
    ) -> AuthResult<better_auth_core::wire::VerificationView> {
        let record = self
            .store
            .create_verification_with_connection(self.tx, Some((self.tx, self)), input)
            .await?;
        if let Some(writer) = writer {
            writer(record.clone()).await?;
        }
        self.queue(Effect::Created(Box::new(record.clone())))?;
        Ok(record)
    }

    pub(super) async fn delete_expired_transaction_verifications(&self) -> AuthResult<usize> {
        let (count, records) = self
            .store
            .delete_expired_verifications_with_connection(self.tx, Some((self.tx, self)))
            .await?;
        for record in records {
            self.queue(Effect::Deleted(Box::new(record)))?;
        }
        Ok(count)
    }
}

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S: AuthSchema,
    S::Verification: SeaOrmVerificationModel,
    S::User: crate::schema::SeaOrmUserModel,
    S::Account: crate::schema::SeaOrmAccountModel,
    S::Session: crate::schema::SeaOrmSessionModel,
{
    pub(super) async fn finish_transaction_effects(
        &self,
        effects: Vec<PendingEffect<S>>,
    ) -> AuthResult<()> {
        for pending in effects {
            let (effect, request) = match pending {
                PendingEffect::External { effect, request } => {
                    match request {
                        Some(request) => {
                            better_auth_core::hooks::with_request_hook_context_value(
                                request, effect,
                            )
                            .await?;
                        }
                        None => effect.await?,
                    }
                    continue;
                }
                PendingEffect::Database { effect, request } => (effect, request),
            };
            let mut context = self.hook_context(None);
            context.request = request;
            for hook in self.hooks() {
                match effect.as_ref() {
                    Effect::UserCreated(record) => better_auth_core::observability::database::with_database_hook(context.config, hook.hook_metadata(), better_auth_core::observability::database::DatabaseHook::AfterCreateUser, hook.after_create_user(record, &context)).await?,
                    Effect::UserUpdated(record) => {
                        better_auth_core::observability::database::with_database_hook(context.config, hook.hook_metadata(), better_auth_core::observability::database::DatabaseHook::AfterUpdateUser, hook.after_update_user(record.as_ref(), &context)).await?
                    }
                    Effect::UserDeleted(record) => better_auth_core::observability::database::with_database_hook(context.config, hook.hook_metadata(), better_auth_core::observability::database::DatabaseHook::AfterDeleteUser, hook.after_delete_user(record, &context)).await?,
                    Effect::AccountCreated(record) => {
                        better_auth_core::observability::database::with_database_hook(context.config, hook.hook_metadata(), better_auth_core::observability::database::DatabaseHook::AfterCreateAccount, hook.after_create_account(record, &context)).await?
                    }
                    Effect::SessionCreated(record) => {
                        better_auth_core::observability::database::with_database_hook(context.config, hook.hook_metadata(), better_auth_core::observability::database::DatabaseHook::AfterCreateSession, hook.after_create_session(record, &context)).await?
                    }
                    Effect::Created(record) => {
                        better_auth_core::observability::database::with_database_hook(context.config, hook.hook_metadata(), better_auth_core::observability::database::DatabaseHook::AfterCreateVerification, hook.after_create_verification(record, &context)).await?
                    }
                    Effect::Deleted(record) => {
                        better_auth_core::observability::database::with_database_hook(context.config, hook.hook_metadata(), better_auth_core::observability::database::DatabaseHook::AfterDeleteVerification, hook.after_delete_verification(record, &context)).await?
                    }
                }
            }
        }
        Ok(())
    }
}

pub(super) async fn after_write<S: AuthSchema>(
    transaction: Option<HookTransaction<'_, S>>,
    effect: TypedTransactionFuture<'static, ()>,
) -> AuthResult<()> {
    match transaction {
        Some((_, transaction)) => transaction.queue_after_commit(effect),
        None => effect.await,
    }
}

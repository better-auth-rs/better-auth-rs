use super::SecondaryStore;
use crate::store::{
    AuthTransaction, BoxedTransactionValue, TransactionStore, TransactionWork,
    TypedTransactionFuture,
};
use crate::types::{CreateAccount, CreateSession, CreateUser};
use crate::{AuthResult, AuthSchema};
use async_trait::async_trait;
use std::sync::Arc;

struct Transaction<S: AuthSchema> {
    inner: Arc<dyn AuthTransaction<S>>,
    runtime: SecondaryStore<S>,
}

impl<S: AuthSchema> Transaction<S> {
    async fn create_session_with_storage(
        &self,
        input: CreateSession,
        deferred: bool,
    ) -> AuthResult<Option<crate::wire::SessionView>> {
        let transaction = (!deferred).then(|| self.inner.clone());
        let writer =
            self.runtime
                .session_create_writer(input.user_id.clone(), deferred, transaction);
        self.inner.create_session_with_writer(input, writer).await
    }
}

#[async_trait]
impl<S: AuthSchema> AuthTransaction<S> for Transaction<S> {
    async fn get_member_value(
        &self,
        organization_id: &crate::FieldValue,
        user_id: &crate::FieldValue,
    ) -> AuthResult<Option<crate::Member>> {
        self.inner.get_member_value(organization_id, user_id).await
    }
    async fn get_organization_by_id_value(
        &self,
        id: &crate::FieldValue,
    ) -> AuthResult<Option<crate::Organization>> {
        self.inner.get_organization_by_id_value(id).await
    }
    async fn get_team_value(&self, id: &crate::FieldValue) -> AuthResult<Option<crate::Team>> {
        self.inner.get_team_value(id).await
    }
    async fn count_organization_members_value(&self, id: &crate::FieldValue) -> AuthResult<i64> {
        self.inner.count_organization_members_value(id).await
    }
    async fn create_member(&self, input: crate::CreateMember) -> AuthResult<crate::Member> {
        self.inner.create_member(input).await
    }
    async fn add_team_member(
        &self,
        team_id: &crate::SchemaValue<String>,
        user_id: &str,
        maximum: Option<usize>,
    ) -> AuthResult<Option<crate::TeamMember>> {
        self.inner.add_team_member(team_id, user_id, maximum).await
    }
    async fn delete_member(&self, id: &str) -> AuthResult<()> {
        self.inner.delete_member(id).await
    }
    async fn delete_member_for_user(
        &self,
        id: &str,
        organization_id: &str,
        user_id: &str,
    ) -> AuthResult<()> {
        self.inner
            .delete_member_for_user(id, organization_id, user_id)
            .await
    }
    fn clone_handle(&self) -> Arc<dyn AuthTransaction<S>> {
        Arc::new(Self {
            inner: self.inner.clone(),
            runtime: self.runtime.clone(),
        })
    }
    async fn create_user_optional(
        &self,
        input: crate::CreateUser,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        self.inner.create_user_optional(input).await
    }
    async fn create_session_with_writer(
        &self,
        input: CreateSession,
        writer: Option<crate::store::SessionCreateWriter>,
    ) -> AuthResult<Option<crate::wire::SessionView>> {
        self.inner.create_session_with_writer(input, writer).await
    }

    async fn before_create_runtime_session_optional(
        &self,
        input: &mut crate::store::PreparedSessionCreate,
    ) -> AuthResult<bool> {
        self.inner
            .before_create_runtime_session_optional(input)
            .await
    }
    async fn create_session_optional(
        &self,
        input: crate::CreateSession,
    ) -> AuthResult<Option<crate::wire::SessionView>> {
        self.create_session_with_storage(input, false).await
    }

    fn queue_after_commit(&self, effect: TypedTransactionFuture<'static, ()>) -> AuthResult<()> {
        self.inner.queue_after_commit(effect)
    }

    async fn create_verification(
        &self,
        input: crate::CreateVerification,
    ) -> AuthResult<crate::wire::VerificationView> {
        let request = crate::hooks::current_request_hook_context();
        let verification = self
            .runtime
            .create_verification_in_transaction(input, Some(self.inner.as_ref()))
            .await?;
        if !self.runtime.database_verifications() {
            let runtime = self.runtime.clone();
            let created = verification.clone();
            self.inner.queue_after_commit(Box::pin(async move {
                runtime
                    .inner
                    .after_create_runtime_verification(&created, request)
                    .await
            }))?;
        }
        Ok(verification)
    }
    async fn create_verification_with_writer(
        &self,
        input: crate::CreateVerification,
        writer: Option<crate::store::VerificationCreateWriter>,
    ) -> AuthResult<crate::wire::VerificationView> {
        self.inner
            .create_verification_with_writer(input, writer)
            .await
    }
    async fn update_verification(
        &self,
        identifier: &str,
        update: crate::store::database_hooks::VerificationUpdate,
    ) -> AuthResult<Option<crate::wire::VerificationView>> {
        self.runtime
            .update_verification_in_transaction(identifier, update, Some(self.inner.as_ref()))
            .await
    }
    async fn get_verification_including_expired(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<crate::wire::VerificationView>> {
        self.runtime
            .find_verification_in_transaction(identifier, Some(self.inner.as_ref()))
            .await
    }
    async fn delete_expired_verifications(&self) -> AuthResult<usize> {
        self.inner.delete_expired_verifications().await
    }
    async fn consume_verification_including_expired(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<crate::wire::VerificationView>> {
        self.runtime
            .consume_verification_in_transaction(identifier, Some(self.inner.as_ref()))
            .await
    }
    async fn delete_verification_by_identifier(&self, identifier: &str) -> AuthResult<()> {
        self.runtime
            .delete_verification_in_transaction(identifier, Some(self.inner.as_ref()))
            .await
    }
    async fn get_user_by_id_field(
        &self,
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        self.inner.get_user_by_id_field(id).await
    }
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<crate::wire::UserView>> {
        self.inner.get_user_by_id(id).await
    }
    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<crate::wire::UserView>> {
        self.inner.get_user_by_email(email).await
    }
    async fn get_user_by_username(
        &self,
        username: &str,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        self.inner.get_user_by_username(username).await
    }
    async fn update_user(
        &self,
        id: &str,
        update: crate::UpdateUser,
    ) -> AuthResult<crate::wire::UserView> {
        let user = self.inner.update_user(id, update).await?;
        self.runtime
            .queue_user_session_refresh(Some(user.clone()), Some(self.inner.as_ref()))
            .await?;
        Ok(user)
    }
    async fn update_user_optional(
        &self,
        id: &str,
        update: crate::UpdateUser,
    ) -> AuthResult<Option<crate::UserView>> {
        self.update_user_by_id_value(&crate::FieldValue::from(id), update)
            .await
    }
    async fn update_user_by_id_value(
        &self,
        id: &crate::FieldValue,
        update: crate::UpdateUser,
    ) -> AuthResult<Option<crate::UserView>> {
        let user = self.inner.update_user_by_id_value(id, update).await?;
        self.runtime
            .queue_user_session_refresh(user.clone(), Some(self.inner.as_ref()))
            .await?;
        Ok(user)
    }
    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        if self.runtime.storage.is_none() {
            return self.inner.delete_user(id).await;
        }
        let sessions = self.runtime.references(id).await?;
        if self
            .inner
            .delete_user_optional(id, self.runtime.database_sessions())
            .await?
            .is_some()
        {
            self.runtime
                .queue_cached_user_session_deletion(
                    id.to_owned(),
                    sessions,
                    Some(self.inner.as_ref()),
                )
                .await?;
        }
        Ok(())
    }

    async fn delete_user_optional(
        &self,
        id: &str,
        delete_database_sessions: bool,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        self.inner
            .delete_user_optional(id, delete_database_sessions)
            .await
    }
    fn passkey_storage(&self) -> crate::PasskeyStorage {
        self.inner.passkey_storage()
    }
    async fn create_passkey(&self, input: crate::CreatePasskey) -> AuthResult<crate::Passkey> {
        self.inner.create_passkey(input).await
    }
    async fn create_user(&self, input: CreateUser) -> AuthResult<crate::wire::UserView> {
        self.inner.create_user(input).await
    }
    async fn create_account(&self, input: CreateAccount) -> AuthResult<crate::wire::AccountView> {
        self.inner.create_account(input).await
    }
    async fn create_session(&self, input: CreateSession) -> AuthResult<crate::wire::SessionView> {
        self.create_session_with_storage(input, false)
            .await?
            .ok_or_else(|| {
                crate::AuthError::forbidden("session creation cancelled by database hook")
            })
    }
    async fn create_session_with_deferred_secondary(
        &self,
        input: CreateSession,
    ) -> AuthResult<crate::wire::SessionView> {
        self.create_session_with_storage(input, true)
            .await?
            .ok_or_else(|| {
                crate::AuthError::forbidden("session creation cancelled by database hook")
            })
    }
}

#[async_trait]
impl<S: AuthSchema> TransactionStore<S> for SecondaryStore<S> {
    async fn transaction_boxed(
        &self,
        work: Box<TransactionWork<S>>,
    ) -> AuthResult<BoxedTransactionValue> {
        if let Some(validation) = &self.schema_validation {
            validation.check_runtime().await?;
        }
        let runtime = self.clone();
        self.inner
            .transaction_boxed(Box::new(move |inner| {
                Box::pin(async move {
                    let validation = runtime.schema_validation.clone();
                    let operation = async move {
                        work(&Transaction {
                            inner: inner.clone_handle(),
                            runtime,
                        })
                        .await
                    };
                    if let Some(validation) = validation {
                        validation.in_transaction(operation).await
                    } else {
                        operation.await
                    }
                })
            }))
            .await
    }
}

#[async_trait]
impl<S: AuthSchema> crate::store::JwksStore for Transaction<S> {
    async fn create_jwk_record(&self, input: crate::FieldMap) -> AuthResult<crate::FieldMap> {
        self.inner.create_jwk_record(input).await
    }
    async fn get_jwk_record(
        &self,
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<Option<crate::FieldMap>> {
        self.inner.get_jwk_record(id).await
    }
    async fn update_jwk_record(
        &self,
        id: &crate::SchemaValue<String>,
        input: crate::FieldMap,
    ) -> AuthResult<Option<crate::FieldMap>> {
        self.inner.update_jwk_record(id, input).await
    }
    async fn delete_jwk_record(&self, id: &crate::SchemaValue<String>) -> AuthResult<()> {
        self.inner.delete_jwk_record(id).await
    }
    async fn list_jwk_records(&self) -> AuthResult<Vec<crate::FieldMap>> {
        self.inner.list_jwk_records().await
    }
}

#[async_trait]
impl<S: AuthSchema> crate::store::WalletStore for Transaction<S> {
    async fn create_wallet_address_record(
        &self,
        input: crate::FieldMap,
    ) -> AuthResult<crate::FieldMap> {
        self.inner.create_wallet_address_record(input).await
    }
    async fn get_wallet_address_record(
        &self,
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<Option<crate::FieldMap>> {
        self.inner.get_wallet_address_record(id).await
    }
    async fn update_wallet_address_record(
        &self,
        id: &crate::SchemaValue<String>,
        input: crate::FieldMap,
    ) -> AuthResult<Option<crate::FieldMap>> {
        self.inner.update_wallet_address_record(id, input).await
    }
    async fn delete_wallet_address_record(
        &self,
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<()> {
        self.inner.delete_wallet_address_record(id).await
    }
    async fn get_wallet_address_value(
        &self,
        address: &crate::FieldValue,
        chain_id: Option<&crate::FieldValue>,
    ) -> AuthResult<Option<crate::WalletAddress>> {
        self.inner.get_wallet_address_value(address, chain_id).await
    }
}

#[async_trait]
impl<S: AuthSchema> crate::store::DeviceCodeStore for Transaction<S> {
    async fn create_device_code_record(
        &self,
        fields: crate::FieldMap,
    ) -> AuthResult<crate::FieldMap> {
        self.inner.create_device_code_record(fields).await
    }
    async fn get_device_code_record(
        &self,
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<Option<crate::FieldMap>> {
        self.inner.get_device_code_record(id).await
    }
    async fn update_device_code_record(
        &self,
        id: &crate::SchemaValue<String>,
        fields: crate::FieldMap,
    ) -> AuthResult<Option<crate::FieldMap>> {
        self.inner.update_device_code_record(id, fields).await
    }

    async fn create_device_code(
        &self,
        input: crate::CreateDeviceCode,
    ) -> AuthResult<crate::DeviceCode> {
        self.inner.create_device_code(input).await
    }
    async fn get_device_code_by_device_code(
        &self,
        device_code: &str,
    ) -> AuthResult<Option<crate::DeviceCode>> {
        self.inner.get_device_code_by_device_code(device_code).await
    }
    async fn get_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> AuthResult<Option<crate::DeviceCode>> {
        self.inner.get_device_code_by_user_code(user_code).await
    }
    async fn update_device_code(
        &self,
        id: &crate::SchemaValue<String>,
        update: crate::UpdateDeviceCode,
    ) -> AuthResult<crate::DeviceCode> {
        self.inner.update_device_code(id, update).await
    }
    async fn update_device_code_if_status(
        &self,
        id: &crate::SchemaValue<String>,
        current_status: &str,
        update: crate::UpdateDeviceCode,
    ) -> AuthResult<bool> {
        self.inner
            .update_device_code_if_status(id, current_status, update)
            .await
    }
    async fn claim_device_code(
        &self,
        id: &crate::SchemaValue<String>,
        user_id: &crate::SchemaValue<String>,
    ) -> AuthResult<bool> {
        self.inner.claim_device_code(id, user_id).await
    }
    async fn consume_device_code(
        &self,
        expected: &crate::DeviceCode,
        ownership: &crate::DeviceCodeOwnership,
    ) -> AuthResult<Option<crate::DeviceCode>> {
        self.inner.consume_device_code(expected, ownership).await
    }
    async fn delete_device_code(&self, id: &crate::SchemaValue<String>) -> AuthResult<()> {
        self.inner.delete_device_code(id).await
    }
    async fn delete_device_code_if_status(
        &self,
        id: &crate::SchemaValue<String>,
        status: &str,
    ) -> AuthResult<bool> {
        self.inner.delete_device_code_if_status(id, status).await
    }
}

use super::*;
use crate::store::TeamStore;
use crate::store::schema::EntityRole;

pub(super) struct EphemeralTransaction {
    pub(super) store: EphemeralStore,
}

pub(super) struct PreparedTransactionCommit {
    store: EphemeralStore,
    consumed: Vec<super::device_codes::DeviceCodeConsumption>,
}

fn transaction_keys(base: &State, working: &State) -> Vec<String> {
    base.keys()
        .into_iter()
        .chain(working.keys())
        .collect::<indexmap::IndexSet<_>>()
        .into_iter()
        .collect()
}

pub(super) struct AtomicTransactionCommit {
    tables: Vec<(String, Option<super::table::ReconcilePlan<FieldMap>>)>,
    consumed: Vec<super::device_codes::DeviceCodeConsumption>,
}

fn validate_consumed_devices(
    op: &super::operation::MemoryOperation<'_>,
    consumed: &[super::device_codes::DeviceCodeConsumption],
) -> AuthResult<()> {
    if consumed.is_empty() {
        return Ok(());
    }
    let live = op.capture_table(EntityRole::DeviceCode)?;
    for consumed in consumed {
        if !consumed.unchanged(&live)? {
            return Err(AuthError::internal(
                "Device code changed before transaction commit",
            ));
        }
    }
    Ok(())
}

impl PreparedTransactionCommit {
    pub(super) fn plan(
        self,
        op: &super::operation::MemoryOperation<'_>,
        base: &State,
    ) -> AuthResult<AtomicTransactionCommit> {
        validate_consumed_devices(op, &self.consumed)?;
        let mut tables = Vec::new();
        let working_root = self.store.operation(|op| op.capture_state())?;
        for name in transaction_keys(base, &working_root) {
            let Some(working) = self
                .store
                .operation(|op| op.capture_physical_table(&name))?
            else {
                tables.push((name, None));
                continue;
            };
            let live = op.table_or_empty(&name)?;
            let empty = super::table::TableRef::new(self.store.operations.clone());
            let before = base.tables.get(&name).unwrap_or(&empty);
            let (_, plan) = live.reconcile_with_plan(before, &working)?;
            if !plan.is_empty() || op.capture_physical_table(&name)?.is_none() {
                tables.push((name, Some(plan)));
            }
        }
        Ok(AtomicTransactionCommit {
            tables,
            consumed: self.consumed,
        })
    }
}

impl AtomicTransactionCommit {
    pub(super) fn publish(self, op: &super::operation::MemoryOperation<'_>) -> AuthResult<()> {
        validate_consumed_devices(op, &self.consumed)?;
        let tables = self
            .tables
            .into_iter()
            .map(|(name, plan)| {
                let table = plan
                    .map(|plan| plan.apply(&op.table_or_empty(&name)?))
                    .transpose()?;
                Ok((name, table))
            })
            .collect::<AuthResult<Vec<_>>>()?;
        for (name, table) in tables {
            op.replace_physical_table(name, table)?;
        }
        Ok(())
    }
}

#[async_trait]
impl AuthTransaction<StatelessSchema> for EphemeralTransaction {
    async fn get_member_value(
        &self,
        organization_id: &Value,
        user_id: &Value,
    ) -> AuthResult<Option<crate::Member>> {
        self.store.get_member_value(organization_id, user_id).await
    }
    async fn get_organization_by_id_value(
        &self,
        id: &Value,
    ) -> AuthResult<Option<crate::Organization>> {
        self.store.get_organization_by_id_value(id).await
    }
    async fn get_team_value(&self, id: &Value) -> AuthResult<Option<crate::Team>> {
        self.store.get_team_value(id).await
    }
    async fn get_team_details_value(
        &self,
        team_id: &Value,
        organization_id: Option<&Value>,
        include_members: bool,
    ) -> AuthResult<Option<crate::store::TeamDetails>> {
        self.store
            .get_team_details_value(team_id, organization_id, include_members)
            .await
    }
    async fn count_organization_members_value(&self, id: &Value) -> AuthResult<i64> {
        self.store.count_organization_members_value(id).await
    }
    async fn create_member(&self, input: crate::CreateMember) -> AuthResult<crate::Member> {
        self.store.create_member(input).await
    }
    async fn add_team_member(
        &self,
        team_id: &crate::SchemaValue<String>,
        user_id: &str,
        maximum: Option<usize>,
    ) -> AuthResult<Option<crate::TeamMember>> {
        self.add_team_member_value(&team_id.field_value(), &user_id.into(), maximum)
            .await
    }
    async fn add_team_member_value(
        &self,
        team_id: &Value,
        user_id: &Value,
        maximum: Option<usize>,
    ) -> AuthResult<Option<crate::TeamMember>> {
        self.store
            .add_team_member_value(team_id, user_id, maximum)
            .await
    }
    async fn delete_member(&self, id: &str) -> AuthResult<()> {
        self.delete_member_value(&id.into()).await
    }
    async fn delete_member_value(&self, id: &Value) -> AuthResult<()> {
        self.store.delete_member_subject(id, None).await
    }
    async fn delete_member_for_user(
        &self,
        id: &str,
        organization_id: &str,
        user_id: &str,
    ) -> AuthResult<()> {
        self.delete_member_for_user_value(&id.into(), &organization_id.into(), &user_id.into())
            .await
    }
    async fn delete_member_for_user_value(
        &self,
        id: &Value,
        organization_id: &Value,
        user_id: &Value,
    ) -> AuthResult<()> {
        self.store
            .delete_member_subject(id, Some((organization_id, user_id)))
            .await
    }
    fn clone_handle(&self) -> Arc<dyn AuthTransaction<StatelessSchema>> {
        Arc::new(Self {
            store: self.store.clone(),
        })
    }
    async fn create_user_fields_optional(
        &self,
        input: crate::FieldMap,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        self.store.create_user_fields_optional(input).await
    }
    async fn update_session_with_writer_by_token_value(
        &self,
        token: &Value,
        update: crate::store::database_hooks::SessionUpdate,
        writer: Option<crate::store::SessionUpdateWriter>,
    ) -> AuthResult<Option<SessionView>> {
        self.store
            .update_session_with_writer_by_token_value(token, update, writer)
            .await
    }

    async fn before_create_runtime_session_optional(
        &self,
        input: &mut crate::store::PreparedSessionCreate,
    ) -> AuthResult<bool> {
        self.store
            .before_create_runtime_session_optional(input)
            .await
    }
    async fn create_session_optional(
        &self,
        input: crate::CreateSession,
    ) -> AuthResult<Option<crate::wire::SessionView>> {
        self.store.create_session_optional(input).await
    }

    async fn create_session_with_writer(
        &self,
        input: crate::CreateSession,
        writer: Option<crate::store::SessionCreateWriter>,
    ) -> AuthResult<Option<crate::wire::SessionView>> {
        self.store.create_session_with_writer(input, writer).await
    }

    fn queue_after_commit(
        &self,
        effect: crate::store::TypedTransactionFuture<'static, ()>,
    ) -> AuthResult<()> {
        let queue = self
            .store
            .pending_hooks
            .as_ref()
            .ok_or_else(|| AuthError::internal("Ephemeral transaction has no hook queue"))?;
        if let Some(queue) = queue.upgrade() {
            queue
                .lock()
                .map_err(|_| AuthError::internal("Ephemeral transaction hook queue lock poisoned"))?
                .push(PendingHook::External { effect });
        }
        Ok(())
    }

    async fn before_create_runtime_verification_optional(
        &self,
        input: &mut CreateVerification,
    ) -> AuthResult<bool> {
        self.store
            .before_create_runtime_verification_optional(input)
            .await
    }
    async fn before_create_runtime_verification(
        &self,
        input: &mut CreateVerification,
    ) -> AuthResult<()> {
        self.store.before_create_runtime_verification(input).await
    }
    async fn before_create_runtime_session(
        &self,
        input: &mut crate::store::PreparedSessionCreate,
    ) -> AuthResult<()> {
        self.store.before_create_runtime_session(input).await
    }
    async fn create_verification_optional(
        &self,
        input: CreateVerification,
    ) -> AuthResult<Option<VerificationView>> {
        self.store.create_verification_optional(input).await
    }
    async fn create_verification(&self, input: CreateVerification) -> AuthResult<VerificationView> {
        self.store.create_verification(input).await
    }
    async fn create_verification_with_writer(
        &self,
        input: CreateVerification,
        writer: Option<crate::store::VerificationCreateWriter>,
    ) -> AuthResult<Option<VerificationView>> {
        self.store
            .create_verification_with_writer(input, writer)
            .await
    }
    async fn update_verification(
        &self,
        identifier: &str,
        update: crate::store::database_hooks::VerificationUpdate,
    ) -> AuthResult<Option<VerificationView>> {
        self.store.update_verification(identifier, update).await
    }
    async fn get_verification_including_expired(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        self.store
            .get_verification_including_expired(identifier)
            .await
    }
    async fn delete_expired_verifications(&self) -> AuthResult<usize> {
        self.store.delete_expired_verifications().await
    }
    async fn consume_verification_including_expired(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        self.store
            .consume_verification_including_expired(identifier)
            .await
    }
    async fn delete_verification_by_identifier(&self, identifier: &str) -> AuthResult<()> {
        self.store
            .delete_verification_by_identifier(identifier)
            .await
    }
    async fn get_user_by_id_field(
        &self,
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        self.store.get_user_by_id_field(id).await
    }
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<UserView>> {
        self.store.get_user_by_id(id).await
    }
    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<UserView>> {
        self.store.get_user_by_email(email).await
    }
    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<UserView>> {
        self.store.get_user_by_username(username).await
    }
    async fn get_user_by_field_value(
        &self,
        field: &str,
        value: &Value,
    ) -> AuthResult<Option<UserView>> {
        self.store.get_user_by_field_value(field, value).await
    }
    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<UserView> {
        self.store.update_user(id, update).await
    }
    async fn update_user_optional(
        &self,
        id: &str,
        update: UpdateUser,
    ) -> AuthResult<Option<UserView>> {
        self.store.update_user_optional(id, update).await
    }
    async fn update_user_by_field_value(
        &self,
        field: &str,
        value: &crate::FieldValue,
        update: UpdateUser,
    ) -> AuthResult<Option<UserView>> {
        self.store
            .update_user_by_field_value(field, value, update)
            .await
    }
    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        self.store.delete_user(id).await
    }
    async fn delete_user_optional(
        &self,
        id: &str,
        delete_database_sessions: bool,
    ) -> AuthResult<Option<UserView>> {
        self.store
            .delete_user_optional(id, delete_database_sessions)
            .await
    }
    async fn delete_user_value(&self, id: &Value) -> AuthResult<()> {
        self.store.delete_user_value(id).await
    }
    async fn delete_user_optional_value(
        &self,
        id: &Value,
        delete_database_sessions: bool,
    ) -> AuthResult<Option<UserView>> {
        self.store
            .delete_user_optional_value(id, delete_database_sessions)
            .await
    }
    async fn delete_user_sessions_by_user_value(&self, user_id: &Value) -> AuthResult<()> {
        self.store.delete_user_sessions_by_user_value(user_id).await
    }
    async fn delete_user_sessions_optional_value(
        &self,
        user_id: &Value,
        preserve: bool,
    ) -> AuthResult<Option<usize>> {
        self.store
            .delete_user_sessions_optional_value(user_id, preserve)
            .await
    }
    async fn delete_user_accounts_value(&self, user_id: &Value) -> AuthResult<()> {
        self.store.delete_user_accounts_value(user_id).await
    }

    fn passkey_storage(&self) -> crate::PasskeyStorage {
        self.store.passkey_storage()
    }
    async fn create_passkey_optional(
        &self,
        input: crate::CreatePasskey,
    ) -> AuthResult<Option<crate::Passkey>> {
        self.store.create_passkey_optional(input).await
    }

    async fn create_passkey(&self, input: CreatePasskey) -> AuthResult<Passkey> {
        self.store.create_passkey(input).await
    }
    async fn create_user(&self, input: CreateUser) -> AuthResult<UserView> {
        self.store.create_user(input).await
    }
    async fn create_account_optional(
        &self,
        input: CreateAccount,
    ) -> AuthResult<Option<crate::wire::AccountView>> {
        self.store.create_account_optional(input).await
    }
    async fn create_account(&self, input: CreateAccount) -> AuthResult<AccountView> {
        self.store.create_account(input).await
    }
    async fn update_accounts(
        &self,
        selectors: &FieldMap,
        update: UpdateAccount,
    ) -> AuthResult<Option<u64>> {
        self.store.update_accounts(selectors, update).await
    }
    async fn create_session(&self, input: CreateSession) -> AuthResult<SessionView> {
        self.store.create_session(input).await
    }
}

impl EphemeralStore {
    pub(super) fn begin_transaction(&self) -> AuthResult<(State, Self, Arc<PendingHookQueue>)> {
        let (base, working, devices) = self.operation(|op| {
            let mut base_context = crate::StructuredCloneContext::deferred();
            let base = op.structured_clone(&mut base_context)?;
            let mut devices = super::device_codes::DeviceCodeTransaction::default();
            let mut working_context = crate::StructuredCloneContext::deferred();
            let working = op.structured_clone_with_device_origins(
                &mut working_context,
                |live, isolated, before| {
                    devices.capture_origin(live, isolated, before);
                },
            )?;
            // Neither independent graph forms cycles until both snapshots are complete.
            base_context.publish();
            working_context.publish();
            Ok((base, working, devices))
        })?;
        let queue = Arc::new(Mutex::new(Vec::new()));
        let isolated = Self {
            config: self.config.clone(),
            model_fields: self.model_fields.clone(),
            state: Arc::new(Mutex::new(working)),
            operations: self.operations.clone(),
            rate_limit_operations: self.rate_limit_operations.clone(),
            verification_locks: self.verification_locks.clone(),
            device_code_transaction: Some(Arc::new(Mutex::new(devices))),
            session_config: self.session_config.clone(),
            passkey_storage: self.passkey_storage,
            organization_fields: Arc::new(RwLock::new(self.organization_fields()?)),
            hooks: self.hooks.clone(),
            pending_hooks: Some(Arc::downgrade(&queue)),
        };
        Ok((base, isolated, queue))
    }

    pub(super) fn begin_adapter_transaction(
        &self,
    ) -> AuthResult<(State, Self, Arc<PendingHookQueue>)> {
        let (base, mut isolated, queue) = self.begin_transaction()?;
        // Internal atomic snapshots share the adapter. Explicit adapter transactions construct a new runtime.
        isolated.model_fields = self.model_fields.fresh_runtime();
        Ok((base, isolated, queue))
    }

    pub(super) fn prepare_transaction_commit(&self) -> AuthResult<PreparedTransactionCommit> {
        let consumed = self
            .device_code_transaction
            .as_ref()
            .map(|consumed| {
                consumed
                    .lock()
                    .map(|transaction| transaction.consumed.clone())
                    .map_err(|_| {
                        AuthError::internal("Ephemeral device consumption write set poisoned")
                    })
            })
            .transpose()?
            .unwrap_or_default();
        Ok(PreparedTransactionCommit {
            store: self.clone(),
            consumed,
        })
    }

    pub(super) async fn drain_transaction_hooks(
        &self,
        pending_hooks: &Arc<PendingHookQueue>,
    ) -> AuthResult<()> {
        loop {
            let pending = std::mem::take(&mut *pending_hooks.lock().map_err(|_| {
                AuthError::internal("Ephemeral transaction hook queue lock poisoned")
            })?);
            if pending.is_empty() {
                break;
            }
            for hook in pending {
                self.run_after(hook).await?;
            }
        }
        Ok(())
    }

    pub(super) async fn commit_adapter_transaction(
        &self,
        base: State,
        isolated: Self,
        pending_hooks: Arc<PendingHookQueue>,
    ) -> AuthResult<()> {
        let committed = isolated.prepare_transaction_commit()?;
        self.operation(|op| {
            validate_consumed_devices(op, &committed.consumed)?;
            let working_root = committed.store.operation(|op| op.capture_state())?;
            let device_model = op.model_name(EntityRole::DeviceCode)?;
            for name in transaction_keys(&base, &working_root) {
                if name == device_model {
                    validate_consumed_devices(op, &committed.consumed)?;
                }
                let Some(working) = committed
                    .store
                    .operation(|op| op.capture_physical_table(&name))?
                else {
                    op.replace_physical_table(name, None)?;
                    continue;
                };
                let live = op.table_or_empty(&name)?;
                let empty = super::table::TableRef::new(self.operations.clone());
                let before = base.tables.get(&name).unwrap_or(&empty);
                let table = live.reconcile(before, &working)?;
                op.replace_physical_table(name, Some(table))?;
            }
            Ok(())
        })?;
        self.drain_transaction_hooks(&pending_hooks).await
    }

    pub(super) async fn commit_transaction(
        &self,
        base: State,
        isolated: Self,
        pending_hooks: Arc<PendingHookQueue>,
    ) -> AuthResult<()> {
        let committed = isolated.prepare_transaction_commit()?;
        self.operation(|op| committed.plan(op, &base)?.publish(op))?;
        self.drain_transaction_hooks(&pending_hooks).await
    }
}

#[async_trait]
impl TransactionStore<StatelessSchema> for EphemeralStore {
    async fn transaction_boxed(
        &self,
        work: Box<crate::store::TransactionWork<StatelessSchema>>,
    ) -> AuthResult<crate::store::BoxedTransactionValue> {
        if self.pending_hooks.is_some() {
            return work(&EphemeralTransaction {
                store: self.clone(),
            })
            .await;
        }
        let (base, isolated, queue) = self.begin_adapter_transaction()?;
        let result = work(&EphemeralTransaction {
            store: isolated.clone(),
        })
        .await?;
        self.commit_adapter_transaction(base, isolated, queue)
            .await?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests;

#[async_trait]
impl crate::store::JwksStore for EphemeralTransaction {
    async fn get_jwk_value(
        &self,
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<crate::FieldValue> {
        self.store.get_jwk_value(id).await
    }
    async fn list_jwk_values(&self) -> AuthResult<crate::FieldValue> {
        self.store.list_jwk_values().await
    }
    async fn create_jwk_record(
        &self,
        input: crate::FieldMap,
    ) -> AuthResult<Option<crate::FieldMap>> {
        self.store.create_jwk_record(input).await
    }
    async fn get_jwk_record(
        &self,
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<Option<crate::FieldMap>> {
        self.store.get_jwk_record(id).await
    }
    async fn update_jwk_record(
        &self,
        id: &crate::SchemaValue<String>,
        input: crate::FieldMap,
    ) -> AuthResult<Option<crate::FieldMap>> {
        self.store.update_jwk_record(id, input).await
    }
    async fn delete_jwk_record(&self, id: &crate::SchemaValue<String>) -> AuthResult<()> {
        self.store.delete_jwk_record(id).await
    }
    async fn list_jwk_records(&self) -> AuthResult<Vec<crate::FieldMap>> {
        self.store.list_jwk_records().await
    }
}

#[async_trait]
impl crate::store::WalletStore for EphemeralTransaction {
    async fn create_wallet_address_record(
        &self,
        input: crate::FieldMap,
    ) -> AuthResult<Option<crate::FieldMap>> {
        self.store.create_wallet_address_record(input).await
    }
    async fn get_wallet_address_record(
        &self,
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<Option<crate::FieldMap>> {
        self.store.get_wallet_address_record(id).await
    }
    async fn update_wallet_address_record(
        &self,
        id: &crate::SchemaValue<String>,
        input: crate::FieldMap,
    ) -> AuthResult<Option<crate::FieldMap>> {
        self.store.update_wallet_address_record(id, input).await
    }
    async fn delete_wallet_address_record(
        &self,
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<()> {
        self.store.delete_wallet_address_record(id).await
    }
    async fn get_wallet_address_value(
        &self,
        address: &crate::FieldValue,
        chain_id: Option<&crate::FieldValue>,
    ) -> AuthResult<Option<crate::WalletAddress>> {
        self.store.get_wallet_address_value(address, chain_id).await
    }
}

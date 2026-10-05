use super::*;
use crate::store::TeamStore;

pub(super) struct EphemeralTransaction {
    pub(super) store: EphemeralStore,
}

#[async_trait]
impl AuthTransaction<StatelessSchema> for EphemeralTransaction {
    async fn get_member_value(
        &self,
        organization_id: &serde_json::Value,
        user_id: &serde_json::Value,
    ) -> AuthResult<Option<crate::Member>> {
        self.store.get_member_value(organization_id, user_id).await
    }
    async fn get_organization_by_id_value(
        &self,
        id: &serde_json::Value,
    ) -> AuthResult<Option<crate::Organization>> {
        self.store.get_organization_by_id_value(id).await
    }
    async fn get_team_value(&self, id: &serde_json::Value) -> AuthResult<Option<crate::Team>> {
        self.store.get_team_value(id).await
    }
    async fn count_organization_members_value(&self, id: &serde_json::Value) -> AuthResult<i64> {
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
        self.store.add_team_member(team_id, user_id, maximum).await
    }
    async fn delete_member(&self, id: &str) -> AuthResult<()> {
        self.store.delete_member_subject(id, None).await
    }
    async fn delete_member_for_user(
        &self,
        id: &str,
        organization_id: &str,
        user_id: &str,
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
    async fn create_user_optional(
        &self,
        input: crate::CreateUser,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        self.store.create_user_optional(input).await
    }
    async fn before_create_runtime_session_optional(
        &self,
        input: &mut crate::CreateSession,
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

    async fn before_create_runtime_verification(
        &self,
        input: &mut CreateVerification,
    ) -> AuthResult<()> {
        self.store.before_create_runtime_verification(input).await
    }
    async fn before_create_runtime_session(&self, input: &mut CreateSession) -> AuthResult<()> {
        self.store.before_create_runtime_session(input).await
    }
    async fn create_verification(&self, input: CreateVerification) -> AuthResult<VerificationView> {
        self.store.create_verification(input).await
    }
    async fn create_verification_with_writer(
        &self,
        input: CreateVerification,
        writer: Option<crate::store::VerificationCreateWriter>,
    ) -> AuthResult<VerificationView> {
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

    fn passkey_storage(&self) -> crate::PasskeyStorage {
        self.store.passkey_storage()
    }
    async fn create_passkey(&self, input: CreatePasskey) -> AuthResult<Passkey> {
        self.store.create_passkey(input).await
    }
    async fn create_user(&self, input: CreateUser) -> AuthResult<UserView> {
        self.store.create_user(input).await
    }
    async fn create_account(&self, input: CreateAccount) -> AuthResult<AccountView> {
        self.store.create_account(input).await
    }
    async fn create_session(&self, input: CreateSession) -> AuthResult<SessionView> {
        self.store.create_session(input).await
    }
}

fn merge_map<T: Clone + PartialEq>(
    live: &mut IndexMap<String, T>,
    base: &IndexMap<String, T>,
    working: IndexMap<String, T>,
) {
    live.retain(|id, _| !base.contains_key(id) || working.contains_key(id));
    for (id, row) in live.iter_mut() {
        if let Some(changed) = working.get(id)
            && base.get(id) != Some(changed)
        {
            row.clone_from(changed);
        }
    }
    for (id, row) in working {
        if !base.contains_key(&id) && !live.contains_key(&id) {
            let _ = live.insert(id, row);
        }
    }
}

impl State {
    fn merge(&mut self, base: &Self, working: Self) -> AuthResult<()> {
        self.users.merge(&base.users, working.users)?;
        self.accounts.merge(&base.accounts, working.accounts)?;
        self.sessions.merge(&base.sessions, working.sessions)?;
        self.verifications
            .merge(&base.verifications, working.verifications)?;
        self.organizations
            .merge(&base.organizations, working.organizations)?;
        self.members.merge(&base.members, working.members)?;
        self.invitations
            .merge(&base.invitations, working.invitations)?;
        self.teams.merge(&base.teams, working.teams)?;
        self.organization_roles
            .merge(&base.organization_roles, working.organization_roles)?;
        self.two_factors
            .merge(&base.two_factors, working.two_factors)?;
        self.device_codes
            .merge(&base.device_codes, working.device_codes)?;
        self.api_keys.merge(&base.api_keys, working.api_keys)?;
        self.passkeys.merge(&base.passkeys, working.passkeys)?;
        merge_map(
            &mut self.rate_limits,
            &base.rate_limits,
            working.rate_limits,
        );
        self.team_members
            .merge(&base.team_members, working.team_members)?;
        self.jwks.merge(&base.jwks, working.jwks)?;
        self.wallets.merge(&base.wallets, working.wallets)?;
        Ok(())
    }
}

impl EphemeralStore {
    pub(super) fn begin_transaction(&self) -> AuthResult<(State, Self, Arc<PendingHookQueue>)> {
        let base = self.lock()?.deep_clone()?;
        let queue = Arc::new(Mutex::new(Vec::new()));
        let isolated = Self {
            config: self.config.clone(),
            model_fields: self.model_fields.clone(),
            state: Arc::new(Mutex::new(base.deep_clone()?)),
            verification_locks: self.verification_locks.clone(),
            device_code_consumptions: Some(Arc::default()),
            session_config: self.session_config.clone(),
            organization_fields: Arc::new(RwLock::new(self.organization_fields()?)),
            hooks: self.hooks.clone(),
            pending_hooks: Some(Arc::downgrade(&queue)),
        };
        Ok((base, isolated, queue))
    }

    pub(super) async fn commit_transaction(
        &self,
        base: State,
        isolated: Self,
        pending_hooks: Arc<PendingHookQueue>,
    ) -> AuthResult<()> {
        let committed = isolated.lock()?.clone();
        let consumed = isolated
            .device_code_consumptions
            .as_ref()
            .map(|consumed| {
                consumed.lock().map(|rows| rows.clone()).map_err(|_| {
                    AuthError::internal("Ephemeral device consumption write set poisoned")
                })
            })
            .transpose()?
            .unwrap_or_default();
        {
            let mut live = self.lock()?;
            for consumed in &consumed {
                let Some(original) = base
                    .device_codes
                    .find(|row| row.id == consumed.id && row.device_code == consumed.device_code)?
                else {
                    // A code created and consumed within this transaction has no live baseline.
                    continue;
                };
                if live
                    .device_codes
                    .find(|row| super::device_codes::same_bindings(row, &original))?
                    .is_none()
                {
                    return Err(AuthError::internal(
                        "Device code changed before transaction commit",
                    ));
                }
            }
            live.merge(&base, committed)?;
        }
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
        let (base, isolated, queue) = self.begin_transaction()?;
        let result = work(&EphemeralTransaction {
            store: isolated.clone(),
        })
        .await?;
        self.commit_transaction(base, isolated, queue).await?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests;

#[async_trait]
impl crate::store::JwksStore for EphemeralTransaction {
    async fn get_jwk(&self, id: &str) -> AuthResult<Option<crate::Jwk>> {
        crate::store::JwksStore::get_jwk(&self.store, id).await
    }
    async fn list_jwks(&self) -> AuthResult<Vec<crate::Jwk>> {
        crate::store::JwksStore::list_jwks(&self.store).await
    }
    async fn create_jwk(&self, input: crate::CreateJwk) -> AuthResult<crate::Jwk> {
        crate::store::JwksStore::create_jwk(&self.store, input).await
    }
}

#[async_trait]
impl crate::store::WalletStore for EphemeralTransaction {
    async fn get_wallet_address(
        &self,
        address: &str,
        chain_id: Option<i64>,
    ) -> AuthResult<Option<crate::WalletAddress>> {
        crate::store::WalletStore::get_wallet_address(&self.store, address, chain_id).await
    }

    async fn create_wallet_address(
        &self,
        input: crate::CreateWalletAddress,
    ) -> AuthResult<crate::WalletAddress> {
        crate::store::WalletStore::create_wallet_address(&self.store, input).await
    }
}

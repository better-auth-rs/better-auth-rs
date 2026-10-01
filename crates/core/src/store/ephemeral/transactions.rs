use super::*;

pub(super) struct EphemeralTransaction<'a> {
    pub(super) store: &'a EphemeralStore,
}

#[async_trait]
impl AuthTransaction<StatelessSchema> for EphemeralTransaction<'_> {
    fn queue_after_commit(
        &self,
        effect: crate::store::TypedTransactionFuture<'static, ()>,
    ) -> AuthResult<()> {
        self.store
            .pending_hooks
            .as_ref()
            .ok_or_else(|| AuthError::internal("Ephemeral transaction has no hook queue"))?
            .lock()
            .map_err(|_| AuthError::internal("Ephemeral transaction hook queue lock poisoned"))?
            .push(PendingHook::External {
                effect,
                request: crate::hooks::current_request_hook_context(),
            });
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

fn merge_rows<T: Clone + PartialEq>(
    live: &mut Vec<T>,
    base: &[T],
    working: Vec<T>,
    id: impl Fn(&T) -> Option<String>,
) {
    let base: HashMap<_, _> = base.iter().map(|row| (id(row), row)).collect();
    let changed: HashMap<_, _> = working.iter().map(|row| (id(row), row)).collect();
    let mut placed = std::collections::HashSet::new();
    live.retain_mut(|row| {
        let key = id(row);
        if base.contains_key(&key) && !changed.contains_key(&key) {
            return false;
        }
        if let Some(replacement) = changed.get(&key)
            && base.get(&key) != Some(replacement)
        {
            row.clone_from(replacement);
        }
        let _ = placed.insert(key);
        true
    });
    for row in working {
        let key = id(&row);
        if !base.contains_key(&key) && !placed.contains(&key) {
            live.push(row);
        }
    }
}

impl State {
    fn merge(&mut self, base: &Self, working: Self) {
        merge_rows(
            self.users.as_mut_vec(),
            &base.users,
            working.users.into_vec(),
            |row| row.id.as_str().map(str::to_owned),
        );
        merge_rows(
            &mut self.accounts,
            &base.accounts,
            working.accounts,
            |row| row.get("id").and_then(Value::as_str).map(str::to_owned),
        );
        let mut sessions: Vec<_> = std::mem::take(&mut self.sessions).into_values().collect();
        let base_sessions: Vec<_> = base.sessions.values().cloned().collect();
        merge_rows(
            &mut sessions,
            &base_sessions,
            working.sessions.into_values().collect(),
            |row| row.id.as_str().map(str::to_owned),
        );
        self.sessions = sessions
            .into_iter()
            .map(|row| (row.token.clone(), row))
            .collect();
        merge_rows(
            &mut self.verifications,
            &base.verifications,
            working.verifications,
            |row| row.get("id").and_then(Value::as_str).map(str::to_owned),
        );
        merge_rows(
            self.organizations.as_mut_vec(),
            &base.organizations,
            working.organizations.into_vec(),
            |row| row.id.as_str().map(str::to_owned),
        );
        merge_rows(
            self.members.as_mut_vec(),
            &base.members,
            working.members.into_vec(),
            |row| row.id.as_str().map(str::to_owned),
        );
        merge_rows(
            self.invitations.as_mut_vec(),
            &base.invitations,
            working.invitations.into_vec(),
            |row| row.id.as_str().map(str::to_owned),
        );
        merge_rows(
            self.teams.as_mut_vec(),
            &base.teams,
            working.teams.into_vec(),
            |row| row.id.as_str().map(str::to_owned),
        );
        merge_rows(
            self.organization_roles.as_mut_vec(),
            &base.organization_roles,
            working.organization_roles.into_vec(),
            |row| row.id.as_str().map(str::to_owned),
        );
        merge_rows(
            self.two_factors.as_mut_vec(),
            &base.two_factors,
            working.two_factors.into_vec(),
            |row| row.id.as_str().map(str::to_owned),
        );
        merge_rows(
            self.device_codes.as_mut_vec(),
            &base.device_codes,
            working.device_codes.into_vec(),
            |row| row.id.as_str().map(str::to_owned),
        );
        merge_rows(
            self.api_keys.as_mut_vec(),
            &base.api_keys,
            working.api_keys.into_vec(),
            |row| row.id.as_str().map(str::to_owned),
        );
        merge_rows(
            self.passkeys.as_mut_vec(),
            &base.passkeys,
            working.passkeys.into_vec(),
            |row| row.id.as_str().map(str::to_owned),
        );
        merge_map(
            &mut self.rate_limits,
            &base.rate_limits,
            working.rate_limits,
        );
        merge_rows(
            &mut self.team_members,
            &base.team_members,
            working.team_members,
            |row| row.id.as_str().map(str::to_owned),
        );
        merge_rows(&mut self.jwks, &base.jwks, working.jwks, |row| {
            row.id.as_str().map(str::to_owned)
        });
        merge_rows(&mut self.wallets, &base.wallets, working.wallets, |row| {
            row.id.as_str().map(str::to_owned)
        });
    }
}

impl EphemeralStore {
    pub(super) fn begin_transaction(&self) -> AuthResult<(State, Self)> {
        let base = self.lock()?.clone();
        let isolated = Self {
            config: self.config.clone(),
            state: Arc::new(Mutex::new(base.clone())),
            verification_locks: self.verification_locks.clone(),
            session_config: self.session_config.clone(),
            organization_fields: RwLock::new(self.organization_fields()?),
            hooks: self.hooks.clone(),
            pending_hooks: Some(Arc::new(Mutex::new(Vec::new()))),
        };
        Ok((base, isolated))
    }

    pub(super) async fn commit_transaction(&self, base: State, isolated: Self) -> AuthResult<()> {
        let committed = Arc::try_unwrap(isolated.state)
            .map_err(|_| AuthError::internal("Ephemeral transaction state is still shared"))?
            .into_inner()
            .map_err(|_| AuthError::internal("Ephemeral transaction state lock poisoned"))?;
        let pending_hooks = isolated
            .pending_hooks
            .ok_or_else(|| AuthError::internal("Ephemeral transaction has no hook queue"))?;
        let pending =
            std::mem::take(&mut *pending_hooks.lock().map_err(|_| {
                AuthError::internal("Ephemeral transaction hook queue lock poisoned")
            })?);
        self.lock()?.merge(&base, committed);
        for hook in pending {
            self.run_after(hook).await?;
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
            return work(&EphemeralTransaction { store: self }).await;
        }
        let (base, isolated) = self.begin_transaction()?;
        let result = work(&EphemeralTransaction { store: &isolated }).await?;
        self.commit_transaction(base, isolated).await?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests;

#[async_trait]
impl crate::store::JwksStore for EphemeralTransaction<'_> {
    async fn get_jwk(&self, id: &str) -> AuthResult<Option<crate::Jwk>> {
        crate::store::JwksStore::get_jwk(self.store, id).await
    }
    async fn list_jwks(&self) -> AuthResult<Vec<crate::Jwk>> {
        crate::store::JwksStore::list_jwks(self.store).await
    }
    async fn create_jwk(&self, input: crate::CreateJwk) -> AuthResult<crate::Jwk> {
        crate::store::JwksStore::create_jwk(self.store, input).await
    }
}

use super::*;
use better_auth_core::store::*;
use better_auth_core::types::*;

pub(super) struct ClaimStore<S: AuthSchema> {
    pub(super) inner: Arc<dyn AuthStore<S>>,
    pub(super) state: Arc<State>,
}

#[better_auth_core::__test_store_forward("../core/src/store/runtime.rs")]
impl<S: AuthSchema> RuntimeStore<S> for ClaimStore<S> {
    fn with_runtime(
        &self,
        config: Arc<better_auth_core::AuthConfig>,
        hooks: Vec<Arc<dyn database_hooks::DatabaseHooks<S>>>,
        fields: better_auth_core::plugin_runtime::ModelFields,
    ) -> AuthResult<Arc<dyn AuthStore<S>>> {
        Ok(Arc::new(Self {
            inner: self.inner.with_runtime(config, hooks, fields)?,
            state: self.state.clone(),
        }))
    }
}

#[better_auth_core::__test_store_forward("../core/src/store/mod.rs")]
impl<S: AuthSchema> UserStore<S> for ClaimStore<S> {
    async fn get_user_by_email(
        &self,
        email: &str,
    ) -> AuthResult<Option<better_auth_core::UserView>> {
        self.state.record("lookup");
        let count = self.state.lookups.fetch_add(1, Ordering::SeqCst) + 1;
        if self.state.mode == "initial-query-error" && count == 1
            || self.state.mode == "retry-query-error" && count == 2
        {
            return Err(self.state.error("lookup"));
        }
        self.inner.get_user_by_email(email).await
    }

    async fn create_user_fields_optional(
        &self,
        input: FieldMap,
    ) -> AuthResult<Option<better_auth_core::UserView>> {
        self.state.record("create");
        let count = self.state.creates.fetch_add(1, Ordering::SeqCst) + 1;
        if self.state.mode.starts_with("create-error") || self.state.mode == "retry-query-error" {
            return Err(self.state.error("create"));
        }
        let created = self.inner.create_user_fields_optional(input).await?;
        *self.state.created_users.lock().unwrap() =
            self.state.raw.storage_rows(EntityRole::User)?;
        if self.state.mode == "retry-success" && count == 1 {
            return Err(self.state.error("create"));
        }
        Ok(created)
    }
}

#[better_auth_core::__test_store_forward("../core/src/store/mod.rs")]
impl<S: AuthSchema> VerificationStore<S> for ClaimStore<S> {
    async fn reserve_verification_value(&self, input: CreateVerification) -> AuthResult<bool> {
        assert_eq!(input.identifier.field_value(), FieldValue::from(CLAIM));
        self.state.record("reserve");
        if self.state.mode == "reserve-before" {
            return Err(self.state.error("reserve"));
        }
        let reserved = self.inner.reserve_verification_value(input).await?;
        *self.state.claimed.lock().unwrap() =
            self.state.raw.storage_rows(EntityRole::Verification)?;
        if self.state.mode == "reserve-after" {
            return Err(self.state.error("reserve"));
        }
        Ok(reserved)
    }

    async fn consume_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<better_auth_core::VerificationView>> {
        self.state.record(if identifier == CLAIM {
            "cleanup"
        } else {
            "nonce"
        });
        if identifier == CLAIM && self.state.mode.ends_with("cleanup-before") {
            return Err(self.state.error("cleanup"));
        }
        let consumed = self
            .inner
            .consume_verification_by_identifier(identifier)
            .await?;
        if identifier == CLAIM && self.state.mode.ends_with("cleanup-after") {
            return Err(self.state.error("cleanup"));
        }
        Ok(consumed)
    }
}

#[better_auth_core::__test_store_forward("../core/src/store/mod.rs")]
impl<S: AuthSchema> SessionStore<S> for ClaimStore<S> {}
#[better_auth_core::__test_store_forward("../core/src/store/mod.rs")]
impl<S: AuthSchema> AccountStore<S> for ClaimStore<S> {}
#[better_auth_core::__test_store_forward("../core/src/store/mod.rs")]
impl<S: AuthSchema> OrganizationStore for ClaimStore<S> {}
#[better_auth_core::__test_store_forward("../core/src/store/mod.rs")]
impl<S: AuthSchema> TeamStore for ClaimStore<S> {}
#[better_auth_core::__test_store_forward("../core/src/store/mod.rs")]
impl<S: AuthSchema> OrganizationRoleStore for ClaimStore<S> {}
#[better_auth_core::__test_store_forward("../core/src/store/mod.rs")]
impl<S: AuthSchema> MemberStore for ClaimStore<S> {}
#[better_auth_core::__test_store_forward("../core/src/store/mod.rs")]
impl<S: AuthSchema> InvitationStore for ClaimStore<S> {}
#[better_auth_core::__test_store_forward("../core/src/store/mod.rs")]
impl<S: AuthSchema> TwoFactorStore for ClaimStore<S> {}
#[better_auth_core::__test_store_forward("../core/src/store/mod.rs")]
impl<S: AuthSchema> ApiKeyStore for ClaimStore<S> {}
#[better_auth_core::__test_store_forward("../core/src/store/mod.rs")]
impl<S: AuthSchema> DeviceCodeStore for ClaimStore<S> {}
#[better_auth_core::__test_store_forward("../core/src/store/mod.rs")]
impl<S: AuthSchema> PasskeyStore for ClaimStore<S> {}
#[better_auth_core::__test_store_forward("../core/src/store/mod.rs")]
impl<S: AuthSchema> WalletStore for ClaimStore<S> {}
#[better_auth_core::__test_store_forward("../core/src/store/mod.rs")]
impl<S: AuthSchema> JwksStore for ClaimStore<S> {}
#[better_auth_core::__test_store_forward("../core/src/store/mod.rs")]
impl<S: AuthSchema> RateLimitStore for ClaimStore<S> {}
#[better_auth_core::__test_store_forward("../core/src/store/mod.rs")]
impl<S: AuthSchema> TransactionStore<S> for ClaimStore<S> {}

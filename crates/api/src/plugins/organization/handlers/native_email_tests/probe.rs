use super::*;
use better_auth_core::{store::*, types::*};
use std::sync::{
    Mutex, OnceLock,
    atomic::{AtomicU64, Ordering},
};
use tracing::{Subscriber, field::Visit, instrument::WithSubscriber};

#[derive(Clone)]
pub(super) struct Call {
    pub(super) operation: &'static str,
    pub(super) arguments: Vec<FieldValue>,
}

#[derive(Default)]
pub(super) struct State {
    calls: Mutex<Vec<Call>>,
    queries: Mutex<Vec<String>>,
    next_span: AtomicU64,
}

impl State {
    fn call(&self, operation: &'static str, arguments: Vec<FieldValue>) -> AuthResult<()> {
        shared::lock(&self.calls)?.push(Call {
            operation,
            arguments,
        });
        Ok(())
    }

    pub(super) fn calls(&self) -> AuthResult<Vec<Call>> {
        Ok(shared::lock(&self.calls)?.clone())
    }

    pub(super) fn queries(&self) -> AuthResult<Vec<String>> {
        Ok(shared::lock(&self.queries)?.clone())
    }

    pub(super) async fn capture<T>(self: &Arc<Self>, future: impl Future<Output = T>) -> T {
        static BASE: OnceLock<tracing::Dispatch> = OnceLock::new();
        // Two retained dispatchers prevent unscoped tasks from disabling the shared callsite cache.
        let _ = BASE
            .get_or_init(|| tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default()));
        future.with_subscriber(self.clone()).await
    }
}

#[derive(Default)]
struct SpanName(Option<String>);

impl Visit for SpanName {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "otel.name" && value.starts_with("db ") {
            self.0 = Some(value.into());
        }
    }
    fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
}

impl Subscriber for State {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target() == "better-auth"
    }

    #[expect(
        clippy::expect_used,
        reason = "Subscriber callbacks cannot propagate errors; poisoning must fail the query contract."
    )]
    fn new_span(&self, attributes: &tracing::span::Attributes<'_>) -> tracing::Id {
        let mut name = SpanName::default();
        attributes.record(&mut name);
        if let Some(name) = name.0 {
            shared::lock(&self.queries)
                .expect("Query observation lock")
                .push(name);
        }
        tracing::Id::from_u64(self.next_span.fetch_add(1, Ordering::Relaxed) + 1)
    }

    fn record(&self, _: &tracing::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::Id, _: &tracing::Id) {}
    fn event(&self, _: &tracing::Event<'_>) {}
    fn enter(&self, _: &tracing::Id) {}
    fn exit(&self, _: &tracing::Id) {}
}

pub(super) struct Store<S: AuthSchema> {
    pub(super) inner: Arc<dyn AuthStore<S>>,
    pub(super) state: Arc<State>,
}

#[better_auth_core::__test_store_forward("../core/src/store/runtime.rs")]
impl<S: AuthSchema> RuntimeStore<S> for Store<S> {
    fn with_runtime(
        &self,
        config: Arc<AuthConfig>,
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
impl<S: AuthSchema> OrganizationStore for Store<S> {
    async fn get_organization_by_id_value(
        &self,
        id: &FieldValue,
    ) -> AuthResult<Option<Organization>> {
        self.state.call("organization", vec![id.clone()])?;
        self.inner.get_organization_by_id_value(id).await
    }
}

#[better_auth_core::__test_store_forward("../core/src/store/mod.rs")]
impl<S: AuthSchema> MemberStore for Store<S> {
    async fn get_member_with_user_value(
        &self,
        organization_id: &FieldValue,
        user_id: &FieldValue,
    ) -> AuthResult<Option<MemberUser>> {
        self.state
            .call("member", vec![organization_id.clone(), user_id.clone()])?;
        self.inner
            .get_member_with_user_value(organization_id, user_id)
            .await
    }
}

#[better_auth_core::__test_store_forward("../core/src/store/mod.rs")]
impl<S: AuthSchema> InvitationStore for Store<S> {
    async fn get_invitation_by_id(&self, id: &str) -> AuthResult<Option<Invitation>> {
        self.state.call("invitation", vec![id.into()])?;
        self.inner.get_invitation_by_id(id).await
    }

    async fn list_user_invitations_value(
        &self,
        email: &FieldValue,
    ) -> AuthResult<Vec<InvitationOrganization>> {
        self.state.call("list", vec![email.clone()])?;
        self.inner.list_user_invitations_value(email).await
    }
}

#[better_auth_core::__test_store_forward("../core/src/store/mod.rs")]
impl<S: AuthSchema> UserStore<S> for Store<S> {}
#[better_auth_core::__test_store_forward("../core/src/store/mod.rs")]
impl<S: AuthSchema> AccountStore<S> for Store<S> {}
#[better_auth_core::__test_store_forward("../core/src/store/mod.rs")]
impl<S: AuthSchema> SessionStore<S> for Store<S> {}
#[better_auth_core::__test_store_forward("../core/src/store/mod.rs")]
impl<S: AuthSchema> VerificationStore<S> for Store<S> {}
#[better_auth_core::__test_store_forward("../core/src/store/mod.rs")]
impl<S: AuthSchema> TeamStore for Store<S> {}
#[better_auth_core::__test_store_forward("../core/src/store/mod.rs")]
impl<S: AuthSchema> OrganizationRoleStore for Store<S> {}
#[better_auth_core::__test_store_forward("../core/src/store/mod.rs")]
impl<S: AuthSchema> TwoFactorStore for Store<S> {}
#[better_auth_core::__test_store_forward("../core/src/store/mod.rs")]
impl<S: AuthSchema> ApiKeyStore for Store<S> {}
#[better_auth_core::__test_store_forward("../core/src/store/mod.rs")]
impl<S: AuthSchema> DeviceCodeStore for Store<S> {}
#[better_auth_core::__test_store_forward("../core/src/store/mod.rs")]
impl<S: AuthSchema> PasskeyStore for Store<S> {}
#[better_auth_core::__test_store_forward("../core/src/store/mod.rs")]
impl<S: AuthSchema> WalletStore for Store<S> {}
#[better_auth_core::__test_store_forward("../core/src/store/mod.rs")]
impl<S: AuthSchema> JwksStore for Store<S> {}
#[better_auth_core::__test_store_forward("../core/src/store/mod.rs")]
impl<S: AuthSchema> RateLimitStore for Store<S> {}
#[better_auth_core::__test_store_forward("../core/src/store/mod.rs")]
impl<S: AuthSchema> TransactionStore<S> for Store<S> {}

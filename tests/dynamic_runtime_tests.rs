use async_trait::async_trait;
use better_auth::{AuthBuilder, AuthConfig};
use better_auth_core::{
    AuthContext, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    BaseUrl, CreateUser, DynamicBaseUrl, HttpMethod,
    plugin_runtime::PluginRuntime,
    store::{
        EphemeralStore, StatelessSchema,
        database_hooks::{DatabaseHookContext, DatabaseHooks},
    },
};
use std::sync::{Arc, OnceLock};

#[derive(Clone)]
struct Capture(Arc<OnceLock<PluginRuntime<StatelessSchema>>>);
#[better_auth::database_hooks()]
impl DatabaseHooks<StatelessSchema> for Capture {
    async fn before_create_user(
        &self,
        input: &mut better_auth_core::FieldMap,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<
        better_auth_core::store::database_hooks::DatabaseHookUpdate<better_auth_core::FieldMap>,
    > {
        let _ = input.insert(
            "name".into(),
            self.0
                .get()
                .unwrap()
                .context()?
                .base_url()
                .to_owned()
                .into(),
        );
        Ok(better_auth_core::store::database_hooks::DatabaseHookUpdate::Continue)
    }
}
#[async_trait]
impl AuthPlugin<StatelessSchema> for Capture {
    fn name(&self) -> &'static str {
        "runtime-capture"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_init(&self, context: &mut AuthInitContext<StatelessSchema>) -> AuthResult<()> {
        self.0.set(context.runtime()).ok().unwrap();
        context.register_database_hook(Arc::new(self.clone()));
        Ok(())
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

#[tokio::test]
async fn runtime_scopes_isolate_instances_and_restore_nested_errors_while_database_hooks_keep_the_tenant()
 {
    let store = Arc::new(EphemeralStore::default());
    async fn build(
        store: Arc<EphemeralStore>,
    ) -> (better_auth::BetterAuth<StatelessSchema>, Capture) {
        let capture = Capture(Default::default());
        let config = AuthConfig::new("dynamic-runtime-secret-with-at-least-32-characters")
            .base_url(BaseUrl::Dynamic(DynamicBaseUrl {
                allowed_hosts: vec!["*.tenant.test".into()],
                fallback: None,
                protocol: None,
            }));
        let auth = AuthBuilder::new(config)
            .store_arc(store)
            .plugin(capture.clone())
            .build()
            .await
            .unwrap();
        (auth, capture)
    }
    let (a, ar) = build(store.clone()).await;
    let (b, br) = build(store.clone()).await;
    let request = |tenant: &str| {
        AuthRequest::new(HttpMethod::Get, "/api/auth/ok").with_url(
            format!("https://{tenant}.tenant.test/api/auth/ok")
                .parse()
                .unwrap(),
        )
    };
    let ra = request("a");
    let rb = request("b");
    let (ar_ref, br_ref, b_ref, rb_ref) = (&ar, &br, &b, &rb);
    a.context()
        .with_http_context(&ra, |ac| async move {
            let (ar, br, b, rb) = (ar_ref, br_ref, b_ref, rb_ref);
            assert_eq!(
                ar.0.get().unwrap().context()?.base_url(),
                "https://a.tenant.test/api/auth"
            );
            assert_eq!(br.0.get().unwrap().context()?.base_url(), "");
            let failure = b
                .context()
                .with_http_context(rb, |bc| async move {
                    assert_eq!(
                        ar.0.get().unwrap().context()?.base_url(),
                        "https://a.tenant.test/api/auth"
                    );
                    assert_eq!(
                        br.0.get().unwrap().context()?.base_url(),
                        "https://b.tenant.test/api/auth"
                    );
                    let b = bc
                        .database
                        .create_user(CreateUser::new().with_email("b@tenant.test"))
                        .await?;
                    assert_eq!(
                        b.name.typed().unwrap().as_deref(),
                        Some("https://b.tenant.test/api/auth")
                    );
                    Err::<(), _>(better_auth_core::AuthError::internal("nested failure"))
                })
                .await;
            assert!(failure.is_err());
            assert_eq!(br.0.get().unwrap().context()?.base_url(), "");
            let a = ac
                .database
                .create_user(CreateUser::new().with_email("a@tenant.test"))
                .await?;
            assert_eq!(
                a.name.typed().unwrap().as_deref(),
                Some("https://a.tenant.test/api/auth")
            );
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(ar.0.get().unwrap().context().unwrap().base_url(), "");
    assert_eq!(br.0.get().unwrap().context().unwrap().base_url(), "");
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let observe = |context: Arc<AuthContext<StatelessSchema>>,
                   runtime: Capture,
                   barrier: Arc<tokio::sync::Barrier>| async move {
        let _ = barrier.wait().await;
        assert_eq!(
            runtime.0.get().unwrap().context()?.base_url(),
            context.base_url()
        );
        Ok(())
    };
    let (one, two) = tokio::join!(
        a.context()
            .with_http_context(&ra, |context| observe(context, ar.clone(), barrier.clone())),
        b.context()
            .with_http_context(&rb, |context| observe(context, br.clone(), barrier.clone()))
    );
    one.unwrap();
    two.unwrap();
}

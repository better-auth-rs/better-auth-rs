use better_auth::config::UserFieldTransform;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use better_auth::plugins::{
    LastLoginMethodConfig, LastLoginMethodPlugin, LastLoginMethodResolver,
    endpoint_context::EndpointContext,
};
use better_auth::{AuthBuilder, AuthConfig, AuthResult, AuthSchema, BetterAuth};
use better_auth_core::{
    AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthRoute,
    AuthUser, CreateSession, CreateUser, HttpMethod,
    config::UserFieldConfig,
    hooks::with_request_hook_context,
    store::{
        EphemeralStore, StatelessSchema, UserStore,
        database_hooks::{DatabaseHookContext, DatabaseHookControl, DatabaseHooks},
    },
};

struct RuntimeResolver;
impl<S: AuthSchema> LastLoginMethodResolver<S> for RuntimeResolver {
    fn resolve(&self, context: &EndpointContext<'_, S>) -> AuthResult<Option<String>> {
        Ok(Some(
            context
                .auth
                .config
                .base_url
                .as_static()
                .unwrap_or("")
                .to_owned(),
        ))
    }
}

#[tokio::test]
async fn shared_ephemeral_records_keep_plugin_bindings_and_field_policies_per_auth_instance() {
    let store = Arc::new(EphemeralStore::default());
    async fn build(
        store: Arc<EphemeralStore>,
        host: &str,
        field: &str,
    ) -> BetterAuth<StatelessSchema> {
        let mut config =
            AuthConfig::new("plugin-runtime-secret-with-at-least-32-characters").base_url(host);
        let _ = config.user.additional_fields.insert(
            "lastLoginMethod".into(),
            UserFieldConfig {
                field_name: Some(field.into()),
                output_transform: Some(UserFieldTransform::new(|value| {
                    Ok(value
                        .map(|value| serde_json::json!(format!("{}:out", value.as_str().unwrap()))))
                })),
                ..Default::default()
            },
        );
        AuthBuilder::new(config)
            .store_arc(store)
            .plugin(
                LastLoginMethodPlugin::new(LastLoginMethodConfig {
                    store_in_database: true,
                    ..Default::default()
                })
                .custom_resolve_method(Arc::new(RuntimeResolver)),
            )
            .build()
            .await
            .unwrap()
    }
    let first = build(store.clone(), "http://first.example", "first_column").await;
    let second = build(store.clone(), "http://second.example", "second_column").await;
    let request = AuthRequest::new(HttpMethod::Post, "/sign-up/email");
    let one = with_request_hook_context(
        &request,
        first
            .store()
            .create_user(CreateUser::new().with_email("one@example.com")),
    )
    .await
    .unwrap();
    let two = with_request_hook_context(
        &request,
        second
            .store()
            .create_user(CreateUser::new().with_email("two@example.com")),
    )
    .await
    .unwrap();
    assert_eq!(
        first
            .context()
            .user_view(&one)
            .await
            .unwrap()
            .additional_fields["lastLoginMethod"],
        "http://first.example:out"
    );
    assert_eq!(
        second
            .context()
            .user_view(&two)
            .await
            .unwrap()
            .additional_fields["lastLoginMethod"],
        "http://second.example:out"
    );
    assert_eq!(store.list_users(Default::default()).await.unwrap().1, 2);

    let session = CreateSession {
        additional_fields: Default::default(),
        user_id: one.id().into_owned(),
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        ip_address: None,
        user_agent: None,
        impersonated_by: None,
        active_organization_id: None,
    };
    let _ = with_request_hook_context(&request, first.store().create_session(session))
        .await
        .unwrap();
    let one = first
        .store()
        .get_user_by_id(one.id().typed().unwrap())
        .await
        .unwrap()
        .unwrap();
    let two = second
        .store()
        .get_user_by_id(two.id().typed().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        one.additional_fields["lastLoginMethod"],
        "http://first.example:out"
    );
    assert_eq!(
        two.additional_fields["lastLoginMethod"],
        "http://second.example:out"
    );
    assert!(
        first
            .store()
            .get_user_by_id(two.id().typed().unwrap())
            .await
            .unwrap()
            .unwrap()
            .additional_fields
            .is_empty()
    );
}

type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

struct NestedHook(Arc<Mutex<Vec<String>>>);
#[better_auth::database_hooks()]
impl DatabaseHooks<Schema> for NestedHook {
    async fn before_create_user(
        &self,
        user: &mut CreateUser,
        context: &DatabaseHookContext<'_, Schema>,
    ) -> AuthResult<DatabaseHookControl> {
        self.0
            .lock()
            .unwrap()
            .push(format!("plugin.before:{}", user.email.as_deref().unwrap()));
        if user.email.as_deref() == Some("parent@example.com") {
            let _ = context
                .transaction
                .ok_or_else(|| AuthError::internal("Missing real transaction"))?
                .create_user(
                    CreateUser::new()
                        .with_email("child@example.com")
                        .with_name("Fixture"),
                )
                .await?;
        }
        Ok(DatabaseHookControl::Continue)
    }
    async fn after_create_user(
        &self,
        user: &better_auth_core::wire::UserView,
        context: &DatabaseHookContext<'_, Schema>,
    ) -> AuthResult<()> {
        assert!(context.transaction.is_none());
        self.0
            .lock()
            .unwrap()
            .push(format!("plugin.after:{}", user.email().unwrap()));
        Ok(())
    }
}

struct ApplicationHook(Arc<Mutex<Vec<String>>>);
#[better_auth::database_hooks()]
impl better_auth_seaorm::hooks::SeaOrmHooks<Schema> for ApplicationHook {
    async fn before_create_user(
        &self,
        user: &mut CreateUser,
        context: &better_auth_seaorm::hooks::SeaOrmHookContext<'_, Schema>,
    ) -> AuthResult<better_auth_seaorm::hooks::HookControl> {
        assert!(context.tx.is_some());
        self.0
            .lock()
            .unwrap()
            .push(format!("app.before:{}", user.email.as_deref().unwrap()));
        Ok(better_auth_seaorm::hooks::HookControl::Continue)
    }
    async fn after_create_user(
        &self,
        user: &better_auth_core::wire::UserView,
        context: &better_auth_seaorm::hooks::SeaOrmHookContext<'_, Schema>,
    ) -> AuthResult<()> {
        assert!(context.tx.is_none());
        self.0
            .lock()
            .unwrap()
            .push(format!("app.after:{}", user.email().unwrap()));
        Ok(())
    }
}

struct HookPlugin(Arc<Mutex<Vec<String>>>);
#[async_trait]
impl AuthPlugin<Schema> for HookPlugin {
    fn name(&self) -> &'static str {
        "nested-hook"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_init(&self, context: &mut AuthInitContext<Schema>) -> AuthResult<()> {
        context.register_database_hook(Arc::new(NestedHook(self.0.clone())));
        Ok(())
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<Schema>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

#[tokio::test]
async fn plugin_hooks_share_the_real_transaction_and_commit_queue_before_application_hooks() {
    let config = AuthConfig::new("plugin-runtime-secret-with-at-least-32-characters");
    let database = better_auth_seaorm::sea_orm::Database::connect("sqlite::memory:")
        .await
        .unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let store = better_auth_seaorm::SeaOrmStore::<Schema>::new(config.clone(), database)
        .hook(ApplicationHook(events.clone()));
    let auth = AuthBuilder::new(config)
        .store(store)
        .plugin(HookPlugin(events.clone()))
        .build()
        .await
        .unwrap();
    for rollback in [true, false] {
        events.lock().unwrap().clear();
        let result = better_auth_core::store::transaction(auth.store().as_ref(), move |tx| {
            Box::pin(async move {
                let _ = tx
                    .create_user(
                        CreateUser::new()
                            .with_email("parent@example.com")
                            .with_name("Fixture"),
                    )
                    .await?;
                if rollback {
                    Err(AuthError::internal("rollback"))
                } else {
                    Ok(())
                }
            })
        })
        .await;
        assert_eq!(result.is_err(), rollback);
        assert_eq!(
            auth.store().list_users(Default::default()).await.unwrap().1,
            if rollback { 0 } else { 2 }
        );
        let mut expected = vec![
            "plugin.before:parent@example.com",
            "plugin.before:child@example.com",
            "app.before:child@example.com",
            "app.before:parent@example.com",
        ];
        if !rollback {
            expected.extend([
                "plugin.after:child@example.com",
                "app.after:child@example.com",
                "plugin.after:parent@example.com",
                "app.after:parent@example.com",
            ]);
        }
        assert_eq!(*events.lock().unwrap(), expected);
    }
}

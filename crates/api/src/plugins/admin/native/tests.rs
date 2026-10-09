#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "Admin native regressions inspect exact hook contexts, native identities, and persisted records"
)]

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use better_auth_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, BeforeRequestAction,
    CreateSession, CreateUser, FieldMap, FieldValue,
    endpoint_dispatch::EndpointDispatcher,
    endpoint_input::EndpointInputPatch,
    observability::{AfterEndpointHook, BeforeEndpointHook, EndpointHooks},
    store::{EphemeralStore, StatelessSchema},
};
use serde_json::{Value, json};

use super::{AdminApi, AdminPlugin, CreateAdminUser};
use crate::plugins::{
    endpoint_context::EndpointContext,
    test_helpers::{create_test_config, initialize_test_context},
    user_admission::{UserValidationData, UserValidationRejection, ValidateUserInfo},
};

struct Probe {
    events: Mutex<Vec<Value>>,
    patch: Option<Value>,
    marker: FieldValue,
    created_at: Mutex<Option<FieldValue>>,
}

impl Probe {
    fn record(&self, phase: &str, request: &AuthRequest) {
        let scope = better_auth_core::hooks::current_request_hook_context().unwrap();
        assert!(!scope.is_http);
        assert!(!request.is_server_only());
        assert_eq!(scope.path.as_deref(), Some("/admin/create-user"));
        assert_eq!(scope.operation_id.as_deref(), Some("createUser"));
        assert_eq!(request.path(), "/admin/create-user");
        assert!(request.original_request().is_none());
        self.events.lock().unwrap().push(json!({
            "phase":phase,
            "headers":request.endpoint_headers(),
        }));
    }

    fn events(&self) -> Vec<Value> {
        self.events.lock().unwrap().clone()
    }
}

#[async_trait]
impl BeforeEndpointHook<StatelessSchema> for Probe {
    async fn before(
        &self,
        request: &AuthRequest,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        self.record("before", request);
        Ok(self.patch.clone().map(|body| {
            BeforeRequestAction::MergeContext(EndpointInputPatch {
                body: Some(body),
                ..Default::default()
            })
        }))
    }
}

#[async_trait]
impl AfterEndpointHook<StatelessSchema> for Probe {
    async fn after(
        &self,
        request: &AuthRequest,
        response: &mut AuthResponse,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<()> {
        self.record("after", request);
        if response.status == 200 {
            let result = response.body.field_value()?;
            let mut user = result.model_property("user")?.as_object().unwrap().clone();
            let created_at = user.get("createdAt").unwrap();
            assert!(matches!(created_at, FieldValue::Date(_)));
            *self.created_at.lock().unwrap() = Some(created_at.clone());
            let _ = user.insert("hookMarker".into(), self.marker.clone());
            let _ = user.insert("name".into(), "After hook".into());
            response.replace_returned(AuthResponse::native(
                200,
                FieldMap::from([("user".into(), user.into())]).into(),
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl ValidateUserInfo<StatelessSchema> for Probe {
    async fn validate(
        &self,
        _: &UserValidationData,
        context: &EndpointContext<'_, StatelessSchema>,
    ) -> AuthResult<Option<UserValidationRejection>> {
        assert!(context.request.is_none());
        assert_eq!(context.path, Some("/admin/create-user"));
        self.events.lock().unwrap().push(json!({
            "phase":"admission",
            "headers":context.headers(),
            "session":context.session.is_some(),
            "body":context.body.json()?,
        }));
        Ok(None)
    }
}

async fn fixture(patch: Option<Value>) -> AuthResult<(AuthContext<StatelessSchema>, Arc<Probe>)> {
    let plugin = AdminPlugin::new();
    let mut config = create_test_config();
    config.session.disable_session_refresh = Some(true);
    let config = Arc::new(config);
    let mut context = initialize_test_context(
        config.clone(),
        Arc::new(EphemeralStore::new(config)),
        &[&plugin],
    )
    .await?;
    let probe = Arc::new(Probe {
        events: Default::default(),
        patch,
        marker: FieldMap::from([("retained".into(), true.into())]).into(),
        created_at: Default::default(),
    });
    let plugins: Vec<Box<dyn AuthPlugin<StatelessSchema>>> = vec![Box::new(plugin)];
    context.extensions.insert(Arc::new(EndpointDispatcher::new(
        Arc::new(plugins),
        EndpointHooks {
            before: Some(probe.clone()),
            after: Some(probe.clone()),
        },
        [],
    )));
    context
        .extensions
        .insert(probe.clone() as Arc<dyn ValidateUserInfo<StatelessSchema>>);
    Ok((context, probe))
}

fn input(email: &str) -> CreateAdminUser {
    CreateAdminUser {
        email: email.into(),
        name: "Before hook".into(),
        password: None,
        role: None,
        data: None,
    }
}

#[tokio::test]
async fn create_user_runs_validation_and_hooks_without_losing_native_response_values()
-> AuthResult<()> {
    let (context, probe) = fixture(Some(json!({
        "email":"PATCHED@native-admin.test",
        "ignored":"removed by the endpoint validator",
    })))
    .await?;
    let response = AdminApi::from_context(&context)?
        .create_user(&input("initial@native-admin.test"), None)
        .await?;
    assert_eq!(
        response.user.email.field_value(),
        "patched@native-admin.test".into()
    );
    assert_eq!(response.user.name.field_value(), "After hook".into());
    assert!(
        response
            .user
            .additional_fields
            .get("hookMarker")
            .unwrap()
            .strict_equals(&probe.marker)
    );
    assert!(
        response
            .user
            .created_at
            .field_value()
            .strict_equals(probe.created_at.lock().unwrap().as_ref().unwrap())
    );
    assert_eq!(
        probe.events(),
        vec![
            json!({"phase":"before","headers":null}),
            json!({"phase":"admission","headers":null,"session":false,"body":{"email":"PATCHED@native-admin.test","name":"Before hook"}}),
            json!({"phase":"after","headers":null}),
        ]
    );
    assert!(
        context
            .database
            .get_user_by_email("initial@native-admin.test")
            .await?
            .is_none()
    );
    let stored = context
        .database
        .get_user_by_email("patched@native-admin.test")
        .await?
        .unwrap();
    assert_eq!(stored.name.field_value(), "Before hook".into());
    assert!(!stored.additional_fields.contains_key("ignored"));
    assert!(!stored.additional_fields.contains_key("hookMarker"));
    Ok(())
}

#[tokio::test]
async fn create_user_preserves_supplied_headers_and_requires_their_session() -> AuthResult<()> {
    let (context, probe) = fixture(None).await?;
    let empty = HashMap::new();
    let error = AdminApi::from_context(&context)?
        .create_user(&input("unauthenticated@native-admin.test"), Some(&empty))
        .await
        .unwrap_err();
    assert_eq!(error.status_code(), 401);
    assert_eq!(
        probe.events(),
        vec![
            json!({"phase":"before","headers":{}}),
            json!({"phase":"after","headers":{}}),
        ]
    );
    assert!(
        context
            .database
            .get_user_by_email("unauthenticated@native-admin.test")
            .await?
            .is_none()
    );
    probe.events.lock().unwrap().clear();
    let owner = context
        .database
        .create_user(
            CreateUser::new()
                .with_email("owner@native-admin.test")
                .with_role("admin"),
        )
        .await?;
    let session = context
        .database
        .create_session(CreateSession {
            user_id: owner.id.clone(),
            expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).into(),
            inherited_fields: Default::default(),
            additional_fields: Default::default(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await?;
    let cookie = format!(
        "{}={}",
        context
            .config
            .auth_cookie("session_token", Default::default())
            .name,
        better_auth_core::utils::cookie_utils::sign_cookie_value(
            session.token.typed()?,
            context.config.signing_secret()
        ),
    );
    let headers = HashMap::from([
        ("Cookie".into(), cookie.clone()),
        ("X-Trace".into(), "native".into()),
    ]);
    let response = AdminApi::from_context(&context)?
        .create_user(&input("authenticated@native-admin.test"), Some(&headers))
        .await?;
    assert_eq!(
        response.user.email.field_value(),
        "authenticated@native-admin.test".into()
    );
    let observed_headers = json!({"cookie":cookie,"x-trace":"native"});
    assert_eq!(
        probe.events(),
        vec![
            json!({"phase":"before","headers":observed_headers}),
            json!({"phase":"admission","headers":observed_headers,"session":true,"body":{"email":"authenticated@native-admin.test","name":"Before hook"}}),
            json!({"phase":"after","headers":observed_headers}),
        ]
    );
    Ok(())
}

#[tokio::test]
async fn invalid_hook_input_runs_after_without_admission_or_store_writes() -> AuthResult<()> {
    let (context, probe) = fixture(Some(json!({"email":17}))).await?;
    let error = AdminApi::from_context(&context)?
        .create_user(&input("invalid@native-admin.test"), None)
        .await
        .unwrap_err();
    assert_eq!(error.status_code(), 400);
    assert_eq!(
        error.to_auth_response().body.json()?,
        Some(json!({
            "code":"VALIDATION_ERROR",
            "message":"[body.email] Invalid input: expected string, received number",
        }))
    );
    assert_eq!(
        probe.events(),
        vec![
            json!({"phase":"before","headers":null}),
            json!({"phase":"after","headers":null}),
        ]
    );
    assert_eq!(context.database.list_users(Default::default()).await?.1, 0);
    Ok(())
}

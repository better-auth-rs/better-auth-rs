use async_trait::async_trait;
use better_auth::plugins::{
    AdminPlugin, DeviceAuthorizationPlugin, JwtPlugin, MagicLinkPlugin, MultiSessionPlugin,
    OAuthPlugin, OrganizationPlugin, SessionManagementPlugin,
    magic_link::{MagicLinkConfig, MagicLinkMessage, SendMagicLink},
    organization::{OrganizationConfig, OrganizationTeamsConfig},
};
use better_auth::server_api::EndpointInput;
use better_auth::{AuthConfig, AuthError, AuthResult, BetterAuth};
use better_auth_core::observability::{AfterEndpointHook, BeforeEndpointHook, EndpointHooks};
use better_auth_core::{
    AuthContext, AuthRequest, AuthResponse, BeforeRequestAction, HttpMethod,
    store::StatelessSchema as S,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

struct Sender;
#[async_trait]
impl SendMagicLink for Sender {
    async fn send(&self, _: &MagicLinkMessage) -> AuthResult<()> {
        Ok(())
    }
}

#[derive(Clone, Default)]
struct Hooks(Arc<Mutex<Vec<Value>>>);
impl Hooks {
    fn record(&self, phase: &str, request: &AuthRequest) {
        self.0.lock().unwrap().push(json!({
            "phase":phase,"body":request.input_body().unwrap(),"query":request.query,
            "request":request.original_request().is_some(),
        }));
    }
}
#[async_trait]
impl BeforeEndpointHook<S> for Hooks {
    async fn before(
        &self,
        req: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        self.record("before", req);
        Ok(None)
    }
}
#[async_trait]
impl AfterEndpointHook<S> for Hooks {
    async fn after(
        &self,
        req: &AuthRequest,
        _: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<()> {
        self.record("after", req);
        Ok(())
    }
}

#[derive(Deserialize)]
struct Case {
    path: String,
    method: String,
    kind: String,
    body: Option<Value>,
    query: Option<Value>,
    status: u16,
    result: Value,
}
#[derive(Deserialize)]
struct Oracle {
    records: Vec<Case>,
    trace: Vec<Value>,
}

// Better Auth 1.7.6: better-call/dist/validator.mjs and the registered endpoint options.
#[tokio::test]
async fn required_headers_preserve_schema_precedence_and_native_request_authority() -> AuthResult<()>
{
    let hooks = Hooks::default();
    let mut config = AuthConfig::new("headers-oracle-secret-at-least-32-characters");
    config.base_url = "http://headers.test".into();
    let auth = BetterAuth::stateless(config)
        .hooks(EndpointHooks {
            before: Some(Arc::new(hooks.clone())),
            after: Some(Arc::new(hooks.clone())),
        })
        .plugin(SessionManagementPlugin::new())
        .plugin(OAuthPlugin::new())
        .plugin(AdminPlugin::new())
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            teams: OrganizationTeamsConfig {
                enabled: true,
                ..Default::default()
            },
            dynamic_access_control: true,
            ..Default::default()
        }))
        .plugin(MultiSessionPlugin::new())
        .plugin(MagicLinkPlugin::with_config(MagicLinkConfig {
            send_magic_link: Some(Arc::new(Sender)),
            ..Default::default()
        }))
        .plugin(JwtPlugin::new())
        .plugin(DeviceAuthorizationPlugin::new())
        .build()
        .await?;
    let oracle: Oracle =
        serde_json::from_str(include_str!("fixtures/required-headers-upstream.json"))?;
    let mut mismatches = Vec::new();
    for case in oracle.records {
        let method = if case.method == "GET" {
            HttpMethod::Get
        } else {
            HttpMethod::Post
        };
        let response = auth
            .call_endpoint(
                method,
                &case.path,
                EndpointInput {
                    body: case.body,
                    query: case.query,
                    headers: (case.kind == "empty").then(Default::default),
                    request: (case.kind == "request")
                        .then(|| AuthRequest::new(HttpMethod::Get, "/source")),
                },
            )
            .await
            .unwrap_or_else(AuthError::to_auth_response);
        let result: Value = if response.body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&response.body)?
        };
        if (response.status, &result) != (case.status, &case.result) {
            mismatches.push(format!(
                "{}/{}: actual ({}, {}), expected ({}, {})",
                case.path, case.kind, response.status, result, case.status, case.result
            ));
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    hooks.0.lock().unwrap().clear();
    let response = auth
        .call_endpoint(
            HttpMethod::Post,
            "/revoke-session",
            EndpointInput {
                body: Some(json!({"token":"fixture","unknown":7})),
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(AuthError::to_auth_response);
    assert_eq!(response.status, 400);
    assert_eq!(*hooks.0.lock().unwrap(), oracle.trace);
    Ok(())
}

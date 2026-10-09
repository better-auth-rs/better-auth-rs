use std::sync::{Arc, Mutex};

use better_auth::{AuthConfig, BetterAuth, server_api::EndpointInput};
use better_auth_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute, BeforeRequestAction,
    HttpMethod, hooks::current_request_hook_context, middleware::RateLimitConfig,
    store::StatelessSchema,
};
use serde_json::{Value, json};

struct Probe(Arc<Mutex<Vec<Value>>>);
#[async_trait::async_trait]
impl AuthPlugin<StatelessSchema> for Probe {
    fn name(&self) -> &'static str {
        "query-probe"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get("/probe", "probe")
                .query_validator(better_auth_core::query::session_query),
        ]
    }
    async fn before_request(
        &self,
        req: &AuthRequest,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        self.0
            .lock()
            .unwrap()
            .push(json!({"phase":"before","query":req.query}));
        Ok(None)
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        let endpoint = better_auth::plugins::endpoint_context::EndpointContext::new(
            Some(req),
            better_auth_core::FieldValue::Null,
            ctx,
        );
        AuthResponse::json(200,&json!({"query":req.query,"scope":current_request_hook_context().unwrap().query,"original":endpoint.request.map(|request|request.query.clone())})).map(Some)
    }
    async fn after_request(
        &self,
        req: &AuthRequest,
        _: &mut AuthResponse,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<()> {
        self.0
            .lock()
            .unwrap()
            .push(json!({"phase":"after","query":req.query}));
        Ok(())
    }
}

#[tokio::test]
async fn validated_query_keeps_original_http_and_native_request_provenance() {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let auth = BetterAuth::stateless(
        AuthConfig::new("query-scope-secret-with-at-least-32-characters")
            .base_url("http://localhost:3000"),
    )
    .rate_limit(RateLimitConfig::new().enabled(false))
    .plugin(Probe(trace.clone()))
    .build()
    .await
    .unwrap();
    let raw = json!({"disableRefresh":"false","unknown":"raw"});
    let mut request = AuthRequest::new(HttpMethod::Get, "/api/auth/probe").with_url(
        "http://localhost:3000/api/auth/probe?disableRefresh=false&unknown=raw"
            .parse()
            .unwrap(),
    );
    request.query = Some(raw.clone());
    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&response.body.bytes().unwrap()).unwrap(),
        json!({"query":{"disableRefresh":true},"scope":{"disableRefresh":true},"original":raw})
    );
    assert_eq!(
        *trace.lock().unwrap(),
        vec![
            json!({"phase":"before","query":raw}),
            json!({"phase":"after","query":raw})
        ]
    );
    for present in [false, true] {
        trace.lock().unwrap().clear();
        let mut original = AuthRequest::new(HttpMethod::Get, "/original");
        original.query = Some(json!({"transport":"original"}));
        let response = auth
            .call_endpoint(
                HttpMethod::Get,
                "/probe",
                EndpointInput {
                    query: Some(raw.clone()),
                    request: present.then_some(original),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&response.body.bytes().unwrap()).unwrap();
        assert_eq!(body["query"], json!({"disableRefresh":true}));
        assert_eq!(body["scope"], body["query"]);
        assert_eq!(
            body["original"],
            if present {
                json!({"transport":"original"})
            } else {
                Value::Null
            }
        );
        assert_eq!(
            *trace.lock().unwrap(),
            vec![
                json!({"phase":"before","query":raw}),
                json!({"phase":"after","query":raw})
            ]
        );
    }
}

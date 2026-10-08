use axum::{
    Json, Router,
    routing::{get, post},
};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::plugins::email_otp::EmailOtpCallbacks;
use better_auth::plugins::{EmailOtpPlugin, EmailOtpType, JwtPlugin, TwoFactorPlugin};
use better_auth::{AuthConfig, AuthError, AuthResult, BetterAuth};
use better_auth_core::endpoint_input::EndpointInputPatch;
use better_auth_core::observability::{
    AfterEndpointHook, BeforeEndpointHook, EndpointHooks, instrumentation::with_endpoint_hook,
};
use better_auth_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthRoute, BeforeRequestAction, FieldMap,
    HttpMethod, NativeRequest, store::StatelessSchema as S,
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
#[derive(Default)]
struct State {
    mode: String,
    operation: String,
    events: Vec<Value>,
}
#[derive(Clone, Default)]
struct Trace(Arc<Mutex<State>>);
fn absent(value: Option<Value>) -> Value {
    value.unwrap_or_else(|| json!({"$undefined":true}))
}
impl Trace {
    fn record(&self, phase: &str, request: &AuthRequest) -> AuthResult<()> {
        self.0.lock().unwrap().events.push(json!({"phase":phase,"path":request.path(),"ambient":absent(better_auth_core::hooks::current_request_hook_context().and_then(|scope|scope.path.map(Value::String))),"body":absent(request.input_body()?),"query":absent(request.query.clone()),"request":request.original_request().and_then(AuthRequest::url).map(|url|url.path()),"header":request.header("x-literal")}));
        Ok(())
    }
    fn output(&self, value: &str) -> Value {
        match self.0.lock().unwrap().operation.as_str() {
            "createVerificationOTP" => json!(value),
            "signJWT" => json!({"token":value}),
            "verifyJWT" => json!({"payload":{"sub":value}}),
            "getVerificationOTP" => json!({"otp":value}),
            "viewBackupCodes" => json!({"status":true,"backupCodes":[value]}),
            _ => json!({"code":value}),
        }
    }
}
#[async_trait::async_trait]
impl BeforeEndpointHook<S> for Trace {
    async fn before(
        &self,
        request: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        self.record("before", request)?;
        let (mode, operation) = {
            let state = self.0.lock().unwrap();
            (state.mode.clone(), state.operation.clone())
        };
        if mode == "stop" {
            if operation == "createVerificationOTP" {
                return Err(AuthError::from(AuthResponse::json(
                    400,
                    &json!({"code":"STOPPED","message":"stopped"}),
                )?));
            }
            return Ok(Some(BeforeRequestAction::Respond(AuthResponse::json(
                200,
                &self.output("stopped"),
            )?)));
        }
        if mode == "options" {
            return Ok(Some(BeforeRequestAction::MergeContext(
                EndpointInputPatch {
                    body: Some(
                        json!({"overrideOptions":{"jwt":{"issuer":"changed-issuer","audience":["one","two"],"expirationTime":"2 minutes"}}}),
                    ),
                    ..Default::default()
                },
            )));
        }
        if matches!(mode.as_str(), "patch" | "invalid") {
            let key = match operation.as_str() {
                "generateTOTP" => "secret",
                "signJWT" => "payload",
                "verifyJWT" => "token",
                _ => "email",
            };
            let value = if mode == "invalid" {
                json!(7)
            } else if key == "payload" {
                json!({"sub":"changed"})
            } else if key == "email" {
                json!("PATCHED@example.test")
            } else {
                json!("patched-secret")
            };
            let patch = json!({key:value,"unknown":true});
            return Ok(Some(BeforeRequestAction::MergeContext(
                if operation == "getVerificationOTP" {
                    EndpointInputPatch {
                        query: Some(patch),
                        ..Default::default()
                    }
                } else {
                    EndpointInputPatch {
                        body: Some(patch),
                        ..Default::default()
                    }
                },
            )));
        }
        Ok(None)
    }
}
#[async_trait::async_trait]
impl AfterEndpointHook<S> for Trace {
    async fn after(
        &self,
        request: &AuthRequest,
        response: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<()> {
        self.record("after", request)?;
        if self.0.lock().unwrap().mode == "after-error" {
            request.set_response_header("x-native-error", "retained")?;
            return Err(AuthError::from(AuthResponse::json(
                400,
                &json!({"code":"AFTER_REJECTION","message":"after rejection"}),
            )?));
        }
        if self.0.lock().unwrap().mode == "replace" {
            response.replace_returned(AuthResponse::json(200, &self.output("replaced"))?);
        }
        Ok(())
    }
}
#[async_trait::async_trait]
impl AuthPlugin<S> for Trace {
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
    fn name(&self) -> &'static str {
        "native-trace"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![]
    }
    async fn before_request(
        &self,
        request: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        with_endpoint_hook(
            &context.config,
            request,
            "before",
            "plugin:native-trace",
            async {
                self.record("plugin.before", request)?;
                Ok(None)
            },
        )
        .await
    }
    async fn after_request(
        &self,
        request: &AuthRequest,
        _: &mut AuthResponse,
        context: &AuthContext<S>,
    ) -> AuthResult<()> {
        with_endpoint_hook(
            &context.config,
            request,
            "after",
            "plugin:native-trace",
            async { self.record("plugin.after", request) },
        )
        .await
    }
}
pub(super) async fn router(base: &str) -> AuthResult<Router> {
    let trace = Trace::default();
    let generator = trace.clone();
    let mut config = AuthConfig::new("native-dispatch-fixture-secret-more-than-32");
    config.base_url = base.to_owned().into();
    let auth =
        Arc::new(
            BetterAuth::stateless(config)
                .hooks(EndpointHooks {
                    before: Some(Arc::new(trace.clone())),
                    after: Some(Arc::new(trace.clone())),
                })
                .plugin(EmailOtpPlugin::new().callbacks(
                    EmailOtpCallbacks::<S>::default().generate(move |_, _, ctx| {
                        let scope =
                            better_auth_core::hooks::current_request_hook_context().unwrap();
                        generator.record("generator", &scope.request)?;
                        if generator.0.lock().unwrap().mode == "ordinary" {
                            return Err(AuthError::internal("generator failed"));
                        }
                        assert_eq!(ctx.path, Some("virtual:"));
                        Ok(Some("123456".into()))
                    }),
                ))
                .plugin(JwtPlugin::new())
                .plugin(TwoFactorPlugin::new())
                .plugin(trace.clone())
                .build()
                .await?,
        );
    let app = auth.clone().axum_router().with_state(auth.clone());
    Ok(Router::new().route("/health",get(||async{Json(json!({"status":"ok"}))})).route("/__health",get(||async{Json(json!({"status":"ok"}))})).route("/__test/reset-state",post(||async{Json(json!({"success":true}))})).route("/__test/native-dispatch",post(move|Json(input):Json<Value>|{let auth=auth.clone();let trace=trace.clone();async move{
  let operation=input["operation"].as_str().unwrap_or_default();{let mut state=trace.0.lock().unwrap();state.mode=input["mode"].as_str().unwrap_or("normal").into();state.operation=operation.into();state.events.clear();}
  let headers:Option<HashMap<String,String>>=input.get("headers").cloned().map(serde_json::from_value).transpose().unwrap();
  let original=input["request"].as_bool().filter(|value|*value).map(|_|AuthRequest::new(HttpMethod::Get,"/original").with_url(auth.context().base_url().parse::<url::Url>().unwrap().join("/original?literal=true").unwrap()));
  let source=NativeRequest{request:original.as_ref(),headers:headers.as_ref()};
  let result:AuthResult<Value>=async{match operation{
   "generateTOTP"=>Ok(json!({"code":auth.two_factor()?.with_request(source).generate_totp(input.get("body").cloned()).await?})),
   "viewBackupCodes"=>Ok(Value::Object(FieldMap::from([
    ("status".into(), true.into()),
    ("backupCodes".into(), auth.two_factor()?.with_request(source).view_backup_codes(input.get("body").cloned()).await?),
   ]).json()?)),
   "createVerificationOTP"=>{let kind:EmailOtpType=serde_json::from_value(input["body"]["type"].clone())?;Ok(json!(auth.email_otp()?.with_request(source).create(input["body"]["email"].as_str().unwrap_or_default(),kind).await?))},
   "getVerificationOTP"=>{let kind:EmailOtpType=serde_json::from_value(input["query"]["type"].clone())?;Ok(json!({"otp":auth.email_otp()?.with_request(source).get(input["query"]["email"].as_str().unwrap_or_default(),kind).await?}))},
   "signJWT"=>Ok(json!({"token":auth.jwt()?.with_request(source).sign(serde_json::from_value(input["body"]["payload"].clone())?).await?})),
   "verifyJWT"=>Ok(json!({"payload":auth.jwt()?.with_request(source).verify(input["body"]["token"].as_str().unwrap_or_default(),input["body"]["issuer"].as_str()).await?})),
   _=>Err(AuthError::bad_request("Unknown native operation")),
  }}.await;
  let events=trace.0.lock().unwrap().events.clone();
  Json(match result{Ok(result)=>json!({"result":result,"events":events}),Err(error) if error.is_api_error()=>{let response=error.to_auth_response();json!({"error":{"status":response.status,"body":serde_json::from_slice::<Value>(&response.body.bytes().expect("The fixture response must serialize")).unwrap()},"events":events,"errorHeaders":response.captured_headers().and_then(|headers|headers.get("x-native-error"))})},Err(AuthError::Internal(message))=>json!({"error":{"ordinary":true,"message":message},"events":events,"errorHeaders":Value::Null}),Err(error)=>json!({"error":{"ordinary":true,"message":error.to_string()},"events":events,"errorHeaders":Value::Null})})
 }})).merge(app))
}

use axum::{
    Json, Router,
    routing::{get, post},
};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::plugins::two_factor::TwoFactorCallbacks;
use better_auth::plugins::{
    EmailPasswordPlugin, PhoneNumberPlugin, TwoFactorPlugin, UsernamePlugin,
};
use better_auth::{
    AuthBuilder, AuthConfig, AuthError, AuthResult, AuthSchema, BetterAuth, PasswordHasher,
};
use better_auth_core::observability::{AfterEndpointHook, EndpointHooks};
use better_auth_core::store::database_hooks::{
    DatabaseHookContext, DatabaseHookControl, DatabaseHooks,
};
use better_auth_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthRoute, CreateVerification, HttpMethod,
    UpdateUser,
};
use better_auth_seaorm::hooks::{HookControl, SeaOrmHookContext, SeaOrmHooks};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

const EMAIL: &str = "factor@example.test";
const PASSWORD: &str = "password123";
#[derive(Default)]
struct State {
    active: bool,
    mode: String,
    user_id: String,
    events: Vec<Value>,
    identifiers: Vec<String>,
    otp: String,
}
#[derive(Clone, Default)]
struct Trace(Arc<Mutex<State>>);
fn target(path: &str) -> bool {
    matches!(
        path,
        "/sign-in/email" | "/sign-in/username" | "/sign-in/phone-number"
    )
}
fn shape(mut value: Value) -> Value {
    if value.get("token").is_some_and(|value| !value.is_null()) {
        value["token"] = true.into();
    }
    if let Some(user) = value.get("user") {
        value["user"] = json!({"email":user["email"],"twoFactorEnabled":user["twoFactorEnabled"]});
    }
    value
}
impl Trace {
    fn event(&self, value: Value) {
        let mut state = self.0.lock().unwrap();
        if state.active {
            state.events.push(value);
        }
    }
    fn mode(&self) -> String {
        self.0.lock().unwrap().mode.clone()
    }
    async fn counts<S: AuthSchema>(&self, ctx: &AuthContext<S>) -> AuthResult<(usize, usize)> {
        let (user_id, identifiers) = {
            let state = self.0.lock().unwrap();
            (state.user_id.clone(), state.identifiers.clone())
        };
        let sessions = ctx.database.get_user_sessions(&user_id).await?.len();
        let mut proofs = 0;
        for id in identifiers {
            if ctx
                .database
                .get_verification_including_expired(&id)
                .await?
                .is_some()
            {
                proofs += 1;
            }
        }
        Ok((sessions, proofs))
    }
    async fn snapshot<S: AuthSchema>(
        &self,
        phase: &str,
        req: &AuthRequest,
        response: &AuthResponse,
        ctx: &AuthContext<S>,
    ) -> AuthResult<()> {
        if !self.0.lock().unwrap().active || !target(req.path()) {
            return Ok(());
        }
        let (sessions, proofs) = self.counts(ctx).await?;
        let body: Value = serde_json::from_slice(&response.body.bytes()?)?;
        let returned = if response.is_api_error() {
            json!({"apiError":{"status":response.status,"body":body}})
        } else {
            shape(body)
        };
        self.event(json!({"phase":phase,"returned":returned,"newSession":req.new_session()?.is_some(),"sessions":sessions,"proofs":proofs}));
        Ok(())
    }
}
#[async_trait::async_trait]
impl<S: AuthSchema> AfterEndpointHook<S> for Trace {
    async fn after(
        &self,
        req: &AuthRequest,
        response: &mut AuthResponse,
        ctx: &AuthContext<S>,
    ) -> AuthResult<()> {
        if !self.0.lock().unwrap().active || !target(req.path()) {
            return Ok(());
        }
        self.snapshot("user-after", req, response, ctx).await?;
        match self.mode().as_str() {
            "replace" => {
                response.replace_returned(AuthResponse::json(200, &json!({"custom":true}))?)
            }
            "api-error" => {
                return Err(AuthResponse::json(
                    400,
                    &json!({"code":"USER_AFTER_ERROR","message":"user after rejected"}),
                )?
                .into());
            }
            "ordinary-error" => return Err(AuthError::internal("user after failed")),
            "clear" => req.clear_new_session()?,
            "cookies" => {
                req.append_response_header(
                    "set-cookie",
                    "better-auth.session_data.0=pending-chunk".into(),
                )?;
                req.append_response_header(
                    "set-cookie",
                    "better-auth.dont_remember=keep-marker".into(),
                )?;
            }
            _ => (),
        }
        Ok(())
    }
}
struct Observer {
    trace: Trace,
    phase: &'static str,
}
#[async_trait::async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Observer {
    fn name(&self) -> &'static str {
        self.phase
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
    async fn after_request(
        &self,
        req: &AuthRequest,
        response: &mut AuthResponse,
        ctx: &AuthContext<S>,
    ) -> AuthResult<()> {
        self.trace.snapshot(self.phase, req, response, ctx).await
    }
}
macro_rules! hooks {
    ($hooks:ident,$context:ident,$control:ident)=>{
        #[better_auth::database_hooks]
        impl<S:AuthSchema> $hooks<S> for Trace {
            async fn after_create_session(&self,_:&better_auth_core::wire::SessionView,_:&$context<'_,S>)->AuthResult<()> {self.event(json!({"phase":"session-created"}));Ok(())}
            async fn before_delete_session(&self,_:&better_auth_core::wire::SessionView,_:&$context<'_,S>)->AuthResult<$control> {
                self.event(json!({"phase":"session-delete-before"}));
                if { let state=self.0.lock().unwrap(); state.active && state.mode=="delete-error" } {return Err(AuthError::internal("session deletion rejected"));}
                Ok($control::Continue)
            }
            async fn after_delete_session(&self,_:&better_auth_core::wire::SessionView,_:&$context<'_,S>)->AuthResult<()> {self.event(json!({"phase":"session-delete-after"}));Ok(())}
            async fn before_create_verification(&self,data:&mut CreateVerification,_:&$context<'_,S>)->AuthResult<$control> {
                let identifier=data.identifier.typed()?.to_owned();
                self.0.lock().unwrap().identifiers.push(identifier.clone());
                if self.0.lock().unwrap().active && identifier.starts_with("2fa-") {
                    self.event(json!({"phase":"proof-create","attempts":identifier.starts_with("2fa-attempts-")}));
                    if self.mode()=="proof-error" {return Err(AuthError::internal("challenge creation rejected"));}
                }
                Ok($control::Continue)
            }
        }
    }
}
hooks!(DatabaseHooks, DatabaseHookContext, DatabaseHookControl);
hooks!(SeaOrmHooks, SeaOrmHookContext, HookControl);
struct FixtureHasher;
#[async_trait::async_trait]
impl PasswordHasher for FixtureHasher {
    async fn hash(&self, password: &str) -> AuthResult<String> {
        Ok(format!("fixture:{password}"))
    }
    async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
        Ok(hash == format!("fixture:{password}"))
    }
}
pub(super) async fn router(profile: &str, base: &str) -> AuthResult<Router> {
    let mut config = AuthConfig::new("two-factor-after-fixture-secret-at-least-32");
    config.base_url = base.to_owned().into();
    let trace = Trace::default();
    if profile.ends_with("sqlite") {
        use better_auth_seaorm::store::__private_test_support::{
            bundled_schema::BundledSchema, migrator,
        };
        let db = better_auth_seaorm::Database::connect("sqlite::memory:")
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        migrator::run_migrations(&db)
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let store = better_auth_seaorm::SeaOrmStore::<BundledSchema>::new(config.clone(), db)
            .with_hooks(vec![Arc::new(trace.clone())]);
        build(BetterAuth::<BundledSchema>::new(config).store(store), trace).await
    } else {
        build(
            BetterAuth::stateless(config).database_hooks(vec![Arc::new(trace.clone())]),
            trace,
        )
        .await
    }
}
async fn build<S: AuthSchema>(builder: AuthBuilder<S>, trace: Trace) -> AuthResult<Router> {
    let sender = trace.clone();
    let callbacks = TwoFactorCallbacks::<S>::default().send(move |_, otp, _| {
        sender.0.lock().unwrap().otp = otp.to_owned();
        Ok(None)
    });
    let auth = Arc::new(
        builder
            .rate_limit(better_auth_core::middleware::RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new().password_hasher(Arc::new(FixtureHasher)))
            .plugin(UsernamePlugin::new(Default::default()))
            .plugin(PhoneNumberPlugin::new())
            .plugin(Observer {
                trace: trace.clone(),
                phase: "plugin-before-2fa",
            })
            .plugin(TwoFactorPlugin::new().callbacks(callbacks))
            .plugin(Observer {
                trace: trace.clone(),
                phase: "plugin-after-2fa",
            })
            .hooks(EndpointHooks {
                before: None,
                after: Some(Arc::new(trace.clone())),
            })
            .build()
            .await?,
    );
    let created = auth
        .call_endpoint(
            HttpMethod::Post,
            "/sign-up/email",
            better_auth::server_api::EndpointInput {
                body: Some(
                    json!({"email":EMAIL,"password":PASSWORD,"name":"Factor","username":"factor"}),
                ),
                ..Default::default()
            },
        )
        .await?;
    let body: Value = serde_json::from_slice(&created.body.bytes()?)?;
    let id = body["user"]["id"]
        .as_str()
        .expect("created user")
        .to_owned();
    let _ = auth
        .store()
        .update_user(
            &id,
            UpdateUser {
                two_factor_enabled: Some(true),
                phone_number: Some(Some("+15551230000".into())),
                phone_number_verified: Some(true),
                ..Default::default()
            },
        )
        .await?;
    trace.0.lock().unwrap().user_id = id;
    let app = auth.clone().axum_router().with_state(auth.clone());
    Ok(Router::new()
        .route("/health", get(|| async { Json(json!({"status":"ok"})) }))
        .route("/__health", get(|| async { Json(json!({"status":"ok"})) }))
        .route(
            "/__test/reset-state",
            post(|| async { Json(json!({"success":true})) }),
        )
        .route(
            "/__test/two-factor-after",
            post(move |Json(input): Json<Value>| {
                let auth = auth.clone();
                let trace = trace.clone();
                async move {
                    Json(
                        control(auth, &trace, input)
                            .await
                            .unwrap_or_else(|error| json!({"fixtureError":error.to_string()})),
                    )
                }
            }),
        )
        .merge(app))
}
fn cookies(response: &AuthResponse) -> Vec<Value> {
    response.headers.get_all("set-cookie").map(|line|{let pair=line.split(';').next().unwrap();let(name,value)=pair.split_once('=').unwrap();json!({"name":name,"empty":value.is_empty(),"clear":line.to_ascii_lowercase().split(';').any(|part|part.trim()=="max-age=0")})}).collect()
}
async fn control<S: AuthSchema>(
    auth: Arc<BetterAuth<S>>,
    trace: &Trace,
    input: Value,
) -> AuthResult<Value> {
    if input["action"] == "state" {
        let (sessions, proofs) = trace.counts(auth.context()).await?;
        let state = trace.0.lock().unwrap();
        return Ok(
            json!({"events":state.events,"otp":state.otp,"sessions":sessions,"proofs":proofs}),
        );
    }
    trace.0.lock().unwrap().active = false;
    if input["clear"] != false {
        let (id, identifiers) = {
            let state = trace.0.lock().unwrap();
            (state.user_id.clone(), state.identifiers.clone())
        };
        auth.store().delete_user_sessions(&id).await?;
        for identifier in identifiers {
            auth.store()
                .delete_verification_by_identifier(&identifier)
                .await?;
        }
        trace.0.lock().unwrap().identifiers.clear();
    }
    {
        let mut state = trace.0.lock().unwrap();
        state.events.clear();
        state.mode = input["mode"].as_str().unwrap_or("normal").into();
        state.active = true;
    }
    let kind = input["kind"].as_str().unwrap_or("email");
    let route = match kind {
        "phone" => "/sign-in/phone-number",
        "username" => "/sign-in/username",
        _ => "/sign-in/email",
    };
    let mut body = json!({"password":PASSWORD,"rememberMe":false});
    match kind {
        "phone" => body["phoneNumber"] = "+15551230000".into(),
        "username" => body["username"] = "factor".into(),
        _ => body["email"] = EMAIL.into(),
    };
    let mut headers = std::collections::HashMap::from([
        ("content-type".into(), "application/json".into()),
        (
            "origin".into(),
            auth.context()
                .base_url()
                .trim_end_matches("/api/auth")
                .to_owned(),
        ),
    ]);
    if let Some(cookie) = input["cookie"].as_str() {
        headers.insert("cookie".into(), cookie.into());
    }
    let result = if input["native"] == true {
        auth.call_endpoint(
            HttpMethod::Post,
            route,
            better_auth::server_api::EndpointInput {
                body: Some(body),
                headers: Some(headers),
                ..Default::default()
            },
        )
        .await
    } else {
        let mut request = AuthRequest::new(HttpMethod::Post, route).with_url(
            format!("{}{}", auth.context().base_url(), route)
                .parse()
                .unwrap(),
        );
        request.body = Some(serde_json::to_vec(&body)?);
        request.headers = headers;
        auth.handle_request(request).await
    };
    let mut result = match result {
        Ok(response) => {
            json!({"status":response.status,"body":if response.body.is_empty(){Value::Null}else{shape(serde_json::from_slice(&response.body.bytes()?)?)},"cookies":cookies(&response)})
        }
        Err(error) if error.is_api_error() => {
            let response = error.to_auth_response();
            let body: Value = serde_json::from_slice(&response.body.bytes()?)?;
            json!({"error":{"ordinary":false,"message":body["message"],"code":body["code"]}})
        }
        Err(AuthError::Internal(message)) => {
            json!({"error":{"ordinary":true,"message":message,"code":null}})
        }
        Err(error) => return Err(error),
    };
    let (sessions, proofs) = trace.counts(auth.context()).await?;
    result["events"] = json!(trace.0.lock().unwrap().events);
    result["sessions"] = sessions.into();
    result["proofs"] = proofs.into();
    Ok(result)
}

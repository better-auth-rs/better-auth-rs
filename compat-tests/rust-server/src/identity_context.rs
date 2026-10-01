use axum::{
    Json, Router,
    routing::{get, post},
};
use better_auth::plugins::endpoint_context::EndpointContext;
use better_auth::plugins::{
    EmailPasswordPlugin,
    anonymous::{AnonymousCallbacks, AnonymousPlugin},
    magic_link::{MagicLinkCallbacks, MagicLinkPlugin},
};
use better_auth::{AuthConfig, AuthError, AuthResult, BetterAuth, server_api::EndpointInput};
use better_auth_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthUser, HttpMethod, UpdateUser,
    config::CookieCacheConfig, middleware::RateLimitConfig, store::StatelessSchema,
    utils::password::PasswordHasher,
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

const PASSWORD: &str = "fixture-password";
type Auth = BetterAuth<StatelessSchema>;

struct Hasher;
#[async_trait::async_trait]
impl PasswordHasher for Hasher {
    async fn hash(&self, value: &str) -> AuthResult<String> {
        Ok(format!("fixture:{value}"))
    }
    async fn verify(&self, hash: &str, value: &str) -> AuthResult<bool> {
        Ok(hash == format!("fixture:{value}"))
    }
}

#[derive(Clone)]
struct Fixture {
    input: Value,
    events: Arc<Mutex<Vec<Value>>>,
}
impl Fixture {
    fn record(&self, value: Value) {
        self.events.lock().unwrap().push(value);
    }
    fn fail(&self) -> AuthResult<()> {
        match self.input["mode"].as_str() {
            Some("api-error") => Err(AuthError::Upstream {
                status: 400,
                code: "CALLBACK_REJECTED",
                message: "Callback rejected",
            }),
            Some("ordinary-error") => Err(AuthError::internal("Callback ordinary failure")),
            _ => Ok(()),
        }
    }
}

fn context(endpoint: &EndpointContext<'_, StatelessSchema>) -> Value {
    let returned: Option<Value> = endpoint
        .response
        .and_then(|response| serde_json::from_slice(&response.body).ok());
    let mut keys: Vec<_> = endpoint
        .body
        .as_object()
        .map(|body| body.keys().cloned().collect())
        .unwrap_or_default();
    keys.sort();
    let mut returned_keys: Vec<_> = returned
        .as_ref()
        .and_then(Value::as_object)
        .map(|body| body.keys().cloned().collect())
        .unwrap_or_default();
    returned_keys.sort();
    json!({"path":endpoint.path,"request":endpoint.request.is_some(),"headers":endpoint.headers().is_some(),
        "tag":endpoint.headers().and_then(|headers|headers.get("x-probe-tag")),"bodyKeys":keys,
        "hasReturned":endpoint.response.is_some(),"returnedKeys":returned_keys,
        "returnedHidden":returned.as_ref().and_then(|body|body.get("user")).and_then(|user|user.get("secretNote")),
        "hasSetCookie":endpoint.response.is_some_and(|response|response.headers.contains_key("set-cookie")),
        "location":endpoint.response.and_then(|response|response.headers.get("location")),
        "actorAnonymous":endpoint.session.as_ref().and_then(|(user,_)|user.is_anonymous)})
}

#[async_trait::async_trait]
impl AuthPlugin<StatelessSchema> for Fixture {
    fn name(&self) -> &'static str {
        "identity-context-application"
    }
    fn routes(&self) -> Vec<better_auth_core::AuthRoute> {
        Vec::new()
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
    async fn after_request(
        &self,
        request: &AuthRequest,
        _: &mut AuthResponse,
        ctx: &AuthContext<StatelessSchema>,
    ) -> AuthResult<()> {
        if self.input["mutate"] == true && request.path() == "/sign-in/email" {
            let data = request.new_session()?.unwrap();
            let _ = ctx
                .database
                .update_user(
                    data.user.id.typed().unwrap(),
                    UpdateUser {
                        name: Some("Changed after issue".into()),
                        additional_fields: serde_json::Map::from_iter([(
                            "secretNote".into(),
                            json!("changed-secret"),
                        )]),
                        ..Default::default()
                    },
                )
                .await?;
            self.record(json!({"event":"application","name":data.user.name,"secret":data.user.additional_fields.get("secretNote")}));
        }
        Ok(())
    }
}

async fn build(base: &str, input: &Value, events: Arc<Mutex<Vec<Value>>>) -> AuthResult<Auth> {
    let fixture = Fixture {
        input: input.clone(),
        events,
    };
    let mut config =
        AuthConfig::new("identity-context-secret-at-least-thirty-two-characters").base_url(base);
    config.session.expires_in = chrono::Duration::hours(1);
    config.session.cookie_cache = Some(CookieCacheConfig {
        enabled: Some(false),
        ..Default::default()
    });
    config.user.additional_fields.insert(
        "secretNote".into(),
        better_auth_core::config::UserFieldConfig {
            returned: false,
            default_value: Some(json!("issued-secret")),
            ..Default::default()
        },
    );
    config.session.additional_fields.insert(
        "secretSession".into(),
        better_auth_core::config::UserFieldConfig {
            returned: false,
            default_value: Some(json!("hidden-session")),
            ..Default::default()
        },
    );
    let name = fixture.clone();
    let link = fixture.clone();
    let magic = fixture.clone();
    let anonymous = AnonymousPlugin::new().callbacks(AnonymousCallbacks::<StatelessSchema>::default()
        .generate_name(move |endpoint| { let fixture=name.clone(); Box::pin(async move {
            fixture.record(json!({"event":"name","context":context(endpoint)}));
            if fixture.input["kind"] == "name" { fixture.fail()?; }
            Ok("Anonymous fixture".into())
        }) })
        .on_link_account(move |linked, endpoint| { let fixture=link.clone(); Box::pin(async move {
            let stored = endpoint.auth.database.get_user_by_id(linked.new_user.id.typed().unwrap()).await?.unwrap();
            let snapshot=endpoint.new_session()?.unwrap();
            fixture.record(json!({"event":"link","context":context(endpoint),
                "oldHidden":linked.anonymous_user.additional_fields.get("secretNote"),"oldSessionHidden":linked.anonymous_session.additional_fields.get("secretSession"),
                "newHidden":linked.new_user.additional_fields.get("secretNote"),"newSessionHidden":linked.new_session.additional_fields.get("secretSession"),
                "newName":linked.new_user.name,"storedName":stored.name(),"storedHidden":stored.additional_fields.get("secretNote"),
                "sameSnapshot":snapshot.user.id == linked.new_user.id && snapshot.user.name == linked.new_user.name,
                "oldExists":endpoint.auth.database.get_user_by_id(linked.anonymous_user.id.typed().unwrap()).await?.is_some()}));
            endpoint.set_header("x-callback-observed","anonymous-link")?;
            fixture.fail()
        }) }));
    let magic = MagicLinkPlugin::new().generate_token(Arc::new(|_| Box::pin(async { Ok("magic-fixture-token".into()) }))).callbacks(MagicLinkCallbacks::<StatelessSchema>::new(move |message, endpoint| {
        let fixture=magic.clone(); Box::pin(async move {
            fixture.record(json!({"event":"magic","context":context(endpoint),"email":message.email,"metadata":message.metadata,
                "stored":endpoint.auth.database.get_verification_by_identifier("magic-fixture-token").await?.is_some()}));
            endpoint.set_header("x-callback-observed","magic-send")?;
            fixture.fail()
        })
    }));
    BetterAuth::stateless(config)
        .rate_limit(RateLimitConfig::new().enabled(false))
        .plugin(
            EmailPasswordPlugin::new()
                .password_hasher(Arc::new(Hasher))
                .auto_sign_in(input["autoSignIn"] != false),
        )
        .plugin(fixture)
        .plugin(anonymous)
        .plugin(magic)
        .build()
        .await
}

async fn invoke(
    auth: &Auth,
    base: &str,
    path: &str,
    body: Value,
    cookie: &str,
    input: &Value,
) -> AuthResult<AuthResponse> {
    let mut headers = HashMap::from([
        ("origin".into(), base.into()),
        ("content-type".into(), "application/json".into()),
        ("x-probe-tag".into(), "callback-fixture".into()),
    ]);
    if !cookie.is_empty() {
        headers.insert("cookie".into(), cookie.into());
    }
    if input["transport"] == "native" {
        let headers = match input["headers"].as_str() {
            Some("omit") => None,
            Some("empty") => Some(HashMap::new()),
            _ => Some(headers),
        };
        auth.call_endpoint(
            HttpMethod::Post,
            path,
            EndpointInput {
                headers,
                body: Some(body),
                ..Default::default()
            },
        )
        .await
    } else {
        let mut request = AuthRequest::new(HttpMethod::Post, format!("/api/auth{path}"))
            .with_url(url::Url::parse(&format!("{base}/api/auth{path}")).unwrap());
        request.headers = headers;
        request.body = Some(serde_json::to_vec(&body)?);
        auth.handle_request(request).await
    }
}

fn observe(result: AuthResult<AuthResponse>) -> Value {
    let (response, thrown) = match result {
        Ok(response) => (response, false),
        Err(AuthError::Internal(message)) => return json!({"thrown":true,"message":message}),
        Err(error) => (error.to_auth_response(), true),
    };
    let body: Option<Value> = serde_json::from_slice(&response.body).ok();
    let mut keys: Vec<_> = body
        .as_ref()
        .and_then(Value::as_object)
        .map(|body| body.keys().cloned().collect())
        .unwrap_or_default();
    keys.sort();
    json!({"status":response.status,"thrown":thrown,"error":if response.status>=400 {body.clone()} else {None},"bodyKeys":keys,
        "name":body.as_ref().and_then(|body|body.get("user")).and_then(|user|user.get("name")),"publicHidden":body.as_ref().and_then(|body|body.get("user")).is_some_and(|user|user.get("secretNote").is_some()),
        "header":response.headers.get("x-callback-observed"),"cookies":response.headers.get_all("set-cookie").map(|value|json!({"name":value.split('=').next(),"persistent":value.to_ascii_lowercase().contains("max-age=")})).collect::<Vec<_>>()})
}

async fn run(base: &str, input: Value) -> AuthResult<Value> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let auth = build(base, &input, events.clone()).await?;
    let mut old_id = None;
    let kind = input["kind"].as_str().unwrap_or("magic");
    let (path, body, cookie) = match kind {
        "link" => {
            let _ = invoke(
                &auth,
                base,
                "/sign-up/email",
                json!({"name":"Original member","email":"member@example.com","password":PASSWORD}),
                "",
                &json!({}),
            )
            .await?;
            let anonymous = invoke(
                &auth,
                base,
                "/sign-in/anonymous",
                json!({"marker":"name-body"}),
                "",
                &json!({}),
            )
            .await?;
            let body: Value = serde_json::from_slice(&anonymous.body)?;
            old_id = body["user"]["id"].as_str().map(str::to_owned);
            let cookie = anonymous
                .headers
                .get_all("set-cookie")
                .map(|value| value.split(';').next().unwrap())
                .collect::<Vec<_>>()
                .join("; ");
            (
                "/sign-in/email",
                json!({"email":"member@example.com","password":PASSWORD,"callbackURL":"/completed","unknown":"stripped"}),
                cookie,
            )
        }
        "name" => (
            "/sign-in/anonymous",
            json!({"marker":"name-body"}),
            String::new(),
        ),
        "signup" => {
            let mut body =
                json!({"name":"Original member","email":"member@example.com","password":PASSWORD});
            if let Some(value) = input.get("rememberMe") {
                body["rememberMe"] = value.clone();
            }
            ("/sign-up/email", body, String::new())
        }
        _ => (
            "/sign-in/magic-link",
            json!({"email":"magic@example.com","metadata":{"label":"metadata"},"unknown":"stripped"}),
            String::new(),
        ),
    };
    let output = observe(invoke(&auth, base, path, body, &cookie, &input).await);
    let store = &auth.context().database;
    let member = store.get_user_by_email("member@example.com").await?;
    let sessions = if let Some(user) = &member {
        store.get_user_sessions(user.id.typed().unwrap()).await?
    } else {
        vec![]
    };
    let lifetime = sessions
        .first()
        .map(|session| (session.expires_at - session.created_at).num_milliseconds())
        .map(|ms| (ms + 500) / 1000);
    let old_exists = if let Some(id) = old_id {
        Some(store.get_user_by_id(&id).await?.is_some())
    } else {
        None
    };
    Ok(
        json!({"output":output,"events":events.lock().unwrap().clone(),"memberExists":member.is_some(),"sessions":sessions.len(),"lifetime":lifetime,"oldExists":old_exists,
        "proof":store.get_verification_by_identifier("magic-fixture-token").await?.is_some()}),
    )
}

pub fn router(base_url: &str) -> Router {
    let base = base_url.to_owned();
    Router::new()
        .route("/health", get(|| async { Json(json!({"status":"ok"})) }))
        .route("/__health", get(|| async { Json(json!({"status":"ok"})) }))
        .route(
            "/__test/reset-state",
            post(|| async { Json(json!({"success":true})) }),
        )
        .route(
            "/__test/identity-context",
            post(move |Json(input): Json<Value>| {
                let base = base.clone();
                async move { Json(run(&base, input).await.unwrap()) }
            }),
        )
}

use super::*;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use josekit::{jwk::Jwk, jws::JwsHeader};
use std::sync::atomic::{AtomicBool, Ordering};

pub(super) fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/paybin-1.7.6.json"
    ))
    .unwrap()
}

pub(super) fn resolved(config: OAuthProvider) -> resolved::ResolvedProvider {
    resolved::ResolvedProvider {
        config,
        generic: None,
    }
}

pub(super) fn public(response: OAuthUserInfoResponse) -> Value {
    json!({"user": types::AccountInfoUser {
        id: None, name: response.user.name, email: response.user.email, image: response.user.image,
        email_verified: response.user.email_verified, additional_fields: response.user.additional_fields,
    }, "data": response.data})
}

pub(super) struct Mapper {
    pub patch: Value,
    pub seen: Arc<Mutex<Vec<Value>>>,
    pub error: bool,
}

#[async_trait]
impl OAuthProfileMapper for Mapper {
    async fn map_profile(&self, profile: &Value) -> AuthResult<OAuthProfile> {
        self.seen.lock().unwrap().push(profile.clone());
        if self.error {
            return Err(AuthError::internal("Ordinary Paybin mapper error"));
        }
        let mut additional_fields = self.patch.as_object().unwrap().clone();
        for field in ["name", "email", "image", "emailVerified"] {
            let _ = additional_fields.remove(field);
        }
        Ok(OAuthProfile {
            name: self
                .patch
                .get("name")
                .cloned()
                .map(serde_json::from_value)
                .transpose()?,
            email: self
                .patch
                .get("email")
                .cloned()
                .map(|value| SchemaValue::from_json(Some(value))),
            image: self
                .patch
                .get("image")
                .cloned()
                .map(serde_json::from_value)
                .transpose()?,
            email_verified: self
                .patch
                .get("emailVerified")
                .cloned()
                .map(|value| SchemaValue::from_json(Some(value))),
            additional_fields,
        })
    }
}

struct ServerState {
    issuer: String,
    public_key: Jwk,
    token: String,
    fixture: Value,
    paths: Arc<Mutex<Vec<String>>>,
    requests: Arc<Mutex<Vec<Value>>>,
    unavailable: Arc<AtomicBool>,
}

async fn discovery(State(state): State<Arc<ServerState>>) -> Json<Value> {
    state
        .paths
        .lock()
        .unwrap()
        .push("/.well-known/openid-configuration".into());
    Json(
        json!({"issuer": state.issuer, "jwks_uri": format!("{}/keys/active", state.issuer),
        "authorization_endpoint": format!("{}/metadata-only/authorize",state.issuer),
        "token_endpoint": format!("{}/metadata-only/token",state.issuer),
        "id_token_signing_alg_values_supported":["RS256"]}),
    )
}

async fn keys(State(state): State<Arc<ServerState>>) -> Json<Value> {
    state.paths.lock().unwrap().push("/keys/active".into());
    Json(json!({"keys":[state.public_key]}))
}

async fn token_response(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    state.paths.lock().unwrap().push("/oauth2/token".into());
    let header = |name| headers.get(name).map(|value| value.to_str().unwrap());
    state.requests.lock().unwrap().push(json!({"url":"https://idp.paybin.io/oauth2/token", "method":"POST",
        "authorization":header("authorization"),"contentType":header("content-type"),"accept":header("accept"),"body":body}));
    if state.unavailable.load(Ordering::SeqCst) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"ordinary_unavailable"})),
        )
            .into_response();
    }
    let grant = if body.starts_with("grant_type=refresh_token") {
        "refresh"
    } else {
        "code"
    };
    let mut response = state.fixture["grants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == grant)
        .unwrap()["rawResponse"]
        .clone();
    response["id_token"] = state.token.clone().into();
    Json(response).into_response()
}

pub(super) struct Server {
    pub issuer: String,
    pub claims: Value,
    pub token: String,
    pub paths: Arc<Mutex<Vec<String>>>,
    pub requests: Arc<Mutex<Vec<Value>>>,
    pub unavailable: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<Result<(), std::io::Error>>,
}

impl Server {
    pub async fn start(mut claims: Value) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let fixture = fixture();
        let now = chrono::Utc::now().timestamp();
        claims["iss"] = issuer.clone().into();
        claims["aud"] = fixture["metadata"]["clientId"].clone();
        claims["iat"] = now.into();
        claims["exp"] = (now + 3600).into();
        let mut key = Jwk::generate_rsa_key(2048).unwrap();
        key.set_key_id("ordinary-paybin");
        let mut public_key = key.to_public_key().unwrap();
        public_key.set_key_id("ordinary-paybin");
        let mut header = JwsHeader::new();
        header.set_algorithm("RS256");
        header.set_key_id("ordinary-paybin");
        let token = josekit::jws::serialize_compact(
            claims.to_string().as_bytes(),
            &header,
            &josekit::jws::RS256.signer_from_jwk(&key).unwrap(),
        )
        .unwrap();
        let paths = Arc::default();
        let requests = Arc::default();
        let unavailable = Arc::default();
        let state = Arc::new(ServerState {
            issuer: issuer.clone(),
            public_key,
            token: token.clone(),
            fixture,
            paths: Arc::clone(&paths),
            requests: Arc::clone(&requests),
            unavailable: Arc::clone(&unavailable),
        });
        let router = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/keys/active", get(keys))
            .route("/oauth2/token", post(token_response))
            .with_state(state);
        let task = tokio::spawn(async move { axum::serve(listener, router).await });
        Self {
            issuer,
            claims,
            token,
            paths,
            requests,
            unavailable,
            task,
        }
    }

    pub fn provider(&self) -> OAuthProvider {
        let fixture = fixture();
        OAuthProvider::paybin_with_issuer(
            fixture["metadata"]["clientId"].as_str().unwrap(),
            fixture["metadata"]["clientSecret"].as_str().unwrap(),
            &self.issuer,
        )
    }

    pub fn request(&self) -> OAuthUserInfoRequest {
        OAuthUserInfoRequest {
            id_token: Some(self.token.clone()),
            ..Default::default()
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

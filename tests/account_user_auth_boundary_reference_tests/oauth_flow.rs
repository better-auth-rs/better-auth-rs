use super::*;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, Method, Uri},
    routing::post,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use std::sync::{
    OnceLock,
    atomic::{AtomicUsize, Ordering},
};

pub(super) const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

struct Proof {
    state: String,
    cookie: String,
    challenge: String,
    verifier: String,
}

impl Proof {
    fn normalize_text(&self, value: &str) -> String {
        value
            .replace(&self.cookie, "<verified-oauth-state-cookie>")
            .replace(&self.state, "<oauth-state>")
            .replace(&self.challenge, "<oauth-code-challenge>")
            .replace(&self.verifier, "<verified-oauth-code-verifier>")
    }

    fn normalize(&self, value: &mut Value) {
        match value {
            Value::String(text) => *text = self.normalize_text(text),
            Value::Array(values) => values.iter_mut().for_each(|value| self.normalize(value)),
            Value::Object(values) => values.values_mut().for_each(|value| self.normalize(value)),
            _ => {}
        }
    }
}

#[derive(Clone)]
struct Exchange {
    events: Events,
    proof: Arc<OnceLock<Proof>>,
    calls: Arc<AtomicUsize>,
    authority: String,
}

#[expect(
    clippy::expect_used,
    reason = "Fixture handler failures must fail the HTTP contract; the handler cannot return AuthError."
)]
fn exchange(
    State(state): State<Exchange>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: String,
) -> std::future::Ready<Json<Value>> {
    assert_eq!(method, Method::POST);
    assert_eq!(uri.to_string(), "/token");
    assert_eq!(
        headers
            .get("host")
            .expect("Token request Host")
            .to_str()
            .expect("ASCII Host"),
        state.authority
    );
    assert_eq!(
        headers
            .get("content-length")
            .expect("Token request length")
            .to_str()
            .expect("ASCII length")
            .parse::<usize>()
            .expect("Numeric length"),
        body.len()
    );
    let pairs = url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect::<Vec<_>>();
    let mut fields = pairs
        .iter()
        .cloned()
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        fields.len(),
        pairs.len(),
        "Token request must not repeat form fields"
    );
    let proof = state
        .proof
        .get()
        .expect("OAuth state must precede token exchange");
    assert_eq!(fields.get("code_verifier"), Some(&proof.verifier));
    assert_eq!(
        URL_SAFE_NO_PAD.encode(Sha256::digest(proof.verifier.as_bytes())),
        proof.challenge
    );
    let _ = fields.insert(
        "code_verifier".into(),
        "<verified-oauth-code-verifier>".into(),
    );
    let mut observed_headers = headers
        .iter()
        .filter(|(name, _)| !matches!(name.as_str(), "host" | "content-length"))
        .map(|(name, value)| {
            [
                name.to_string(),
                value.to_str().expect("ASCII token header").to_owned(),
            ]
        })
        .collect::<Vec<_>>();
    observed_headers.sort();
    let response = json!({"access_token": "callback-access", "id_token": ID_TOKEN});
    state
        .events
        .push(json!({"kind": "provider.exchange", "request": {
        "url": TOKEN_URL, "method": "POST", "headers": observed_headers, "body": fields,
    }, "response": response}))
        .expect("Record token exchange");
    let _ = state.calls.fetch_add(1, Ordering::SeqCst);
    std::future::ready(Json(response))
}

pub(super) struct Flow {
    pub(super) endpoint: String,
    proof: Arc<OnceLock<Proof>>,
    calls: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Drop for Flow {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Flow {
    pub(super) async fn start(events: Events) -> TestResult<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let authority = listener.local_addr()?.to_string();
        let endpoint = format!("http://{authority}/token");
        let proof = Arc::new(OnceLock::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let router = Router::new()
            .route("/token", post(exchange))
            .with_state(Exchange {
                events,
                proof: proof.clone(),
                calls: calls.clone(),
                authority,
            });
        let task = tokio::spawn(async move { axum::serve(listener, router).await });
        Ok(Self {
            endpoint,
            proof,
            calls,
            task,
        })
    }

    pub(super) async fn prepare<S: AuthSchema>(
        &self,
        auth: Arc<BetterAuth<S>>,
        setup: &fixture::Setup,
        request: &fixture::Request,
    ) -> TestResult<fixture::Request> {
        let start = chrono::Utc::now().timestamp_millis();
        let response = http::request(auth, &setup.request).await?;
        let end = chrono::Utc::now().timestamp_millis();
        assert_eq!(response.status, setup.response.status);
        let mut body: Value = serde_json::from_str(&response.body)?;
        let authorization = url::Url::parse(
            body["url"]
                .as_str()
                .ok_or("Missing OAuth authorization URL")?,
        )?;
        assert_eq!(
            authorization.origin().ascii_serialization(),
            "https://accounts.google.com"
        );
        let parameters = authorization
            .query_pairs()
            .into_owned()
            .collect::<std::collections::BTreeMap<_, _>>();
        let state = parameters
            .get("state")
            .ok_or("Missing OAuth state")?
            .clone();
        assert_eq!(state.len(), 32);
        let challenge = parameters
            .get("code_challenge")
            .ok_or("Missing PKCE challenge")?
            .clone();
        assert_eq!(
            parameters.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );
        assert_eq!(response.cookies.len(), 1);
        let cookie = response
            .cookies
            .first()
            .ok_or("Missing OAuth state Cookie")?
            .split_once(';')
            .ok_or("Missing OAuth state Cookie attributes")?
            .0
            .strip_prefix("better-auth.oauth_state=")
            .ok_or("Unexpected OAuth Cookie name")?
            .to_owned();
        let decrypted = better_auth_core::utils::symmetric::decrypt(SECRET, &cookie)?;
        let payload: Value = serde_json::from_str(&decrypted)?;
        assert_eq!(payload["oauthState"], state);
        assert_eq!(payload["callbackURL"], format!("{ORIGIN}/welcome"));
        let expiry = payload["expiresAt"]
            .as_f64()
            .ok_or("Missing OAuth state expiry")?;
        assert!(expiry.is_finite() && expiry.fract() == 0.0);
        assert!(((start as f64)..=(end as f64)).contains(&(expiry - 600_000.0)));
        let verifier = payload["codeVerifier"]
            .as_str()
            .ok_or("Missing encrypted PKCE verifier")?
            .to_owned();
        assert_eq!(
            URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
            challenge
        );
        let proof = Proof {
            state,
            cookie,
            challenge,
            verifier,
        };
        proof.normalize(&mut body);
        assert_eq!(body, setup.response.body);
        assert_eq!(
            response
                .headers
                .iter()
                .map(|[name, value]| [name.clone(), proof.normalize_text(value)])
                .collect::<Vec<_>>(),
            setup.response.headers
        );
        assert_eq!(
            response
                .cookies
                .iter()
                .map(|value| proof.normalize_text(value))
                .collect::<Vec<_>>(),
            setup.response.cookies
        );
        let mut request = request.clone();
        request.url = request.url.replace("<oauth-state>", &proof.state);
        for [_, value] in &mut request.headers {
            *value = value.replace("<verified-oauth-state-cookie>", &proof.cookie);
        }
        self.proof
            .set(proof)
            .map_err(|_| "OAuth setup must run once")?;
        Ok(request)
    }

    pub(super) fn verify_and_normalize(&self, events: &mut [Value]) -> TestResult {
        assert_eq!(self.calls.load(Ordering::SeqCst), 1);
        let proof = self.proof.get().ok_or("OAuth setup missing")?;
        for event in events {
            proof.normalize(event);
        }
        Ok(())
    }
}

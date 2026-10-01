use josekit::{jwk::Jwk, jws::JwsHeader};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::OAuthProvider;

pub(super) struct GoogleFixture {
    pub(super) url: String,
    pub(super) token: String,
    pub(super) requests: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl GoogleFixture {
    pub(super) async fn start(mut claims: Value) -> Self {
        let mut key = Jwk::generate_rsa_key(2048).unwrap();
        key.set_key_id("google-normal-fixture");
        let mut public = key.to_public_key().unwrap();
        public.set_key_id("google-normal-fixture");
        let now = chrono::Utc::now().timestamp();
        let fields = claims.as_object_mut().unwrap();
        for (name, value) in [
            ("iss", json!("https://accounts.google.com")),
            ("aud", json!("client")),
            ("iat", json!(now)),
            ("exp", json!(now + 3600)),
        ] {
            let _ = fields.entry(name).or_insert(value);
        }
        let mut header = JwsHeader::new();
        header.set_algorithm("RS256");
        header.set_key_id("google-normal-fixture");
        let token = josekit::jws::serialize_compact(
            claims.to_string().as_bytes(),
            &header,
            &josekit::jws::RS256.signer_from_jwk(&key).unwrap(),
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let logged = requests.clone();
        let signed_token = token.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = [0; 8192];
                let size = stream.read(&mut bytes).await.unwrap();
                let request = String::from_utf8_lossy(&bytes[..size]);
                let path = request.split_whitespace().nth(1).unwrap();
                logged.lock().unwrap().push(path.to_owned());
                let body = match path {
                    "/jwks" => json!({"keys":[public]}),
                    "/token" => json!({"id_token":signed_token,"access_token":"normal-access","expires_in":3600}),
                    _ => panic!("unexpected Google fixture request: {path}"),
                }
                .to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        Self {
            url,
            token,
            requests,
            task,
        }
    }

    pub(super) fn provider(&self) -> OAuthProvider {
        let mut provider = OAuthProvider::google("client", "secret");
        self.configure(&mut provider);
        provider
    }

    pub(super) fn configure(&self, provider: &mut OAuthProvider) {
        provider.set_google_jwks_url(format!("{}/jwks", self.url));
        provider.token_url = format!("{}/token", self.url);
        provider.user_info_url = Some(format!("{}/userinfo", self.url));
    }
}

impl Drop for GoogleFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

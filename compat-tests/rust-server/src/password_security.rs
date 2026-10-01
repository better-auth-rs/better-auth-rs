use std::sync::{Arc, Mutex};

use axum::{Json, Router, response::IntoResponse, routing::post};
use better_auth::plugins::{
    EmailPasswordPlugin,
    have_i_been_pwned::{HaveIBeenPwnedConfig, HaveIBeenPwnedPlugin, PasswordCompromiseClient},
};
use better_auth_core::{
    AuthError, AuthResult, AuthSchema, AuthUser, PasswordHasher, ScryptPasswordHasher,
    UpdateAccount, store::AuthStore,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Default)]
struct Data {
    body: String,
    status: u16,
    drop_connection: bool,
    requests: Vec<Value>,
    hashes: Vec<String>,
}

#[derive(Clone)]
pub struct PasswordSecurityFixture {
    data: Arc<Mutex<Data>>,
    client: PasswordCompromiseClient,
}

impl PasswordSecurityFixture {
    pub async fn new() -> Self {
        let data = Arc::new(Mutex::new(Data::default()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = PasswordCompromiseClient::new(format!(
            "http://{}/range/",
            listener.local_addr().unwrap()
        ));
        let server_data = data.clone();
        tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let data = server_data.clone();
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buffer = [0; 1024];
                    while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                        let length = socket.read(&mut buffer).await.unwrap();
                        if length == 0 {
                            return;
                        }
                        request.extend_from_slice(&buffer[..length]);
                    }
                    let request = String::from_utf8(request).unwrap();
                    let mut lines = request.lines();
                    let path = lines.next().unwrap().split_whitespace().nth(1).unwrap();
                    let headers: std::collections::HashMap<_, _> = lines
                        .filter_map(|line| line.split_once(':'))
                        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
                        .collect();
                    let (body, status, drop_connection) = {
                        let mut data = data.lock().unwrap();
                        data.requests.push(json!({ "prefix":path.trim_start_matches("/range/"), "padding":headers.get("add-padding"), "agent":headers.get("user-agent") }));
                        (
                            data.body.clone(),
                            if data.status == 0 { 200 } else { data.status },
                            data.drop_connection,
                        )
                    };
                    if drop_connection {
                        return;
                    }
                    let response = format!(
                        "HTTP/1.1 {status} Fixture\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    socket.write_all(response.as_bytes()).await.unwrap();
                });
            }
        });
        Self { data, client }
    }

    pub fn plugin(&self, profile: &str) -> HaveIBeenPwnedPlugin {
        let mut config = HaveIBeenPwnedConfig::default();
        if profile == "password-security-disabled" {
            config.enabled = false;
        }
        if profile == "password-security-empty" {
            config.paths.clear();
        }
        if profile == "password-security-custom" {
            config.paths = vec!["/change-password".into(), "/sign-in/email".into()];
            config.custom_password_compromised_message = Some("Choose another password".into());
        }
        HaveIBeenPwnedPlugin::with_config(config).client(self.client.clone())
    }

    pub fn configure(&self, profile: &str, plugin: EmailPasswordPlugin) -> EmailPasswordPlugin {
        if profile.starts_with("password-security") {
            plugin.password_hasher(Arc::new(CountingHasher(self.data.clone())))
        } else {
            plugin
        }
    }

    pub fn reset(&self) {
        *self.data.lock().unwrap() = Data::default();
    }

    pub fn router<S: AuthSchema>(&self, store: Arc<dyn AuthStore<S>>) -> Router {
        let fixture = self.clone();
        Router::new().route(
            "/__test/password-security",
            post(move |Json(body): Json<Value>| {
                let fixture = fixture.clone();
                let store = store.clone();
                async move {
                    match fixture.control(&body, store.as_ref()).await {
                        Ok(value) => Json(value).into_response(),
                        Err(error) => error.into_response(),
                    }
                }
            }),
        )
    }

    async fn control<S: AuthSchema>(
        &self,
        body: &Value,
        store: &dyn AuthStore<S>,
    ) -> AuthResult<Value> {
        let action = body["action"].as_str().unwrap_or("state");
        if action == "configure" {
            let mut data = self.data.lock().unwrap();
            data.body = body["body"].as_str().unwrap_or("").into();
            data.status = body["status"].as_u64().unwrap_or(200) as u16;
            data.drop_connection = body["drop"].as_bool().unwrap_or(false);
            data.requests.clear();
            data.hashes.clear();
            return Ok(json!({"ok":true}));
        }
        if action == "state" {
            let data = self.data.lock().unwrap();
            return Ok(json!({"requests":data.requests,"hashes":data.hashes}));
        }
        if action == "check" {
            return Ok(
                json!({"compromised":self.client.is_password_compromised(body["password"].as_str().unwrap()).await?}),
            );
        }
        if action == "hash" {
            return Ok(
                json!({"hash":ScryptPasswordHasher.hash(body["password"].as_str().unwrap()).await?}),
            );
        }
        if action == "verify" {
            return Ok(
                json!({"valid":ScryptPasswordHasher.verify(body["hash"].as_str().unwrap(), body["password"].as_str().unwrap()).await?}),
            );
        }
        let Some(user) = store
            .get_user_by_email(body["email"].as_str().unwrap())
            .await?
        else {
            return Ok(json!({"user":false,"hash":null}));
        };
        let account = store
            .get_user_accounts(user.id().as_ref())
            .await?
            .into_iter()
            .find(|account| account.provider_id == "credential");
        if action == "write" {
            let account = account
                .as_ref()
                .ok_or_else(|| AuthError::not_found("Credential missing"))?;
            _ = store
                .update_account(
                    account.id.typed()?,
                    UpdateAccount {
                        password: (Some(body["hash"].as_str().unwrap().into())).into(),
                        ..Default::default()
                    },
                )
                .await?;
            return Ok(json!({"ok":true}));
        }
        Ok(
            json!({"user":true,"hash":account.as_ref().map(|account| account.password.json()).transpose()?.flatten()}),
        )
    }
}

struct CountingHasher(Arc<Mutex<Data>>);
#[async_trait::async_trait]
impl PasswordHasher for CountingHasher {
    async fn hash(&self, password: &str) -> AuthResult<String> {
        self.0.lock().unwrap().hashes.push(password.to_owned());
        ScryptPasswordHasher.hash(password).await
    }
    async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
        ScryptPasswordHasher.verify(hash, password).await
    }
}

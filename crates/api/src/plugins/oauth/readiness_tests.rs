use super::*;
use better_auth_core::{AuthError, AuthInitContext};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct DiscoveryServer {
    url: String,
    requests: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl DiscoveryServer {
    async fn start(status: &'static str, body: Value) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/discovery", listener.local_addr().unwrap());
        let requests = Arc::new(AtomicUsize::new(0));
        let count = requests.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buffer = [0; 4096];
                let _ = stream.read(&mut buffer).await.unwrap();
                count.fetch_add(1, Ordering::Relaxed);
                let body = body.to_string();
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        Self {
            url,
            requests,
            task,
        }
    }

    fn provider(&self) -> GenericOAuthConfig {
        GenericOAuthConfig {
            client_id: "client".into(),
            client_secret: Some("secret".into()),
            discovery_url: Some(self.url.clone()),
            require_id_token_verification: true,
            ..Default::default()
        }
    }
}

impl Drop for DiscoveryServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn valid_discovery() -> Value {
    json!({
        "issuer": "https://identity.example",
        "authorization_endpoint": "https://identity.example/authorize",
        "token_endpoint": "https://identity.example/token",
        "jwks_uri": "https://identity.example/jwks",
        "id_token_signing_alg_values_supported": ["RS256"]
    })
}

#[tokio::test]
async fn availability_uses_discovery_results_and_reuses_them_during_initialization() {
    for (status, document, available) in [
        ("503 Service Unavailable", json!({}), false),
        (
            "200 OK",
            json!({
                "authorization_endpoint": "https://identity.example/authorize",
                "token_endpoint": "https://identity.example/token"
            }),
            false,
        ),
        ("200 OK", valid_discovery(), true),
    ] {
        let server = DiscoveryServer::start(status, document).await;
        let plugin = OAuthPlugin::new().add_generic_provider("oidc", server.provider());
        let (known, unknown) =
            tokio::join!(plugin.has_provider("oidc"), plugin.has_provider("missing"));
        assert_eq!(known.unwrap(), available);
        assert!(!unknown.unwrap());
        let ctx = crate::plugins::test_helpers::create_test_context().await;
        let mut init = AuthInitContext::new(ctx.config, ctx.database);
        plugin.on_init(&mut init).await.unwrap();
        assert_eq!(plugin.has_provider("oidc").await.unwrap(), available);
        assert_eq!(server.requests.load(Ordering::Relaxed), 1);
    }
}

#[tokio::test]
async fn availability_propagates_static_configuration_errors() {
    let plugin = OAuthPlugin::new().add_generic_provider(
        "oidc",
        GenericOAuthConfig {
            require_id_token_verification: true,
            ..Default::default()
        },
    );
    assert!(matches!(
        plugin.has_provider("oidc").await,
        Err(AuthError::Config(_))
    ));
}

#[tokio::test]
async fn configuring_providers_after_inspection_invalidates_the_resolved_snapshot() {
    let plugin = OAuthPlugin::new();
    assert!(!plugin.has_provider("google").await.unwrap());
    let plugin = plugin.add_provider("google", OAuthProvider::google("client", "secret"));
    assert!(plugin.has_provider("google").await.unwrap());
    let server = DiscoveryServer::start("200 OK", valid_discovery()).await;
    let plugin = plugin.add_generic_provider("oidc", server.provider());
    assert!(plugin.has_provider("oidc").await.unwrap());
    assert!(plugin.has_provider("google").await.unwrap());
    assert_eq!(server.requests.load(Ordering::Relaxed), 1);
}

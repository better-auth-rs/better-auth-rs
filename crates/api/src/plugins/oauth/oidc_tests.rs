use super::*;
use josekit::{jwk::Jwk, jws::JwsHeader};
use serde_json::json;
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct MockServer {
    url: Url,
    body: Arc<Mutex<Value>>,
    requests: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl MockServer {
    async fn start(body: Value) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!("http://{}/jwks", listener.local_addr().unwrap())).unwrap();
        let body = Arc::new(Mutex::new(body));
        let requests = Arc::new(AtomicUsize::new(0));
        let response_body = body.clone();
        let request_count = requests.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = vec![0; 4096];
                let _ = stream.read(&mut bytes).await.unwrap();
                request_count.fetch_add(1, Ordering::Relaxed);
                let body = response_body.lock().unwrap().to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        Self {
            url,
            body,
            requests,
            task,
        }
    }

    fn verifier(&self) -> OidcVerifier {
        let mut verifier = OidcVerifier::new(
            self.url.clone(),
            "https://issuer.example".into(),
            "client".into(),
            None,
        )
        .unwrap();
        verifier.client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        verifier
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn rsa_key(kid: &str) -> Jwk {
    let mut key = Jwk::generate_rsa_key(2048).unwrap();
    key.set_key_id(kid);
    key
}

fn public_key(key: &Jwk) -> Value {
    let mut public = key.to_public_key().unwrap();
    if let Some(kid) = key.key_id() {
        public.set_key_id(kid);
    }
    serde_json::to_value(public).unwrap()
}

fn sign(key: &Jwk, claims: Value) -> String {
    let mut header = JwsHeader::new();
    header.set_algorithm("RS256");
    if let Some(kid) = key.key_id() {
        header.set_key_id(kid);
    }
    josekit::jws::serialize_compact(
        claims.to_string().as_bytes(),
        &header,
        &josekit::jws::RS256.signer_from_jwk(key).unwrap(),
    )
    .unwrap()
}

fn claims() -> Value {
    json!({"iss":"https://issuer.example","aud":"client","sub":"subject","nonce":"expected"})
}

fn age_cache(verifier: &OidcVerifier, elapsed: Duration) {
    let mut cache = verifier.cache.write().unwrap();
    let current = cache.as_ref().unwrap();
    *cache = Some(Arc::new(CachedJwks {
        keys: current.keys.clone(),
        fetched_at: Instant::now() - elapsed,
    }));
}

#[tokio::test]
async fn verifies_upstream_jose_signatures_for_all_supported_asymmetric_algorithms() {
    // Generated and verified by the jose version installed with better-auth 1.7.6.
    // Fixtures contain only public keys and tokens for a synthetic issuer.
    #[derive(Deserialize)]
    struct Fixture {
        alg: String,
        key: Value,
        token: String,
    }
    let fixtures: Vec<Fixture> =
        serde_json::from_str(include_str!("oidc_signatures.json")).unwrap();
    for fixture in fixtures {
        let server = MockServer::start(json!({"keys":[fixture.key]})).await;
        let verifier = server.verifier();
        let result = verifier.verify(&fixture.token, Some("expected")).await;
        assert!(result.is_ok(), "{}: {result:?}", fixture.alg);
        let (message, signature) = fixture.token.rsplit_once('.').unwrap();
        let mut bytes = decode_base64(signature).unwrap();
        *bytes.first_mut().unwrap() ^= 1;
        let forged = format!("{message}.{}", URL_SAFE_NO_PAD.encode(bytes));
        assert!(
            verifier.verify(&forged, None).await.is_err(),
            "{} signature tampering",
            fixture.alg
        );
    }
}

#[tokio::test]
async fn verifies_real_signatures_and_oidc_claim_boundaries() {
    let key = rsa_key("original");
    let server = MockServer::start(json!({"keys":[public_key(&key)]})).await;
    let verifier = server.verifier();
    let token = sign(&key, claims());
    let verified = verifier.verify(&token, Some("expected")).await.unwrap();
    assert_eq!(verified.get("sub").and_then(Value::as_str), Some("subject"));
    assert!(verifier.verify(&token, Some("wrong")).await.is_err());
    assert!(verifier.verify(&token, Some("")).await.is_ok());

    let now = chrono::Utc::now().timestamp();
    for (name, value, accepted) in [
        ("iss", json!("https://attacker.example"), false),
        ("aud", json!("another-client"), false),
        ("aud", json!(["another-client", "client", 42]), true),
        ("exp", json!(now), false),
        ("exp", json!(now as f64 + 60.5), true),
        ("exp", json!("9999999999"), false),
        ("exp", Value::Null, false),
        ("nbf", json!(now + 60), false),
        ("nbf", json!(now - 60), true),
        ("iat", json!(now + 3600), true),
        ("iat", Value::Null, false),
        ("nonce", json!(42), false),
    ] {
        let mut payload = claims();
        let _ = payload.as_object_mut().unwrap().insert(name.into(), value);
        assert_eq!(
            verifier
                .verify(&sign(&key, payload), Some("expected"))
                .await
                .is_ok(),
            accepted,
            "claim {name}"
        );
    }
    let forged = sign(&rsa_key("original"), claims());
    assert!(verifier.verify(&forged, None).await.is_err());
    assert_eq!(server.requests.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn caches_keys_and_reloads_only_after_rotation_cooldown_or_expiry() {
    let original = rsa_key("original");
    let rotated = rsa_key("rotated");
    let server = MockServer::start(json!({"keys":[public_key(&original)]})).await;
    let verifier = server.verifier();
    let original_token = sign(&original, claims());
    let rotated_token = sign(&rotated, claims());
    let (first, second) = tokio::join!(
        verifier.verify(&original_token, None),
        verifier.verify(&original_token, None)
    );
    assert!(first.is_ok() && second.is_ok());
    assert_eq!(server.requests.load(Ordering::Relaxed), 1);

    *server.body.lock().unwrap() = json!({"keys":[public_key(&rotated)]});
    assert!(verifier.verify(&rotated_token, None).await.is_err());
    assert_eq!(server.requests.load(Ordering::Relaxed), 1);
    age_cache(&verifier, RELOAD_COOLDOWN + Duration::from_secs(1));
    assert!(verifier.verify(&rotated_token, None).await.is_ok());
    assert_eq!(server.requests.load(Ordering::Relaxed), 2);

    *server.body.lock().unwrap() = json!({"keys":[]});
    assert!(verifier.verify(&rotated_token, None).await.is_ok());
    age_cache(&verifier, CACHE_MAX_AGE + Duration::from_secs(1));
    assert!(verifier.verify(&rotated_token, None).await.is_err());
    assert_eq!(server.requests.load(Ordering::Relaxed), 3);
}

#[tokio::test]
async fn rejects_ambiguous_keys_and_non_verification_key_metadata() {
    let key = rsa_key("original");
    let public = public_key(&key);
    let server = MockServer::start(json!({"keys":[public.clone(), public.clone()]})).await;
    assert!(
        server
            .verifier()
            .verify(&sign(&key, claims()), None)
            .await
            .is_err()
    );
    for (field, value) in [
        ("use", json!("enc")),
        ("alg", json!("RS512")),
        ("key_ops", json!(["sign"])),
        ("key_ops", json!(["sign", "verify"])),
        ("key_ops", json!(["verify", "verify"])),
        ("ext", json!("true")),
        ("d", json!("private")),
    ] {
        let mut invalid = public.clone();
        let _ = invalid.as_object_mut().unwrap().insert(field.into(), value);
        *server.body.lock().unwrap() = json!({"keys":[invalid]});
        assert!(
            server
                .verifier()
                .verify(&sign(&key, claims()), None)
                .await
                .is_err(),
            "key field {field}"
        );
    }
    *server.body.lock().unwrap() = json!({"keys":[public]});
    let mut verifier = server.verifier();
    verifier.algorithms = Some(vec!["ES256".into()]);
    assert!(verifier.verify(&sign(&key, claims()), None).await.is_err());
}

#[tokio::test]
async fn rejects_jwks_redirects_without_contacting_the_redirect_target() {
    let target = MockServer::start(json!({"keys":[]})).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let redirect = format!("http://{}/jwks", listener.local_addr().unwrap());
    let location = target.url.to_string();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = vec![0; 4096];
        let _ = stream.read(&mut bytes).await.unwrap();
        stream.write_all(format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    });
    let mut verifier = target.verifier();
    verifier.jwks_url = Url::parse(&redirect).unwrap();
    assert!(matches!(
        verifier
            .verify(&sign(&rsa_key("original"), claims()), None)
            .await,
        Err(OidcError::Status(StatusCode::FOUND))
    ));
    task.await.unwrap();
    assert_eq!(target.requests.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn discovery_rejects_invalid_issuer_and_preserves_endpoint_overrides_for_the_caller() {
    let server = MockServer::start(json!({"issuer":"not an absolute URL"})).await;
    assert!(
        fetch_discovery(server.url.as_str(), &HeaderMap::new())
            .await
            .is_err()
    );
    *server.body.lock().unwrap() = json!({"issuer":"https://issuer.example", "authorization_endpoint":"https://issuer.example/authorize", "jwks_uri":"./keys", "id_token_signing_alg_values_supported":["RS256"]});
    let document = fetch_discovery(server.url.as_str(), &HeaderMap::new())
        .await
        .unwrap();
    assert_eq!(document.issuer.as_deref(), Some("https://issuer.example"));
    assert_eq!(document.jwks_uri.as_deref(), Some("./keys"));
}

#[tokio::test]
async fn discovery_signing_metadata_does_not_discard_usable_endpoints() {
    let key = rsa_key("original");
    let server = MockServer::start(Value::Null).await;
    let token = sign(&key, claims());
    for (algorithms, accepted) in [
        (json!("RS256"), true),
        (json!({"alg":"RS256"}), true),
        (json!([]), true),
        (json!(["RS256", 42]), false),
    ] {
        *server.body.lock().unwrap() = json!({
            "issuer":"https://issuer.example",
            "authorization_endpoint":"https://issuer.example/authorize",
            "jwks_uri":server.url,
            "id_token_signing_alg_values_supported":algorithms
        });
        let document = fetch_discovery(server.url.as_str(), &HeaderMap::new())
            .await
            .unwrap();
        assert_eq!(
            document.authorization_endpoint.as_deref(),
            Some("https://issuer.example/authorize")
        );
        let mut verifier = server.verifier();
        verifier.algorithms = document
            .id_token_signing_alg_values_supported
            .filter(|values| !values.is_empty());
        *server.body.lock().unwrap() = json!({"keys":[public_key(&key)]});
        assert_eq!(
            verifier.verify(&token, Some("expected")).await.is_ok(),
            accepted
        );
    }
}

use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;

fn code_request(params: &HashMap<String, String>) -> TokenRequest {
    TokenRequest::authorization_code(AuthorizationCodeRequest {
        code: "original-code",
        redirect_uri: "https://app.example/callback",
        code_verifier: Some("verifier"),
        client_key: None,
        device_id: None,
        headers: &HeaderMap::new(),
        additional_params: params,
        resources: &[],
    })
}

fn authentication<'a>(
    grant_type: TokenGrantType,
    strategy: Option<&'a TokenEndpointAuth>,
    secret: Option<&'a str>,
) -> TokenAuthentication<'a> {
    TokenAuthentication {
        client_id: "client",
        client_secret: secret,
        token_endpoint: "https://idp.example/token",
        grant_type,
        token_endpoint_auth: strategy,
        authentication: None,
    }
}

fn value<'a>(request: &'a TokenRequest, key: &str) -> Option<&'a str> {
    request
        .body
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.as_str())
}

// Upstream: @better-auth/core/oauth2 authorizationCodeRequest and refreshAccessTokenRequest.
#[tokio::test]
async fn grant_parameters_and_secret_auth_have_upstream_precedence() {
    let params = HashMap::from([
        ("code".to_string(), "replacement-code".to_string()),
        ("grant_type".to_string(), "password".to_string()),
        (
            "redirect_uri".to_string(),
            "https://wrong.example".to_string(),
        ),
        ("client_id".to_string(), "replacement-client".to_string()),
        (
            "client_secret".to_string(),
            "replacement-secret".to_string(),
        ),
        ("audience".to_string(), "fleet".to_string()),
        ("resource".to_string(), "replacement-resource".to_string()),
    ]);
    let mut headers = HeaderMap::new();
    headers.insert("x-provider", HeaderValue::from_static("provider-value"));
    headers.insert(ACCEPT, HeaderValue::from_static("application/custom+json"));
    let resources = ["one".to_string(), "two".to_string()];
    let mut request = TokenRequest::authorization_code(AuthorizationCodeRequest {
        code: "original-code",
        redirect_uri: "https://app.example/callback",
        code_verifier: Some("verifier"),
        client_key: Some("client-key"),
        device_id: Some("device"),
        headers: &headers,
        additional_params: &params,
        resources: &resources,
    });
    request
        .authenticate(authentication(
            TokenGrantType::AuthorizationCode,
            None,
            Some("secret"),
        ))
        .await
        .unwrap();
    assert_eq!(value(&request, "grant_type"), Some("authorization_code"));
    assert_eq!(value(&request, "code"), Some("original-code"));
    assert_eq!(
        value(&request, "redirect_uri"),
        Some("https://app.example/callback")
    );
    assert_eq!(value(&request, "client_id"), Some("client"));
    assert_eq!(value(&request, "client_secret"), Some("secret"));
    assert_eq!(value(&request, "audience"), Some("fleet"));
    assert_eq!(value(&request, "client_key"), Some("client-key"));
    assert_eq!(value(&request, "device_id"), Some("device"));
    assert_eq!(request.headers[ACCEPT], "application/custom+json");
    assert_eq!(request.headers["x-provider"], "provider-value");
    assert_eq!(
        request
            .body
            .iter()
            .filter(|(key, _)| key == "resource")
            .count(),
        2
    );

    let mut refresh_params = params;
    refresh_params.insert(
        "refresh_token".to_string(),
        "replacement-refresh".to_string(),
    );
    for key in ["__proto__", "constructor", "prototype"] {
        refresh_params.insert(key.to_string(), "blocked".to_string());
    }
    let mut refresh = TokenRequest::refresh_token("refresh", &refresh_params, &resources);
    refresh
        .authenticate(authentication(
            TokenGrantType::RefreshToken,
            None,
            Some("secret"),
        ))
        .await
        .unwrap();
    assert_eq!(value(&refresh, "grant_type"), Some("refresh_token"));
    assert_eq!(value(&refresh, "refresh_token"), Some("refresh"));
    assert_eq!(value(&refresh, "client_id"), Some("client"));
    assert_eq!(value(&refresh, "client_secret"), Some("secret"));
    assert_eq!(value(&refresh, "resource"), Some("replacement-resource"));
    assert_eq!(
        refresh
            .body
            .iter()
            .filter(|(key, _)| key == "resource")
            .count(),
        1
    );
    assert_eq!(refresh.headers[ACCEPT], "application/json");
    for key in ["__proto__", "constructor", "prototype"] {
        assert_eq!(value(&refresh, key), None);
    }
}

// Upstream encodes each Basic credential as form data before joining with a colon.
#[tokio::test]
async fn basic_auth_encodes_credentials_and_does_not_send_secrets_in_body() {
    let strategy = TokenEndpointAuth::ClientSecretBasic;
    let expected = "client+id%3A%2B%2F:s+e%3A%2B%2F%21%27%28%29*%C3%BC";
    for grant in [
        TokenGrantType::AuthorizationCode,
        TokenGrantType::RefreshToken,
    ] {
        let mut request = match grant {
            TokenGrantType::AuthorizationCode => code_request(&HashMap::new()),
            TokenGrantType::RefreshToken => {
                TokenRequest::refresh_token("refresh", &HashMap::new(), &[])
            }
        };
        request
            .authenticate(TokenAuthentication {
                client_id: "client id:+/",
                client_secret: Some("s e:+/!'()*ü"),
                ..authentication(grant, Some(&strategy), None)
            })
            .await
            .unwrap();
        let header = request.headers[AUTHORIZATION].to_str().unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(header.strip_prefix("Basic ").unwrap())
            .unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), expected);
        assert_eq!(value(&request, "client_secret"), None);
        assert_eq!(value(&request, "client_id"), None);
    }
}

#[tokio::test]
async fn authentication_rejects_incompatible_credentials_before_dispatch() {
    let cases = [
        (
            TokenEndpointAuth::None,
            Some("secret"),
            "none token endpoint authentication cannot be combined with clientSecret",
        ),
        (
            TokenEndpointAuth::ClientSecretPost,
            None,
            "client_secret_post token endpoint authentication requires clientSecret",
        ),
        (
            TokenEndpointAuth::ClientSecretBasic,
            Some(""),
            "client_secret_basic token endpoint authentication requires clientSecret",
        ),
    ];
    for (strategy, secret, expected) in cases {
        let mut request = code_request(&HashMap::new());
        let error = request
            .authenticate(authentication(
                TokenGrantType::AuthorizationCode,
                Some(&strategy),
                secret,
            ))
            .await
            .unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
    }
    let mut request = code_request(&HashMap::from([(
        "client_secret".to_string(),
        "injected".to_string(),
    )]));
    let error = request
        .authenticate(authentication(
            TokenGrantType::AuthorizationCode,
            Some(&TokenEndpointAuth::ClientSecretBasic),
            Some("secret"),
        ))
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("cannot be combined with client_secret body parameters")
    );

    let mut public = code_request(&HashMap::new());
    public
        .authenticate(authentication(
            TokenGrantType::AuthorizationCode,
            None,
            Some(""),
        ))
        .await
        .unwrap();
    assert_eq!(value(&public, "client_id"), Some("client"));
    assert_eq!(value(&public, "client_secret"), None);
    let error = public
        .authenticate(TokenAuthentication {
            client_id: "",
            ..authentication(TokenGrantType::AuthorizationCode, None, None)
        })
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("none token endpoint authentication requires clientId")
    );
}

struct FreshAssertion(AtomicUsize);

#[async_trait]
impl ClientAssertion for FreshAssertion {
    async fn get_client_assertion(
        &self,
        context: ClientAssertionContext<'_>,
    ) -> AuthResult<String> {
        assert_eq!(context.client_id, "client");
        assert_eq!(context.token_endpoint, "https://idp.example/token");
        Ok(format!(
            "{}.{}",
            context.grant_type.as_str(),
            self.0.fetch_add(1, Ordering::SeqCst)
        ))
    }
}

#[tokio::test]
async fn private_key_jwt_gets_a_fresh_assertion_for_each_grant() {
    let getter = Arc::new(FreshAssertion(AtomicUsize::new(0)));
    let strategy = TokenEndpointAuth::PrivateKeyJwt(getter.clone());
    for (index, grant) in [
        TokenGrantType::AuthorizationCode,
        TokenGrantType::RefreshToken,
    ]
    .into_iter()
    .enumerate()
    {
        let mut request = TokenRequest::new(grant);
        request
            .authenticate(authentication(grant, Some(&strategy), None))
            .await
            .unwrap();
        assert_eq!(value(&request, "client_id"), Some("client"));
        assert_eq!(
            value(&request, "client_assertion_type"),
            Some(CLIENT_ASSERTION_TYPE)
        );
        assert_eq!(
            value(&request, "client_assertion"),
            Some(format!("{}.{index}", grant.as_str()).as_str())
        );
        assert_eq!(value(&request, "client_secret"), None);
    }
    let mut request = code_request(&HashMap::new());
    assert!(
        request
            .authenticate(authentication(
                TokenGrantType::AuthorizationCode,
                Some(&strategy),
                Some("secret")
            ))
            .await
            .is_err()
    );
    assert_eq!(getter.0.load(Ordering::SeqCst), 2);
}

struct CustomAuthentication {
    complete_assertion: bool,
}

#[async_trait]
impl TokenRequestHook for CustomAuthentication {
    async fn customize_request(&self, context: TokenEndpointRequestContext<'_>) -> AuthResult<()> {
        assert_eq!(context.client_id, "client");
        assert_eq!(context.client_secret, Some("custom-secret"));
        assert_eq!(context.token_endpoint, "https://idp.example/token");
        context
            .headers
            .insert("x-provider-auth", HeaderValue::from_static("custom-auth"));
        context.body.push((
            "client_assertion".to_string(),
            context.grant_type.as_str().to_string(),
        ));
        if self.complete_assertion {
            context.body.push((
                "client_assertion_type".to_string(),
                "custom-type".to_string(),
            ));
        }
        Ok(())
    }
}

#[tokio::test]
async fn custom_auth_controls_requests_but_must_supply_complete_assertions() {
    for grant in [
        TokenGrantType::AuthorizationCode,
        TokenGrantType::RefreshToken,
    ] {
        let mut request = TokenRequest::new(grant);
        let strategy = TokenEndpointAuth::Custom(Arc::new(CustomAuthentication {
            complete_assertion: true,
        }));
        request
            .authenticate(authentication(
                grant,
                Some(&strategy),
                Some("custom-secret"),
            ))
            .await
            .unwrap();
        assert_eq!(request.headers["x-provider-auth"], "custom-auth");
        assert_eq!(value(&request, "client_assertion"), Some(grant.as_str()));
        assert_eq!(value(&request, "client_secret"), None);
    }
    let mut request = code_request(&HashMap::new());
    let strategy = TokenEndpointAuth::Custom(Arc::new(CustomAuthentication {
        complete_assertion: false,
    }));
    let error = request
        .authenticate(authentication(
            TokenGrantType::AuthorizationCode,
            Some(&strategy),
            Some("custom-secret"),
        ))
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("client_assertion and client_assertion_type must both be provided")
    );
}

#[tokio::test]
async fn manual_assertion_is_exclusive_with_configured_authentication() {
    let mut params = HashMap::from([("client_assertion".to_string(), "assertion".to_string())]);
    let mut incomplete = code_request(&params);
    assert!(
        incomplete
            .authenticate(authentication(
                TokenGrantType::AuthorizationCode,
                None,
                None
            ))
            .await
            .unwrap_err()
            .to_string()
            .contains("must both be provided")
    );
    params.insert(
        "client_assertion_type".to_string(),
        CLIENT_ASSERTION_TYPE.to_string(),
    );
    let mut request = code_request(&params);
    request
        .authenticate(authentication(
            TokenGrantType::AuthorizationCode,
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(value(&request, "client_id"), Some("client"));
    assert_eq!(value(&request, "client_assertion"), Some("assertion"));
    let error = request
        .authenticate(authentication(
            TokenGrantType::AuthorizationCode,
            Some(&TokenEndpointAuth::None),
            None,
        ))
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("cannot be combined with tokenEndpointAuth")
    );
    let error = request
        .authenticate(authentication(
            TokenGrantType::AuthorizationCode,
            None,
            Some("secret"),
        ))
        .await
        .unwrap_err();
    assert!(error.to_string().contains(
        "private_key_jwt token endpoint authentication cannot be combined with clientSecret"
    ));
}

#[tokio::test]
async fn token_request_refuses_redirects_without_replaying_credentials() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/token", listener.local_addr().unwrap());
    let (captured_tx, captured_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        loop {
            let mut buffer = [0; 1024];
            let read = stream.read(&mut buffer).await.unwrap();
            assert_ne!(read, 0);
            request.extend_from_slice(&buffer[..read]);
            if let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap();
                if request.len() >= header_end + 4 + length {
                    break;
                }
            }
        }
        stream.write_all(b"HTTP/1.1 307 Temporary Redirect\r\nLocation: /elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
        captured_tx
            .send(String::from_utf8(request).unwrap())
            .unwrap();
        let second =
            tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept()).await;
        assert!(
            second.is_err(),
            "the token request must not follow the redirect"
        );
    });
    let mut request = code_request(&HashMap::new());
    request
        .authenticate(authentication(
            TokenGrantType::AuthorizationCode,
            None,
            Some("secret"),
        ))
        .await
        .unwrap();
    let error = request.send(&endpoint).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Server-side OAuth fetches refuse redirects")
    );
    let captured = captured_rx.await.unwrap();
    assert!(captured.starts_with("POST /token HTTP/1.1\r\n"));
    assert!(captured.contains("client_secret=secret"));
    task.await.unwrap();
}

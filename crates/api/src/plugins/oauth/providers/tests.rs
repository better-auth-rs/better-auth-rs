use super::*;

use std::sync::{Arc, Once};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

static LOCAL_PROXY_BYPASS: Once = Once::new();

fn ensure_local_proxy_bypass() {
    LOCAL_PROXY_BYPASS.call_once(|| {
        // SAFETY: Test code in this module only needs localhost proxy bypass
        // values, and they are set once before issuing local HTTP requests.
        unsafe { std::env::set_var("NO_PROXY", "localhost,127.0.0.1") };
        // SAFETY: Test code in this module only needs localhost proxy bypass
        // values, and they are set once before issuing local HTTP requests.
        unsafe { std::env::set_var("no_proxy", "localhost,127.0.0.1") };
    });
}

async fn start_github_mock_server(
    profile: Value,
    emails: Value,
    statuses: (&'static str, &'static str),
) -> (String, String, Arc<Mutex<Vec<String>>>) {
    ensure_local_proxy_bypass();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured_requests = requests.clone();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let profile = profile.clone();
            let emails = emails.clone();
            let requests = captured_requests.clone();
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 4096];
                let read = stream.read(&mut buffer).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buffer[..read]).to_string();
                requests.lock().await.push(request.clone());

                let (status, body) = if request.contains("/user/emails") {
                    (statuses.1, emails.to_string())
                } else if request.contains("/user") {
                    (statuses.0, profile.to_string())
                } else {
                    (
                        "404 Not Found",
                        serde_json::json!({ "error": "not found" }).to_string(),
                    )
                };

                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len(),
                );

                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.flush().await;
            });
        }
    });

    let base_url = format!("http://127.0.0.1:{}", addr.port());
    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    (
        format!("{base_url}/user"),
        format!("{base_url}/user/emails"),
        requests,
    )
}

// Upstream source: packages/core/src/social-providers/github.ts :: github().createAuthorizationURL default scope list.
#[test]
fn github_provider_uses_ts_default_scopes() {
    let provider = OAuthProvider::github("github-client-id", "github-client-secret").resolve();

    assert_eq!(
        provider.social_scopes(None),
        vec!["read:user", "user:email"]
    );
    assert!(provider.get_user_info.is_none());
    assert!(provider.map_user_info.is_none());
}

// Upstream source: packages/core/src/social-providers/github.ts :: github().getUserInfo fallback from profile.email to /user/emails, login fallback for name, and request headers.
#[tokio::test]
async fn github_provider_get_user_info_uses_email_fallback_and_login_name() {
    let (user_url, emails_url, requests) = start_github_mock_server(
        serde_json::json!({
            "id": 42,
            "login": "octocat",
            "name": null,
            "email": null,
            "avatar_url": "https://avatars.githubusercontent.com/u/42?v=4",
        }),
        serde_json::json!([
            {
                "email": "octocat@example.com",
                "primary": true,
                "verified": true,
                "visibility": "private"
            },
            {
                "email": "secondary@example.com",
                "primary": false,
                "verified": false,
                "visibility": "private"
            }
        ]),
        ("200 OK", "200 OK"),
    )
    .await;

    let provider = OAuthProvider::github_with_endpoints(
        "github-client-id",
        "github-client-secret",
        "https://github.com/login/oauth/authorize",
        "https://github.com/login/oauth/access_token",
        &user_url,
        &emails_url,
    )
    .resolve();
    let (user_url, emails_url) = provider.github_endpoints().unwrap();
    let response = github_profile(
        user_url,
        emails_url,
        &OAuthUserInfoRequest {
            access_token: Some("github-access-token".to_string()),
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(response.user.id, "42");
    assert_eq!(
        response.user.email.typed().unwrap().as_deref(),
        Some("octocat@example.com")
    );
    assert_eq!(response.user.name.as_deref(), Some("octocat"));
    assert_eq!(
        response.user.image.as_ref().and_then(Option::as_deref),
        Some("https://avatars.githubusercontent.com/u/42?v=4")
    );
    assert!(response.user.email_verified);
    assert_eq!(
        response.data["email"],
        serde_json::json!("octocat@example.com")
    );

    let requests = requests.lock().await;
    assert_eq!(requests.len(), 2);
    for request in requests.iter() {
        let lowered = request.to_ascii_lowercase();
        assert!(lowered.contains("authorization: bearer github-access-token"));
        assert!(lowered.contains("user-agent: better-auth"));
    }
}

// Upstream source: packages/core/src/social-providers/github.ts :: github().getUserInfo keeps profile.email when present and resolves verified status from the matching email record.
#[tokio::test]
async fn github_provider_get_user_info_keeps_inline_email() {
    let (user_url, emails_url, _) = start_github_mock_server(
        serde_json::json!({
            "id": "github-inline-email",
            "login": "octocat",
            "name": "Octo Cat",
            "email": "public@example.com",
            "avatar_url": null,
        }),
        serde_json::json!([
            {
                "email": "primary@example.com",
                "primary": true,
                "verified": true,
                "visibility": "private"
            },
            {
                "email": "public@example.com",
                "primary": false,
                "verified": false,
                "visibility": "public"
            }
        ]),
        ("200 OK", "200 OK"),
    )
    .await;

    let provider = OAuthProvider::github_with_endpoints(
        "github-client-id",
        "github-client-secret",
        "https://github.com/login/oauth/authorize",
        "https://github.com/login/oauth/access_token",
        &user_url,
        &emails_url,
    )
    .resolve();
    let (user_url, emails_url) = provider.github_endpoints().unwrap();
    let response = github_profile(
        user_url,
        emails_url,
        &OAuthUserInfoRequest {
            access_token: Some("github-access-token".to_string()),
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(
        response.user.email.typed().unwrap().as_deref(),
        Some("public@example.com")
    );
    assert_eq!(response.user.name.as_deref(), Some("Octo Cat"));
    assert!(!response.user.email_verified);
}
#[tokio::test]
async fn github_http_errors_distinguish_missing_profile_from_optional_email_data() {
    for primary_failure in [false, true] {
        let (user_url, emails_url, requests) = start_github_mock_server(
            serde_json::json!({"id":42,"login":"octocat","email":"public@example.test"}),
            serde_json::json!({"error":"temporarily_unavailable"}),
            if primary_failure {
                ("503 Service Unavailable", "200 OK")
            } else {
                ("200 OK", "503 Service Unavailable")
            },
        )
        .await;
        let response = github_profile(
            &user_url,
            &emails_url,
            &OAuthUserInfoRequest {
                access_token: Some("ordinary-access-token".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        if primary_failure {
            assert!(response.is_none());
            assert_eq!(requests.lock().await.len(), 1);
        } else {
            let response = response.unwrap();
            assert_eq!(
                response.user.email.typed().unwrap().as_deref(),
                Some("public@example.test")
            );
            assert!(!response.user.email_verified);
            assert_eq!(requests.lock().await.len(), 2);
        }
    }
}

struct GitHubEmailMapper {
    expected: Value,
    requests: Arc<Mutex<Vec<String>>>,
}

#[async_trait::async_trait]
impl OAuthProfileMapper for GitHubEmailMapper {
    async fn map_profile(
        &self,
        profile: &Value,
    ) -> AuthResult<crate::plugins::oauth::OAuthProfile> {
        assert_eq!(profile, &self.expected);
        self.requests.lock().await.push("mapper".into());
        Ok(Default::default())
    }
}

#[tokio::test]
async fn github_email_presence_and_fallback_match_pinned_normal_json() {
    use serde_json::json;

    let primary = json!([
        {"email":"secondary@example.test","primary":false,"verified":false},
        {"email":"primary@example.test","primary":true,"verified":true}
    ]);
    let cases = [
        (
            "omitted with empty list",
            None,
            "200 OK",
            json!([]),
            None,
            false,
        ),
        (
            "null with empty list",
            Some(Value::Null),
            "200 OK",
            json!([]),
            None,
            false,
        ),
        (
            "empty with empty list",
            Some(json!("")),
            "200 OK",
            json!([]),
            None,
            false,
        ),
        (
            "omitted with unavailable list",
            None,
            "503 Service Unavailable",
            json!({}),
            None,
            false,
        ),
        (
            "null with unavailable list",
            Some(Value::Null),
            "503 Service Unavailable",
            json!({}),
            Some(Value::Null),
            false,
        ),
        (
            "empty with unavailable list",
            Some(json!("")),
            "503 Service Unavailable",
            json!({}),
            Some(json!("")),
            false,
        ),
        (
            "null selects primary",
            Some(Value::Null),
            "200 OK",
            primary.clone(),
            Some(json!("primary@example.test")),
            true,
        ),
        (
            "empty selects primary",
            Some(json!("")),
            "200 OK",
            primary,
            Some(json!("primary@example.test")),
            true,
        ),
        (
            "nonempty with empty list",
            Some(json!("public@example.test")),
            "200 OK",
            json!([]),
            Some(json!("public@example.test")),
            false,
        ),
        (
            "no primary selects first",
            Some(Value::Null),
            "200 OK",
            json!([
                {"email":"first@example.test","primary":false,"verified":true},
                {"email":"second@example.test","primary":false,"verified":false}
            ]),
            Some(json!("first@example.test")),
            true,
        ),
        (
            "selected empty email is retained",
            Some(Value::Null),
            "200 OK",
            json!([
                {"email":"secondary@example.test","primary":false,"verified":false},
                {"email":"","primary":true,"verified":true}
            ]),
            Some(json!("")),
            true,
        ),
    ];
    for (label, email, status, emails, expected_email, verified) in cases {
        let base = json!({
            "id":42, "login":"octocat", "name":"Octo Cat",
            "avatar_url":"https://images.example.test/octocat.png"
        });
        let mut profile = base.clone();
        if let Some(email) = email {
            profile["email"] = email;
        }
        let mut expected_data = base;
        if let Some(email) = &expected_email {
            expected_data["email"] = email.clone();
        }
        let (user_url, emails_url, requests) =
            start_github_mock_server(profile, emails, ("200 OK", status)).await;
        let mut config = OAuthProvider::github_with_endpoints(
            "ordinary-client",
            "ordinary-client-secret",
            "https://github.com/login/oauth/authorize",
            "https://github.com/login/oauth/access_token",
            &user_url,
            &emails_url,
        );
        config.map_profile_to_user = Some(Arc::new(GitHubEmailMapper {
            expected: expected_data.clone(),
            requests: requests.clone(),
        }));
        let provider = crate::plugins::oauth::resolved::ResolvedProvider {
            config,
            generic: None,
        };
        let response = crate::plugins::oauth::social_profile::fetch_user_info_for_code(
            &provider,
            OAuthUserInfoRequest {
                access_token: Some("ordinary-github-token".into()),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            response.user.email.is_undefined(),
            expected_email.is_none(),
            "{label}"
        );
        let user = crate::plugins::oauth::types::AccountInfoUser {
            id: None,
            name: response.user.name,
            email: response.user.email,
            image: response.user.image,
            email_verified: response.user.email_verified,
            additional_fields: response.user.additional_fields,
        };
        let mut expected_user = json!({
            "name":"Octo Cat", "image":"https://images.example.test/octocat.png",
            "emailVerified":verified
        });
        if let Some(email) = expected_email {
            expected_user["email"] = email;
        }
        // serde_json::Value represents upstream own undefined email by omitting the JSON key.
        assert_eq!(
            json!({"user":user,"data":response.data}),
            json!({"user":expected_user,"data":expected_data}),
            "{label}"
        );
        let requests = requests.lock().await;
        assert_eq!(requests.len(), 3, "{label}");
        assert!(requests[0].starts_with("GET /user HTTP/1.1\r\n"), "{label}");
        assert!(
            requests[1].starts_with("GET /user/emails HTTP/1.1\r\n"),
            "{label}"
        );
        assert_eq!(requests[2], "mapper", "{label}");
    }
}

#[tokio::test]
async fn github_rejects_nonstring_profile_email_before_using_fallback_values() {
    let (user_url, emails_url, _) = start_github_mock_server(
        serde_json::json!({
            "id":42, "login":"octocat", "name":"Octo Cat", "email":123,
            "avatar_url":"https://images.example.test/octocat.png"
        }),
        serde_json::json!([{"email":"primary@example.test","primary":true,"verified":true}]),
        ("200 OK", "200 OK"),
    )
    .await;
    let error = github_profile(
        &user_url,
        &emails_url,
        &OAuthUserInfoRequest {
            access_token: Some("ordinary-github-token".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert!(
        matches!(error, AuthError::Internal(message) if message.starts_with("Invalid provider email:"))
    );
}

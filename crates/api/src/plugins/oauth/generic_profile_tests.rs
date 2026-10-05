use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use async_trait::async_trait;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use crate::plugins::oauth::generic::{
    GenericOAuthConfig, GenericOAuthUserInfoHandler, OAuthAccountSubject, OAuthProfile,
    OAuthProfileMapper,
};
use crate::plugins::oauth::oidc::OidcVerifier;

fn provider(config: GenericOAuthConfig, is_oidc: bool) -> ResolvedGenericOAuth {
    ResolvedGenericOAuth {
        config,
        issuer: None,
        is_oidc,
        verifier: None,
    }
}

fn encoded_claims(claims: Value) -> String {
    format!(
        "header.{}.signature",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    )
}

struct MapProfile;

#[async_trait]
impl OAuthProfileMapper for MapProfile {
    async fn map_profile(&self, profile: &Value) -> AuthResult<OAuthProfile> {
        assert_eq!(profile["email"], "original@example.com");
        Ok(OAuthProfile {
            email: Some(Some("mapped@example.com".to_string()).into()),
            name: Some(Some("Mapped name".to_string()).into()),
            email_verified: Some(Some(true).into()),
            ..Default::default()
        })
    }
}

#[tokio::test]
async fn id_token_profile_is_preferred_and_mapping_cannot_change_account_subject() {
    let provider = provider(
        GenericOAuthConfig {
            user_info_url: Some("http://127.0.0.1:1/must-not-be-called".to_string()),
            map_profile_to_user: Some(Arc::new(MapProfile)),
            ..Default::default()
        },
        true,
    );
    let tokens = OAuthUserInfoRequest {
        id_token: Some(encoded_claims(json!({
            "sub": "immutable-subject",
            "id": "profile-alias",
            "email": "original@example.com",
            "email_verified": false,
            "picture": "https://example.com/image.png",
            "name": "Original name"
        }))),
        ..Default::default()
    };
    let response = fetch_user_info(&provider, &tokens, None, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.user.id, "immutable-subject");
    assert_eq!(
        response.user.email.typed().unwrap().as_deref(),
        Some("mapped@example.com")
    );
    assert_eq!(
        response.user.name.typed().unwrap().as_deref(),
        Some("Mapped name")
    );
    assert!(matches!(response.user.email_verified(), Ok(true)));
    assert_eq!(
        response.user.image.as_ref().and_then(Option::as_deref),
        Some("https://example.com/image.png")
    );
    assert_eq!(response.data["email"], "original@example.com");
    assert_eq!(response.data["id"], "profile-alias");
    assert_eq!(response.data["emailVerified"], false);
}

struct RawProfile {
    profile: Value,
    calls: AtomicUsize,
}

struct ClearProfileFields;

#[async_trait]
impl OAuthProfileMapper for ClearProfileFields {
    async fn map_profile(&self, _profile: &Value) -> AuthResult<OAuthProfile> {
        Ok(OAuthProfile {
            name: Some(None.into()),
            image: Some(None),
            ..Default::default()
        })
    }
}

#[tokio::test]
async fn mapped_null_omits_image_without_changing_raw_profile() {
    let provider = provider(
        GenericOAuthConfig {
            map_profile_to_user: Some(Arc::new(ClearProfileFields)),
            ..Default::default()
        },
        true,
    );
    let tokens = OAuthUserInfoRequest {
        id_token: Some(encoded_claims(json!({
            "sub": "subject", "email": "operator@example.com", "name": "Provider name",
            "picture": "https://example.com/provider-image.png"
        }))),
        ..Default::default()
    };
    let response = fetch_user_info(&provider, &tokens, None, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.user.name, None);
    assert_eq!(response.user.image, None);
    assert_eq!(response.data["name"], "Provider name");
    assert_eq!(
        response.data["image"],
        "https://example.com/provider-image.png"
    );
}

#[async_trait]
impl GenericOAuthUserInfoHandler for RawProfile {
    async fn get_user_info(&self, _tokens: &OAuthUserInfoRequest) -> AuthResult<Option<Value>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Some(self.profile.clone()))
    }
}

#[tokio::test]
async fn generic_profile_preserves_email_presence_without_normalization() {
    for (label, email) in [
        ("absent", None),
        ("null", Some(Value::Null)),
        ("empty", Some(json!(""))),
        ("ordinary", Some(json!("reader@example.test"))),
    ] {
        let mut profile = json!({
            "sub": "ordinary-profile",
            "name": "Profile Reader",
            "image": "https://images.example.test/profile.png",
            "emailVerified": false,
        });
        let mut expected_user = json!({
            "name": "Profile Reader",
            "image": "https://images.example.test/profile.png",
            "emailVerified": false,
        });
        if let Some(email) = &email {
            profile["email"] = email.clone();
            expected_user["email"] = email.clone();
        }
        let raw = Arc::new(RawProfile {
            profile,
            calls: AtomicUsize::new(0),
        });
        let provider = provider(
            GenericOAuthConfig {
                get_user_info: Some(raw.clone()),
                ..Default::default()
            },
            false,
        );
        let response = fetch_profile(&provider, &OAuthUserInfoRequest::default(), None, None)
            .await
            .unwrap()
            .unwrap();
        let user = serde_json::to_value(response.user).unwrap();
        assert_eq!(user.get("email"), email.as_ref(), "{label}");
        assert_eq!(user, expected_user, "{label}");
        assert_eq!(response.data, raw.profile, "{label}");
        assert_eq!(raw.calls.load(Ordering::SeqCst), 1, "{label}");
    }
}

struct NameMapper {
    profile: Value,
    name: Option<better_auth_core::SchemaValue<Option<String>>>,
    calls: AtomicUsize,
}

#[async_trait]
impl OAuthProfileMapper for NameMapper {
    async fn map_profile(&self, profile: &Value) -> AuthResult<OAuthProfile> {
        assert_eq!(profile, &self.profile);
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(OAuthProfile {
            name: self.name.clone(),
            ..Default::default()
        })
    }
}

#[tokio::test]
async fn generic_profile_preserves_name_presence_and_mapper_overrides() {
    use better_auth_core::SchemaValue;

    for (raw_label, raw_name) in [
        ("absent", None),
        ("null", Some(Value::Null)),
        ("empty", Some(json!(""))),
        ("ordinary", Some(json!("Profile Reader"))),
    ] {
        for (mapped_label, mapped_name, mapped_json) in [
            ("unchanged", None, None),
            ("undefined", Some(SchemaValue::Undefined), None),
            ("null", Some(None.into()), Some(Value::Null)),
            ("empty", Some(Some(String::new()).into()), Some(json!(""))),
            (
                "ordinary",
                Some(Some("Mapped Reader".to_owned()).into()),
                Some(json!("Mapped Reader")),
            ),
        ] {
            let mut profile = json!({
                "sub": "ordinary-profile",
                "email": "reader@example.test",
                "image": "https://images.example.test/profile.png",
                "emailVerified": false,
            });
            if let Some(name) = &raw_name {
                profile["name"] = name.clone();
            }
            let expected_name = if mapped_name.is_some() {
                mapped_json
            } else {
                raw_name.clone()
            };
            let mut expected_user = json!({
                "email": "reader@example.test",
                "image": "https://images.example.test/profile.png",
                "emailVerified": false,
            });
            if let Some(name) = &expected_name {
                expected_user["name"] = name.clone();
            }
            let mapper = Arc::new(NameMapper {
                profile: profile.clone(),
                name: mapped_name,
                calls: AtomicUsize::new(0),
            });
            let raw = Arc::new(RawProfile {
                profile,
                calls: AtomicUsize::new(0),
            });
            let provider = provider(
                GenericOAuthConfig {
                    get_user_info: Some(raw.clone()),
                    map_profile_to_user: Some(mapper.clone()),
                    ..Default::default()
                },
                false,
            );
            let response = fetch_profile(&provider, &OAuthUserInfoRequest::default(), None, None)
                .await
                .unwrap()
                .unwrap();
            let user = serde_json::to_value(response.user).unwrap();
            let case = format!("{raw_label}/{mapped_label}");
            assert_eq!(user.get("name"), expected_name.as_ref(), "{case}");
            assert_eq!(user, expected_user, "{case}");
            assert_eq!(response.data, raw.profile, "{case}");
            assert_eq!(raw.calls.load(Ordering::SeqCst), 1, "{case}");
            assert_eq!(mapper.calls.load(Ordering::SeqCst), 1, "{case}");
        }
    }
}

struct AccountSubject;

#[async_trait]
impl OAuthAccountSubject for AccountSubject {
    async fn resolve_subject(
        &self,
        tokens: &OAuthUserInfoRequest,
        profile: &Value,
    ) -> AuthResult<String> {
        assert_eq!(tokens.access_token.as_deref(), Some("access"));
        assert_eq!(profile["email"], "original@example.com");
        assert_eq!(profile["name"], "Original name");
        Ok(format!("tenant:{}", profile["id"]))
    }
}

#[tokio::test]
async fn custom_profile_and_subject_callbacks_receive_original_data() {
    let raw = Arc::new(RawProfile {
        profile: json!({ "id": 42, "email": "original@example.com", "name": "Original name" }),
        calls: AtomicUsize::new(0),
    });
    let provider = provider(
        GenericOAuthConfig {
            get_user_info: Some(raw.clone()),
            account_subject: Some(Arc::new(AccountSubject)),
            map_profile_to_user: Some(Arc::new(MapProfile)),
            ..Default::default()
        },
        false,
    );
    let tokens = OAuthUserInfoRequest {
        access_token: Some("access".to_string()),
        ..Default::default()
    };
    let response = fetch_user_info(&provider, &tokens, None, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.user.id, "tenant:42");
    assert_eq!(
        response.user.email.typed().unwrap().as_deref(),
        Some("mapped@example.com")
    );
    assert_eq!(response.data, raw.profile);
    assert_eq!(raw.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn id_token_without_email_falls_back_to_userinfo_with_access_token() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/userinfo", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.windows(4).any(|part| part == b"\r\n\r\n") {
            let mut buffer = [0; 1024];
            let read = stream.read(&mut buffer).await.unwrap();
            assert_ne!(read, 0);
            request.extend_from_slice(&buffer[..read]);
        }
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("GET /userinfo HTTP/1.1\r\n"));
        assert!(
            request
                .to_lowercase()
                .contains("authorization: bearer access-token\r\n")
        );
        let body = json!({
            "id": 19,
            "sub": "userinfo-subject",
            "email": "userinfo@example.com",
            "emailVerified": true,
            "email_verified": null,
            "image": "https://ignored.example.com/image.png",
            "picture": "https://example.com/picture.png"
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    });
    let provider = provider(
        GenericOAuthConfig {
            user_info_url: Some(endpoint),
            ..Default::default()
        },
        true,
    );
    let tokens = OAuthUserInfoRequest {
        access_token: Some("access-token".to_string()),
        id_token: Some(encoded_claims(json!({ "sub": "id-token-subject" }))),
        ..Default::default()
    };
    let response = fetch_user_info(&provider, &tokens, None, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.user.id, "userinfo-subject");
    assert_eq!(
        response.user.email.typed().unwrap().as_deref(),
        Some("userinfo@example.com")
    );
    assert!(matches!(response.user.email_verified(), Ok(false)));
    assert_eq!(
        response.user.image.as_ref().and_then(Option::as_deref),
        Some("https://example.com/picture.png")
    );
    task.await.unwrap();
}

#[tokio::test]
async fn invalid_verified_id_token_cannot_fall_back_to_custom_profile() {
    let raw = Arc::new(RawProfile {
        profile: json!({ "sub": "forged", "email": "admin@example.com" }),
        calls: AtomicUsize::new(0),
    });
    let mut provider = provider(
        GenericOAuthConfig {
            get_user_info: Some(raw.clone()),
            ..Default::default()
        },
        true,
    );
    provider.verifier = Some(Arc::new(
        OidcVerifier::new(
            url::Url::parse("http://127.0.0.1:1/jwks").unwrap(),
            "https://issuer.example".to_string(),
            "client".to_string(),
            None,
        )
        .unwrap(),
    ));
    let tokens = OAuthUserInfoRequest {
        id_token: Some("invalid-token".to_string()),
        ..Default::default()
    };
    let error = fetch_user_info(&provider, &tokens, Some("expected-nonce"), None)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("ID token verification failed"));
    assert_eq!(raw.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn account_subject_is_validated_before_local_account_lookup() {
    for subject in [
        json!(null),
        json!(""),
        json!("  "),
        json!("undefined"),
        json!("null"),
    ] {
        let provider = provider(
            GenericOAuthConfig {
                get_user_info: Some(Arc::new(RawProfile {
                    profile: json!({ "id": subject, "email": "subject@example.com" }),
                    calls: AtomicUsize::new(0),
                })),
                ..Default::default()
            },
            false,
        );
        let error = fetch_user_info(&provider, &OAuthUserInfoRequest::default(), None, None)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("OAUTH_ACCOUNT_SUBJECT_INVALID"));
    }
    for (subject, expected) in [(42.0, "42"), (-0.0, "0"), (1e-7, "1e-7"), (1e21, "1e+21")] {
        let provider = provider(
            GenericOAuthConfig {
                get_user_info: Some(Arc::new(RawProfile {
                    profile: json!({ "id": subject, "email": "subject@example.com" }),
                    calls: AtomicUsize::new(0),
                })),
                ..Default::default()
            },
            false,
        );
        assert_eq!(
            fetch_user_info(&provider, &OAuthUserInfoRequest::default(), None, None)
                .await
                .unwrap()
                .unwrap()
                .user
                .id,
            expected
        );
    }
}

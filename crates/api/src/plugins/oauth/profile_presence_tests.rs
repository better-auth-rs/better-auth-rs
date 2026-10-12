#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report exact contract mismatches while Result propagates fixture errors."
)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use better_auth_core::{AuthError, AuthResult, FieldValue};
use serde_json::Value;

use super::fetch_user_info_for_code;
use crate::plugins::oauth::{
    OAuthProfile, OAuthProfileMapper, OAuthProvider, OAuthUserInfoHandler, OAuthUserInfoRequest,
    resolved::ResolvedProvider,
};

struct EmptyProfile(Arc<Mutex<Vec<&'static str>>>);

#[async_trait]
impl OAuthUserInfoHandler for EmptyProfile {
    async fn get_user_info_native(&self, request: OAuthUserInfoRequest) -> AuthResult<FieldValue> {
        assert_eq!(
            request.access_token.field_value().as_str(),
            Some("ordinary-profile-token")
        );
        self.0
            .lock()
            .map_err(|_| AuthError::internal("callback log poisoned"))?
            .push("custom");
        Ok(FieldValue::Null)
    }
}

#[async_trait]
impl OAuthProfileMapper for EmptyProfile {
    async fn map_profile(&self, _: &Value) -> AuthResult<OAuthProfile> {
        self.0
            .lock()
            .map_err(|_| AuthError::internal("callback log poisoned"))?
            .push("mapper");
        Err(AuthError::internal("custom user info must skip mapper"))
    }
}

#[tokio::test]
async fn custom_null_skips_default_http_and_mapper() -> AuthResult<()> {
    let constructors = [
        OAuthProvider::google,
        OAuthProvider::github,
        OAuthProvider::discord,
        OAuthProvider::gitlab,
        OAuthProvider::spotify,
        OAuthProvider::huggingface,
        OAuthProvider::polar,
        OAuthProvider::vercel,
        OAuthProvider::figma,
        OAuthProvider::dropbox,
        OAuthProvider::kick,
        OAuthProvider::cloudflare,
        OAuthProvider::atlassian,
        OAuthProvider::kakao,
    ];
    for constructor in constructors {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let callback = Arc::new(EmptyProfile(calls.clone()));
        let mut config = constructor("client", "secret");
        config.get_user_info = Some(callback.clone());
        config.map_profile_to_user = Some(callback);
        config.user_info_url = None;
        let provider = ResolvedProvider {
            config,
            generic: None,
        };
        let profile_request = OAuthUserInfoRequest {
            access_token: (Some("ordinary-profile-token".into())).into(),
            ..Default::default()
        };
        let result = fetch_user_info_for_code(&provider, profile_request, None).await?;
        assert!(result.value.is_null());
        assert_eq!(
            *calls
                .lock()
                .map_err(|_| AuthError::internal("callback log poisoned"))?,
            ["custom"]
        );
    }
    Ok(())
}

#[expect(
    clippy::indexing_slicing,
    reason = "These fixtures index known JSON keys and read lengths returned for the same buffer."
)]
mod discord {
    use super::*;
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct Mapper {
        expected: Value,
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    #[async_trait]
    impl OAuthProfileMapper for Mapper {
        async fn map_profile(&self, profile: &Value) -> AuthResult<OAuthProfile> {
            assert_eq!(profile, &self.expected);
            self.events
                .lock()
                .map_err(|_| AuthError::internal("callback log poisoned"))?
                .push("map");
            Ok(OAuthProfile::default())
        }
    }

    #[tokio::test]
    async fn normal_avatar_and_name_fields_are_prepared_before_the_mapper()
    -> Result<(), Box<dyn std::error::Error>> {
        let png = "https://cdn.discordapp.com/avatars/123456789/portrait.png";
        let cases = [
            ("static PNG", json!({}), png, "Owner"),
            (
                "animated GIF",
                json!({"avatar":"a_portrait"}),
                "https://cdn.discordapp.com/avatars/123456789/a_portrait.gif",
                "Owner",
            ),
            (
                "migrated default",
                json!({"avatar":null,"discriminator":"0"}),
                "https://cdn.discordapp.com/embed/avatars/5.png",
                "Owner",
            ),
            (
                "legacy default",
                json!({"avatar":null,"discriminator":"1234"}),
                "https://cdn.discordapp.com/embed/avatars/4.png",
                "Owner",
            ),
            (
                "global name",
                json!({"global_name":"Global Owner"}),
                png,
                "Global Owner",
            ),
            ("empty global name", json!({"global_name":""}), png, "Owner"),
            (
                "empty names",
                json!({"global_name":"","username":""}),
                png,
                "",
            ),
        ];
        for (label, patch, image, name) in cases {
            let mut profile = json!({"id":"123456789","email":"owner@example.test","username":"Owner","avatar":"portrait","verified":true});
            profile
                .as_object_mut()
                .ok_or("profile fixture must be an object")?
                .extend(
                    patch
                        .as_object()
                        .ok_or("patch fixture must be an object")?
                        .clone(),
                );
            let mut prepared = profile.clone();
            prepared["image_url"] = json!(image);
            let events = Arc::new(Mutex::new(Vec::new()));
            let server_events = events.clone();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let endpoint = format!("http://{}/profile", listener.local_addr()?);
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await?;
                let mut request = Vec::new();
                while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                    let mut buffer = [0; 1024];
                    let read = stream.read(&mut buffer).await?;
                    if read == 0 {
                        return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
                    }
                    request.extend_from_slice(&buffer[..read]);
                }
                let request = String::from_utf8(request).map_err(std::io::Error::other)?;
                assert!(request.starts_with("GET /profile HTTP/1.1\r\n"));
                assert!(
                    request
                        .to_ascii_lowercase()
                        .contains("authorization: bearer ordinary-profile-token\r\n")
                );
                server_events
                    .lock()
                    .map_err(|_| std::io::Error::other("callback log poisoned"))?
                    .push("http");
                let body = profile.to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await?;
                Ok::<(), std::io::Error>(())
            });
            let mut config = OAuthProvider::discord("client", "secret");
            config.user_info_url = Some(endpoint);
            config.map_profile_to_user = Some(Arc::new(Mapper {
                expected: prepared.clone(),
                events: events.clone(),
            }));
            let provider = ResolvedProvider {
                config,
                generic: None,
            };
            let profile_request = OAuthUserInfoRequest {
                access_token: (Some("ordinary-profile-token".into())).into(),
                ..Default::default()
            };
            let response = fetch_user_info_for_code(&provider, profile_request, None).await?;
            server.await??;
            assert_eq!(
                crate::plugins::oauth::profile_test_support::json(response),
                json!({
                    "user": {
                        "name": name,
                        "image": image,
                        "email": "owner@example.test",
                        "emailVerified": true
                    },
                    "data": prepared
                }),
                "{label}"
            );
            assert_eq!(
                *events
                    .lock()
                    .map_err(|_| AuthError::internal("callback log poisoned"))?,
                ["http", "map"],
                "{label}"
            );
        }
        Ok(())
    }
}

#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "Impersonation regressions compare complete cookie and persistence outcomes"
)]

use std::{collections::HashMap, sync::Arc};

use better_auth_core::{
    AuthConfig, AuthContext, AuthRequest, AuthResponse, AuthResult, CookieAttributes,
    CookieOverride, CreateSession, CreateUser, HttpMethod, SameSite,
    store::{EphemeralStore, StatelessSchema},
    utils::cookie_utils::{related_cookie_name, sign_cookie_value, verify_cookie_value},
    wire::{SessionView, UserView},
};
use chrono::{Duration, Utc};
use serde_json::{Value, json};

use super::AdminPlugin;
use crate::plugins::test_helpers::{
    create_auth_json_request_no_query, create_test_config, finalize_response,
    initialize_test_context,
};

struct Fixture {
    ctx: AuthContext<StatelessSchema>,
    admin: UserView,
    admin_session: SessionView,
    target: UserView,
}

impl Fixture {
    async fn new(mut config: AuthConfig) -> AuthResult<Self> {
        config.session.disable_session_refresh = Some(true);
        let config = Arc::new(config);
        let ctx = initialize_test_context(
            config.clone(),
            Arc::new(EphemeralStore::new(config)),
            &[&AdminPlugin::new()],
        )
        .await?;
        let admin = ctx
            .database
            .create_user(
                CreateUser::new()
                    .with_email("cookie-admin@example.test")
                    .with_role("admin"),
            )
            .await?;
        let target = ctx
            .database
            .create_user(
                CreateUser::new()
                    .with_email("cookie-target@example.test")
                    .with_role("user"),
            )
            .await?;
        let admin_session = session(&ctx, admin.id.typed()?, None).await?;
        Ok(Self {
            ctx,
            admin,
            admin_session,
            target,
        })
    }

    fn request(
        &self,
        path: &str,
        token: &str,
        cookies: Option<String>,
        body: Option<Value>,
    ) -> AuthRequest {
        let mut request =
            create_auth_json_request_no_query(HttpMethod::Post, path, Some(token), body);
        if let Some(cookies) = cookies {
            let _ = request.headers.insert("cookie".into(), cookies);
        }
        request
    }

    async fn start(&self, cookies: Option<String>) -> AuthResult<(AuthResponse, String)> {
        let request = self.request(
            "/admin/impersonate-user",
            self.admin_session.token.typed()?,
            cookies,
            Some(json!({"userId":self.target.id})),
        );
        let response = AdminPlugin::new()
            .handle_impersonate_user(&request, &self.ctx)
            .await?;
        let response = finalize_response(&self.ctx, &request, response);
        let body: Value = serde_json::from_slice(&response.body.bytes()?)?;
        let token = body
            .get("session")
            .and_then(|value| value.get("token"))
            .and_then(Value::as_str)
            .unwrap()
            .to_owned();
        let stored = self.ctx.database.get_session(&token).await?.unwrap();
        assert_eq!(
            stored.impersonated_by.field_value(),
            self.admin.id.field_value()
        );
        Ok((response, token))
    }

    fn stop_request(&self, token: &str, cookie: Option<&str>) -> AuthRequest {
        let name = related_cookie_name(&self.ctx.config, "admin_session");
        self.request(
            "/admin/stop-impersonating",
            token,
            cookie.map(|value| format!("{name}={value}")),
            None,
        )
    }
}

async fn session(
    ctx: &AuthContext<StatelessSchema>,
    user_id: &str,
    actor: Option<&str>,
) -> AuthResult<SessionView> {
    ctx.database
        .create_session(CreateSession {
            user_id: user_id.into(),
            expires_at: (Utc::now() + Duration::hours(1)).into(),
            impersonated_by: actor.map(str::to_owned),
            inherited_fields: Default::default(),
            additional_fields: Default::default(),
            ip_address: None,
            user_agent: None,
            active_organization_id: None,
        })
        .await
}

fn cookie_header<'a>(response: &'a AuthResponse, name: &str) -> &'a str {
    response
        .headers
        .get_all("Set-Cookie")
        .filter(|header| header.starts_with(&format!("{name}=")))
        .last()
        .unwrap()
}

fn cookie_value(header: &str) -> &str {
    header.split_once('=').unwrap().1.split(';').next().unwrap()
}

#[tokio::test]
async fn impersonation_signed_cookies_round_trip_original_remember_markers() -> AuthResult<()> {
    for (marker, authentic, expected_marker, remember) in [
        (None, true, "", false),
        (Some("true"), true, "true", true),
        (Some("false"), true, "false", true),
        (Some(":ignored"), true, ":ignored", false),
        (Some("true"), false, "", false),
    ] {
        let fixture = Fixture::new(create_test_config()).await?;
        let secret = fixture.ctx.config.signing_secret();
        let marker_name = related_cookie_name(&fixture.ctx.config, "dont_remember");
        let input = marker.map(|value| {
            format!(
                "{marker_name}={}",
                sign_cookie_value(value, if authentic { secret } else { "wrong-secret" })
            )
        });
        let (response, token) = fixture.start(input).await?;
        let admin_name = related_cookie_name(&fixture.ctx.config, "admin_session");
        let saved = cookie_value(cookie_header(&response, &admin_name));
        assert_eq!(
            verify_cookie_value(saved, secret),
            Some(format!(
                "{}:{expected_marker}",
                fixture.admin_session.token.typed()?
            ))
        );
        let headers = response.headers.get_all("Set-Cookie").collect::<Vec<_>>();
        let admin_index = headers
            .iter()
            .position(|header| header.starts_with(&format!("{admin_name}=")))
            .unwrap();
        let session_name = related_cookie_name(&fixture.ctx.config, "session_token");
        let session_index = headers
            .iter()
            .rposition(|header| header.starts_with(&format!("{session_name}=")))
            .unwrap();
        assert!(admin_index < session_index);
        assert!(!cookie_header(&response, &session_name).contains("Max-Age="));

        let request = fixture.stop_request(&token, Some(saved));
        let restored = AdminPlugin::new()
            .handle_stop_impersonating(&request, &fixture.ctx)
            .await?;
        let restored = finalize_response(&fixture.ctx, &request, restored);
        let restored_cookie = cookie_header(&restored, &session_name);
        assert_eq!(
            verify_cookie_value(cookie_value(restored_cookie), secret).as_deref(),
            Some(fixture.admin_session.token.typed()?.as_str())
        );
        assert_eq!(restored_cookie.contains("Max-Age="), !remember);
        if remember {
            assert_eq!(
                verify_cookie_value(cookie_value(cookie_header(&restored, &marker_name)), secret)
                    .as_deref(),
                Some("true")
            );
        }
        assert!(cookie_header(&restored, &admin_name).contains("Max-Age=0"));
        let body: Value = serde_json::from_slice(&restored.body.bytes()?)?;
        assert_eq!(
            body.get("user")
                .and_then(|user| user.get("id"))
                .and_then(Value::as_str),
            Some(fixture.admin.id.typed()?.as_str())
        );
        assert!(fixture.ctx.database.get_session(&token).await?.is_none());
        assert_eq!(
            fixture
                .ctx
                .database
                .get_session(fixture.admin_session.token.typed()?)
                .await?,
            Some(fixture.admin_session.clone())
        );
    }
    Ok(())
}

#[tokio::test]
async fn impersonation_uses_session_attributes_when_saving_and_admin_attributes_when_clearing()
-> AuthResult<()> {
    let mut config = create_test_config();
    config.advanced.cookies = Some(HashMap::from([
        (
            "session_token".into(),
            CookieOverride {
                name: Some("custom.session".into()),
                attributes: CookieAttributes {
                    path: Some("/session".into()),
                    domain: Some("session.example.test".into()),
                    secure: Some(true),
                    same_site: Some(SameSite::Strict),
                    max_age: Some(7200.0),
                    ..Default::default()
                },
            },
        ),
        (
            "admin_session".into(),
            CookieOverride {
                name: Some("custom.admin".into()),
                attributes: CookieAttributes {
                    path: Some("/admin".into()),
                    domain: Some("admin.example.test".into()),
                    secure: Some(false),
                    same_site: Some(SameSite::Lax),
                    max_age: Some(77.0),
                    ..Default::default()
                },
            },
        ),
    ]));
    let fixture = Fixture::new(config).await?;
    let (response, token) = fixture.start(None).await?;
    let header = cookie_header(&response, "custom.admin");
    assert!(header.contains("Max-Age=7200"));
    assert!(header.contains("Domain=session.example.test"));
    assert!(header.contains("Path=/session"));
    assert!(header.contains("Secure"));
    assert!(header.contains("SameSite=Strict"));
    let request = fixture.stop_request(&token, Some(cookie_value(header)));
    let response = AdminPlugin::new()
        .handle_stop_impersonating(&request, &fixture.ctx)
        .await?;
    let response = finalize_response(&fixture.ctx, &request, response);
    let header = cookie_header(&response, "custom.admin");
    assert!(header.contains("Max-Age=0"));
    assert!(header.contains("Domain=admin.example.test"));
    assert!(header.contains("Path=/admin"));
    assert!(!header.contains("Secure"));
    assert!(header.contains("SameSite=Lax"));
    Ok(())
}

#[tokio::test]
async fn invalid_impersonation_cookies_preserve_both_sessions_and_user_lookup_order()
-> AuthResult<()> {
    let fixture = Fixture::new(create_test_config()).await?;
    let (response, token) = fixture.start(None).await?;
    let saved = cookie_value(cookie_header(
        &response,
        &related_cookie_name(&fixture.ctx.config, "admin_session"),
    ));
    let secret = fixture.ctx.config.signing_secret();
    let current = fixture.ctx.database.get_session(&token).await?;
    let other = session(&fixture.ctx, fixture.target.id.typed()?, None).await?;
    for cookie in [
        None,
        Some("not.a.signature".to_owned()),
        Some(format!("tampered{saved}")),
        Some(saved.trim_end_matches("%3D").to_owned()),
        Some(sign_cookie_value("", secret)),
        Some(sign_cookie_value("missing:true", secret)),
        Some(sign_cookie_value(
            &format!("{}:true", other.token.typed()?),
            secret,
        )),
    ] {
        let request = fixture.stop_request(&token, cookie.as_deref());
        let error = AdminPlugin::new()
            .handle_stop_impersonating(&request, &fixture.ctx)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "Failed to find admin session");
        assert_eq!(fixture.ctx.database.get_session(&token).await?, current);
        assert_eq!(
            fixture
                .ctx
                .database
                .get_session(fixture.admin_session.token.typed()?)
                .await?,
            Some(fixture.admin_session.clone())
        );
        assert!(request.new_session()?.is_none());
        assert!(
            request
                .take_response_headers()?
                .get_all("Set-Cookie")
                .next()
                .is_none()
        );
    }
    let orphan = session(
        &fixture.ctx,
        fixture.target.id.typed()?,
        Some("missing-admin"),
    )
    .await?;
    let request = fixture.stop_request(orphan.token.typed()?, None);
    let error = AdminPlugin::new()
        .handle_stop_impersonating(&request, &fixture.ctx)
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "Failed to find user");
    assert_eq!(
        fixture
            .ctx
            .database
            .get_session(orphan.token.typed()?)
            .await?,
        Some(orphan.clone())
    );
    Ok(())
}

#[tokio::test]
async fn signed_admin_token_without_a_remember_separator_restores_persistent_session()
-> AuthResult<()> {
    let fixture = Fixture::new(create_test_config()).await?;
    let (_, token) = fixture.start(None).await?;
    let signed = sign_cookie_value(
        fixture.admin_session.token.typed()?,
        fixture.ctx.config.signing_secret(),
    );
    let request = fixture.stop_request(&token, Some(&signed));
    let response = AdminPlugin::new()
        .handle_stop_impersonating(&request, &fixture.ctx)
        .await?;
    let response = finalize_response(&fixture.ctx, &request, response);
    let cookie = cookie_header(
        &response,
        &related_cookie_name(&fixture.ctx.config, "session_token"),
    );
    assert!(cookie.contains("Max-Age="));
    assert!(fixture.ctx.database.get_session(&token).await?.is_none());
    Ok(())
}

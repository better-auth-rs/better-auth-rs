use super::*;
use crate::config::{BearerConfig, CookieCacheConfig};
use crate::test_store::{BundledSchema, test_database};
use crate::utils::cookie_utils::{
    create_clear_cookie, create_session_cookie_with_max_age, sign_cookie_value,
};
use crate::{AuthResponse, CreateUser};
use chrono::Duration;

async fn refreshed_request() -> (SessionManager<BundledSchema>, AuthRequest, SessionData) {
    let mut config = AuthConfig::new("response-secret-at-least-32-characters");
    config.session.bearer = Some(BearerConfig::default());
    config.session.cookie_cache = Some(CookieCacheConfig {
        enabled: Some(true),
        ..Default::default()
    });
    let manager = SessionManager::new(Arc::new(config), test_database().await);
    let user = manager
        .database
        .create_user(
            CreateUser::new()
                .with_email("rotation@example.com")
                .with_name("Rotation owner"),
        )
        .await
        .unwrap();
    let session = manager.create_session(&user, None, None).await.unwrap();
    let _ = manager
        .database
        .update_session_expiry(
            session.token.typed().unwrap(),
            Utc::now() + Duration::hours(1),
        )
        .await
        .unwrap();
    let mut req = AuthRequest::new(HttpMethod::Post, "/two-factor/enable");
    req.headers.insert(
        "cookie".into(),
        format!(
            "better-auth.session_token={}",
            sign_cookie_value(session.token.typed().unwrap(), &manager.config.secret)
        ),
    );
    let data = manager
        .resolve(&req, SessionRead::Cached)
        .await
        .unwrap()
        .data
        .unwrap();
    (manager, req, data)
}

#[tokio::test]
async fn rotation_preserves_order_and_the_browser_uses_the_last_token_and_cache() {
    let (manager, req, old) = refreshed_request().await;
    let user = manager
        .database
        .get_user_by_id(old.user.id.typed().unwrap())
        .await
        .unwrap()
        .unwrap();
    let next = manager.create_session(&user, None, None).await.unwrap();
    manager
        .database
        .delete_session(old.session.token.typed().unwrap())
        .await
        .unwrap();
    let issued = manager.internal_data(&user, &next).await.unwrap();
    manager
        .set_session_cookie(&req, issued, None)
        .await
        .unwrap();
    let mut response = AuthResponse::new(200);
    manager.finish_response(&req, &mut response).unwrap();
    let response = response.into_http_response();

    let mut browser = AuthRequest::new(HttpMethod::Get, "/get-session");
    let cookies = response
        .headers
        .get_all("set-cookie")
        .map(|header| header.split(';').next().unwrap().split_once('=').unwrap())
        .collect::<std::collections::BTreeMap<_, _>>()
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ");
    browser.headers.insert("cookie".into(), cookies);
    assert_eq!(
        manager.extract_session_token(&browser).as_deref(),
        Some(next.token.typed().unwrap().as_str())
    );
    let cache = cookie_cache::read(&browser, "better-auth.session_data").unwrap();
    let payload = cookie_cache::decode(
        &cache,
        &manager.config,
        manager.config.session.cookie_cache.as_ref().unwrap(),
    )
    .unwrap()
    .0;
    assert_eq!(payload.data.session.token, next.token);
    assert_eq!(
        verify_cookie_value(
            response.headers.get("set-auth-token").unwrap(),
            &manager.config.secret
        )
        .as_deref(),
        Some(next.token.typed().unwrap().as_str())
    );
    assert_eq!(
        response
            .headers
            .get_all("set-cookie")
            .filter(|header| header.starts_with("better-auth.session_token="))
            .count(),
        2
    );
}

#[tokio::test]
async fn challenge_expiration_supersedes_earlier_refresh_credentials() {
    let (manager, req, _) = refreshed_request().await;
    for name in ["better-auth.session_token", "better-auth.session_data"] {
        crate::utils::cookie_utils::remove_set_cookie_entries(&req, None, name).unwrap();
    }
    let mut response = AuthResponse::json(200, &serde_json::json!({"twoFactorRedirect": true}))
        .unwrap()
        .with_appended_header(
            "Set-Cookie",
            create_clear_cookie(
                &manager
                    .config
                    .auth_cookie("session_token", Default::default())
                    .name,
                &manager.config,
            )
            .unwrap(),
        )
        .with_appended_header(
            "Set-Cookie",
            create_clear_cookie("better-auth.session_data", &manager.config).unwrap(),
        );
    manager.finish_response(&req, &mut response).unwrap();
    let response = response.into_http_response();
    assert!(!response.headers.contains_key("set-auth-token"));
    let cookies: Vec<_> = response.headers.get_all("set-cookie").collect();
    assert_eq!(cookies.len(), 2);
    assert!(cookies.iter().all(|cookie| cookie.contains("Max-Age=0")));
}

#[tokio::test]
async fn explicit_remember_marker_expiration_survives_browser_session_cookie() {
    let (manager, req, data) = refreshed_request().await;
    let mut response = AuthResponse::new(200)
        .with_appended_header(
            "Set-Cookie",
            create_session_cookie_with_max_age(
                Some(data.session.token.typed().unwrap()),
                None,
                &manager.config,
            )
            .unwrap(),
        )
        .with_appended_header(
            "Set-Cookie",
            create_clear_cookie("better-auth.dont_remember", &manager.config).unwrap(),
        );
    manager.finish_response(&req, &mut response).unwrap();
    let response = response.into_http_response();
    let marker = response
        .headers
        .get_all("set-cookie")
        .find(|cookie| cookie.starts_with("better-auth.dont_remember="))
        .unwrap();
    assert!(marker.contains("Max-Age=0"));
}

#[tokio::test]
async fn raw_session_cookie_does_not_create_a_remember_preference() {
    let config = Arc::new(AuthConfig::new("response-secret-at-least-32-characters"));
    let manager = SessionManager::new(config, test_database().await);
    let req = AuthRequest::new(HttpMethod::Get, "/oauth2/callback/probe");
    let cookie = "better-auth.session_token=raw%2Btoken.signature%3D; Path=/; HttpOnly";
    let mut response = AuthResponse::new(302).with_appended_header("Set-Cookie", cookie);
    manager.finish_response(&req, &mut response).unwrap();
    let response = response.into_http_response();
    assert_eq!(
        response.headers.get_all("set-cookie").collect::<Vec<_>>(),
        [cookie]
    );
    assert!(req.new_session().unwrap().is_none());
}

#[tokio::test]
async fn explicit_browser_session_keeps_the_signed_remember_preference() {
    let config = Arc::new(AuthConfig::new("response-secret-at-least-32-characters"));
    let manager = SessionManager::new(config, test_database().await);
    let req = AuthRequest::new(HttpMethod::Post, "/sign-in/phone-number");
    let mut response = AuthResponse::new(200);
    for cookie in
        crate::utils::cookie_utils::create_session_cookies("session-token", true, &manager.config)
            .unwrap()
    {
        response.headers.append("Set-Cookie", cookie);
    }
    manager.finish_response(&req, &mut response).unwrap();
    let response = response.into_http_response();
    let cookies: Vec<_> = response.headers.get_all("set-cookie").collect();
    assert_eq!(cookies.len(), 2);
    assert!(cookies.iter().all(|cookie| !cookie.contains("Max-Age=")));
    let marker = cookies
        .iter()
        .find(|cookie| cookie.starts_with("better-auth.dont_remember="))
        .unwrap();
    let value = marker.split(';').next().unwrap().split_once('=').unwrap().1;
    assert_eq!(
        verify_cookie_value(value, manager.config.signing_secret()).as_deref(),
        Some("true")
    );
}

#[tokio::test]
async fn explicit_expiration_scrubs_both_scopes_without_deduplicating_ordinary_cookies() {
    let manager = SessionManager::new(
        Arc::new(AuthConfig::new("response-secret-at-least-32-characters")),
        test_database().await,
    );
    let req = AuthRequest::new(HttpMethod::Get, "/cookie-contract");
    for value in [
        "ordinary=first; Path=/",
        "ordinary=second; Path=/",
        "ordinary=; Max-Age=0; Path=/",
        "credential=secret; Path=/",
        "credential.0=chunk; Path=/",
        "credential-other=retained; Path=/",
    ] {
        req.append_response_header("Set-Cookie", value.into())
            .unwrap();
    }
    let mut response = AuthResponse::new(200)
        .with_appended_header("Set-Cookie", "credential.1=outer-secret; Path=/");
    crate::utils::cookie_utils::remove_set_cookie_entries(
        &req,
        Some(&mut response.headers),
        "credential",
    )
    .unwrap();
    response
        .headers
        .append("Set-Cookie", "credential=; Max-Age=0; Path=/");
    manager.finish_response(&req, &mut response).unwrap();
    let response = response.into_http_response();
    assert_eq!(
        response
            .headers
            .get_all("set-cookie")
            .map(|line| line.split(';').next().unwrap())
            .collect::<Vec<_>>(),
        [
            "credential=",
            "ordinary=first",
            "ordinary=second",
            "ordinary=",
            "credential-other=retained"
        ]
    );
}

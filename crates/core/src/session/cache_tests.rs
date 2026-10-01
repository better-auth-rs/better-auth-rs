use super::*;
use crate::config::{BearerConfig, CookieCacheConfig, CookieCacheStrategy};
use crate::test_store::{BundledSchema, test_database};
use crate::utils::cookie_utils::{create_session_cookie, sign_cookie_value};
use crate::{AuthResponse, CreateUser};
use chrono::Duration;

fn request(token: &str, config: &AuthConfig) -> AuthRequest {
    let mut req = AuthRequest::new(HttpMethod::Get, "/get-session");
    req.headers.insert(
        "cookie".into(),
        format!(
            "{}={}",
            config.auth_cookie("session_token", Default::default()).name,
            sign_cookie_value(token, &config.secret)
        ),
    );
    req
}

async fn setup(config: AuthConfig) -> (SessionManager<BundledSchema>, SessionData) {
    let db = test_database().await;
    let manager = SessionManager::new(Arc::new(config), db);
    let user = manager
        .database
        .create_user(
            CreateUser::new()
                .with_email("cache@example.com")
                .with_name("Cache User"),
        )
        .await
        .unwrap();
    let session = manager.create_session(&user, None, None).await.unwrap();
    (
        manager,
        SessionData {
            session: SessionView::from(&session),
            user: UserView::from(&user),
        },
    )
}

fn config(strategy: CookieCacheStrategy) -> AuthConfig {
    let mut config = AuthConfig::new("fixture-secret-at-least-32-characters");
    config.session.cookie_cache = Some(CookieCacheConfig {
        enabled: Some(true),
        strategy: Some(strategy),
        ..Default::default()
    });
    config
}

fn with_cache(mut req: AuthRequest, value: &str) -> AuthRequest {
    req.headers
        .get_mut("cookie")
        .unwrap()
        .push_str(&format!("; better-auth.session_data={value}"));
    req
}

#[tokio::test]
async fn cache_renewal_preserves_account_binding_chunks_and_pending_cookies() {
    let mut config = config(CookieCacheStrategy::Jwe);
    config.account.store_account_cookie = Some(true);
    let (manager, data) = setup(config).await;
    let account = serde_json::json!({
        "userId": "different-user", "accessToken": "x".repeat(8_000),
        "providerAttribute": { "nested": true }
    });
    let value = crate::utils::jwe::encode(
        account.as_object().unwrap().clone(),
        manager.config.encryption_secret(),
        "better-auth-account",
        30,
    )
    .unwrap();
    let name = "better-auth.account_data";
    let account_cookies = crate::utils::cookie_utils::create_chunked_cookies(
        &AuthRequest::new(HttpMethod::Get, "/"),
        &manager.config.auth_cookie(
            "account_data",
            crate::CookieAttributes {
                max_age: Some(30),
                ..Default::default()
            },
        ),
        &value,
    )
    .unwrap();
    assert!(account_cookies.len() > 1);
    let request_with_account = || {
        let mut req = request(&data.session.token, &manager.config);
        for cookie in &account_cookies {
            req.headers
                .get_mut("cookie")
                .unwrap()
                .push_str(&format!("; {}", cookie.split(';').next().unwrap()));
        }
        req
    };
    for database in [false, true] {
        let manager = manager
            .clone()
            .with_store_capabilities(crate::store::StoreCapabilities {
                database,
                secondary: !database,
            });
        let req = request_with_account();
        manager.write_cache(&req, &data, false).await.unwrap();
        let headers = req.take_response_headers().unwrap();
        let cookies: Vec<_> = headers
            .get_all("set-cookie")
            .filter(|value| value.starts_with(name))
            .collect();
        assert!(!cookies.is_empty());
        if database {
            assert!(cookies.iter().all(|cookie| cookie.contains("Max-Age=0")));
            for original in &account_cookies {
                let original_name = original.split('=').next().unwrap();
                assert!(
                    cookies
                        .iter()
                        .any(|cookie| cookie.starts_with(&format!("{original_name}=")))
                );
            }
        } else {
            let mut renewed = AuthRequest::new(HttpMethod::Get, "/");
            renewed.headers.insert(
                "cookie".into(),
                cookies
                    .iter()
                    .map(|cookie| cookie.split(';').next().unwrap())
                    .collect::<Vec<_>>()
                    .join("; "),
            );
            let value = cookie_cache::read(&renewed, name).unwrap();
            let payload = crate::utils::jwe::decode(
                &value,
                manager.config.encryption_secret(),
                "better-auth-account",
            )
            .unwrap();
            assert_eq!(payload.get("userId"), account.get("userId"));
            assert_eq!(payload.get("accessToken"), account.get("accessToken"));
            assert_eq!(
                payload.get("providerAttribute"),
                account.get("providerAttribute")
            );
        }
    }
    for queued in [false, true] {
        let req = request_with_account();
        let mut endpoint = crate::Headers::new();
        let replacement = format!("{name}=new-account; Path=/");
        if queued {
            req.append_response_header("Set-Cookie", replacement.clone())
                .unwrap();
        } else {
            endpoint.append("Set-Cookie", replacement.clone());
        }
        manager
            .write_cache_with_response(&req, &data, false, Some(&endpoint), None)
            .await
            .unwrap();
        let headers = req.take_response_headers().unwrap();
        let cookies: Vec<_> = headers
            .get_all("set-cookie")
            .chain(endpoint.get_all("set-cookie"))
            .filter(|value| value.starts_with(name))
            .collect();
        assert_eq!(cookies, vec![&replacement]);
    }
}

#[tokio::test]
async fn reads_upstream_cache_formats_without_a_server_session() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("ts-cache-fixtures.json")).unwrap();
    assert_eq!(
        sign_cookie_value("fixture-token", "fixture-secret-at-least-32-characters"),
        fixture["signedCookie"].as_str().unwrap()
    );
    for (name, strategy) in [
        ("compact", CookieCacheStrategy::Compact),
        ("jwt", CookieCacheStrategy::Jwt),
        ("jwe", CookieCacheStrategy::Jwe),
    ] {
        let config = config(strategy);
        let manager = SessionManager::new(Arc::new(config), test_database().await);
        let req = with_cache(
            request("fixture-token", &manager.config),
            fixture[name].as_str().unwrap(),
        );
        let data = manager
            .resolve(&req, SessionRead::Cached)
            .await
            .unwrap()
            .data
            .unwrap_or_else(|| panic!("upstream {name} fixture should authenticate"));
        assert_eq!(data.user.id, "fixture-user", "{name}");
        assert_eq!(data.session.token, "fixture-token", "{name}");
        assert!(data.session.active);
        assert!(req.take_response_headers().unwrap().is_empty());
        assert!(
            manager
                .resolve(&req, SessionRead::Authoritative)
                .await
                .unwrap()
                .data
                .is_none()
        );
    }
}

#[tokio::test]
async fn cache_is_bound_to_session_token_and_signature() {
    for strategy in [
        CookieCacheStrategy::Compact,
        CookieCacheStrategy::Jwt,
        CookieCacheStrategy::Jwe,
    ] {
        let (manager, original) = setup(config(strategy)).await;
        let cache = manager.config.session.cookie_cache.as_ref().unwrap();
        let encoded = cookie_cache::encode(&original, &manager.config, cache, false)
            .await
            .unwrap();
        let user = manager
            .database
            .create_user(CreateUser::new().with_email("other@example.com"))
            .await
            .unwrap();
        let other = manager.create_session(&user, None, None).await.unwrap();
        let req = with_cache(request(other.token(), &manager.config), &encoded);
        let resolved = manager
            .resolve(&req, SessionRead::Cached)
            .await
            .unwrap()
            .data
            .unwrap();
        assert_eq!(resolved.user.id, user.id().as_ref());
        assert_eq!(resolved.session.token, other.token());
        let headers = req.take_response_headers().unwrap();
        assert!(
            headers
                .get_all("Set-Cookie")
                .any(|value| value.starts_with("better-auth.session_data=;")
                    && value.contains("Max-Age=0"))
        );

        let mut tampered = encoded.into_bytes();
        let position = tampered.len() / 2;
        tampered[position] = if tampered[position] == b'A' {
            b'B'
        } else {
            b'A'
        };
        assert!(
            cookie_cache::decode(
                std::str::from_utf8(&tampered).unwrap(),
                &manager.config,
                cache
            )
            .is_none()
        );
    }
}

#[tokio::test]
async fn valid_cache_survives_revocation_until_authoritative_read() {
    let (manager, data) = setup(config(CookieCacheStrategy::Compact)).await;
    let cache = manager.config.session.cookie_cache.as_ref().unwrap();
    let encoded = cookie_cache::encode(&data, &manager.config, cache, false)
        .await
        .unwrap();
    manager
        .database
        .delete_session(&data.session.token)
        .await
        .unwrap();
    let req = with_cache(request(&data.session.token, &manager.config), &encoded);
    assert!(
        manager
            .resolve(&req, SessionRead::Cached)
            .await
            .unwrap()
            .data
            .is_some()
    );
    let mut changed_version = (*manager.config).clone();
    changed_version
        .session
        .cookie_cache
        .as_mut()
        .unwrap()
        .version = "2".into();
    let changed = SessionManager::new(Arc::new(changed_version), manager.database.clone());
    assert!(
        changed
            .resolve(&req, SessionRead::Cached)
            .await
            .unwrap()
            .data
            .is_none()
    );
    let mut without_token = AuthRequest::new(HttpMethod::Get, "/get-session");
    without_token.headers.insert(
        "cookie".into(),
        format!("better-auth.session_data={encoded}"),
    );
    assert!(
        manager
            .resolve(&without_token, SessionRead::Cached)
            .await
            .unwrap()
            .data
            .is_none()
    );
    let mut bypass = req.clone();
    // Zod coerces every non-empty query string, including "false", to true.
    bypass
        .query
        .insert("disableCookieCache".into(), "false".into());
    assert!(
        manager
            .resolve(&bypass, SessionRead::Cached)
            .await
            .unwrap()
            .data
            .is_none()
    );
}

#[tokio::test]
async fn deferred_get_reports_refresh_and_post_updates_storage_and_cookie() {
    let mut cfg = config(CookieCacheStrategy::Compact);
    cfg.session.defer_session_refresh = true;
    cfg.session.cookie_cache = None;
    let (manager, data) = setup(cfg).await;
    let stale = Utc::now() + Duration::hours(1);
    let _ = manager
        .database
        .update_session_expiry(&data.session.token, stale)
        .await
        .unwrap();
    let req = request(&data.session.token, &manager.config);
    let resolved = manager.resolve(&req, SessionRead::Cached).await.unwrap();
    assert_eq!(resolved.needs_refresh, Some(true));
    assert_eq!(
        manager
            .database
            .get_session(&data.session.token)
            .await
            .unwrap()
            .unwrap()
            .expires_at(),
        stale
    );
    assert!(req.take_response_headers().unwrap().is_empty());

    let mut post = req.clone();
    post.method = HttpMethod::Post;
    let refreshed = manager.resolve(&post, SessionRead::Cached).await.unwrap();
    assert!(refreshed.needs_refresh.is_none());
    assert!(refreshed.data.unwrap().session.expires_at > stale);
    assert!(
        post.take_response_headers()
            .unwrap()
            .get_all("Set-Cookie")
            .any(|cookie| cookie.starts_with("better-auth.session_token=")
                && cookie.contains("Max-Age=604800"))
    );
}

#[tokio::test]
async fn disable_refresh_and_dont_remember_do_not_extend_expiry() {
    let (manager, data) = setup(AuthConfig::new("fixture-secret-at-least-32-characters")).await;
    let stale = Utc::now() + Duration::hours(1);
    let _ = manager
        .database
        .update_session_expiry(&data.session.token, stale)
        .await
        .unwrap();
    let mut query = request(&data.session.token, &manager.config);
    query.query.insert("disableRefresh".into(), "true".into());
    let mut remembered = request(&data.session.token, &manager.config);
    remembered
        .headers
        .get_mut("cookie")
        .unwrap()
        .push_str(&format!(
            "; better-auth.dont_remember={}",
            sign_cookie_value("true", &manager.config.secret)
        ));
    for req in [query, remembered] {
        let resolved = manager.resolve(&req, SessionRead::Cached).await.unwrap();
        assert_eq!(resolved.data.unwrap().session.expires_at, stale);
        assert!(resolved.needs_refresh.is_none());
        assert!(req.take_response_headers().unwrap().is_empty());
    }
    assert_eq!(
        manager
            .database
            .get_session(&data.session.token)
            .await
            .unwrap()
            .unwrap()
            .expires_at(),
        stale
    );
}

#[tokio::test]
async fn bearer_requires_opt_in_and_supports_signed_tokens_and_case_folding() {
    let (manager, data) = setup(AuthConfig::new("fixture-secret-at-least-32-characters")).await;
    let mut req = AuthRequest::new(HttpMethod::Get, "/get-session");
    req.headers.insert(
        "authorization".into(),
        format!("bEaReR   {}  ", data.session.token),
    );
    assert!(manager.extract_session_token(&req).is_none());
    let mut enabled = (*manager.config).clone();
    enabled.session.bearer = Some(BearerConfig::default());
    let manager = SessionManager::new(Arc::new(enabled.clone()), manager.database);
    assert_eq!(
        manager.extract_session_token(&req),
        Some(data.session.token.clone())
    );
    enabled.session.bearer.as_mut().unwrap().require_signature = true;
    let strict = SessionManager::new(Arc::new(enabled), manager.database.clone());
    assert!(strict.extract_session_token(&req).is_none());
    let signed = sign_cookie_value(&data.session.token, &strict.config.secret);
    req.headers
        .insert("authorization".into(), format!("bearer {signed}"));
    assert_eq!(
        strict.extract_session_token(&req),
        Some(data.session.token.clone())
    );
    let mut response = AuthResponse::json(200, &serde_json::json!({}))
        .unwrap()
        .with_header(
            "Set-Cookie",
            create_session_cookie(&data.session.token, &strict.config),
        );
    strict.finish_response(&req, &mut response).unwrap();
    let signed_raw = percent_encoding::percent_decode_str(&signed)
        .decode_utf8()
        .unwrap();
    assert_eq!(
        response.headers.get("set-auth-token").map(String::as_str),
        Some(signed_raw.as_ref())
    );
    req.headers
        .insert("authorization".into(), format!("Bearer {signed_raw}"));
    assert_eq!(
        strict.extract_session_token(&req),
        Some(data.session.token.clone())
    );
    assert!(
        response
            .headers
            .get("access-control-expose-headers")
            .unwrap()
            .contains("set-auth-token")
    );
}

#[tokio::test]
async fn large_cache_chunks_are_read_and_cleared_after_revocation() {
    let (manager, mut data) = setup(config(CookieCacheStrategy::Jwe)).await;
    data.user.name = Some("name".repeat(3000));
    let req = request(&data.session.token, &manager.config);
    manager.write_cache(&req, &data, false).await.unwrap();
    let headers = req.take_response_headers().unwrap();
    let chunks: Vec<_> = headers
        .get_all("Set-Cookie")
        .map(|value| value.split(';').next().unwrap().to_string())
        .collect();
    assert!(chunks.len() > 1);
    assert!(
        headers
            .get_all("Set-Cookie")
            .all(|cookie| cookie.len() <= 4050)
    );
    let mut cached = request(&data.session.token, &manager.config);
    cached
        .headers
        .get_mut("cookie")
        .unwrap()
        .push_str(&format!("; {}", chunks.join("; ")));
    assert_eq!(
        manager
            .resolve(&cached, SessionRead::Cached)
            .await
            .unwrap()
            .data
            .unwrap()
            .user
            .name,
        data.user.name
    );
    manager
        .database
        .delete_session(&data.session.token)
        .await
        .unwrap();
    assert!(
        manager
            .resolve(&cached, SessionRead::Authoritative)
            .await
            .unwrap()
            .data
            .is_none()
    );
    let cleared = cached.take_response_headers().unwrap();
    for chunk in chunks {
        let name = chunk.split('=').next().unwrap();
        assert!(cleared.get_all("Set-Cookie").any(|value| value.starts_with(&format!("{name}=;")) && value.contains("Max-Age=0")));
    }
}

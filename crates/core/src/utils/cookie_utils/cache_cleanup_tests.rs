use super::*;
use crate::{AuthRequest, CookieAttributes, HttpMethod, SameSite};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Action {
    Existing,
    Base,
    BaseThenExisting,
}

#[derive(Deserialize)]
struct Input {
    action: Action,
    logical: String,
    incoming: Vec<(String, String)>,
    issued: Vec<String>,
}

#[derive(Deserialize)]
struct Case {
    input: Input,
    headers: Vec<String>,
}

#[test]
fn direct_cache_actions_match_ordered_display_cookie_capture() -> AuthResult<()> {
    let cases: Vec<Case> = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/cookie-cache-cleanup-1.7.6.json"
    )))?;
    let mut config = AuthConfig::new("ordinary-cookie-cache-cleanup-secret-at-least-32-characters")
        .base_url("https://cookie-cache-cleanup.test");
    config.advanced.use_secure_cookies = Some(false);
    config.advanced.default_cookie_attributes = CookieAttributes {
        secure: Some(true),
        http_only: Some(true),
        same_site: Some(SameSite::Lax),
        path: Some("/ordinary".into()),
        domain: Some(".cookie-cache-cleanup.test".into()),
        partitioned: Some(true),
        ..Default::default()
    };
    for case in cases {
        let mut request = AuthRequest::new(HttpMethod::Get, "/ordinary-cookie-display");
        if !case.input.incoming.is_empty() {
            let cookie = case
                .input
                .incoming
                .iter()
                .map(|(name, value)| format!("better-auth.{name}={value}"))
                .collect::<Vec<_>>()
                .join("; ");
            let _ = request.headers.insert("cookie".into(), cookie);
        }
        for name in &case.input.issued {
            let cookie = config.auth_cookie(name, Default::default());
            request.append_response_header("Set-Cookie", render_cookie("display", &cookie)?)?;
        }
        let cookie = config.auth_cookie(&case.input.logical, Default::default());
        match case.input.action {
            Action::Existing => clear_existing_cookies(&request, &cookie, None)?,
            Action::Base => expire_cookie(&request, &cookie, None)?,
            Action::BaseThenExisting => {
                expire_cookie(&request, &cookie, None)?;
                clear_existing_cookies(&request, &cookie, None)?;
            }
        }
        let actual = request.take_response_headers()?;
        assert_eq!(
            actual.get_all("set-cookie").cloned().collect::<Vec<_>>(),
            case.headers,
            "{:?}, incoming={:?}",
            case.input.action,
            case.input.incoming,
        );
    }
    Ok(())
}

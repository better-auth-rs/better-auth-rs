#![expect(
    clippy::indexing_slicing,
    reason = "Read the captured ordinary Cookie fixture and report complete header differences"
)]

use async_trait::async_trait;
use better_auth::{AuthConfig, BetterAuth};
use better_auth_core::config::OAuthStateStrategy;
use better_auth_core::store::StatelessSchema;
use better_auth_core::utils::cookie_utils::render_cookie;
use better_auth_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute, CookieAttributes,
    HttpMethod, SameSite,
};
use serde::Deserialize;
use serde_json::{Value, json};

type S = StatelessSchema;

#[derive(Clone, Deserialize)]
struct Input {
    account: bool,
    state: bool,
    skip: bool,
    incoming: Vec<(String, String)>,
    issued: Vec<String>,
}

#[derive(Deserialize)]
struct Case {
    input: Input,
    response: Value,
}

#[derive(Clone, Copy, Debug)]
enum Entry {
    ApiQueued,
    ApiResponse,
    SessionManager,
}

struct CleanupEndpoint {
    input: Input,
    entry: Entry,
}

#[async_trait]
impl AuthPlugin<S> for CleanupEndpoint {
    fn name(&self) -> &'static str {
        "ordinary-cookie-cleanup"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::get("/cookie-cleanup", "cookie_cleanup")]
    }

    async fn on_request(
        &self,
        request: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        let mut response = AuthResponse::json(200, &json!({ "ok": true }))?;
        for logical in &self.input.issued {
            let cookie = context.config.auth_cookie(logical, Default::default());
            let header = render_cookie("display", &cookie)?;
            if matches!(self.entry, Entry::ApiResponse) {
                response.headers.append("Set-Cookie", header);
            } else {
                request.append_response_header("Set-Cookie", header)?;
            }
        }
        match self.entry {
            Entry::ApiQueued => better_auth_api::plugins::helpers::delete_session_cookies(
                request,
                &context.config,
                self.input.skip,
                None,
            )?,
            Entry::ApiResponse => better_auth_api::plugins::helpers::delete_session_cookies(
                request,
                &context.config,
                self.input.skip,
                Some(&mut response.headers),
            )?,
            Entry::SessionManager => context.session_manager().clear_cookies(request)?,
        }
        Ok(Some(response))
    }
}

#[tokio::test]
async fn aggregate_cleanup_preserves_ordered_complete_headers() -> AuthResult<()> {
    let cases: Vec<Case> =
        serde_json::from_str(include_str!("fixtures/cookie-cleanup-1.7.6.json"))?;
    for case in cases {
        for entry in [Entry::ApiQueued, Entry::ApiResponse, Entry::SessionManager] {
            if matches!(entry, Entry::SessionManager) && case.input.skip {
                continue;
            }
            let mut config =
                AuthConfig::new("ordinary-cookie-cleanup-secret-at-least-32-characters")
                    .base_url("https://cookie-cleanup.test");
            config.logger.disabled = Some(true);
            config.telemetry.enabled = false;
            config.session.cookie_cache = Some(better_auth_core::CookieCacheConfig {
                enabled: Some(false),
                ..Default::default()
            });
            config.account.store_account_cookie = Some(case.input.account);
            config.account.store_state_strategy = Some(if case.input.state {
                OAuthStateStrategy::Cookie
            } else {
                OAuthStateStrategy::Database
            });
            config.advanced.use_secure_cookies = Some(false);
            config.advanced.default_cookie_attributes = CookieAttributes {
                secure: Some(true),
                http_only: Some(true),
                same_site: Some(SameSite::Lax),
                path: Some("/ordinary".into()),
                domain: Some(".cookie-cleanup.test".into()),
                partitioned: Some(true),
                ..Default::default()
            };
            let auth = BetterAuth::stateless(config)
                .plugin(CleanupEndpoint {
                    input: case.input.clone(),
                    entry,
                })
                .rate_limit(better_auth_core::middleware::RateLimitConfig {
                    enabled: Some(false),
                    ..Default::default()
                })
                .build()
                .await?;
            let mut request = AuthRequest::new(HttpMethod::Get, "/api/auth/cookie-cleanup");
            let cookie = case
                .input
                .incoming
                .iter()
                .map(|(name, value)| format!("better-auth.{name}={value}"))
                .collect::<Vec<_>>()
                .join("; ");
            let _ = request.headers.insert("cookie".into(), cookie);
            let actual = auth.handle_request(request).await?;
            assert_eq!(json!(actual.status), case.response["status"], "{entry:?}");
            assert_eq!(
                serde_json::from_slice::<Value>(&actual.body.bytes()?)?,
                case.response["body"],
                "{entry:?}"
            );
            let expected: Vec<String> = serde_json::from_value(case.response["headers"].clone())?;
            assert_eq!(
                actual
                    .headers
                    .get_all("set-cookie")
                    .cloned()
                    .collect::<Vec<_>>(),
                expected,
                "{entry:?}: account={}, state={}, skip={}",
                case.input.account,
                case.input.state,
                case.input.skip,
            );
        }
    }
    Ok(())
}

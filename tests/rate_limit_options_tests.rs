#![expect(
    clippy::panic_in_result_fn,
    reason = "tests propagate setup failures and assert observable rate-limit behavior"
)]

use async_trait::async_trait;
use better_auth::__private_core::{AuthError, AuthRequest, AuthResult, HttpMethod};
use better_auth::middleware::{
    EndpointRateLimit, Middleware, RateLimitConfig, RateLimitDecision, RateLimitMiddleware,
    RateLimitStorage,
};
use std::sync::{Arc, Mutex};

#[test]
fn environment_defaults_and_explicit_switches_use_separate_processes()
-> Result<(), Box<dyn std::error::Error>> {
    for environment in ["development", "production"] {
        let output = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", "environment_case", "--ignored"])
            .env("NODE_ENV", environment)
            .output()?;
        assert!(
            output.status.success(),
            "{environment}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore = "the parent runs this case in fresh development and production processes"]
async fn environment_case() -> AuthResult<()> {
    let production = std::env::var("NODE_ENV")
        .map_err(|error| AuthError::internal(error.to_string()))?
        == "production";
    for (index, configured) in [None, Some(false), Some(true)].into_iter().enumerate() {
        let limiter = RateLimitMiddleware::new(RateLimitConfig {
            window: Some(60.0),
            max_requests: Some(1.0),
            enabled: configured,
            ..Default::default()
        });
        let mut request = AuthRequest::new(HttpMethod::Get, "/rate-environment");
        let _ = request
            .headers
            .insert("x-forwarded-for".into(), format!("192.0.2.{}", index + 1));
        assert!(limiter.before_request(&request).await?.is_none());
        let response = limiter.before_request(&request).await?;
        assert_eq!(
            response.map(|response| response.status),
            configured.unwrap_or(production).then_some(429)
        );
    }
    Ok(())
}

#[derive(Default)]
struct Capture(Mutex<Vec<EndpointRateLimit>>);
#[async_trait]
impl RateLimitStorage for Capture {
    async fn consume(&self, _: &str, rule: EndpointRateLimit) -> AuthResult<RateLimitDecision> {
        self.0
            .lock()
            .map_err(|_| AuthError::internal("rate rule capture poisoned"))?
            .push(rule);
        Ok(RateLimitDecision {
            allowed: true,
            retry_after: None,
        })
    }
}

#[tokio::test]
async fn optional_defaults_reach_storage_as_concrete_rules() -> AuthResult<()> {
    for (window, maximum, expected) in [
        (None, None, (10.0, 100.0)),
        (Some(0.0), Some(0.0), (10.0, 100.0)),
        (Some(f64::NAN), Some(f64::NAN), (10.0, 100.0)),
        (Some(30.0), None, (30.0, 100.0)),
        (None, Some(7.0), (10.0, 7.0)),
        (Some(0.5), Some(1.5), (0.5, 1.5)),
    ] {
        let capture = Arc::new(Capture::default());
        let limiter = RateLimitMiddleware::new(RateLimitConfig {
            window,
            max_requests: maximum,
            enabled: Some(true),
            custom_storage: Some(capture.clone()),
            ..Default::default()
        });
        let mut request = AuthRequest::new(HttpMethod::Get, "/rate-options");
        let _ = request
            .headers
            .insert("x-forwarded-for".into(), "192.0.2.20".into());
        assert!(limiter.before_request(&request).await?.is_none());
        let rules = capture
            .0
            .lock()
            .map_err(|_| AuthError::internal("rate rule capture poisoned"))?;
        assert_eq!(
            rules
                .iter()
                .map(|rule| (rule.window, rule.max_requests))
                .collect::<Vec<_>>(),
            vec![expected]
        );
    }
    Ok(())
}

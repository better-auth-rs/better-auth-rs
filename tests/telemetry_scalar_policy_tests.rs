#![expect(
    clippy::panic_in_result_fn,
    reason = "tests propagate setup failures and assert the observable HTTP error policy"
)]

use async_trait::async_trait;
use better_auth::__private_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthRoute, HttpMethod,
    api_error::{ApiErrorHandler, ApiErrorTask},
    store::StatelessSchema,
};
use better_auth::{AuthConfig, AuthError, AuthResult, BetterAuth};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

type S = StatelessSchema;

struct Failure;
#[async_trait]
impl AuthPlugin<S> for Failure {
    fn name(&self) -> &'static str {
        "failure"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::get("/failure", "failure")]
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Err(AuthError::internal("controlled endpoint failure"))
    }
}
#[derive(Default)]
struct Observer(AtomicUsize);
impl ApiErrorHandler<S> for Observer {
    fn on_error(&self, _: &AuthError, _: &AuthContext<S>) -> AuthResult<Option<ApiErrorTask>> {
        let _ = self.0.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }
}

#[tokio::test]
async fn omitted_and_explicit_http_error_defaults_keep_the_same_runtime_policy() -> AuthResult<()> {
    for configured in [None, Some(false), Some(true)] {
        let mut config = AuthConfig::new("scalar-policy-secret-more-than-32-characters")
            .base_url("https://example.test");
        config.logger.disabled = Some(true);
        config.api_error.throw_errors = configured;
        let observer = Arc::new(Observer::default());
        let auth = BetterAuth::stateless(config)
            .plugin(Failure)
            .on_api_error(observer.clone())
            .build()
            .await?;
        let result = auth
            .handle_request(AuthRequest::new(HttpMethod::Get, "/api/auth/failure"))
            .await;
        if configured == Some(true) {
            assert!(
                matches!(result, Err(AuthError::Internal(message)) if message == "controlled endpoint failure")
            );
            assert_eq!(observer.0.load(Ordering::SeqCst), 0);
        } else {
            let response = result?;
            assert_eq!(response.status, 500);
            assert!(response.body.is_empty());
            assert_eq!(observer.0.load(Ordering::SeqCst), 1);
        }
    }
    Ok(())
}

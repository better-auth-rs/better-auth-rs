#![expect(
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract."
)]

use super::*;
use better_auth_core::{AuthError, HttpMethod};

struct ResponsePlugin {
    replace: bool,
    fail: bool,
}

#[async_trait::async_trait]
impl<S: AuthSchema> AuthPlugin<S> for ResponsePlugin {
    fn name(&self) -> &'static str {
        "response-delegation"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
    async fn on_http_response(
        &self,
        request: &AuthRequest,
        response: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        if self.fail {
            return Err(AuthError::bad_request("response hook rejected"));
        }
        let _ = response
            .headers
            .insert("x-request-path".to_owned(), request.path().to_owned());
        Ok(self.replace.then(|| AuthResponse::text(202, "replacement")))
    }
}

#[tokio::test]
async fn callback_wrapper_preserves_http_response_mutations_replacement_and_errors() {
    let context = crate::plugins::test_helpers::create_test_context().await;
    let request = AuthRequest::new(HttpMethod::Get, "/response-probe/");
    for (replace, fail) in [(false, false), (true, false), (false, true)] {
        let plugin = WithCallbacks {
            plugin: ResponsePlugin { replace, fail },
            callbacks: Arc::new(()),
        };
        let mut response = AuthResponse::new(200);
        let result = plugin
            .on_http_response(&request, &mut response, &context)
            .await;
        if fail {
            assert_eq!(result.unwrap_err().status_code().unwrap(), 400);
            assert!(response.headers.get("x-request-path").is_none());
        } else {
            assert_eq!(
                response.headers.get("x-request-path"),
                Some(&"/response-probe/".to_owned())
            );
            let replacement = result.unwrap();
            assert_eq!(
                replacement.as_ref().map(|response| response.status),
                replace.then_some(202)
            );
            if let Some(replacement) = replacement {
                assert_eq!(replacement.body.bytes().unwrap().as_ref(), b"replacement");
            }
        }
    }
}

#[tokio::test]
#[expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "The context contract asserts explicit root presence, identity, and live mutations."
)]
async fn owned_endpoint_retains_explicit_native_root_and_live_mutations() -> AuthResult<()> {
    let context = crate::plugins::test_helpers::create_test_context().await;
    let body: FieldValue = better_auth_core::FieldMap::from([("typed".into(), true.into())]).into();
    let endpoint = EndpointContext::native(None, None, body.clone(), &context);
    assert!(endpoint.native_root().is_none());
    assert!(endpoint.to_owned().as_endpoint().native_root().is_none());
    let root: FieldValue = better_auth_core::FieldMap::new().into();
    for value in [
        FieldValue::Undefined,
        FieldValue::Null,
        7.into(),
        "native".into(),
        root.clone(),
    ] {
        let endpoint = EndpointContext::native(None, None, body.clone(), &context)
            .with_native_root(value.clone());
        let owned = endpoint.to_owned();
        let retained = owned.as_endpoint();
        assert!(retained.native_root().unwrap().strict_equals(&value));
        assert!(retained.body.strict_equals(&body));
        assert!(std::ptr::eq(
            retained.auth.database.as_ref(),
            context.database.as_ref()
        ));
    }
    let owned = endpoint.with_native_root(root.clone()).to_owned();
    root.set_model_property("late", body.clone())?;
    assert!(
        owned
            .as_endpoint()
            .native_root()
            .unwrap()
            .model_property("late")?
            .strict_equals(&body)
    );
    Ok(())
}

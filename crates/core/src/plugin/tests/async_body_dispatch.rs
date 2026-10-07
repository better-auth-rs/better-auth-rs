use crate::endpoint_dispatch::EndpointDispatcher;
use crate::endpoint_input::ValidatedBody;
use crate::hooks::current_request_hook_context;
use crate::test_store::{test_config, test_database};
use crate::{AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthRoute, HttpMethod};
use serde_json::{Value, json};
use std::{cell::RefCell, collections::HashMap, sync::Arc};
use tokio::sync::Notify;

const RAW_BODY: &[u8] = br#"{ "displayName": "  Ada  ", "ignored": "keep" }"#;

tokio::task_local! {
    static PHASES: RefCell<Vec<&'static str>>;
}

fn record(phase: &'static str) {
    PHASES.with(|phases| phases.borrow_mut().push(phase));
}

fn phases() -> Vec<&'static str> {
    PHASES.with(|phases| phases.borrow().clone())
}

fn validate_query(query: Option<Value>) -> AuthResult<Option<Value>> {
    record("query");
    if query.as_ref().and_then(|query| query.get("page")) != Some(&json!("1")) {
        return Err(AuthError::Upstream {
            status: 400,
            code: "INVALID_PAGE",
            message: "Page must be 1",
        });
    }
    Ok(Some(json!({"page": 1})))
}

#[tokio::test]
async fn async_body_transform_finishes_before_query_headers_and_endpoint() {
    let context = AuthContext::new(test_config(), test_database().await);
    for (page, headers, status, expected) in [
        ("1", true, 200, json!({"displayName": "Ada", "page": 1})),
        (
            "1",
            false,
            400,
            json!({"code": "VALIDATION_ERROR", "message": "Headers is required"}),
        ),
        (
            "invalid",
            false,
            400,
            json!({"code": "INVALID_PAGE", "message": "Page must be 1"}),
        ),
    ] {
        let release = Arc::new(Notify::new());
        let validator_release = release.clone();
        let route = AuthRoute::post("/async-input", "asyncInput")
            .body_validator_async(move |request| {
                let release = validator_release.clone();
                async move {
                    record("body:start");
                    assert_eq!(request.body.as_deref(), Some(RAW_BODY));
                    assert_eq!(
                        request.input_body()?,
                        Some(json!({"displayName": "  Ada  ", "ignored": "keep"}))
                    );
                    release.notified().await;
                    let body = request.input_body()?.unwrap();
                    let name = body["displayName"].as_str().unwrap().trim().to_owned();
                    record("body:complete");
                    Ok(ValidatedBody::new(
                        Some(json!({"displayName": name.clone()})),
                        name,
                    ))
                }
            })
            .query_validator(validate_query)
            .require_headers(true);
        let dispatcher = EndpointDispatcher::new(Arc::new(Vec::new()), Default::default(), [route]);
        let mut request = AuthRequest::new(HttpMethod::Post, "/async-input")
            .with_optional_headers(headers.then(HashMap::new));
        request.body = Some(RAW_BODY.to_vec());
        request.query = Some(json!({"page": page, "ignored": "keep"}));
        let original = request.clone();

        PHASES
            .scope(RefCell::new(Vec::new()), async {
                crate::with_request_hook_context(&original, async {
                    let dispatch =
                        dispatcher.run(&mut request, true, &context, None, |request| async move {
                            record("endpoint");
                            assert!(request.endpoint_headers().is_some());
                            assert_eq!(request.input_body()?, Some(json!({"displayName": "Ada"})));
                            assert_eq!(request.query, Some(json!({"page": 1})));
                            assert_eq!(request.body.as_deref(), Some(RAW_BODY));
                            let original = request.original_request().unwrap();
                            assert_eq!(original.body.as_deref(), Some(RAW_BODY));
                            assert_eq!(
                                original.query,
                                Some(json!({"page": "1", "ignored": "keep"}))
                            );
                            let scope = current_request_hook_context().unwrap();
                            assert_eq!(scope.body, request.input_body()?);
                            assert_eq!(scope.query, request.query);
                            assert_eq!(scope.request.body.as_deref(), Some(RAW_BODY));
                            assert_eq!(scope.request.query, original.query);
                            Ok(AuthResponse::json(
                                200,
                                &json!({
                                    "displayName": request.validated_body::<String>().unwrap(),
                                    "page": request.query.as_ref().unwrap()["page"],
                                }),
                            )?)
                        });
                    let mut dispatch = Box::pin(dispatch);
                    assert!(futures_util::poll!(dispatch.as_mut()).is_pending());
                    assert_eq!(phases(), ["body:start"]);
                    release.notify_one();
                    let response = dispatch.await.unwrap();
                    assert_eq!(response.status, status);
                    assert_eq!(
                        serde_json::from_slice::<Value>(&response.body.bytes().unwrap()).unwrap(),
                        expected
                    );
                    let scope = current_request_hook_context().unwrap();
                    assert_eq!(scope.body, original.input_body().unwrap());
                    assert_eq!(scope.query, original.query);
                })
                .await;
                let expected_phases = if status == 200 {
                    vec!["body:start", "body:complete", "query", "endpoint"]
                } else {
                    vec!["body:start", "body:complete", "query"]
                };
                assert_eq!(phases(), expected_phases);
            })
            .await;
        assert_eq!(request.body, original.body);
        assert_eq!(request.query, original.query);
    }
}

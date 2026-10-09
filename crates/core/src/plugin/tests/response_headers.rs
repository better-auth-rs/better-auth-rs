#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "Paired endpoint contracts inspect complete fixture responses and private observation locks"
)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::{Value, json};

use crate::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute, BeforeRequestAction,
    Headers, HttpMethod,
    endpoint_dispatch::EndpointDispatcher,
    observability::{AfterEndpointHook, BeforeEndpointHook, EndpointHooks},
    store::{EphemeralStore, StatelessSchema as S},
};

fn headers(headers: &Headers) -> BTreeMap<String, String> {
    headers
        .iter()
        .map(|(key, value)| (key.to_ascii_lowercase(), value.clone()))
        .collect()
}

fn response(phase: &str, content_type: Option<&str>) -> AuthResult<AuthResponse> {
    let mut response = if phase == "error" {
        AuthResponse::json(
            400,
            &json!({"code":"FIXTURE_ERROR","message":"fixture rejection"}),
        )?
        .with_header("x-error", "1")
    } else if phase == "endpoint" {
        AuthResponse::native(200, crate::FieldValue::from_json(json!({"phase":phase}))?)
    } else {
        AuthResponse::json(200, &json!({"phase":phase}))?
    };
    if let Some(content_type) = content_type {
        let _ = response.headers.insert("CoNtEnT-TyPe", content_type);
    }
    Ok(response)
}

#[derive(Clone)]
struct Hooks {
    mode: &'static str,
    content_type: Option<&'static str>,
    events: Arc<Mutex<Vec<Value>>>,
}

impl Hooks {
    fn observe(&self, phase: &str, response: &AuthResponse) {
        self.events.lock().unwrap().push(json!({
            "phase":phase,"headers":headers(&response.headers),"body":response.body.json().unwrap(),
        }));
    }
}

#[async_trait]
impl BeforeEndpointHook<S> for Hooks {
    async fn before(
        &self,
        request: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        if self.mode == "before" || self.mode == "before-error" {
            request.set_response_header("x-before", "1")?;
            if self.mode == "before-error" {
                return Err(response("error", self.content_type)?.into());
            }
            return Ok(Some(BeforeRequestAction::Respond(response(
                "before",
                self.content_type,
            )?)));
        }
        Ok(None)
    }
}

#[async_trait]
impl AfterEndpointHook<S> for Hooks {
    async fn after(
        &self,
        request: &AuthRequest,
        returned: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<()> {
        self.observe("after", returned);
        request.set_response_header("x-after", "1")?;
        match self.mode {
            "replace" => returned
                .replace_returned(response("after", None)?.with_header("x-replacement", "1")),
            "replace-json" => {
                returned.replace_json(&json!({"phase":"after"}))?;
                request.set_response_header("x-replacement", "1")?;
            }
            "after-error" => return Err(response("error", None)?.into()),
            _ => {}
        }
        Ok(())
    }
}

#[async_trait]
impl AuthPlugin<S> for Hooks {
    fn name(&self) -> &'static str {
        "response-header-observer"
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
    async fn after_request(
        &self,
        _: &AuthRequest,
        response: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<()> {
        self.observe("observer", response);
        Ok(())
    }
}

#[tokio::test]
async fn json_headers_are_materialized_after_hooks_only_for_http() -> AuthResult<()> {
    let config = crate::test_store::test_config();
    let context = AuthContext::new(config.clone(), Arc::new(EphemeralStore::new(config)));
    for mode in [
        "before",
        "endpoint",
        "replace",
        "replace-json",
        "endpoint-error",
        "after-error",
        "before-error",
    ] {
        for content_type in [
            None,
            Some("application/json"),
            Some("application/problem+json"),
        ] {
            for http in [false, true] {
                if http && mode == "before-error" {
                    continue;
                }
                let hook = Hooks {
                    mode,
                    content_type,
                    events: Default::default(),
                };
                let route = AuthRoute::get("/header-contract", "headerContract");
                let dispatcher = EndpointDispatcher::new(
                    Arc::new(vec![Box::new(hook.clone()) as Box<dyn AuthPlugin<S>>]),
                    EndpointHooks {
                        before: Some(Arc::new(hook.clone())),
                        after: Some(Arc::new(hook.clone())),
                    },
                    [route.clone()],
                );
                let mut request = AuthRequest::new(HttpMethod::Get, "/header-contract");
                let handler = |request: AuthRequest| async move {
                    request.set_response_header("x-endpoint", "1")?;
                    if mode == "endpoint-error" {
                        return Err(response("error", content_type)?.into());
                    }
                    response("endpoint", content_type)
                };
                let result = if http {
                    dispatcher
                        .run(&mut request, true, &context, None, handler)
                        .await
                } else {
                    dispatcher.native(request, route, &context, handler).await
                };
                let failed = mode.ends_with("error");
                assert_eq!(
                    result.is_err(),
                    failed && !http,
                    "{mode} {content_type:?} {http}"
                );
                let returned = match result {
                    Ok(value) => value,
                    Err(error) => error.to_auth_response(),
                };
                let expected_body = if failed {
                    json!({"code":"FIXTURE_ERROR","message":"fixture rejection"})
                } else {
                    json!({"phase": match mode { "before" => "before", "replace" | "replace-json" => "after", _ => "endpoint" }})
                };
                assert_eq!(returned.body.json()?, Some(expected_body.clone()));
                let mut expected_headers = BTreeMap::new();
                if let Some(value) = content_type {
                    let _ = expected_headers.insert("content-type".into(), value.into());
                }
                if mode == "before" {
                    let _ = expected_headers.insert("x-before".into(), "1".into());
                } else if mode != "before-error" {
                    let _ = expected_headers.insert("x-endpoint".into(), "1".into());
                    let _ = expected_headers.insert("x-after".into(), "1".into());
                }
                if failed {
                    let _ = expected_headers.insert("x-error".into(), "1".into());
                }
                if mode == "replace" || mode == "replace-json" {
                    let _ = expected_headers.insert("x-replacement".into(), "1".into());
                }
                let native_headers = expected_headers.clone();
                if http {
                    let _ =
                        expected_headers.insert("content-type".into(), "application/json".into());
                }
                assert_eq!(
                    headers(&returned.headers),
                    expected_headers,
                    "{mode} {content_type:?} {http}"
                );
                let events = hook.events.lock().unwrap().clone();
                if mode.starts_with("before") {
                    assert!(events.is_empty());
                } else {
                    let mut initial = BTreeMap::from([("x-endpoint".to_owned(), "1".to_owned())]);
                    if let Some(value) = content_type {
                        let _ = initial.insert("content-type".into(), value.into());
                    }
                    if mode == "endpoint-error" {
                        let _ = initial.insert("x-error".into(), "1".into());
                    }
                    let initial_body = if mode == "endpoint-error" {
                        expected_body.clone()
                    } else {
                        json!({"phase":"endpoint"})
                    };
                    assert_eq!(
                        events,
                        vec![
                            json!({"phase":"after","headers":initial,"body":initial_body}),
                            json!({"phase":"observer","headers":native_headers,"body":expected_body}),
                        ]
                    );
                }
                if failed && !http {
                    let explicit = BTreeMap::from([("x-error".to_owned(), "1".to_owned())]);
                    let mut explicit = explicit;
                    if mode != "after-error"
                        && let Some(value) = content_type
                    {
                        let _ = explicit.insert("content-type".into(), value.into());
                    }
                    assert_eq!(headers(returned.api_error_headers().unwrap()), explicit);
                    let captured = if mode == "before-error" {
                        BTreeMap::from([("x-before".to_owned(), "1".to_owned())])
                    } else {
                        native_headers
                    };
                    assert_eq!(headers(returned.captured_headers().unwrap()), captured);
                }
                let output = returned
                    .into_http_response()
                    .with_header("content-type", "application/custom")
                    .into_http_response();
                assert_eq!(
                    output.headers.get("content-type").map(String::as_str),
                    Some("application/custom")
                );
            }
        }
    }
    Ok(())
}

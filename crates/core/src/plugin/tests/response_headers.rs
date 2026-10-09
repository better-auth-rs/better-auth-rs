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
        AuthResponse::native(None, crate::FieldValue::from_json(json!({"phase":phase}))?)
    } else {
        AuthResponse::json(None, &json!({"phase":phase}))?
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
                assert_eq!(returned.status, if failed { 400 } else { 200 });
                if !failed {
                    assert_eq!(
                        returned.native_status(),
                        if mode == "before" {
                            crate::NativeResponseStatus::Absent
                        } else {
                            crate::NativeResponseStatus::Undefined
                        }
                    );
                }
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

#[tokio::test]
async fn json_http_output_strips_request_headers_but_native_output_preserves_them() -> AuthResult<()>
{
    let request_headers = [
        "host",
        "user-agent",
        "referer",
        "from",
        "expect",
        "authorization",
        "proxy-authorization",
        "cookie",
        "origin",
        "accept-charset",
        "accept-encoding",
        "accept-language",
        "if-match",
        "if-none-match",
        "if-modified-since",
        "if-unmodified-since",
        "if-range",
        "range",
        "max-forwards",
        "connection",
        "keep-alive",
        "transfer-encoding",
        "te",
        "upgrade",
        "trailer",
        "proxy-connection",
        "content-length",
    ];
    let config = crate::test_store::test_config();
    let context = AuthContext::new(config.clone(), Arc::new(EphemeralStore::new(config)));
    let route = AuthRoute::get("/header-filter", "headerFilter");
    let dispatcher =
        EndpointDispatcher::new(Arc::new(Vec::new()), Default::default(), [route.clone()]);
    for failed in [false, true] {
        for http in [false, true] {
            let body = if failed {
                json!({"code":"FIXTURE_ERROR","message":"fixture rejection"})
            } else {
                json!({"ok":true})
            };
            let mut supplied = BTreeMap::from([
                ("accept".to_owned(), "application/example".to_owned()),
                ("www-authenticate".to_owned(), "Example".to_owned()),
                ("x-result".to_owned(), "preserved".to_owned()),
            ]);
            supplied.extend(request_headers.map(|name| (name.to_owned(), "1".to_owned())));
            let mut request = AuthRequest::new(HttpMethod::Get, "/header-filter");
            let handler = |request: AuthRequest| {
                let supplied = supplied.clone();
                let body = body.clone();
                async move {
                    for (name, value) in supplied {
                        request.set_response_header(&name.to_ascii_uppercase(), value)?;
                    }
                    request.append_response_header("Set-Cookie", "first=1".into())?;
                    request.append_response_header("Set-Cookie", "second=2".into())?;
                    let returned = AuthResponse::json(failed.then_some(400), &body)?;
                    if failed {
                        Err(returned.into())
                    } else {
                        Ok(returned)
                    }
                }
            };
            let result = if http {
                dispatcher
                    .run(&mut request, true, &context, None, handler)
                    .await
            } else {
                dispatcher
                    .native(request, route.clone(), &context, handler)
                    .await
            };
            assert_eq!(result.is_err(), failed && !http);
            let returned = result.unwrap_or_else(crate::AuthError::to_auth_response);
            assert_eq!(returned.body.json()?, Some(body));
            assert_eq!(
                returned
                    .headers
                    .get_all("set-cookie")
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                ["first=1", "second=2"]
            );
            let mut actual = headers(&returned.headers);
            let _ = actual.remove("set-cookie");
            if http {
                supplied.retain(|name, _| !request_headers.contains(&name.as_str()));
                let _ = supplied.insert("content-type".into(), "application/json".into());
            }
            assert_eq!(actual, supplied, "failed={failed}, http={http}");
        }
    }
    Ok(())
}

fn header_values(value: &Headers) -> Value {
    let mut entries = headers(value);
    let _ = entries.remove("set-cookie");
    json!({"entries":entries, "cookies":value.get_all("set-cookie").collect::<Vec<_>>()})
}

fn explicit_response() -> AuthResponse {
    AuthResponse::text(207, "explicit body")
        .with_header("authorization", "owned credential")
        .with_header("host", "owned.example")
        .with_header("x-result", "owned")
        .with_header("content-type", "application/explicit")
        .with_appended_header("set-cookie", "owned=1")
}

fn queue_explicit_headers(
    request: &AuthRequest,
    phase: &str,
    override_type: bool,
) -> AuthResult<()> {
    for (name, value) in [
        ("origin", "queued.example"),
        ("authorization", "queued credential"),
        ("host", "queued.example"),
        ("x-result", phase),
    ] {
        request.set_response_header(name, value)?;
    }
    if override_type {
        request.set_response_header("content-type", "application/queued")?;
    }
    request.append_response_header("set-cookie", format!("{phase}=1"))
}

#[derive(Clone)]
struct ExplicitHooks {
    mode: &'static str,
    override_type: bool,
    events: Arc<Mutex<Vec<Value>>>,
}

impl ExplicitHooks {
    fn observe(&self, phase: &str, response: &AuthResponse) -> AuthResult<()> {
        let owned = response.explicit_response_headers().map(header_values);
        let body = if owned.is_some() {
            assert_eq!(response.status, 207);
            json!(std::str::from_utf8(&response.body.bytes()?).unwrap())
        } else {
            response.body.json()?.unwrap()
        };
        self.events.lock().unwrap().push(json!({
            "phase":phase, "headers":header_values(&response.headers), "owned":owned, "body":body,
        }));
        Ok(())
    }
}

#[async_trait]
impl BeforeEndpointHook<S> for ExplicitHooks {
    async fn before(
        &self,
        request: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        if self.mode == "before" {
            queue_explicit_headers(request, "before", self.override_type)?;
            return Ok(Some(BeforeRequestAction::Respond(explicit_response())));
        }
        Ok(None)
    }
}

#[async_trait]
impl AfterEndpointHook<S> for ExplicitHooks {
    async fn after(
        &self,
        request: &AuthRequest,
        response: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<()> {
        self.observe("after", response)?;
        queue_explicit_headers(request, "after", self.override_type)?;
        if self.mode == "replace" {
            response.replace_returned(explicit_response());
        }
        Ok(())
    }
}

#[async_trait]
impl AuthPlugin<S> for ExplicitHooks {
    fn name(&self) -> &'static str {
        "explicit-response-observer"
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
        self.observe("observer", response)
    }
}

#[tokio::test]
async fn explicit_responses_keep_owned_headers_separate_until_http_materialization()
-> AuthResult<()> {
    let config = crate::test_store::test_config();
    let context = AuthContext::new(config.clone(), Arc::new(EphemeralStore::new(config)));
    let owned = header_values(&explicit_response().headers);
    for mode in ["before", "endpoint", "replace"] {
        for override_type in [false, true] {
            for http in [false, true] {
                let hook = ExplicitHooks {
                    mode,
                    override_type,
                    events: Default::default(),
                };
                let route = AuthRoute::get("/explicit-header-contract", "explicitHeaderContract");
                let dispatcher = EndpointDispatcher::new(
                    Arc::new(vec![Box::new(hook.clone()) as Box<dyn AuthPlugin<S>>]),
                    EndpointHooks {
                        before: Some(Arc::new(hook.clone())),
                        after: Some(Arc::new(hook.clone())),
                    },
                    [route.clone()],
                );
                let mut request = AuthRequest::new(HttpMethod::Get, "/explicit-header-contract");
                let handler = |request: AuthRequest| async move {
                    queue_explicit_headers(&request, "endpoint", override_type)?;
                    if mode == "replace" {
                        Ok(AuthResponse::json(None, &json!({"phase":"endpoint"}))?)
                    } else {
                        Ok(explicit_response())
                    }
                };
                let returned = if http {
                    dispatcher
                        .run(&mut request, true, &context, None, handler)
                        .await?
                } else {
                    dispatcher.native(request, route, &context, handler).await?
                };
                assert_eq!(returned.status, 207);
                assert_eq!(
                    returned.native_status(),
                    if mode == "before" {
                        crate::NativeResponseStatus::Absent
                    } else {
                        crate::NativeResponseStatus::Undefined
                    }
                );
                assert_eq!(returned.body.bytes()?.as_ref(), b"explicit body");
                let phases: &[&str] = if mode == "before" {
                    &["before"]
                } else {
                    &["endpoint", "after"]
                };
                let expected = AuthRequest::new(HttpMethod::Get, "/expected");
                for phase in phases {
                    queue_explicit_headers(&expected, phase, override_type)?;
                }
                let queued = header_values(&expected.take_response_headers()?);
                if http {
                    let entries = BTreeMap::from([
                        ("authorization", "owned credential"),
                        ("host", "owned.example"),
                        ("x-result", *phases.last().unwrap()),
                        (
                            "content-type",
                            if override_type {
                                "application/queued"
                            } else {
                                "application/explicit"
                            },
                        ),
                    ]);
                    let expected = json!({"entries":entries,"cookies":std::iter::once("owned=1".to_owned()).chain(phases.iter().map(|phase|format!("{phase}=1"))).collect::<Vec<_>>()});
                    assert_eq!(
                        header_values(&returned.headers),
                        expected,
                        "{mode} {override_type} HTTP"
                    );
                } else {
                    assert_eq!(
                        header_values(&returned.headers),
                        queued,
                        "{mode} {override_type} native queued"
                    );
                    assert_eq!(
                        returned.explicit_response_headers().map(header_values),
                        Some(owned.clone()),
                        "{mode} {override_type} native owned"
                    );
                }
                let events = hook.events.lock().unwrap().clone();
                if mode == "before" {
                    assert!(events.is_empty());
                } else {
                    let expected = AuthRequest::new(HttpMethod::Get, "/expected");
                    queue_explicit_headers(&expected, "endpoint", override_type)?;
                    assert_eq!(
                        events,
                        [
                            json!({"phase":"after", "headers":header_values(&expected.take_response_headers()?), "owned":if mode == "replace" { Value::Null } else { owned.clone() }, "body":if mode == "replace" { json!({"phase":"endpoint"}) } else { json!("explicit body") }}),
                            json!({"phase":"observer", "headers":queued, "owned":owned, "body":"explicit body"}),
                        ]
                    );
                }
            }
        }
    }
    Ok(())
}

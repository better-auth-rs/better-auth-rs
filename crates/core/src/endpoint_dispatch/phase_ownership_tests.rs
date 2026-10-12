use super::*;
use crate::store::{EphemeralStore, StatelessSchema as S};
use crate::{
    FieldMap, FieldValue, Headers,
    observability::{AfterEndpointHook, BeforeEndpointHook},
};
use async_trait::async_trait;
use std::sync::Mutex;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Complete,
    BeforeReturn,
    HandlerError,
    AfterError,
}

type RetainedPhase = (&'static str, AuthRequest, FieldValue);

#[derive(Clone)]
struct Phases {
    outcome: Outcome,
    retained: Arc<Mutex<Vec<RetainedPhase>>>,
    shared: FieldValue,
}

impl Phases {
    fn enter(&self, phase: &'static str, request: &AuthRequest, status: u16) -> AuthResult<()> {
        let headers = request.response_headers_value()?;
        if !request.snapshot_response_headers()?.is_empty() || request.response_status()?.is_some()
        {
            return Err(AuthError::internal(format!(
                "{phase} inherited another phase's response state"
            )));
        }
        if phase == "before-user" {
            request.set_server_context("phase-shared", self.shared.clone())?;
        } else if !request
            .server_context("phase-shared")?
            .is_some_and(|value| value.strict_equals(&self.shared))
        {
            return Err(AuthError::internal(format!(
                "{phase} lost the shared dispatch context"
            )));
        }
        request.set_response_header("x-phase", phase)?;
        request.append_response_header("set-cookie", format!("{phase}=1"))?;
        request.set_response_status(status)?;
        self.retained
            .lock()
            .map_err(|_| AuthError::internal("Phase fixture lock poisoned"))?
            .push((phase, request.clone(), headers));
        Ok(())
    }
}

#[async_trait]
impl BeforeEndpointHook<S> for Phases {
    async fn before(
        &self,
        request: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        self.enter("before-user", request, 201)?;
        Ok(None)
    }
}

#[async_trait]
impl AfterEndpointHook<S> for Phases {
    async fn after(
        &self,
        request: &AuthRequest,
        _: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<()> {
        self.enter("after-user", request, 204)?;
        if self.outcome == Outcome::AfterError {
            return Err(AuthError::bad_request("after failed"));
        }
        Ok(())
    }
}

#[async_trait]
impl AuthPlugin<S> for Phases {
    fn name(&self) -> &'static str {
        "phase-ownership"
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
    async fn before_request(
        &self,
        request: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        self.enter("before-plugin", request, 202)?;
        Ok((self.outcome == Outcome::BeforeReturn).then(|| {
            BeforeRequestAction::Respond(AuthResponse::native(
                None,
                FieldMap::from([("early".into(), true.into())]).into(),
            ))
        }))
    }
    async fn after_request(
        &self,
        request: &AuthRequest,
        _: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<()> {
        self.enter("after-plugin", request, 205)
    }
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The regression compares retained phase identities, status values, and full header output after production dispatch."
)]
async fn dispatch_retains_phase_header_bindings_and_handler_status() -> AuthResult<()> {
    for outcome in [
        Outcome::Complete,
        Outcome::BeforeReturn,
        Outcome::HandlerError,
        Outcome::AfterError,
    ] {
        let config = crate::test_store::test_config();
        let context = AuthContext::new(config.clone(), Arc::new(EphemeralStore::new(config)))?;
        let phases = Phases {
            outcome,
            retained: Default::default(),
            shared: FieldMap::from([("retained".into(), true.into())]).into(),
        };
        let route = AuthRoute::get("/phase-ownership", "phaseOwnership");
        let dispatcher = EndpointDispatcher::new(
            Arc::new(vec![Box::new(phases.clone()) as Box<dyn AuthPlugin<S>>]),
            EndpointHooks {
                before: Some(Arc::new(phases.clone())),
                after: Some(Arc::new(phases.clone())),
            },
            [route.clone()],
        );
        let request = AuthRequest::new(HttpMethod::Get, &route.path);
        let source_headers = request.response_headers_value()?;
        request.set_response_header("x-source", "original")?;
        let source = request.clone();
        let handler_phases = phases.clone();
        let result = dispatcher
            .native(request, route, &context, move |request, _| async move {
                handler_phases.enter("handler", &request, 203)?;
                if outcome == Outcome::HandlerError {
                    return Err(AuthError::bad_request("handler failed"));
                }
                Ok(AuthResponse::native(
                    None,
                    FieldMap::from([("ok".into(), true.into())]).into(),
                ))
            })
            .await;
        let failed = matches!(outcome, Outcome::HandlerError | Outcome::AfterError);
        assert_eq!(result.is_err(), failed);
        let response = match result {
            Ok(response) => response,
            Err(error) => error.to_auth_response()?,
        };
        let expected_phases: &[&str] = if outcome == Outcome::BeforeReturn {
            &["before-user", "before-plugin"]
        } else {
            &["handler", "after-user", "after-plugin"]
        };
        let mut expected = Headers::new();
        for phase in expected_phases {
            let _ = expected.insert("x-phase", *phase);
            expected.append("set-cookie", format!("{phase}=1"));
        }
        let actual = if failed {
            response
                .captured_headers()?
                .ok_or_else(|| AuthError::internal("Missing dispatch error headers"))?
        } else {
            response.headers.clone()
        };
        assert_eq!(actual, expected);
        if !failed {
            assert_eq!(
                response.native_status(),
                if outcome == Outcome::BeforeReturn {
                    crate::NativeResponseStatus::Absent
                } else {
                    crate::NativeResponseStatus::Present(203.into())
                }
            );
        }
        let retained = phases
            .retained
            .lock()
            .map_err(|_| AuthError::internal("Phase fixture lock poisoned"))?
            .clone();
        assert_eq!(
            retained.len(),
            if outcome == Outcome::BeforeReturn {
                2
            } else {
                5
            }
        );
        for (index, (phase, request, original)) in retained.iter().enumerate() {
            assert!(
                request.response_headers_value()?.strict_equals(original),
                "{phase} binding changed"
            );
            assert_eq!(
                request.response_status()?,
                Some((201 + index as u16).into())
            );
            let headers = Headers::from_field_value(original)?;
            assert_eq!(headers.get("x-phase").map(String::as_str), Some(*phase));
            assert_eq!(
                headers.get_all("set-cookie").cloned().collect::<Vec<_>>(),
                [format!("{phase}=1")]
            );
            for (_, _, other) in retained.iter().take(index) {
                assert!(!original.strict_equals(other));
            }
            request.set_response_header("x-retained", *phase)?;
            assert_eq!(
                Headers::from_field_value(original)?
                    .get("x-retained")
                    .map(String::as_str),
                Some(*phase)
            );
        }
        assert!(
            source
                .response_headers_value()?
                .strict_equals(&source_headers)
        );
        assert_eq!(
            source.snapshot_response_headers()?,
            Headers::from_field_value(&source_headers)?
        );
        assert_eq!(
            source
                .snapshot_response_headers()?
                .get("x-source")
                .map(String::as_str),
            Some("original")
        );
    }
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The regression proves nested production dispatch creates a separate response binding while preserving the parent status."
)]
async fn nested_dispatch_retains_parent_response_binding() -> AuthResult<()> {
    let config = crate::test_store::test_config();
    let context = AuthContext::new(config.clone(), Arc::new(EphemeralStore::new(config)))?;
    let outer_route = AuthRoute::get("/outer-phase", "outerPhase");
    let inner_route = AuthRoute::get("/inner-phase", "innerPhase");
    let dispatcher = Arc::new(EndpointDispatcher::new(
        Arc::new(Vec::new()),
        EndpointHooks::default(),
        [outer_route.clone(), inner_route.clone()],
    ));
    let nested = dispatcher.clone();
    let result = dispatcher
        .native(
            AuthRequest::new(HttpMethod::Get, &outer_route.path),
            outer_route,
            &context,
            move |request, context| async move {
                let parent_headers = request.response_headers_value()?;
                request.append_response_header("set-cookie", "parent=1".into())?;
                request.set_response_status(202)?;
                let parent = request.clone();
                let inner = nested
                    .native(
                        request.clone(),
                        inner_route,
                        &context,
                        move |inner, _| async move {
                            assert!(inner.snapshot_response_headers()?.is_empty());
                            assert!(
                                !inner
                                    .response_headers_value()?
                                    .strict_equals(&parent.response_headers_value()?)
                            );
                            inner.append_response_header("set-cookie", "child=1".into())?;
                            inner.set_response_status(207)?;
                            Ok(AuthResponse::native(None, true.into()))
                        },
                    )
                    .await?;
                assert_eq!(
                    inner.native_status(),
                    crate::NativeResponseStatus::Present(207.into())
                );
                assert_eq!(
                    inner
                        .headers
                        .get_all("set-cookie")
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                    ["child=1"]
                );
                assert!(
                    request
                        .response_headers_value()?
                        .strict_equals(&parent_headers)
                );
                assert_eq!(request.response_status()?, Some(202.into()));
                Ok(AuthResponse::native(None, true.into()))
            },
        )
        .await?;
    assert_eq!(
        result.native_status(),
        crate::NativeResponseStatus::Present(202.into())
    );
    assert_eq!(
        result
            .headers
            .get_all("set-cookie")
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["parent=1"]
    );
    Ok(())
}

#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "The dispatch regression asserts native identity and the complete hook lifecycle."
)]

use super::ValidatedBody;
use crate::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    BeforeRequestAction, FieldMap, FieldObject, FieldValue, HttpMethod,
    endpoint_dispatch::EndpointDispatcher,
    hooks::{RequestHookContext, current_request_hook_context, with_request_hook_context_value},
    observability::{AfterEndpointHook, BeforeEndpointHook, EndpointHooks},
    store::{EphemeralStore, StatelessSchema},
};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::sync::Arc;

const BYTES: &[u8] = br#"{ "name": "before", "metadata": { "value": 1 }, "ignored": true }"#;

fn object(value: &FieldValue) -> AuthResult<&FieldObject> {
    value
        .as_object()
        .ok_or_else(|| AuthError::internal("Expected body object"))
}

fn scope() -> AuthResult<RequestHookContext> {
    current_request_hook_context()
        .ok_or_else(|| AuthError::internal("Expected endpoint hook context"))
}

#[derive(Clone)]
struct Hooks {
    raw: FieldValue,
    phases: Arc<Mutex<Vec<&'static str>>>,
}

impl Hooks {
    fn observe_raw(&self, phase: &'static str, request: &AuthRequest) -> AuthResult<()> {
        self.phases.lock().push(phase);
        assert!(self.raw.strict_equals(&request.input_field_value()?));
        assert!(self.raw.strict_equals(&scope()?.body));
        assert!(
            self.raw
                .strict_equals(&scope()?.request.input_field_value()?)
        );
        assert!(request.validated_body::<String>().is_none());
        assert_eq!(request.body.as_deref(), Some(BYTES));
        Ok(())
    }
}

#[async_trait]
impl BeforeEndpointHook<StatelessSchema> for Hooks {
    async fn before(
        &self,
        request: &AuthRequest,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        self.observe_raw("before", request)?;
        object(&request.input_field_value()?)?.set("name", "from hook".into())?;
        Ok(None)
    }
}

#[async_trait]
impl AuthPlugin<StatelessSchema> for Hooks {
    fn name(&self) -> &'static str {
        "native-input-probe"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    async fn before_request(
        &self,
        request: &AuthRequest,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        self.observe_raw("plugin", request)?;
        assert_eq!(
            object(&request.input_field_value()?)?.get("name")?,
            Some("from hook".into())
        );
        object(&scope()?.body)?.set("name", "from plugin".into())?;
        Ok(None)
    }

    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

#[async_trait]
impl AfterEndpointHook<StatelessSchema> for Hooks {
    async fn after(
        &self,
        request: &AuthRequest,
        _: &mut AuthResponse,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<()> {
        self.observe_raw("after", request)?;
        assert_eq!(
            object(&request.input_field_value()?)?.get("name")?,
            Some("from plugin".into())
        );
        assert_eq!(
            object(&request.input_field_value()?)?.get("ignored")?,
            Some(true.into())
        );
        Ok(())
    }
}

#[tokio::test]
async fn hook_mutations_reach_validation_and_handler_without_replacing_raw_scope() -> AuthResult<()>
{
    let config = crate::test_store::test_config();
    let context = AuthContext::new(config.clone(), Arc::new(EphemeralStore::new(config)))
        .expect("fixture context initializes");
    for http in [false, true] {
        let mut request = AuthRequest::new(HttpMethod::Post, "/input");
        request.body = Some(BYTES.to_vec());
        if http {
            let _ = request
                .headers
                .insert("content-type".into(), "application/json".into());
            request.parse_http_body(&["application/json".into()])?;
        }
        let hooks = Hooks {
            raw: request.input_field_value()?,
            phases: Arc::default(),
        };
        let validator = hooks.clone();
        let route = AuthRoute::post("/input", "inputProbe").body_validator(move |request| {
            validator.observe_raw("validate", request)?;
            let raw = request.input_field_value()?;
            assert_eq!(object(&raw)?.get("name")?, Some("from plugin".into()));
            Ok(ValidatedBody::native(
                FieldMap::from([
                    ("name".into(), "validated".into()),
                    (
                        "metadata".into(),
                        object(&raw)?.get("metadata")?.unwrap_or_default(),
                    ),
                ])
                .into(),
                "validated".to_owned(),
            ))
        });
        let dispatcher = EndpointDispatcher::new(
            Arc::new(vec![Box::new(hooks.clone())]),
            EndpointHooks {
                before: Some(Arc::new(hooks.clone())),
                after: Some(Arc::new(hooks.clone())),
            },
            [route.clone()],
        );
        let handler_observer = hooks.clone();
        let handler = move |request: AuthRequest, _context| async move {
            handler_observer.phases.lock().push("handler");
            let body = request.input_field_value()?;
            assert!(!handler_observer.raw.strict_equals(&body));
            assert!(body.strict_equals(&request.clone().input_field_value()?));
            assert!(body.strict_equals(&scope()?.body));
            assert!(
                handler_observer
                    .raw
                    .strict_equals(&scope()?.request.input_field_value()?)
            );
            let raw_metadata = object(&handler_observer.raw)?
                .get("metadata")?
                .unwrap_or_default();
            let metadata = object(&body)?.get("metadata")?.unwrap_or_default();
            assert!(raw_metadata.strict_equals(&metadata));
            assert_eq!(object(&body)?.get("name")?, Some("validated".into()));
            assert_eq!(object(&body)?.get("ignored")?, None);
            assert_eq!(
                request.validated_body::<String>().map(String::as_str),
                Some("validated")
            );
            assert_eq!(request.body.as_deref(), Some(BYTES));
            object(&metadata)?.set("value", 2.into())?;
            AuthResponse::json(200, &serde_json::json!({"ok": true}))
        };
        let response = if http {
            let mut scope = RequestHookContext::from_request(&request)?;
            scope.is_http = true;
            with_request_hook_context_value(
                scope,
                dispatcher.run(&mut request, true, &context, None, handler),
            )
            .await?
        } else {
            dispatcher.native(request, route, &context, handler).await?
        };
        assert_eq!(response.status, 200);
        assert_eq!(
            *hooks.phases.lock(),
            ["before", "plugin", "validate", "handler", "after"]
        );
        let metadata = object(&hooks.raw)?.get("metadata")?.unwrap_or_default();
        assert_eq!(object(&metadata)?.get("value")?, Some(2.into()));
    }
    Ok(())
}

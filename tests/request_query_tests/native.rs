#![expect(
    clippy::panic_in_result_fn,
    reason = "The native dispatch contract asserts identities, complete phases, and original errors."
)]

use super::*;
use better_auth::plugins::endpoint_context::{EndpointContext, OwnedEndpointContext};
use better_auth::server_api::NativeEndpointInput;
use better_auth_core::{
    FieldDate, FieldMap, FieldValue,
    endpoint_input::ValidatedInput,
    observability::{AfterEndpointHook, BeforeEndpointHook, EndpointHooks},
};
use std::sync::Mutex as StateMutex;

#[derive(Clone)]
struct NativeProbe {
    raw: FieldValue,
    body: FieldValue,
    failure: Option<FieldValue>,
    phases: Arc<StateMutex<Vec<&'static str>>>,
    retained: Arc<StateMutex<Option<OwnedEndpointContext<StatelessSchema>>>>,
}

impl NativeProbe {
    fn raw(&self, phase: &'static str, request: &AuthRequest) -> AuthResult<()> {
        lock(&self.phases)?.push(phase);
        let scope = required(current_request_hook_context())?;
        assert!(self.raw.strict_equals(&request.input_query_field_value()?));
        assert!(self.raw.strict_equals(&scope.query));
        assert!(
            self.raw
                .strict_equals(&scope.request.input_query_field_value()?)
        );
        assert!(self.body.strict_equals(&request.input_field_value()?));
        assert!(request.validated_query::<String>().is_none());
        assert!(request.query.is_none());
        Ok(())
    }
}

#[async_trait::async_trait]
impl BeforeEndpointHook<StatelessSchema> for NativeProbe {
    async fn before(
        &self,
        request: &AuthRequest,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        self.raw("before", request)?;
        required(self.raw.as_object())?.set("name", "before".into())?;
        Ok(None)
    }
}

#[async_trait::async_trait]
impl AfterEndpointHook<StatelessSchema> for NativeProbe {
    async fn after(
        &self,
        request: &AuthRequest,
        _: &mut AuthResponse,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<()> {
        self.raw("after", request)
    }
}

#[async_trait::async_trait]
impl AuthPlugin<StatelessSchema> for NativeProbe {
    fn name(&self) -> &'static str {
        "native-query-probe"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        let probe = self.clone();
        vec![
            AuthRoute::get("/native-query", "nativeQuery").query_validator_async(move |request| {
                let probe = probe.clone();
                async move {
                    probe.raw("schema:start", &request)?;
                    tokio::task::yield_now().await;
                    probe.raw("schema:end", &request)?;
                    assert_eq!(request.query_string("name")?, Some("plugin".to_owned()));
                    if let Some(failure) = probe.failure {
                        return Err(AuthError::from_thrown(failure));
                    }
                    Ok(ValidatedInput::native(
                        FieldMap::from([
                            ("name".into(), "validated".into()),
                            ("metadata".into(), probe.raw.model_property("metadata")?),
                        ])
                        .into(),
                        "validated".to_owned(),
                    ))
                }
            }),
        ]
    }

    async fn before_request(
        &self,
        request: &AuthRequest,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        self.raw("plugin.before", request)?;
        assert_eq!(request.query_string("name")?, Some("before".to_owned()));
        required(self.raw.as_object())?.set("name", "plugin".into())?;
        Ok(None)
    }

    async fn on_request(
        &self,
        request: &AuthRequest,
        context: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        lock(&self.phases)?.push("handler");
        let query = request.input_query_field_value()?;
        let scope = required(current_request_hook_context())?;
        assert!(query.strict_equals(&scope.query));
        assert!(
            self.raw
                .strict_equals(&scope.request.input_query_field_value()?)
        );
        assert!(!self.raw.strict_equals(&query));
        assert!(self.body.strict_equals(&request.input_field_value()?));
        assert_eq!(
            request.validated_query::<String>().map(String::as_str),
            Some("validated")
        );
        assert_eq!(
            required(query.as_object())?.own_keys()?,
            ["name", "metadata"]
        );
        assert_eq!(request.query_string("name")?, Some("validated".to_owned()));
        assert!(
            query
                .model_property("metadata")?
                .strict_equals(&self.raw.model_property("metadata")?)
        );

        let endpoint = EndpointContext::new(Some(request), request.input_field_value()?, context);
        assert!(query.strict_equals(&endpoint.query_field_value()?));
        assert_eq!(
            required(endpoint.request)?.query,
            Some(json!({"transport":true}))
        );
        *lock(&self.retained)? = Some(endpoint.to_owned());
        Ok(Some(AuthResponse::native(None, query)))
    }

    async fn after_request(
        &self,
        request: &AuthRequest,
        _: &mut AuthResponse,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<()> {
        self.raw("plugin.after", request)
    }
}

#[tokio::test]
async fn native_endpoint_query_retains_identity_through_hooks_schema_and_owned_callbacks()
-> AuthResult<()> {
    for fail in [false, true] {
        let date = FieldValue::Date(FieldDate::invalid());
        let metadata: FieldValue = FieldMap::from([
            ("date".into(), date.clone()),
            ("nan".into(), f64::NAN.into()),
            ("ownUndefined".into(), FieldValue::Undefined),
            ("null".into(), FieldValue::Null),
        ])
        .into();
        let raw: FieldValue = FieldMap::from([
            ("name".into(), "initial".into()),
            ("metadata".into(), metadata.clone()),
            ("ignored".into(), true.into()),
        ])
        .into();
        let failure: FieldValue = FieldMap::from([("failure".into(), "schema".into())]).into();
        let probe = NativeProbe {
            raw: raw.clone(),
            body: date.clone(),
            failure: fail.then(|| failure.clone()),
            phases: Arc::default(),
            retained: Arc::default(),
        };
        let auth = BetterAuth::stateless(
            AuthConfig::new("native-query-secret-with-at-least-32-characters")
                .base_url("http://native-query.test"),
        )
        .rate_limit(RateLimitConfig::new().enabled(false))
        .hooks(EndpointHooks {
            before: Some(Arc::new(probe.clone())),
            after: Some(Arc::new(probe.clone())),
        })
        .plugin(probe.clone())
        .build()
        .await?;
        let mut original = AuthRequest::new(HttpMethod::Get, "/transport");
        original.query = Some(json!({"transport":true}));
        let result = auth
            .call_endpoint_value(
                HttpMethod::Get,
                "/native-query",
                NativeEndpointInput {
                    request: Some(original),
                    query: raw.clone(),
                    body: date,
                    ..Default::default()
                },
            )
            .await;
        if fail {
            let error = result.err().ok_or_else(|| {
                AuthError::internal("Failing query validation unexpectedly returned a response")
            })?;
            assert!(required(error.raw_value())?.strict_equals(&failure));
            assert!(lock(&probe.retained)?.is_none());
            assert_eq!(
                *lock(&probe.phases)?,
                ["before", "plugin.before", "schema:start", "schema:end"]
            );
        } else {
            let response = result?;
            let output = response.body.field_value()?;
            assert_eq!(response.status, 200);
            let retained = lock(&probe.retained)?;
            let endpoint = required(retained.as_ref())?.as_endpoint();
            assert!(output.strict_equals(&endpoint.query_field_value()?));
            assert!(metadata.strict_equals(&output.model_property("metadata")?));
            assert_eq!(
                required(output.model_property("metadata")?.as_object())?.get("ownUndefined")?,
                Some(FieldValue::Undefined)
            );
            assert!(
                required(
                    output
                        .model_property("metadata")?
                        .model_property("nan")?
                        .as_f64()
                )?
                .is_nan()
            );
            assert_eq!(
                *lock(&probe.phases)?,
                [
                    "before",
                    "plugin.before",
                    "schema:start",
                    "schema:end",
                    "handler",
                    "after",
                    "plugin.after"
                ]
            );
        }
        assert_eq!(raw.model_property("name")?, "plugin".into());
        assert_eq!(raw.model_property("ignored")?, true.into());
        assert!(raw.model_property("metadata")?.strict_equals(&metadata));
        let _ = lock(&probe.retained)?.take();
    }
    Ok(())
}

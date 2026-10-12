//! Paired native input contracts retain the endpoint runtime after getter, conversion, and setter failures.

#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "Contract assertions compare original identities, exact callback order, and unchanged storage."
)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
    AuthRoute, BeforeRequestAction, FieldDate, FieldFunction, FieldMap, FieldObject, FieldValue,
    HttpMethod,
    endpoint_dispatch::EndpointDispatcher,
    endpoint_input::ValidatedBody,
    field_value::{FieldObjectSource, FieldPropertyDefinition, FieldPropertyDescriptor},
    observability::{BeforeEndpointHook, EndpointHooks},
    store::{EphemeralStore, StatelessSchema as S, schema::EntityRole},
};

use super::{CALLBACK_CONTEXT, OAuthProxyPlugin};
use crate::plugins::test_helpers;

const ORIGIN: &str = "http://preview.proxy-input.test";
const BASE: &str = "http://preview.proxy-input.test/api/auth";
const PRODUCTION: &str = "http://production.proxy-input.test";
const PRODUCTION_BASE: &str = "http://production.proxy-input.test/api/auth";

#[derive(Default)]
struct Trace {
    events: Mutex<Vec<String>>,
    written: Mutex<Option<FieldValue>>,
    runtime: Mutex<Option<AuthContext<S>>>,
}

struct CaptureRuntime(Arc<Trace>);

#[async_trait]
impl BeforeEndpointHook<S> for CaptureRuntime {
    async fn before(
        &self,
        _: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        *self.0.runtime.lock().unwrap() = Some(context.clone());
        Ok(None)
    }
}

struct ObservedBody {
    case: &'static str,
    child: FieldValue,
    trace: Arc<Trace>,
    sentinel: FieldValue,
}

impl ObservedBody {
    fn converted(&self, name: &'static str, value: &'static str) -> FieldValue {
        let trace = self.trace.clone();
        let sentinel = self.sentinel.clone();
        let case = self.case;
        FieldMap::from([(
            "toString".into(),
            FieldFunction::contextual(move |_, arguments| {
                assert!(arguments.is_empty());
                trace
                    .events
                    .lock()
                    .unwrap()
                    .push(format!("toString:{name}"));
                if matches!(
                    (case, name),
                    ("convert-provider", "provider") | ("convert-callback", "callbackURL")
                ) {
                    return Err(AuthError::from_thrown(sentinel.clone()));
                }
                Ok(value.into())
            })
            .into(),
        )])
        .into()
    }
}

impl FieldObjectSource for ObservedBody {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        Err(AuthError::internal(
            "Proxy initiation must not enumerate its body",
        ))
    }

    fn own_property_descriptor(&self, _: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        Err(AuthError::internal(
            "Proxy initiation must not inspect unrelated descriptors",
        ))
    }

    fn get_with_receiver(&self, name: &str, _: &FieldValue) -> AuthResult<Option<FieldValue>> {
        if name == "child" {
            return Ok(Some(self.child.clone()));
        }
        self.trace
            .events
            .lock()
            .unwrap()
            .push(format!("get:{name}"));
        if matches!(
            (self.case, name),
            ("get-provider", "provider") | ("get-callback", "callbackURL")
        ) {
            return Err(AuthError::from_thrown(self.sentinel.clone()));
        }
        match name {
            "provider" => Ok(Some(self.converted("provider", "provider ?#segment"))),
            "callbackURL" => Ok(Some(self.converted("callbackURL", "/complete?x=1&y=~"))),
            _ => Err(AuthError::internal(
                "Proxy initiation read an unrelated property",
            )),
        }
    }

    fn set_with_receiver(
        &self,
        name: String,
        value: FieldValue,
        _: &FieldValue,
    ) -> AuthResult<bool> {
        self.trace
            .events
            .lock()
            .unwrap()
            .push(format!("set:{name}"));
        assert_eq!(name, "callbackURL");
        if self.case == "set-callback" {
            return Err(AuthError::from_thrown(self.sentinel.clone()));
        }
        *self.trace.written.lock().unwrap() = Some(value);
        Ok(true)
    }

    fn define_own_property(&self, _: String, _: FieldPropertyDefinition) -> AuthResult<bool> {
        Err(AuthError::internal("The probe does not define properties"))
    }

    fn delete(&self, _: &str) -> AuthResult<bool> {
        Err(AuthError::internal(
            "Proxy initiation must not delete properties",
        ))
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Err(AuthError::internal(
            "Proxy initiation must not snapshot its body",
        ))
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self).addr()
    }
}

struct Following {
    body: FieldValue,
    expected: Option<FieldValue>,
    dynamic: bool,
    child: FieldValue,
    trace: Arc<Trace>,
    blocker: FieldValue,
}

#[async_trait]
impl AuthPlugin<S> for Following {
    fn name(&self) -> &'static str {
        "observe-proxy-input"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    async fn before_request(
        &self,
        request: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        self.trace.events.lock().unwrap().push("following".into());
        assert!(request.input_field_value()?.strict_equals(&self.body));
        assert_eq!(
            request.body.as_deref(),
            Some(b"original transport bytes".as_slice())
        );
        assert_eq!(
            context.base_url(),
            if self.expected.is_some() {
                PRODUCTION_BASE
            } else {
                BASE
            },
        );
        if let Some(expected) = &self.expected {
            let actual = if self.dynamic {
                self.trace.written.lock().unwrap().clone().unwrap()
            } else {
                self.body.model_property("callbackURL")?
            };
            assert!(actual.strict_equals(expected));
            assert_eq!(
                request.server_context(CALLBACK_CONTEXT)?,
                Some(expected.clone())
            );
            if self.dynamic || self.body.has_property("child")? {
                assert!(
                    self.body
                        .model_property("child")?
                        .strict_equals(&self.child)
                );
            }
        }
        Err(AuthError::from_thrown(self.blocker.clone()))
    }

    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

#[tokio::test]
async fn native_input_preserves_identity_effect_order_and_runtime_mutation() -> AuthResult<()> {
    for case in [
        "missing",
        "null",
        "false",
        "number",
        "string",
        "array",
        "empty",
        "provider-null",
        "provider-false",
        "provider-zero",
        "provider-empty",
        "ordinary",
        "numeric",
        "boolean",
        "dynamic",
        "get-provider",
        "get-callback",
        "convert-provider",
        "convert-callback",
        "set-callback",
    ] {
        let trace = Arc::new(Trace::default());
        let sentinel = AuthError::from_status(
            "CONFLICT",
            FieldMap::from([("message".into(), "proxy input sentinel".into())]).into(),
        )
        .raw_value()
        .unwrap()
        .clone();
        let blocker = AuthError::from_status(
            "CONFLICT",
            FieldMap::from([("message".into(), "following hook".into())]).into(),
        )
        .raw_value()
        .unwrap()
        .clone();
        let child: FieldValue = FieldMap::from([
            ("ownUndefined".into(), FieldValue::Undefined),
            ("date".into(), FieldDate::invalid().into()),
        ])
        .into();
        let body = match case {
            "missing" => FieldValue::Undefined,
            "null" => FieldValue::Null,
            "false" => false.into(),
            "number" => 7.into(),
            "string" => "text".into(),
            "array" => Vec::<FieldValue>::new().into(),
            "empty" => FieldMap::new().into(),
            "provider-null" => FieldMap::from([("provider".into(), FieldValue::Null)]).into(),
            "provider-false" => FieldMap::from([("provider".into(), false.into())]).into(),
            "provider-zero" => FieldMap::from([("provider".into(), 0.into())]).into(),
            "provider-empty" => FieldMap::from([("provider".into(), "".into())]).into(),
            "ordinary" => FieldMap::from([
                ("provider".into(), "google".into()),
                ("callbackURL".into(), "/complete".into()),
                ("child".into(), child.clone()),
                ("absent".into(), FieldValue::Undefined),
            ])
            .into(),
            "numeric" => FieldMap::from([
                ("provider".into(), 7.into()),
                ("callbackURL".into(), FieldValue::Null),
            ])
            .into(),
            "boolean" => FieldMap::from([
                ("provider".into(), true.into()),
                ("callbackURL".into(), "".into()),
            ])
            .into(),
            _ => FieldObject::from_source(Arc::new(ObservedBody {
                case,
                child: child.clone(),
                trace: trace.clone(),
                sentinel: sentinel.clone(),
            }))
            .into(),
        };
        let expected: Option<FieldValue> = match case {
            "ordinary" => Some(format!("{BASE}/callback/google/oauth-proxy?callbackURL=%2Fcomplete").into()),
            "numeric" => Some(format!("{BASE}/callback/7/oauth-proxy?callbackURL=http%3A%2F%2Fpreview.proxy-input.test%2Fapi%2Fauth").into()),
            "boolean" => Some(format!("{BASE}/callback/true/oauth-proxy?callbackURL=http%3A%2F%2Fpreview.proxy-input.test%2Fapi%2Fauth").into()),
            "dynamic" => Some(format!("{BASE}/callback/provider ?#segment/oauth-proxy?callbackURL=%2Fcomplete%3Fx%3D1%26y%3D~").into()),
            _ => None,
        };
        let proxy = OAuthProxyPlugin::new()
            .current_url(ORIGIN.into())
            .production_url(PRODUCTION.into());
        let following = Following {
            body: body.clone(),
            expected: expected.clone(),
            dynamic: case == "dynamic",
            child,
            trace: trace.clone(),
            blocker: blocker.clone(),
        };
        let config = Arc::new(
            AuthConfig::new("oauth-proxy-native-input-secret-at-least-32-characters")
                .base_url(ORIGIN),
        );
        let store = Arc::new(EphemeralStore::new(config.clone()));
        let context =
            test_helpers::initialize_test_context(config, store.clone(), &[&proxy, &following])
                .await?;
        let route = AuthRoute::post("/sign-in/social", "socialSignIn");
        let dispatcher = EndpointDispatcher::new(
            Arc::new(vec![
                Box::new(proxy) as Box<dyn AuthPlugin<S>>,
                Box::new(following),
            ]),
            EndpointHooks {
                before: Some(Arc::new(CaptureRuntime(trace.clone()))),
                after: None,
            },
            [route.clone()],
        );
        let mut request = AuthRequest::new(HttpMethod::Post, "/sign-in/social");
        request.body = Some(b"original transport bytes".to_vec());
        request.set_endpoint_body(ValidatedBody::unvalidated_native(body.clone()));
        let observation = request.clone();
        let error = dispatcher
            .native(request, route, &context, |_, _| async {
                Err(AuthError::internal(
                    "The following hook must stop before endpoint validation",
                ))
            })
            .await
            .unwrap_err();
        let failed = matches!(
            case,
            "get-provider"
                | "get-callback"
                | "convert-provider"
                | "convert-callback"
                | "set-callback"
        );
        assert!(error.raw_value().unwrap().strict_equals(if failed {
            &sentinel
        } else {
            &blocker
        }));
        let reads = [
            "get:provider",
            "get:callbackURL",
            "toString:provider",
            "toString:callbackURL",
            "set:callbackURL",
        ];
        let end = match case {
            "get-provider" => 1,
            "get-callback" => 2,
            "convert-provider" => 3,
            "convert-callback" => 4,
            _ => 5,
        };
        let mut events = if failed || case == "dynamic" {
            reads[..end].to_vec()
        } else {
            Vec::new()
        };
        if !failed {
            events.push("following");
        }
        assert_eq!(*trace.events.lock().unwrap(), events, "{case}");
        let redirected = expected.is_some()
            || matches!(
                case,
                "convert-provider" | "convert-callback" | "set-callback"
            );
        assert_eq!(
            trace.runtime.lock().unwrap().as_ref().unwrap().base_url(),
            if redirected { PRODUCTION_BASE } else { BASE },
            "{case}"
        );
        assert_eq!(context.base_url(), BASE, "{case}: outer runtime");
        if case == "ordinary" {
            assert_eq!(
                body.as_object().unwrap().own_keys()?,
                ["provider", "callbackURL", "child", "absent"]
            );
            assert!(body.has_property("absent")?);
        }
        if failed {
            assert!(trace.written.lock().unwrap().is_none());
            assert!(observation.server_context(CALLBACK_CONTEXT)?.is_none());
        }
        for role in [
            EntityRole::User,
            EntityRole::Session,
            EntityRole::Account,
            EntityRole::Verification,
        ] {
            assert!(store.storage_rows(role)?.is_empty(), "{case}: {role:?}");
        }
    }
    Ok(())
}

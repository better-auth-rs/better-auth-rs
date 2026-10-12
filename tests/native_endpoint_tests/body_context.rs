//! Paired with contracts/native-body-context.test.ts; no input serialization is permitted between callbacks.

use super::*;
use better_auth::plugins::{
    AnonymousPlugin,
    anonymous::AnonymousCallbacks,
    api_key::{ApiKeyEndpoint, ApiKeyGetter, ApiKeyPlugin, ApiKeyValidator},
};
use better_auth::server_api::EndpointInput;
use better_auth_core::{
    AuthPlugin, AuthRoute, FieldDate, FieldFunction, FieldMap, FieldValue, HttpMethod,
    field_value::{
        FieldObject, FieldObjectSource, FieldProperty, FieldPropertyDefinition,
        FieldPropertyDescriptor,
    },
    store::{EphemeralStore, schema::EntityRole},
};
use std::collections::HashMap;

#[path = "body_context/api_key.rs"]
mod api_key;
#[path = "body_context/permissions.rs"]
mod permissions;

const PATH: &str = "/sign-in/anonymous";
const ORIGIN: &str = "http://native-body-context.test";

fn lock<T>(value: &Mutex<T>) -> AuthResult<std::sync::MutexGuard<'_, T>> {
    value
        .lock()
        .map_err(|_| AuthError::internal("Body context recorder lock poisoned"))
}

struct Unread(FieldObject);

impl Unread {
    fn new(fields: FieldMap) -> Self {
        let mut properties = fields
            .into_iter()
            .map(|(name, value)| (name, FieldPropertyDescriptor::data(value)))
            .collect::<indexmap::IndexMap<_, _>>();
        let _ = properties.insert(
            "unread".into(),
            FieldPropertyDescriptor {
                enumerable: true,
                configurable: true,
                property: FieldProperty::Accessor {
                    get: Some(FieldFunction::contextual(|_, _| {
                        Err(AuthError::internal("Body must not be enumerated"))
                    })),
                    set: None,
                },
            },
        );
        Self(properties.into())
    }
}

impl FieldObjectSource for Unread {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        self.0.own_keys()
    }

    fn own_property_descriptor(&self, name: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        self.0.own_property_descriptor(name)
    }

    fn get_with_receiver(
        &self,
        name: &str,
        receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        self.0.get_with_receiver(name, receiver)
    }

    fn set_with_receiver(
        &self,
        name: String,
        value: FieldValue,
        receiver: &FieldValue,
    ) -> AuthResult<bool> {
        self.0.set_with_receiver(&name, value, receiver)
    }

    fn define_own_property(
        &self,
        name: String,
        definition: FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        self.0.define_own_property(name, definition)
    }

    fn delete(&self, name: &str) -> AuthResult<bool> {
        self.0.delete(name)
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        self.own_keys()?
            .into_iter()
            .map(|name| {
                Ok((
                    name.clone(),
                    self.get_with_receiver(&name, &FieldValue::Undefined)?
                        .unwrap_or_default(),
                ))
            })
            .collect()
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self).addr()
    }
}

#[derive(Default)]
struct Observed {
    body: FieldValue,
    events: Vec<&'static str>,
}

#[derive(Clone)]
struct Contract {
    object: bool,
    http: bool,
    input: Option<Value>,
    raw: Option<Vec<u8>>,
    shared: FieldValue,
    date: FieldValue,
    failure: FieldValue,
    observed: Arc<Mutex<Observed>>,
}

impl Contract {
    fn new(input: Option<Value>, message: &str, http: bool) -> AuthResult<Self> {
        let date: FieldValue = FieldDate::from_milliseconds(1_893_456_000_000.0).into();
        let shared = FieldObject::from_source(Arc::new(Unread::new(FieldMap::from([
            ("ownUndefined".into(), FieldValue::Undefined),
            ("date".into(), date.clone()),
        ]))))
        .into();
        let failure = AuthError::from_status(
            "CONFLICT",
            FieldMap::from([("message".into(), message.into())]).into(),
        )
        .raw_value()
        .cloned()
        .ok_or_else(|| AuthError::internal("Body contract error must retain its native value"))?;
        Ok(Self {
            object: input.as_ref().is_some_and(Value::is_object),
            http,
            raw: input.as_ref().map(serde_json::to_vec).transpose()?,
            input,
            shared,
            date,
            failure,
            observed: Arc::default(),
        })
    }

    fn record(&self, event: &'static str) -> AuthResult<()> {
        lock(&self.observed)?.events.push(event);
        Ok(())
    }

    fn check(&self, body: &FieldValue, event: &'static str) -> AuthResult<()> {
        self.record(event)?;
        assert!(body.strict_equals(&lock(&self.observed)?.body));
        if self.object {
            assert_eq!(body.model_property("label")?, "changed".into());
            assert!(body.model_property("shared")?.strict_equals(&self.shared));
            assert!(body.model_property("alias")?.strict_equals(&self.shared));
            assert!(body.model_property("self")?.strict_equals(body));
            assert!(self.shared.model_property("ownUndefined")?.is_undefined());
            assert!(
                self.shared
                    .model_property("date")?
                    .strict_equals(&self.date)
            );
            assert!(
                self.shared
                    .as_object()
                    .ok_or_else(|| AuthError::internal("Shared body value is not an object"))?
                    .has_property("ownUndefined")?
            );
        } else {
            assert_eq!(body.json()?, self.input);
        }
        Ok(())
    }
}

#[async_trait]
impl BeforeEndpointHook<S> for Contract {
    async fn before(
        &self,
        request: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        if request.path() != PATH {
            return Ok(None);
        }
        self.record("before")?;
        let body = request.input_field_value()?;
        assert_eq!(request.body, self.raw);
        lock(&self.observed)?.body = body.clone();
        if self.object {
            let fields = body
                .as_object()
                .ok_or_else(|| AuthError::internal("Expected body object"))?;
            for (name, value) in [
                ("label", "changed".into()),
                ("shared", self.shared.clone()),
                ("alias", self.shared.clone()),
                ("self", body.clone()),
            ] {
                fields.set(name, value)?;
            }
        }
        Ok(None)
    }
}

#[async_trait]
impl AfterEndpointHook<S> for Contract {
    async fn after(
        &self,
        request: &AuthRequest,
        response: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<()> {
        if request.path() == PATH {
            self.check(&request.input_field_value()?, "after")?;
            assert!(response.body.field_value()?.strict_equals(&self.failure));
            assert!(request.new_session()?.is_none());
            assert_eq!(request.body, self.raw);
        }
        Ok(())
    }
}

#[async_trait]
impl AuthPlugin<S> for Contract {
    fn name(&self) -> &'static str {
        "body-observer"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    async fn before_request(
        &self,
        request: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        if request.path() == PATH {
            self.check(&request.input_field_value()?, "plugin-before")?;
        }
        Ok(None)
    }

    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

impl ApiKeyGetter for Contract {
    fn get(&self, endpoint: ApiKeyEndpoint<'_>) -> AuthResult<Option<String>> {
        self.check(endpoint.body, "key-getter")?;
        assert_eq!(endpoint.request.is_some(), self.http);
        Ok(Some("x".repeat(64)))
    }
}

#[async_trait]
impl ApiKeyValidator for Contract {
    async fn validate(&self, _: &str, endpoint: ApiKeyEndpoint<'_>) -> AuthResult<bool> {
        self.check(endpoint.body, "key-validator")?;
        assert_eq!(endpoint.request.is_some(), self.http);
        Err(AuthError::from_thrown(self.failure.clone()))
    }
}

macro_rules! body_case {
    ($name:ident, $input:expr, $http:literal, $api_key:literal) => {
        #[tokio::test]
        async fn $name() -> AuthResult<()> {
            check($input, $http, $api_key).await
        }
    };
}

body_case!(native_anonymous_missing, None, false, false);
body_case!(native_anonymous_null, Some(Value::Null), false, false);
body_case!(native_anonymous_false, Some(json!(false)), false, false);
body_case!(native_anonymous_number, Some(json!(7)), false, false);
body_case!(native_anonymous_array, Some(json!([1, 2])), false, false);
body_case!(
    native_anonymous_object,
    Some(json!({"label": "original"})),
    false,
    false
);
body_case!(native_api_key_missing, None, false, true);
body_case!(native_api_key_null, Some(Value::Null), false, true);
body_case!(native_api_key_false, Some(json!(false)), false, true);
body_case!(native_api_key_number, Some(json!(7)), false, true);
body_case!(native_api_key_array, Some(json!([1, 2])), false, true);
body_case!(
    native_api_key_object,
    Some(json!({"label": "original"})),
    false,
    true
);
body_case!(http_anonymous_missing, None, true, false);
body_case!(http_anonymous_null, Some(Value::Null), true, false);
body_case!(http_anonymous_false, Some(json!(false)), true, false);
body_case!(http_anonymous_number, Some(json!(7)), true, false);
body_case!(http_anonymous_array, Some(json!([1, 2])), true, false);
body_case!(
    http_anonymous_object,
    Some(json!({"label": "original"})),
    true,
    false
);
body_case!(http_api_key_missing, None, true, true);
body_case!(http_api_key_null, Some(Value::Null), true, true);
body_case!(http_api_key_false, Some(json!(false)), true, true);
body_case!(http_api_key_number, Some(json!(7)), true, true);
body_case!(http_api_key_array, Some(json!([1, 2])), true, true);
body_case!(
    http_api_key_object,
    Some(json!({"label": "original"})),
    true,
    true
);

async fn check(input: Option<Value>, http: bool, api_key: bool) -> AuthResult<()> {
    let contract = Contract::new(input.clone(), "body observed", http)?;
    let mut config = AuthConfig::new("native-body-context-secret-at-least-32-characters");
    config.base_url = ORIGIN.into();
    {
        let better_auth_core::LoggerSource::Config(logger_options) = &mut config.logger else {
            return Err(AuthError::internal(
                "fixture requires authored logger options",
            ));
        };
        logger_options.disabled = Some(true);
    }
    let store = Arc::new(EphemeralStore::new(Arc::new(config.clone())));
    let mut builder = BetterAuth::new(config)
        .store_arc(store.clone())
        .hooks(EndpointHooks {
            before: Some(Arc::new(contract.clone())),
            after: Some(Arc::new(contract.clone())),
        })
        .plugin(contract.clone());
    if api_key {
        builder = builder.plugin(
            ApiKeyPlugin::builder()
                .enable_session_for_api_keys(true)
                .custom_api_key_getter(Arc::new(contract.clone()))
                .custom_api_key_validator(Arc::new(contract.clone()))
                .build(),
        );
    }
    let email = contract.clone();
    let name = contract.clone();
    let auth = builder
        .plugin(
            AnonymousPlugin::new()
                .generate_random_email(move || {
                    let contract = email.clone();
                    async move {
                        contract.record("email")?;
                        Ok("body@anonymous.test".into())
                    }
                })
                .callbacks(
                    AnonymousCallbacks::<S>::default().generate_name(move |endpoint| {
                        let contract = name.clone();
                        Box::pin(async move {
                            contract.check(&endpoint.body, "name")?;
                            assert_eq!(endpoint.request.is_some(), contract.http);
                            Err(AuthError::from_thrown(contract.failure.clone()))
                        })
                    }),
                ),
        )
        .build()
        .await?;
    let result =
        if http {
            auth.handle_request(
                AuthRequest::from_parts(
                    HttpMethod::Post,
                    format!("/api/auth{PATH}"),
                    HashMap::from([("content-type".into(), "application/json".into())]),
                    contract.raw.clone(),
                    None,
                )
                .with_url(format!("{ORIGIN}/api/auth{PATH}").parse().map_err(
                    |error| AuthError::internal(format!("Invalid body contract URL: {error}")),
                )?),
            )
            .await
        } else {
            auth.call_endpoint(
                HttpMethod::Post,
                PATH,
                EndpointInput {
                    body: input,
                    ..Default::default()
                },
            )
            .await
        };
    if let Some(fields) = lock(&contract.observed)?.body.as_object() {
        let _ = fields.delete("self")?;
    }
    if http {
        let response = result?;
        assert_eq!(response.status, 409);
        assert!(!response.headers.contains_key("set-cookie"));
        assert_eq!(
            response.body.bytes()?.as_ref(),
            br#"{"message":"body observed"}"#
        );
    } else {
        let error = result
            .err()
            .ok_or_else(|| AuthError::internal("Body callback must reject"))?;
        assert!(
            error
                .raw_value()
                .is_some_and(|value| value.strict_equals(&contract.failure))
        );
    }
    assert_eq!(
        lock(&contract.observed)?.events,
        if api_key {
            vec![
                "before",
                "plugin-before",
                "key-getter",
                "key-getter",
                "key-validator",
            ]
        } else {
            vec!["before", "plugin-before", "email", "name", "after"]
        }
    );
    for role in [
        EntityRole::User,
        EntityRole::Session,
        EntityRole::Account,
        EntityRole::Verification,
        EntityRole::ApiKey,
    ] {
        assert!(store.storage_rows(role)?.is_empty());
    }
    Ok(())
}

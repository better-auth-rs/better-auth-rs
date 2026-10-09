#![expect(
    clippy::unwrap_used,
    reason = "Contract fixtures fail immediately when setup or response decoding fails"
)]

use async_trait::async_trait;
use better_auth::plugins::organization::{
    OrganizationConfig, OrganizationPlugin, OrganizationTeamsConfig,
};
use better_auth::plugins::{
    CustomSessionCallback, CustomSessionInput, CustomSessionPlugin, MultiSessionPlugin,
    SessionManagementPlugin,
};
use better_auth::{AuthConfig, AuthError, AuthResult, BetterAuth};
use better_auth_core::config::CookieCacheConfig;
use better_auth_core::observability::{AfterEndpointHook, EndpointHooks};
use better_auth_core::store::{EphemeralStore, StatelessSchema};
use better_auth_core::user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform};
use better_auth_core::utils::cookie_utils::sign_cookie_value;
use better_auth_core::{
    AuthContext, AuthRequest, AuthResponse, CreateUser, FieldDate, FieldMap, FieldValue,
    HttpMethod, UserView,
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

const SECRET: &str = "custom-session-native-fields-secret-at-least-32-characters";
const LIST_PATH: &str = "/multi-session/list-device-sessions";

enum Event {
    After,
    Customize { path: String, user: Box<UserView> },
}

type Trace = Arc<Mutex<Vec<Event>>>;

#[derive(Clone)]
struct Capture(Trace);

#[async_trait]
impl CustomSessionCallback<StatelessSchema> for Capture {
    async fn customize(
        &self,
        mut input: CustomSessionInput,
        request: &AuthRequest,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Value> {
        self.0
            .lock()
            .map_err(|_| AuthError::internal("Custom session trace lock poisoned"))?
            .push(Event::Customize {
                path: request.path().into(),
                user: Box::new(input.data.user.clone()),
            });
        request.set_response_header("x-custom-session", "observed")?;
        // This callback selects JSON output, whose Rust value cannot represent a lone surrogate.
        let _ = input.data.user.additional_fields.remove("loneSurrogate");
        Ok(serde_json::to_value(input)?)
    }
}

struct AfterHook {
    trace: Trace,
    replace_list: bool,
}

#[async_trait]
impl AfterEndpointHook<StatelessSchema> for AfterHook {
    async fn after(
        &self,
        request: &AuthRequest,
        response: &mut AuthResponse,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<()> {
        self.trace
            .lock()
            .map_err(|_| AuthError::internal("Custom session trace lock poisoned"))?
            .push(Event::After);
        let _ = response.headers.insert("x-after-hook", "observed");
        if self.replace_list && request.path() == LIST_PATH {
            let FieldValue::Array(mut sessions) = response.body.field_value()? else {
                return Err(AuthError::internal(
                    "Expected a device session list to replace",
                ));
            };
            let Some(FieldValue::Object(session)) = Arc::make_mut(&mut sessions).first_mut() else {
                return Err(AuthError::internal("Expected a device session to replace"));
            };
            let Some(FieldValue::Object(user)) = Arc::make_mut(session).get_mut("user") else {
                return Err(AuthError::internal(
                    "Expected a device session user to replace",
                ));
            };
            let _ = Arc::make_mut(user).remove("loneSurrogate");
            let mut value = FieldValue::Array(sessions)
                .json()?
                .ok_or_else(|| AuthError::internal("Expected a JSON session list"))?;
            let user = value
                .as_array_mut()
                .and_then(|sessions| sessions.first_mut())
                .and_then(|session| session.get_mut("user"))
                .and_then(Value::as_object_mut)
                .ok_or_else(|| AuthError::internal("Expected a device session to replace"))?;
            let _ = user.insert("name".into(), "After hook".into());
            let _ = user.insert("replacement".into(), true.into());
            response.replace_returned(AuthResponse::json(200, &value)?);
        }
        Ok(())
    }
}

struct Fixture {
    auth: BetterAuth<StatelessSchema>,
    cookies: String,
    trace: Trace,
    date: FieldValue,
    shared: FieldValue,
}

impl Fixture {
    async fn new(replace_list: bool) -> AuthResult<Self> {
        let date = FieldValue::from(FieldDate::from_milliseconds(1_735_689_600_123.0));
        let shared = FieldValue::from(FieldMap::from([("marker".into(), "shared".into())]));
        let mut config = AuthConfig::new(SECRET)
            .base_url("http://custom-session.test")
            .session_update_age(chrono::Duration::zero());
        config.session.store_session_in_database = Some(true);
        config.session.cookie_cache = Some(CookieCacheConfig {
            enabled: Some(false),
            ..Default::default()
        });
        let mut input = CreateUser::new()
            .with_email("custom-session@example.test")
            .with_name("Stored user");
        for (name, output) in [
            ("nativeDate", date.clone()),
            ("ownUndefined", FieldValue::Undefined),
            ("left", shared.clone()),
            ("right", shared.clone()),
            (
                "loneSurrogate",
                better_auth_core::Utf16String::from_units(vec![0xd800]).into(),
            ),
        ] {
            let _ = config.user.fields_mut().insert(
                name.into(),
                UserFieldConfig {
                    transform: Some(FieldTransforms {
                        output: Some(UserFieldTransform::new(move |_| Ok(output.clone()))),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            );
            let _ = input.additional_fields.insert(name.into(), "stored".into());
        }
        let trace = Trace::default();
        let auth = BetterAuth::<StatelessSchema>::new(config.clone())
            .store(EphemeralStore::new(Arc::new(config)))
            .hooks(EndpointHooks {
                before: None,
                after: Some(Arc::new(AfterHook {
                    trace: trace.clone(),
                    replace_list,
                })),
            })
            .plugin(SessionManagementPlugin::new())
            .plugin(MultiSessionPlugin::new())
            .plugin(OrganizationPlugin::with_config(OrganizationConfig {
                teams: OrganizationTeamsConfig {
                    enabled: true,
                    ..Default::default()
                },
                ..Default::default()
            }))
            .plugin(
                CustomSessionPlugin::new(Capture(trace.clone())).mutate_list_device_sessions(true),
            )
            .build()
            .await?;
        let user = auth.store().create_user(input).await?;
        let session = auth
            .session_manager()
            .create_session(&user, None, None)
            .await?;
        let signed = sign_cookie_value(session.token.typed().unwrap(), SECRET);
        let cookies = format!(
            "better-auth.session_token={signed}; better-auth.session_token_multi-{}={signed}",
            session.token.typed()?.to_lowercase(),
        );
        Ok(Self {
            auth,
            cookies,
            trace,
            date,
            shared,
        })
    }

    async fn request(&self, path: &str) -> AuthResult<AuthResponse> {
        let mut request = AuthRequest::new(HttpMethod::Get, path);
        let _ = request
            .headers
            .insert("cookie".into(), self.cookies.clone());
        self.auth.handle_request(request).await
    }

    fn take_events(&self) -> AuthResult<Vec<Event>> {
        Ok(std::mem::take(&mut *self.trace.lock().map_err(|_| {
            AuthError::internal("Custom session trace lock poisoned")
        })?))
    }
}

async fn check_native_fields(path: &str) {
    let fixture = Fixture::new(false).await.unwrap();
    let response = fixture.request(path).await.unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(
        response.headers.get("x-custom-session").map(String::as_str),
        Some("observed")
    );
    assert_eq!(
        response.headers.get("x-after-hook").map(String::as_str),
        Some("observed")
    );
    let events = fixture.take_events().unwrap();
    let phases = events
        .iter()
        .map(|event| match event {
            Event::After => "after",
            Event::Customize { .. } => "customize",
        })
        .collect::<Vec<_>>();
    assert_eq!(
        phases,
        if path == LIST_PATH {
            vec!["after", "customize"]
        } else {
            vec!["customize", "after"]
        }
    );
    let (callback_path, user) = events
        .iter()
        .find_map(|event| match event {
            Event::Customize { path, user } => Some((path, user)),
            Event::After => None,
        })
        .unwrap();
    assert_eq!(callback_path, path);
    let fields = &user.additional_fields;
    assert!(matches!(
        fields.get("nativeDate"),
        Some(FieldValue::Date(_))
    ));
    let date = fields.get("nativeDate").unwrap();
    assert_eq!(date, &fixture.date);
    assert_eq!(date.strict_equals(&fixture.date), path == LIST_PATH);
    assert!(fields.contains_key("ownUndefined"));
    assert!(matches!(
        fields.get("ownUndefined"),
        Some(FieldValue::Undefined)
    ));
    assert!(
        matches!(fields.get("loneSurrogate"), Some(FieldValue::Utf16String(value)) if value.as_utf16() == [0xd800])
    );
    let left = fields.get("left").unwrap();
    let right = fields.get("right").unwrap();
    assert_eq!(left, &fixture.shared);
    assert_eq!(right, &fixture.shared);
    assert!(left.strict_equals(right));
    assert_eq!(left.strict_equals(&fixture.shared), path == LIST_PATH);

    let body: Value = serde_json::from_slice(response.body.bytes().unwrap().as_ref()).unwrap();
    let data = if path == LIST_PATH {
        body.as_array()
            .and_then(|sessions| sessions.first())
            .unwrap()
    } else {
        assert_eq!(
            response.headers.get("cache-control").map(String::as_str),
            Some("no-store")
        );
        assert!(
            response
                .headers
                .get_all("set-cookie")
                .any(|value| value.starts_with("better-auth.session_token="))
        );
        &body
    };
    let user = data.get("user").unwrap();
    assert_eq!(
        user.get("nativeDate"),
        Some(&json!("2025-01-01T00:00:00.123Z"))
    );
    assert!(user.get("ownUndefined").is_none());
    assert_eq!(user.get("left"), Some(&json!({"marker":"shared"})));
    assert_eq!(user.get("right"), user.get("left"));
}

#[tokio::test]
async fn get_session_preserves_native_fields_until_custom_callback() {
    check_native_fields("/get-session").await
}

#[tokio::test]
async fn list_device_sessions_preserves_native_fields_until_custom_callback() {
    check_native_fields(LIST_PATH).await
}

#[tokio::test]
async fn list_custom_callback_observes_global_after_hook_replacement() {
    let fixture = Fixture::new(true).await.unwrap();
    let response = fixture.request(LIST_PATH).await.unwrap();
    assert_eq!(response.status, 200);
    let events = fixture.take_events().unwrap();
    assert!(matches!(
        events.as_slice(),
        [Event::After, Event::Customize { .. }]
    ));
    let (path, user) = events
        .iter()
        .find_map(|event| match event {
            Event::Customize { path, user } => Some((path, user)),
            Event::After => None,
        })
        .unwrap();
    assert_eq!(path, LIST_PATH);
    assert_eq!(user.name.typed().unwrap().as_deref(), Some("After hook"));
    assert_eq!(
        user.additional_fields.get("replacement"),
        Some(&FieldValue::Bool(true))
    );
    let body: Value = serde_json::from_slice(response.body.bytes().unwrap().as_ref()).unwrap();
    let user = body
        .as_array()
        .and_then(|sessions| sessions.first())
        .and_then(|session| session.get("user"))
        .unwrap();
    assert_eq!(user.get("name"), Some(&json!("After hook")));
    assert_eq!(user.get("replacement"), Some(&Value::Bool(true)));
}

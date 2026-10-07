use better_auth::{AuthConfig, BetterAuth, plugins::DeviceAuthorizationPlugin};
use better_auth_api::plugins::device_authorization::{
    DeviceFieldValidation, DeviceRequestField, DeviceRequestFields, DeviceRequestIssue,
};
use better_auth_core::{
    AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
    AuthRoute, AuthSchema, HttpMethod,
    hooks::current_request_hook_context,
    middleware::RateLimitConfig,
    store::{EphemeralStore, StatelessSchema, schema::EntityRole},
    user_fields::{UserConfig, UserFieldConfig},
};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::sync::{Arc, mpsc};

const ORIGIN: &str = "http://device-request-fields.test";
const DEVICE_CODE: &str = "ordinary-request-device";
const USER_CODE: &str = "ABCD2345";

#[derive(Clone, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Input {
    name: String,
    encoding: String,
    translate_error: bool,
    request_body: String,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SyncObservation {
    input: Value,
    status: u16,
    headers: Vec<(String, String)>,
    body: Value,
    requests: Vec<Value>,
    original_bodies: Vec<String>,
    issues: Vec<Value>,
    transforms: Vec<String>,
    hook_inputs: Vec<Value>,
    stored: Option<StoredObservation>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredObservation {
    client_id: String,
    scope: String,
    status: String,
    polling_interval: f64,
    label: String,
}

enum Event {
    Request(Value),
    OriginalBody(String),
    Issues(Value),
    Transform(&'static str),
    Hook(Value),
}

fn record(sender: &mpsc::Sender<Event>, event: Event) -> AuthResult<()> {
    sender
        .send(event)
        .map_err(|error| AuthError::internal(format!("Record Device observation: {error}")))
}

fn invalid_string(value: Option<&Value>) -> DeviceFieldValidation {
    let received = match value {
        None => "undefined",
        Some(Value::Null) => "null",
        Some(Value::Bool(_)) => "boolean",
        Some(Value::Number(_)) => "number",
        Some(Value::String(_)) => "string",
        Some(Value::Array(_)) => "array",
        Some(Value::Object(_)) => "object",
    };
    DeviceFieldValidation::Issues(vec![DeviceRequestIssue {
        message: format!("Invalid input: expected string, received {received}"),
        path: Vec::new(),
        details: Map::from_iter([
            ("code".into(), json!("invalid_type")),
            ("expected".into(), json!("string")),
        ]),
    }])
}

fn fields(
    sender: &mpsc::Sender<Event>,
    asynchronous: bool,
    translate: bool,
) -> AuthResult<DeviceRequestFields> {
    let label_sender = sender.clone();
    let label = if asynchronous {
        DeviceRequestField::new_async(move |value| {
            let sender = label_sender.clone();
            async move {
                let Some(Value::String(value)) = value else {
                    return Ok(invalid_string(value.as_ref()));
                };
                record(&sender, Event::Transform("label:start"))?;
                tokio::task::yield_now().await;
                record(&sender, Event::Transform("label:resolved"))?;
                let value = value.trim();
                Ok(if value.is_empty() {
                    DeviceFieldValidation::Issues(vec![DeviceRequestIssue {
                        message: "Display label is required".into(),
                        path: Vec::new(),
                        details: Map::from_iter([("code".into(), json!("custom"))]),
                    }])
                } else {
                    DeviceFieldValidation::Value(Some(json!(value)))
                })
            }
        })
    } else {
        DeviceRequestField::new(move |value| {
            let Some(Value::String(value)) = value else {
                return Ok(invalid_string(value.as_ref()));
            };
            record(&label_sender, Event::Transform("label"))?;
            Ok(DeviceFieldValidation::Value(Some(json!(value.trim()))))
        })
    };
    let issue_sender = sender.clone();
    Ok(DeviceRequestFields::new()
        .field("label", label)?
        .field(
            "note",
            DeviceRequestField::new(|value| {
                Ok(match value {
                    None | Some(Value::String(_)) => DeviceFieldValidation::Value(value),
                    _ => invalid_string(value.as_ref()),
                })
            }),
        )?
        .on_validation_error(move |issues| {
            record(&issue_sender, Event::Issues(serde_json::to_value(issues)?))?;
            if translate {
                return Err(AuthResponse::json(
                    400,
                    &json!({
                        "error":"invalid_request", "error_description":"Display fields need review",
                    }),
                )?
                .into());
            }
            Ok(())
        }))
}

struct StoredDisplay;

#[async_trait::async_trait]
impl<S: AuthSchema> AuthPlugin<S> for StoredDisplay {
    fn name(&self) -> &'static str {
        "ordinary-device-request-stored-display"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        context.register_model_fields(
            EntityRole::DeviceCode,
            UserConfig {
                additional_fields: Some(
                    [(
                        "label".into(),
                        UserFieldConfig {
                            required: Some(false),
                            default_value: Some("Stored display".into()),
                            ..Default::default()
                        },
                    )]
                    .into(),
                ),
            },
        )
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

async fn observe(input: Input, asynchronous: bool) -> AuthResult<Value> {
    let (sender, receiver) = mpsc::channel();
    let callback_sender = sender.clone();
    let plugin =
        DeviceAuthorizationPlugin::new()
            .request_fields(fields(&sender, asynchronous, input.translate_error)?)
            .generate_device_code_with(|| async { Ok(DEVICE_CODE.into()) })
            .generate_user_code_with(|| async { Ok(USER_CODE.into()) })
            .validate_client(|client| async move { Ok(client == "ordinary-client") })
            .on_device_auth_request(move |client_id, scope| {
                let sender = callback_sender.clone();
                async move {
                    let context = current_request_hook_context().ok_or_else(|| {
                        AuthError::internal("Device callback request context is missing")
                    })?;
                    let original = context.request.original_request().ok_or_else(|| {
                        AuthError::internal("Device HTTP original request is missing")
                    })?;
                    let bytes = original.body.as_deref().ok_or_else(|| {
                        AuthError::internal("Device HTTP original body is missing")
                    })?;
                    let original_body = std::str::from_utf8(bytes).map_err(|error| {
                        AuthError::internal(format!("Read original Device body: {error}"))
                    })?;
                    record(&sender, Event::OriginalBody(original_body.into()))?;
                    let body = context.body.json()?.ok_or_else(|| {
                        AuthError::internal("Device callback projection is missing")
                    })?;
                    record(&sender, Event::Request(body))?;
                    record(
                        &sender,
                        Event::Hook(json!({"clientId":client_id,"scope":scope})),
                    )
                }
            });
    let mut config =
        AuthConfig::new("ordinary-device-request-fields-secret-at-least-32-characters")
            .base_url(ORIGIN);
    config.logger.disabled = Some(true);
    let store = EphemeralStore::new(Arc::new(config.clone()));
    let auth = BetterAuth::<StatelessSchema>::new(config)
        .store(store)
        .rate_limit(RateLimitConfig::new().enabled(false))
        .plugin(plugin)
        .plugin(StoredDisplay)
        .build()
        .await?;
    let content_type = match input.encoding.as_str() {
        "json" => "application/json",
        "form" => "application/x-www-form-urlencoded",
        value => {
            return Err(AuthError::internal(format!(
                "Unknown fixture encoding: {value}"
            )));
        }
    };
    let response = auth
        .handle_request(AuthRequest::from_parts(
            HttpMethod::Post,
            "/api/auth/device/code".into(),
            [
                ("origin".into(), ORIGIN.into()),
                ("accept".into(), "application/json".into()),
                ("content-type".into(), content_type.into()),
            ]
            .into(),
            Some(input.request_body.as_bytes().to_vec()),
            None,
        ))
        .await?;
    let mut headers: Vec<_> = response
        .headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
        .collect();
    headers.sort();
    let body: Value = serde_json::from_slice(&response.body.bytes()?)?;
    let stored = match auth
        .store()
        .get_device_code_by_device_code(DEVICE_CODE)
        .await?
    {
        Some(row) => json!({
            "clientId": row.client_id.json()?, "scope": row.scope.json()?, "status": row.status,
            "pollingInterval":row.polling_interval, "label":row.additional_fields.json()?.get("label"),
        }),
        None => Value::Null,
    };
    let mut requests = Vec::new();
    let mut original_bodies = Vec::new();
    let mut issues = Vec::new();
    let mut transforms = Vec::new();
    let mut hook_inputs = Vec::new();
    for event in receiver.try_iter() {
        match event {
            Event::Request(value) => requests.push(value),
            Event::OriginalBody(value) => original_bodies.push(value),
            Event::Issues(value) => issues.push(value),
            Event::Transform(value) => transforms.push(value),
            Event::Hook(value) => hook_inputs.push(value),
        }
    }
    Ok(
        json!({"input":input,"status":response.status,"headers":headers,"body":body,
        "requests":requests,"originalBodies":original_bodies,"issues":issues,"transforms":transforms,"hookInputs":hook_inputs,"stored":stored}),
    )
}

fn same<T: std::fmt::Debug + PartialEq>(actual: &T, expected: &T, name: &str) -> AuthResult<()> {
    if actual != expected {
        return Err(AuthError::internal(format!(
            "Device contract {name}: actual {actual:?}; expected {expected:?}"
        )));
    }
    Ok(())
}

fn fixture() -> AuthResult<Value> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/device-request-validation-1.7.6.json");
    let content = std::fs::read_to_string(path)
        .map_err(|error| AuthError::internal(format!("Read Device fixture: {error}")))?;
    let fixture: Value = serde_json::from_str(&content)?;
    same(
        fixture
            .get("version")
            .ok_or_else(|| AuthError::internal("Missing fixture version"))?,
        &json!("1.7.6"),
        "version",
    )?;
    Ok(fixture)
}

fn rows<'a>(fixture: &'a Value, name: &str) -> AuthResult<&'a Vec<Value>> {
    fixture
        .get(name)
        .and_then(Value::as_array)
        .ok_or_else(|| AuthError::internal(format!("Missing fixture {name}")))
}

#[tokio::test]
async fn synchronous_device_display_fields_match_pinned_endpoint_contract() -> AuthResult<()> {
    let fixture = fixture()?;
    for expected in rows(&fixture, "syncCases")? {
        let input: Input = serde_json::from_value(
            expected
                .get("input")
                .cloned()
                .ok_or_else(|| AuthError::internal("Missing sync input"))?,
        )?;
        let name = input.name.clone();
        let actual: SyncObservation = serde_json::from_value(observe(input, false).await?)?;
        let expected: SyncObservation = serde_json::from_value(expected.clone())?;
        same(&actual, &expected, &name)?;
    }
    Ok(())
}

#[tokio::test]
async fn asynchronous_device_display_fields_match_pinned_schema_results() -> AuthResult<()> {
    let fixture = fixture()?;
    for expected in rows(&fixture, "asyncCases")? {
        let name = expected
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| AuthError::internal("Missing async case name"))?;
        let body = expected
            .get("input")
            .ok_or_else(|| AuthError::internal("Missing async input"))?;
        let observed = observe(
            Input {
                name: name.into(),
                encoding: "json".into(),
                translate_error: false,
                request_body: serde_json::to_string(body)?,
            },
            true,
        )
        .await?;
        let result = expected
            .get("result")
            .ok_or_else(|| AuthError::internal("Missing async schema result"))?;
        let actual = if result.get("value").is_some() {
            same(
                observed
                    .get("status")
                    .ok_or_else(|| AuthError::internal("Missing endpoint status"))?,
                &json!(200),
                name,
            )?;
            let requests = rows(&observed, "requests")?;
            let [request] = requests.as_slice() else {
                return Err(AuthError::internal(
                    "Async endpoint must expose one parsed request",
                ));
            };
            json!({"value":request})
        } else {
            same(
                observed
                    .get("status")
                    .ok_or_else(|| AuthError::internal("Missing endpoint status"))?,
                &json!(400),
                name,
            )?;
            let issues = rows(&observed, "issues")?;
            let [issues] = issues.as_slice() else {
                return Err(AuthError::internal(
                    "Async endpoint must report one issue collection",
                ));
            };
            json!({"issues":issues})
        };
        same(&actual, result, name)?;
        same(
            observed
                .get("transforms")
                .ok_or_else(|| AuthError::internal("Missing async observations"))?,
            &json!(["label:start", "label:resolved"]),
            name,
        )?;
    }
    Ok(())
}

use super::contract_chrono as chrono;
use better_auth::__private_core::{
    AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema, AuthSession, AuthStore, AuthUser,
    CreateUser, DeviceCode, FieldMap, HttpMethod, UserView,
    middleware::RateLimitConfig,
    user_fields::{UserConfig, UserFieldConfig},
};
use better_auth::plugins::device_authorization::{
    DeviceFieldValidation, DeviceGrant, DeviceGrantAuthorization, DeviceRequestField,
    DeviceRequestFields,
};
use better_auth::{
    AuthConfig, BetterAuth, plugins::DeviceAuthorizationPlugin, server_api::EndpointInput,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, mpsc},
};

const ORIGIN: &str = "http://device-grant.test";
const SECRET: &str = "ordinary-device-grant-secret-at-least-32-characters";
pub(crate) const DEVICE_CODE: &str = "ordinary-grant-device";
pub(crate) const USER_CODE: &str = "ABCD2345";
const SESSION_LIFETIME: i64 = 600;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Mode {
    Authorized,
    Fallback,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Transport {
    Http,
    Native,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum Failure {
    AuthorizeRequest,
    GetVerificationContext,
    AssertSessionRedemption,
}

impl Failure {
    pub(crate) fn phase(self) -> &'static str {
        match self {
            Self::AuthorizeRequest => "authorizeRequest",
            Self::GetVerificationContext => "getVerificationContext",
            Self::AssertSessionRedemption => "assertSessionRedemption",
        }
    }

    fn reject(self) -> AuthError {
        AuthError::internal(format!("ordinary {} failure", self.phase()))
    }
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    mode: Mode,
    pub(crate) transport: Transport,
    pub(crate) body: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) failure: Option<Failure>,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Response {
    pub(crate) status: u16,
    headers: Vec<(String, String)>,
    body: Value,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Row {
    client_id: String,
    scope: String,
    status: String,
    // JSON.stringify emits integral JavaScript numbers without a fractional suffix.
    polling_interval: f64,
    label: String,
    has_owner: bool,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(tag = "phase", deny_unknown_fields)]
enum Event {
    #[serde(rename = "authorizeRequest")]
    AuthorizeRequest {
        request: Value,
        #[serde(rename = "hasRequest")]
        has_request: bool,
        #[serde(rename = "originalBody")]
        original_body: Value,
    },
    #[serde(rename = "validateClient")]
    ValidateClient {
        #[serde(rename = "clientId")]
        client_id: String,
    },
    #[serde(rename = "onDeviceAuthRequest")]
    OnDeviceAuthRequest {
        #[serde(rename = "clientId")]
        client_id: String,
        scope: String,
    },
    #[serde(rename = "getVerificationContext")]
    GetVerificationContext { row: Row },
    #[serde(rename = "assertSessionRedemption")]
    AssertSessionRedemption { row: Row },
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Observation {
    input: Input,
    issuance: Response,
    issued: Row,
    verification: Response,
    claimed: Row,
    approval: Response,
    approved: Row,
    redemption: Response,
    events: Vec<Event>,
    consumed: bool,
}

fn field<'a>(value: &'a Value, name: &str) -> AuthResult<&'a Value> {
    value
        .get(name)
        .ok_or_else(|| AuthError::internal(format!("Missing Device grant field {name}")))
}

fn same<T: std::fmt::Debug + PartialEq>(actual: &T, expected: &T, label: &str) -> AuthResult<()> {
    if actual != expected {
        return Err(AuthError::internal(format!(
            "Device grant {label}: actual {actual:?}; expected {expected:?}"
        )));
    }
    Ok(())
}

fn record(sender: &mpsc::Sender<Value>, event: Value) -> AuthResult<()> {
    sender
        .send(event)
        .map_err(|error| AuthError::internal(format!("Record Device grant event: {error}")))
}

fn observe_row(row: &DeviceCode) -> AuthResult<Value> {
    Ok(json!({
        "clientId": row.client_id.json()?, "scope": row.scope.json()?, "status": row.status,
        "pollingInterval": row.polling_interval, "label": row.additional_fields.json()?.get("label"),
        "hasOwner": row.user_id.is_some(),
    }))
}

pub(crate) async fn stored<S: AuthSchema>(auth: &BetterAuth<S>) -> AuthResult<Value> {
    let row = auth
        .store()
        .get_device_code_by_device_code(DEVICE_CODE)
        .await?
        .ok_or_else(|| AuthError::internal("The ordinary issued Device record is missing"))?;
    observe_row(&row)
}

pub(crate) async fn request<S: AuthSchema>(
    auth: &BetterAuth<S>,
    transport: Transport,
    method: HttpMethod,
    path: &str,
    body: Option<Value>,
    query: Option<Value>,
    cookie: Option<&str>,
) -> AuthResult<AuthResponse> {
    let mut headers = HashMap::new();
    if let Some(cookie) = cookie {
        let _ = headers.insert("cookie".into(), cookie.into());
    }
    let response = match transport {
        Transport::Native => {
            auth.call_endpoint(
                method,
                path,
                EndpointInput {
                    body,
                    query,
                    headers: Some(headers),
                    ..Default::default()
                },
            )
            .await?
        }
        Transport::Http => {
            let _ = headers.insert("origin".into(), ORIGIN.into());
            let _ = headers.insert("accept".into(), "application/json".into());
            if body.is_some() {
                let _ = headers.insert("content-type".into(), "application/json".into());
            }
            auth.handle_request(AuthRequest::from_parts(
                method,
                format!("/api/auth{path}"),
                headers,
                body.map(|body| serde_json::to_vec(&body)).transpose()?,
                query,
            ))
            .await?
        }
    };
    Ok(response)
}

pub(crate) async fn call<S: AuthSchema>(
    auth: &BetterAuth<S>,
    transport: Transport,
    method: HttpMethod,
    path: &str,
    body: Option<Value>,
    query: Option<Value>,
    cookie: Option<&str>,
) -> AuthResult<Response> {
    response_value(request(auth, transport, method, path, body, query, cookie).await?)
}

fn response_value(response: AuthResponse) -> AuthResult<Response> {
    let mut headers: Vec<_> = response
        .headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
        .collect();
    headers.sort();
    Ok(Response {
        status: response.status,
        headers,
        body: serde_json::from_slice(&response.body.bytes()?)?,
    })
}

pub(crate) struct Fixture<S: AuthSchema> {
    pub(crate) auth: BetterAuth<S>,
    pub(crate) owner: UserView,
    pub(crate) cookie: String,
    pub(crate) events: mpsc::Receiver<Value>,
}

pub(crate) async fn setup<S: AuthSchema>(
    input: &Input,
    raw: Arc<dyn AuthStore<S>>,
) -> AuthResult<Fixture<S>> {
    let (sender, receiver) = mpsc::channel();
    let authorize_events = sender.clone();
    let policy_events = sender.clone();
    let verification_events = sender.clone();
    let mode = input.mode;
    let failure = input.failure;
    let grant =
        DeviceGrant::<S>::new(
            move |request, endpoint| {
                let sender = authorize_events.clone();
                Box::pin(async move {
                    let original_body = endpoint
                        .request
                        .and_then(|request| request.body.as_deref())
                        .map(std::str::from_utf8)
                        .transpose()
                        .map_err(|error| {
                            AuthError::internal(format!("Read original Device body: {error}"))
                        })?;
                    record(
                        &sender,
                        json!({
                            "phase": "authorizeRequest", "request": request,
                            "hasRequest": endpoint.request.is_some(), "originalBody": original_body,
                        }),
                    )?;
                    if failure == Some(Failure::AuthorizeRequest) {
                        return Err(Failure::AuthorizeRequest.reject());
                    }
                    match mode {
                        Mode::Fallback => Ok(None),
                        Mode::Authorized => Ok(Some(DeviceGrantAuthorization {
                            client_id: "ordinary-grant-client".into(),
                            additional_fields: FieldMap::from_json(Map::from_iter([(
                                "label".into(),
                                request.additional_fields.get("label").cloned().ok_or_else(
                                    || AuthError::internal("Authorized display label is missing"),
                                )?,
                            )]))?,
                        })),
                    }
                })
            },
            move |row, _endpoint| {
                let sender = policy_events.clone();
                Box::pin(async move {
                    record(
                        &sender,
                        json!({"phase":"assertSessionRedemption", "row":observe_row(row)?}),
                    )?;
                    same(
                        &json!(row.status),
                        &json!("approved"),
                        "session policy status",
                    )?;
                    same(
                        &json!(row.scope.json()?),
                        &json!("read"),
                        "session policy scope",
                    )?;
                    same(
                        &json!(row.user_id.is_some()),
                        &json!(true),
                        "session policy owner",
                    )?;
                    if failure == Some(Failure::AssertSessionRedemption) {
                        return Err(Failure::AssertSessionRedemption.reject());
                    }
                    Ok(())
                })
            },
        )
        .stored_fields(UserConfig {
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
        })
        .verification_context(move |row| {
            record(
                &verification_events,
                json!({"phase":"getVerificationContext", "row":observe_row(row)?}),
            )?;
            if failure == Some(Failure::GetVerificationContext) {
                return Err(Failure::GetVerificationContext.reject());
            }
            Ok(Some(
                FieldMap::from_iter([(
                    "label".into(),
                    row.additional_fields
                        .get("label")
                        .cloned()
                        .ok_or_else(|| AuthError::internal("Stored display label is missing"))?,
                )])
                .json()?,
            ))
        });
    let validate_events = sender.clone();
    let request_events = sender.clone();
    let plugin = DeviceAuthorizationPlugin::new()
        .request_fields(DeviceRequestFields::new().field(
            "label",
            DeviceRequestField::new(|value| match value {
                Some(Value::String(value)) => {
                    Ok(DeviceFieldValidation::Value(Some(json!(value.trim()))))
                }
                None => Ok(DeviceFieldValidation::Value(None)),
                _ => Err(AuthError::bad_request(
                    "The ordinary display label must be a string",
                )),
            }),
        )?)
        .generate_device_code_with(|| async { Ok(DEVICE_CODE.into()) })
        .generate_user_code_with(|| async { Ok(USER_CODE.into()) })
        .validate_client(move |client_id| {
            let sender = validate_events.clone();
            async move {
                record(
                    &sender,
                    json!({"phase":"validateClient", "clientId":client_id}),
                )?;
                Ok(matches!(
                    client_id.as_str(),
                    "ordinary-client" | "ordinary-grant-client"
                ))
            }
        })
        .on_device_auth_request(move |client_id, scope| {
            let sender = request_events.clone();
            async move {
                record(
                    &sender,
                    json!({"phase":"onDeviceAuthRequest", "clientId":client_id, "scope":scope}),
                )
            }
        })
        .grant(grant);
    let auth = BetterAuth::<S>::new(config())
        .store_arc(raw)
        .rate_limit(RateLimitConfig::new().enabled(false))
        .plugin(plugin)
        .build()
        .await?;
    let owner = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_name("Device owner")
                .with_email("owner@device-grant.test"),
        )
        .await?;
    let login = auth
        .context()
        .session_manager()
        .create_session(&owner, None, None)
        .await?;
    let cookie = format!(
        "better-auth.session_token={}",
        better_auth::__private_core::utils::cookie_utils::sign_cookie_value(
            &login.token,
            auth.config().signing_secret()
        )
    );
    Ok(Fixture {
        auth,
        owner,
        cookie,
        events: receiver,
    })
}

async fn observe<S: AuthSchema>(input: Input, raw: Arc<dyn AuthStore<S>>) -> AuthResult<Value> {
    let Fixture {
        auth,
        owner,
        cookie,
        events: receiver,
    } = setup(&input, raw).await?;
    let issuance = call(
        &auth,
        input.transport,
        HttpMethod::Post,
        "/device/code",
        Some(input.body.clone()),
        None,
        None,
    )
    .await?;
    same(&json!(issuance.status), &json!(200), "issuance status")?;
    let issued = stored(&auth).await?;
    let verification = call(
        &auth,
        input.transport,
        HttpMethod::Get,
        "/device",
        None,
        Some(json!({"user_code":USER_CODE})),
        Some(&cookie),
    )
    .await?;
    same(
        &json!(verification.status),
        &json!(200),
        "verification status",
    )?;
    let claimed = stored(&auth).await?;
    let approval = call(
        &auth,
        input.transport,
        HttpMethod::Post,
        "/device/approve",
        Some(json!({"userCode":USER_CODE})),
        None,
        Some(&cookie),
    )
    .await?;
    same(&json!(approval.status), &json!(200), "approval status")?;
    let approved = stored(&auth).await?;
    let started = chrono::Utc::now().timestamp_millis();
    let mut redemption = call(
        &auth,
        input.transport,
        HttpMethod::Post,
        "/device/token",
        Some(
            json!({"grant_type":"urn:ietf:params:oauth:grant-type:device_code",
            "device_code":DEVICE_CODE,"client_id":field(&issued, "clientId")?}),
        ),
        None,
        None,
    )
    .await?;
    let finished = chrono::Utc::now().timestamp_millis();
    same(&json!(redemption.status), &json!(200), "redemption status")?;
    let token = field(&redemption.body, "access_token")?
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AuthError::internal("Device access token is empty or not a string"))?;
    let session = auth
        .store()
        .get_session(token)
        .await?
        .ok_or_else(|| AuthError::internal("Device access token has no persisted session"))?;
    let expiry = session
        .expires_at()
        .to_datetime()?
        .ok_or_else(|| AuthError::internal("Device session expiration is invalid"))?
        .timestamp_millis();
    let remaining = field(&redemption.body, "expires_in")?
        .as_i64()
        .ok_or_else(|| AuthError::internal("Device expires_in is not an integer"))?;
    let remaining_within_observed_window = (expiry - finished).div_euclid(1000) <= remaining
        && remaining <= (expiry - started).div_euclid(1000);
    let expiry_within_configured_window =
        started + SESSION_LIFETIME * 1000 <= expiry && expiry <= finished + SESSION_LIFETIME * 1000;
    same(
        &json!(remaining_within_observed_window),
        &json!(true),
        "remaining session lifetime",
    )?;
    same(
        &json!(expiry_within_configured_window),
        &json!(true),
        "configured session lifetime",
    )?;
    let stored_for_owner = session.user_id().json()? == owner.id().json()?;
    same(&json!(stored_for_owner), &json!(true), "session owner")?;
    let body = redemption
        .body
        .as_object_mut()
        .ok_or_else(|| AuthError::internal("Device token response is not an object"))?;
    let _ = body.insert(
        "access_token".into(),
        json!({"nonempty":true, "storedForOwner":stored_for_owner}),
    );
    let _ = body.insert(
        "expires_in".into(),
        json!({
            "remainingWithinObservedWindow":remaining_within_observed_window,
            "expiryWithinConfiguredWindow":expiry_within_configured_window,
        }),
    );
    let consumed = auth
        .store()
        .get_device_code_by_device_code(DEVICE_CODE)
        .await?
        .is_none();
    same(&json!(consumed), &json!(true), "consumed record")?;
    let events: Vec<_> = receiver.try_iter().collect();
    Ok(
        json!({"input":input,"issuance":issuance,"issued":issued,"verification":verification,
        "claimed":claimed,"approval":approval,"approved":approved,"redemption":redemption,
        "events":events,"consumed":consumed}),
    )
}

pub(crate) fn config() -> AuthConfig {
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.logger.disabled = Some(true);
    config.session.expires_in = Some(chrono::Duration::seconds(SESSION_LIFETIME));
    config
}

pub(crate) fn cases(fixture: &Value) -> AuthResult<&[Value]> {
    same(
        field(fixture, "version")?,
        &json!("1.7.6"),
        "fixture version",
    )?;
    same(
        field(fixture, "sessionLifetime")?,
        &json!(SESSION_LIFETIME),
        "fixture lifetime",
    )?;
    let cases = field(fixture, "cases")?
        .as_array()
        .ok_or_else(|| AuthError::internal("Device grant fixture cases are not an array"))?;
    same(&json!(cases.len()), &json!(4), "fixture case count")?;
    Ok(cases)
}

pub(crate) async fn check<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    expected: &Value,
) -> AuthResult<()> {
    let input = serde_json::from_value(field(expected, "input")?.clone())?;
    let actual: Observation = serde_json::from_value(observe(input, raw).await?)?;
    let expected: Observation = serde_json::from_value(expected.clone())?;
    same(&actual, &expected, "ordinary lifecycle")
}

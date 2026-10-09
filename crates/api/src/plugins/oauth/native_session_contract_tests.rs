//! Pinned HTTP, cache, native callback, OAuth state, and selected-row contracts.
//! Adapter CRUD events remain in the fixture. The store API has no complete CRUD observer.
//! Account and verification snapshots use the provider identity and state identifier written by the flow.

#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "Contract fixtures fail immediately when setup or a complete captured value differs."
)]

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRecordFields, AuthRequest,
    AuthResponse, AuthResult, AuthRoute, AuthSchema, CreateAccount, CreateSession, FieldMap,
    FieldValue, HttpMethod, ListUsersParams, OAuthStateStrategy, UpdateUser,
    api_error::{ApiErrorHandler, ApiErrorTask, handle_http_error},
    endpoint_dispatch::EndpointDispatcher,
    hooks::{current_request_hook_context, set_request_hook_route, with_request_hook_context},
    id::{IdGeneration, IdGenerator},
    observability::{AfterEndpointHook, EndpointHooks},
    session::NativeSessionData,
    store::{
        AuthStore, EphemeralStore, SecondaryStorage, StatelessSchema, schema::SchemaConfiguration,
        secondary::SecondaryStore,
    },
    user_fields::{UserFieldConfig, UserFieldReference},
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Schema, Statement},
    store::{__private_test_support::bundled_schema::BundledSchema, entities},
};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use super::{
    OAuthCallbacks, OAuthPlugin, OAuthProvider, OAuthUserInfo, OAuthUserInfoHandler,
    OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use crate::plugins::test_helpers::initialize_test_context;

const ORIGIN: &str = "http://oauth-native-session.test";
const SECRET: &str = "oauth-native-session-contract-secret-at-least-32-characters";
const TOKEN: &str = "native-oauth-owner-session";
const EMAIL: &str = "Owner@oauth-native-session.test";
const DATE: &str = "2030-01-02T03:04:05.000Z";
const EXPIRES: &str = "2030-01-02T03:14:05.000Z";
const TIMESTAMP: f64 = 1_893_553_445_000.0;

fn object<const N: usize>(entries: [(&str, FieldValue); N]) -> FieldValue {
    entries
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect::<FieldMap>()
        .into()
}

fn field<'a>(value: &'a FieldValue, key: &str) -> &'a FieldValue {
    value.as_object().unwrap().get(key).unwrap()
}

fn text<'a>(value: &'a FieldValue, key: &str) -> &'a str {
    field(value, key).as_str().unwrap()
}

fn native(value: &FieldValue) -> AuthResult<FieldValue> {
    Ok(match value {
        FieldValue::Undefined => object([("type", "undefined".into())]),
        FieldValue::Date(date) => object([
            ("type", "date".into()),
            (
                "value",
                if date.milliseconds().is_nan() {
                    "Invalid Date".into()
                } else {
                    FieldValue::from_json(value.json()?.unwrap())?
                },
            ),
        ]),
        FieldValue::Number(number) if !number.is_finite() => object([
            ("type", "number".into()),
            (
                "value",
                if number.is_nan() {
                    "NaN"
                } else if number.is_sign_positive() {
                    "Infinity"
                } else {
                    "-Infinity"
                }
                .into(),
            ),
        ]),
        FieldValue::Array(values) => values
            .iter()
            .map(native)
            .collect::<AuthResult<Vec<_>>>()?
            .into(),
        FieldValue::Object(fields) => fields
            .iter()
            .map(|(key, value)| Ok((key.clone(), native(value)?)))
            .collect::<AuthResult<FieldMap>>()?
            .into(),
        FieldValue::Function(_) => {
            return Err(AuthError::internal("Unexpected function in OAuth capture"));
        }
        value => value.clone(),
    })
}

fn session(value: Option<&NativeSessionData>) -> FieldValue {
    value.map_or(FieldValue::Null, |value| {
        object([
            ("session", FieldMap::from(value.session.clone()).into()),
            ("user", value.user.clone()),
        ])
    })
}

#[derive(Clone, Default)]
struct Events(Arc<Mutex<Vec<FieldValue>>>);

impl Events {
    fn push(&self, value: FieldValue) -> AuthResult<()> {
        self.0.lock().unwrap().push(native(&value)?);
        Ok(())
    }
}

#[async_trait]
impl<S: AuthSchema> AfterEndpointHook<S> for Events {
    async fn after(
        &self,
        request: &AuthRequest,
        _: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<()> {
        let context = current_request_hook_context().unwrap();
        self.push(object([
            ("kind", "after".into()),
            ("path", context.path.unwrap().into()),
            (
                "session",
                session(request.native_session_snapshot()?.as_ref()),
            ),
            (
                "state",
                super::get_oauth_state(request)?.unwrap_or(FieldValue::Null),
            ),
        ]))
    }
}

impl<S: AuthSchema> ApiErrorHandler<S> for Events {
    fn on_error(&self, error: &AuthError, _: &AuthContext<S>) -> AuthResult<Option<ApiErrorTask>> {
        let AuthError::TypeError(message) = error else {
            return Err(AuthError::internal(format!(
                "Unexpected OAuth router error: {error:?}"
            )));
        };
        self.push(object([
            ("kind", "api-error".into()),
            (
                "error",
                object([
                    ("name", "TypeError".into()),
                    ("message", message.clone().into()),
                    ("keys", Vec::<FieldValue>::new().into()),
                    ("properties", FieldMap::new().into()),
                ]),
            ),
        ]))?;
        Ok(None)
    }
}

struct Profile(Events);

#[async_trait]
impl OAuthUserInfoHandler for Profile {
    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> AuthResult<Option<OAuthUserInfoResponse>> {
        assert!(
            request.token_type.is_none()
                && request.access_token_expires_at.is_none()
                && request.refresh_token_expires_at.is_none()
                && request.scopes.is_empty()
                && request.raw.is_none()
                && request.user.is_none()
        );
        self.0.push(object([
            ("kind", "profile".into()),
            (
                "tokens",
                object([
                    (
                        "idToken",
                        request.id_token.map_or(FieldValue::Undefined, Into::into),
                    ),
                    (
                        "accessToken",
                        request
                            .access_token
                            .map_or(FieldValue::Undefined, Into::into),
                    ),
                    (
                        "refreshToken",
                        request
                            .refresh_token
                            .map_or(FieldValue::Undefined, Into::into),
                    ),
                ]),
            ),
        ]))?;
        Ok(Some(OAuthUserInfoResponse {
            user: OAuthUserInfo {
                id: "provider-owner".into(),
                name: Some("Provider Owner".into()).into(),
                email: Some(EMAIL.into()).into(),
                email_verified: Some(true).into(),
                image: None,
                additional_fields: Default::default(),
            },
            data: json!({"id":"provider-owner","name":"Provider Owner","email":EMAIL,"emailVerified":true,"sub":"provider-owner"}),
        }))
    }
}

struct Cache {
    events: Events,
    rows: Mutex<indexmap::IndexMap<String, String>>,
}

impl Cache {
    fn read(&self, key: &str) -> Option<String> {
        self.rows.lock().unwrap().get(key).cloned()
    }

    fn snapshot(&self) -> AuthResult<FieldValue> {
        self.rows
            .lock()
            .unwrap()
            .iter()
            .map(|(key, value)| {
                Ok(object([
                    ("key", key.clone().into()),
                    ("value", FieldValue::parse_json(value)?),
                ]))
            })
            .collect::<AuthResult<Vec<_>>>()
            .map(Into::into)
    }
}

#[async_trait]
impl SecondaryStorage for Cache {
    async fn get(&self, key: &str) -> AuthResult<Option<Value>> {
        self.events.push(object([
            ("kind", "cache".into()),
            ("operation", "get".into()),
            ("key", key.into()),
        ]))?;
        Ok(self.read(key).map(Value::String))
    }

    async fn set_native(&self, key: &FieldValue, value: &str, ttl: Option<f64>) -> AuthResult<()> {
        self.events.push(object([
            ("kind", "cache".into()),
            ("operation", "set".into()),
            ("key", key.clone()),
            ("value", FieldValue::parse_json(value)?),
            ("ttl", ttl.map_or(FieldValue::Undefined, Into::into)),
        ]))?;
        let _ = self
            .rows
            .lock()
            .unwrap()
            .insert(key.as_str().unwrap().into(), value.into());
        Ok(())
    }

    async fn delete(&self, key: &str) -> AuthResult<()> {
        self.events.push(object([
            ("kind", "cache".into()),
            ("operation", "delete".into()),
            ("key", key.into()),
        ]))?;
        let _ = self.rows.lock().unwrap().shift_remove(key);
        Ok(())
    }

    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<Value>> {
        self.events.push(object([
            ("kind", "cache".into()),
            ("operation", "get-and-delete".into()),
            ("key", key.into()),
        ]))?;
        Ok(self
            .rows
            .lock()
            .unwrap()
            .shift_remove(key)
            .map(Value::String))
    }
}

struct CachePlugin(Option<Arc<Cache>>);

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for CachePlugin {
    fn name(&self) -> &'static str {
        "native-session-contract-cache"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        context.secondary_storage = self
            .0
            .clone()
            .map(|cache| cache as Arc<dyn SecondaryStorage>);
        Ok(())
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

fn selector(name: &str) -> FieldValue {
    match name {
        "number" | "profile-update-number" => 7.0.into(),
        "string-number" => "7".into(),
        "zero" => 0.0.into(),
        "false" => false.into(),
        "null" => FieldValue::Null,
        "undefined" | "profile-update-undefined" | "missing-session" => FieldValue::Undefined,
        "empty" => "".into(),
        "object" => object([("owner", 7.0.into())]),
        "array" => vec![7.0.into()].into(),
        "surrogate" => better_auth_core::Utf16String::from_units(vec![0xd800]).into(),
        _ => "owner".into(),
    }
}

fn config(case: &FieldValue) -> AuthConfig {
    let scenario = text(case, "scenario");
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.session.store_session_in_database = Some(true);
    config.account.store_state_strategy = Some(if text(case, "strategy") == "cookie" {
        OAuthStateStrategy::Cookie
    } else {
        OAuthStateStrategy::Database
    });
    config.account.account_linking.allow_different_emails = scenario.ends_with("different-allowed");
    config.account.account_linking.update_user_info_on_link =
        Some(scenario.starts_with("profile-update"));
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(|request| {
            Ok(Some(if request.model == "session" {
                "owner-session".into()
            } else {
                better_auth_core::id::random_id(request.size)
            }))
        })));
    if scenario.starts_with("many") {
        let _ = config.user.fields_mut().insert(
            "image".into(),
            UserFieldConfig {
                references: Some(UserFieldReference {
                    model: "session".into(),
                    field: "id".into(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
    }
    config
}

fn owner(id: &str, name: &str, email: &str, image: FieldValue) -> FieldMap {
    let date: DateTime<Utc> = DATE.parse().unwrap();
    [
        ("id".into(), id.into()),
        ("name".into(), name.into()),
        ("email".into(), email.into()),
        ("emailVerified".into(), true.into()),
        ("image".into(), image),
        ("createdAt".into(), date.into()),
        ("updatedAt".into(), date.into()),
    ]
    .into()
}

async fn seed<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    case: &FieldValue,
    cache: Option<&Cache>,
) -> AuthResult<()> {
    let scenario = text(case, "scenario");
    let related = scenario == "many";
    let user = owner("owner", "Owner", EMAIL, FieldValue::Null);
    let _ = store
        .create_user_fields_optional(user.clone())
        .await?
        .unwrap();
    let date: DateTime<Utc> = DATE.parse().unwrap();
    let session = store
        .create_session(CreateSession {
            user_id: "owner".into(),
            expires_at: "2100-01-01T00:00:00Z"
                .parse::<DateTime<Utc>>()
                .unwrap()
                .into(),
            ip_address: Some("127.0.0.1".into()),
            user_agent: Some("native-oauth-contract".into()),
            impersonated_by: None,
            active_organization_id: None,
            inherited_fields: Default::default(),
            additional_fields: [
                ("token".into(), TOKEN.into()),
                ("createdAt".into(), date.into()),
                ("updatedAt".into(), date.into()),
            ]
            .into(),
        })
        .await?;
    assert_eq!(session.id.field_value(), FieldValue::from("owner-session"));
    if related {
        let _ = store
            .update_user(
                "owner",
                UpdateUser {
                    image: Some("owner-session".into()).into(),
                    additional_fields: [("updatedAt".into(), date.into())].into(),
                    ..Default::default()
                },
            )
            .await?;
        let _ = store
            .create_user_fields_optional(owner(
                "other",
                "Other",
                "other@oauth-native-session.test",
                "owner-session".into(),
            ))
            .await?
            .unwrap();
    }
    if field(case, "existing") == &FieldValue::Bool(true) {
        let _ = store
            .create_account(CreateAccount {
                id: "linked-account".into(),
                account_id: "provider-owner".into(),
                provider_id: "google".into(),
                user_id: "owner".into(),
                created_at: date.into(),
                updated_at: date.into(),
                ..Default::default()
            })
            .await?;
    }
    if let Some(cache) = cache {
        let mut user = user;
        let _ = user.insert("id".into(), selector(scenario));
        if scenario.starts_with("email-") {
            let _ = user.insert(
                "email".into(),
                if scenario.starts_with("email-undefined") {
                    FieldValue::Undefined
                } else if scenario.starts_with("email-null") {
                    FieldValue::Null
                } else {
                    7.0.into()
                },
            );
        }
        let value = object([
            ("session", FieldMap::from(session).into()),
            ("user", user.into()),
        ]);
        let _ = cache
            .rows
            .lock()
            .unwrap()
            .insert(TOKEN.into(), value.stringify()?.unwrap());
    }
    Ok(())
}

async fn sqlite(many: bool) -> AuthResult<DatabaseConnection> {
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(db_error)?;
    let schema = Schema::new(DbBackend::Sqlite);
    for statement in [
        schema.create_table_from_entity(entities::user::Entity),
        schema.create_table_from_entity(entities::session::Entity),
        schema.create_table_from_entity(entities::account::Entity),
    ] {
        let _ = database.execute(&statement).await.map_err(db_error)?;
    }
    if many {
        let _ = database
            .execute(&schema.create_table_from_entity(entities::verification::Entity))
            .await
            .map_err(db_error)?;
    }
    Ok(database)
}

fn db_error(error: better_auth_seaorm::sea_orm::DbErr) -> AuthError {
    AuthError::internal(format!("OAuth fixture database: {error}"))
}

async fn dispatch<S: AuthSchema>(
    context: &AuthContext<S>,
    plugins: &Arc<Vec<Box<dyn AuthPlugin<S>>>>,
    dispatcher: &EndpointDispatcher<S>,
    mut request: AuthRequest,
) -> AuthResult<AuthResponse> {
    let original = request.clone();
    with_request_hook_context(&original, async {
        let route = plugins
            .iter()
            .flat_map(|plugin| plugin.routes())
            .find(|route| route.matches(request.method(), request.path()))
            .unwrap();
        set_request_hook_route(request.path(), Some(&route));
        match dispatcher
            .run(&mut request, true, context, None, |request| async move {
                for plugin in plugins.iter() {
                    if let Some(response) = plugin.on_request(&request, context).await? {
                        return Ok(response);
                    }
                }
                Err(AuthError::internal(
                    "OAuth capture endpoint was not handled",
                ))
            })
            .await
        {
            Ok(response) => Ok(response),
            Err(error) => handle_http_error(error, context).await,
        }
    })
    .await
}

fn request(method: HttpMethod, path: &str) -> AuthRequest {
    AuthRequest::new(method, path).with_url(format!("{ORIGIN}/api/auth{path}").parse().unwrap())
}

fn cookies(response: &AuthResponse) -> String {
    response
        .headers
        .get_all("set-cookie")
        .map(|value| value.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ")
}

#[derive(Default)]
struct Normalize {
    strings: HashMap<String, String>,
    expiry: Option<f64>,
    start: i64,
    end: i64,
}

impl Normalize {
    fn generated_date(&mut self, value: &FieldValue, target: &str, offset: i64) -> AuthResult<()> {
        let string = match value {
            FieldValue::Date(_) => value.json()?.unwrap().as_str().unwrap().to_owned(),
            FieldValue::String(value) => value.clone(),
            _ => return Err(AuthError::internal("Expected a generated OAuth date")),
        };
        if string != target {
            let timestamp = string.parse::<DateTime<Utc>>().unwrap().timestamp_millis();
            assert!(
                (self.start + offset..=self.end + offset).contains(&timestamp),
                "Generated date {string} is outside its request window"
            );
            let _ = self.strings.insert(string, target.into());
        }
        Ok(())
    }

    fn dates(&mut self, value: &FieldValue, expires: bool) -> AuthResult<()> {
        for key in ["createdAt", "updatedAt"] {
            self.generated_date(field(value, key), DATE, 0)?;
        }
        if expires {
            self.generated_date(field(value, "expiresAt"), EXPIRES, 600_000)?;
        }
        Ok(())
    }

    fn value(&self, value: &FieldValue) -> AuthResult<FieldValue> {
        Ok(match value {
            FieldValue::String(value) => self.strings.get(value).unwrap_or(value).clone().into(),
            FieldValue::Number(value) if Some(*value) == self.expiry => {
                (TIMESTAMP + 600_000.0).into()
            }
            FieldValue::Date(_) => {
                let mut value = native(value)?.as_object().unwrap().clone();
                let normalized = self.value(value.get("value").unwrap())?;
                let _ = value.insert("value".into(), normalized);
                value.into()
            }
            FieldValue::Array(values) => values
                .iter()
                .map(|value| self.value(value))
                .collect::<AuthResult<Vec<_>>>()?
                .into(),
            FieldValue::Object(fields) => fields
                .iter()
                .map(|(key, value)| Ok((key.clone(), self.value(value)?)))
                .collect::<AuthResult<FieldMap>>()?
                .into(),
            value => native(value)?,
        })
    }
}

fn response(response: &AuthResponse, normalize: &mut Normalize) -> AuthResult<FieldValue> {
    let bytes = response.body.bytes().unwrap();
    let mut body = if bytes.is_empty() {
        object([("empty", true.into())])
    } else if response
        .headers
        .get("content-type")
        .is_some_and(|value| value.contains("application/json"))
    {
        FieldValue::parse_json(std::str::from_utf8(&bytes).unwrap())?
    } else {
        object([("text", std::str::from_utf8(&bytes).unwrap().into())])
    };
    if let Some(url) = body
        .as_object()
        .and_then(|body| body.get("url"))
        .and_then(FieldValue::as_str)
        .filter(|value| !value.is_empty())
    {
        let mut url = url::Url::parse(url).unwrap();
        let pairs = url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();
        let _ = url.query_pairs_mut().clear();
        for (key, value) in pairs {
            let value = if ["state", "code_challenge", "nonce"].contains(&key.as_str()) {
                assert!(!value.is_empty());
                let replacement = format!("<{key}>");
                let _ = normalize.strings.insert(value, replacement.clone());
                replacement
            } else {
                value
            };
            let _ = url.query_pairs_mut().append_pair(&key, &value);
        }
        let mut fields = body.as_object().unwrap().clone();
        let _ = fields.insert("url".into(), url.to_string().into());
        body = fields.into();
    }
    let cookies = response
        .headers
        .get_all("set-cookie")
        .map(|cookie| {
            let mut fields = cookie.split(';');
            let (name, value) = fields.next().unwrap().split_once('=').unwrap();
            object([
                ("name", name.into()),
                ("value", if value.is_empty() { "" } else { "<set>" }.into()),
                (
                    "attributes",
                    fields.map(FieldValue::from).collect::<Vec<_>>().into(),
                ),
            ])
        })
        .collect::<Vec<_>>();
    Ok(object([
        ("status", (response.status as f64).into()),
        ("body", native(&body)?),
        (
            "location",
            response
                .headers
                .get("location")
                .map_or(FieldValue::Null, |value| value.clone().into()),
        ),
        ("cookies", cookies.into()),
    ]))
}

async fn run<S: AuthSchema>(
    case: &FieldValue,
    raw: Arc<dyn AuthStore<S>>,
    database: Option<&DatabaseConnection>,
) -> AuthResult<()> {
    let scenario = text(case, "scenario");
    let many = scenario.starts_with("many");
    let events = Events::default();
    let cache = (!many).then(|| {
        Arc::new(Cache {
            events: events.clone(),
            rows: Default::default(),
        })
    });
    let mut provider = OAuthProvider::google("client", "secret");
    provider.get_user_info = Some(Arc::new(Profile(events.clone())));
    let observed = events.clone();
    let callbacks =
        OAuthCallbacks::<S>::default().verify_id_token("google", move |token, nonce, context| {
            let observed = observed.clone();
            Box::pin(async move {
                observed.push(object([
                    ("kind", "verify".into()),
                    ("token", token.into()),
                    ("nonce", nonce.map_or(FieldValue::Undefined, Into::into)),
                    (
                        "path",
                        context.path.map_or(FieldValue::Undefined, Into::into),
                    ),
                    ("hasRequest", context.request.is_some().into()),
                    ("session", session(context.session.as_ref())),
                ]))?;
                Ok(true)
            })
        });
    let plugins: Arc<Vec<Box<dyn AuthPlugin<S>>>> = Arc::new(vec![
        Box::new(
            OAuthPlugin::new()
                .add_provider("google", provider)
                .callbacks(callbacks),
        ),
        Box::new(CachePlugin(cache.clone())),
    ]);
    let config = Arc::new(config(case));
    let borrowed = plugins.iter().map(AsRef::as_ref).collect::<Vec<_>>();
    let mut context = initialize_test_context(config.clone(), raw.clone(), &borrowed).await?;
    let adapter = context.database.clone();
    seed(adapter.as_ref(), case, cache.as_deref()).await?;
    context.database = Arc::new(if let Some(cache) = &cache {
        SecondaryStore::new(
            adapter.clone(),
            cache.clone(),
            context.config.clone(),
            context.metadata.clone(),
        )?
    } else {
        SecondaryStore::without_secondary(
            adapter.clone(),
            context.config.clone(),
            context.metadata.clone(),
        )
    });
    let on_error: Arc<dyn ApiErrorHandler<S>> = Arc::new(events.clone());
    context.extensions.insert(on_error);
    let dispatcher = EndpointDispatcher::new(
        plugins.clone(),
        EndpointHooks {
            before: None,
            after: Some(Arc::new(events.clone())),
        },
        [],
    );
    let mut start = request(HttpMethod::Post, "/link-social");
    let _ = start.headers.insert("origin".into(), ORIGIN.into());
    let _ = start
        .headers
        .insert("content-type".into(), "application/json".into());
    if scenario != "missing-session" {
        let _ = start.headers.insert(
            "cookie".into(),
            format!(
                "better-auth.session_token={}",
                better_auth_core::utils::cookie_utils::sign_cookie_value(TOKEN, SECRET)
            ),
        );
    }
    let mut body = json!({"provider":"google","callbackURL":format!("{ORIGIN}/complete"),"errorCallbackURL":format!("{ORIGIN}/failed"),"disableRedirect":true});
    if text(case, "operation") == "id-token" {
        body["idToken"] = json!({"token":"native-id-token","nonce":"native-nonce"});
    }
    start.body = Some(serde_json::to_vec(&body)?);
    let mut normalize = Normalize {
        start: Utc::now().timestamp_millis(),
        ..Default::default()
    };
    let start = dispatch(&context, &plugins, &dispatcher, start).await?;
    let result = response(&start, &mut normalize)?;
    let mut pending = FieldValue::Null;
    let mut callback = FieldValue::Null;
    let mut state = None;
    let mut serialized = None;
    if text(case, "operation") == "redirect" && start.status == 200 {
        let body: Value = serde_json::from_slice(&start.body.bytes().unwrap())?;
        let url = url::Url::parse(body["url"].as_str().unwrap()).unwrap();
        let identifier = url
            .query_pairs()
            .find(|(key, _)| key == "state")
            .unwrap()
            .1
            .into_owned();
        let value = if text(case, "strategy") == "database" {
            let row = if let Some(cache) = &cache {
                FieldValue::parse_json(&cache.read(&format!("verification:{identifier}")).unwrap())?
            } else {
                adapter
                    .get_verification_by_identifier(&identifier)
                    .await?
                    .unwrap()
                    .fields()?
                    .into()
            };
            normalize.end = Utc::now().timestamp_millis();
            normalize.dates(&row, true)?;
            if let Some(id) = row.as_object().unwrap().get("id") {
                let _ = normalize
                    .strings
                    .insert(id.as_str().unwrap().into(), "<verification-id>".into());
            }
            let _ = normalize.strings.insert(
                format!("verification:{identifier}"),
                "verification:<state>".into(),
            );
            let cookie = super::state::get_cookie(
                &AuthRequest::from_parts(
                    HttpMethod::Get,
                    "/".into(),
                    HashMap::from([("cookie".into(), cookies(&start))]),
                    None,
                    None,
                ),
                "better-auth.state",
            )
            .unwrap();
            assert_eq!(
                super::state::decode_database_state_cookie_value(SECRET, &cookie)?,
                identifier
            );
            text(&row, "value").to_owned()
        } else {
            let pair = cookies(&start)
                .split("; ")
                .find(|pair| pair.starts_with("better-auth.oauth_state="))
                .unwrap()
                .to_owned();
            let encrypted = urlencoding::decode(pair.split_once('=').unwrap().1).unwrap();
            crate::plugins::symmetric::decrypt(config.encryption_secret(), &encrypted)?
        };
        pending = FieldValue::parse_json(&value)?;
        assert_eq!(
            field(&pending, "oauthState"),
            &FieldValue::from(identifier.clone())
        );
        let expiry = field(&pending, "expiresAt").as_f64().unwrap();
        normalize.end = Utc::now().timestamp_millis();
        assert!(
            (normalize.start as f64 + 600_000.0..=normalize.end as f64 + 600_000.0)
                .contains(&expiry)
        );
        normalize.expiry = Some(expiry);
        let verifier = text(&pending, "codeVerifier");
        assert!(!verifier.is_empty());
        let _ = normalize
            .strings
            .insert(verifier.into(), "<code-verifier>".into());
        serialized = Some(value);
        let mut request = request(HttpMethod::Get, "/callback/google");
        request.headers = HashMap::from([
            ("origin".into(), ORIGIN.into()),
            ("cookie".into(), cookies(&start)),
        ]);
        request.query = Some(json!({"state":identifier,"error":"access_denied"}));
        callback = response(
            &dispatch(&context, &plugins, &dispatcher, request).await?,
            &mut normalize,
        )?;
        state = Some(identifier);
    }
    normalize.end = Utc::now().timestamp_millis();
    let observed = events.0.lock().unwrap().clone();
    let models = SchemaConfiguration {
        config: context.config.clone(),
        plugins: vec!["oauth"],
        metadata: context.metadata.clone(),
        secondary_storage: cache.is_some(),
        database_rate_limit: false,
    }
    .models();
    let (users, count) = adapter
        .list_users(ListUsersParams {
            limit: Some(100.0),
            ..Default::default()
        })
        .await?;
    assert_eq!(users.len(), count);
    let user_rows = users
        .iter()
        .map(|user| FieldValue::from(FieldMap::from(user.clone())))
        .collect::<Vec<_>>();
    if scenario.starts_with("profile-update") {
        for user in &user_rows {
            normalize.generated_date(field(user, "updatedAt"), DATE, 0)?;
        }
    }
    let sessions = adapter
        .get_user_sessions("owner")
        .await?
        .into_iter()
        .map(|session| FieldMap::from(session).into())
        .collect::<Vec<FieldValue>>();
    let accounts = adapter
        .get_account("google", "provider-owner")
        .await?
        .into_iter()
        .map(|account| account.field_values().map(FieldValue::from))
        .collect::<AuthResult<Vec<_>>>()?;
    for account in &accounts {
        normalize.dates(account, false)?;
        if text(account, "id") != "linked-account" {
            let _ = normalize
                .strings
                .insert(text(account, "id").into(), "<account-id>".into());
        }
    }
    let verification = if many {
        let rows = if let Some(state) = &state {
            adapter
                .get_verification_by_identifier(state)
                .await?
                .into_iter()
                .map(|row| row.fields().map(FieldValue::from))
                .collect::<AuthResult<Vec<_>>>()?
        } else {
            Vec::new()
        };
        rows.into()
    } else if let Some(database) = database {
        let exists = database
            .query_one_raw(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'verifications'"
                    .to_owned(),
            ))
            .await
            .map_err(db_error)?
            .is_some();
        object([
            ("modelRegistered", false.into()),
            ("tableExists", exists.into()),
        ])
    } else {
        let row = raw
            .get_verification_by_identifier(state.as_deref().unwrap_or("unused-state"))
            .await?;
        object([
            ("modelRegistered", false.into()),
            (
                "rows",
                row.into_iter()
                    .map(|row| row.fields().map(FieldValue::from))
                    .collect::<AuthResult<Vec<_>>>()?
                    .into(),
            ),
        ])
    };
    if let Some(serialized) = serialized {
        let _ = normalize
            .strings
            .insert(serialized, normalize.value(&pending)?.stringify()?.unwrap());
    }
    let stored = object([
        ("user", user_rows.into()),
        ("session", sessions.into()),
        ("account", accounts.into()),
        ("verification", verification),
    ]);
    for (key, actual) in [
        ("result", result),
        ("pending", pending),
        ("callback", callback),
        (
            "registeredModels",
            models
                .into_iter()
                .map(|(_, name)| FieldValue::from(name))
                .collect::<Vec<_>>()
                .into(),
        ),
        ("stored", stored),
        (
            "cache",
            cache
                .as_ref()
                .map_or(Ok(Vec::<FieldValue>::new().into()), |cache| {
                    cache.snapshot()
                })?,
        ),
    ] {
        assert_eq!(
            normalize.value(&actual)?,
            *field(case, key),
            "{}/{}/{scenario}/{} {key}",
            text(case, "backend"),
            text(case, "operation"),
            text(case, "strategy")
        );
    }
    // Keep adapter observations in the immutable fixture until a real CRUD observation seam exists.
    let expected = field(case, "events")
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| text(event, "kind") != "adapter")
        .collect::<Vec<_>>();
    assert_eq!(
        observed.len(),
        expected.len(),
        "{scenario}: complete observable event count"
    );
    for (index, (actual, expected)) in observed.iter().zip(expected).enumerate() {
        assert_eq!(
            normalize.value(actual)?,
            *expected,
            "{}/{}/{scenario} event {index}",
            text(case, "backend"),
            text(case, "operation")
        );
    }
    Ok(())
}

#[tokio::test]
async fn native_session_http_cache_state_and_selected_rows_match_172_captured_cases()
-> AuthResult<()> {
    let fixture = FieldValue::parse_json(include_str!(
        "../../../../../tests/fixtures/oauth-native-session-1.7.6.json"
    ))?;
    assert_eq!(text(&fixture, "version"), "1.7.6");
    let cases = field(&fixture, "cases").as_array().unwrap();
    assert_eq!(cases.len(), 172);
    for case in cases.iter() {
        let config = config(case);
        if text(case, "backend") == "memory" {
            run::<StatelessSchema>(case, Arc::new(EphemeralStore::new(Arc::new(config))), None)
                .await?;
        } else {
            assert_eq!(text(case, "backend"), "sqlite");
            let database = sqlite(text(case, "scenario").starts_with("many")).await?;
            run::<BundledSchema>(
                case,
                Arc::new(SeaOrmStore::<BundledSchema>::new(config, database.clone())),
                Some(&database),
            )
            .await?;
        }
    }
    Ok(())
}

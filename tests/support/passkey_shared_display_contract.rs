#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "The paired contract asserts complete captured records and fails immediately on missing fixture fields"
)]

use better_auth::{
    __private_core::{
        __private_async_trait::async_trait,
        AuthContext, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
        AuthSchema, AuthStore, CreatePasskey, CreateSession, CreateUser, HttpMethod, Passkey,
        PasskeyCredentialState, PasskeyStorage, UpdatePasskeyAuthentication,
        entity::{AuthSession, AuthUser},
        id::{IdGeneration, IdGenerator},
        store::schema::EntityRole,
        user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform},
        utils::cookie_utils::sign_cookie_value,
        wire::PasskeyView,
    },
    AuthConfig, BetterAuth,
    plugins::passkey::PasskeyPlugin,
    seaorm::{
        __private_chrono as chrono,
        sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement},
    },
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex, OnceLock};

#[path = "passkey_shared_display_observation.rs"]
mod observations;
use observations::{Check, normalized, observation};

pub(crate) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub(crate) type Trace = Arc<Mutex<Vec<Value>>>;
const ORIGIN: &str = "http://passkey-shared-display.test";
const OWNER: &str = "shared-display-owner";
const ID: &str = "shared-display-passkey";
const AAGUID: &str = "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4";

pub(crate) fn config() -> AuthConfig {
    let mut config =
        AuthConfig::new("ordinary-shared-passkey-display-secret-at-least-32-characters")
            .base_url(ORIGIN);
    config.telemetry.enabled = false;
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(|request| {
            Ok(Some(
                match request.model {
                    "user" => OWNER,
                    "passkey" => ID,
                    _ => "shared-display-session",
                }
                .into(),
            ))
        })));
    config
}

pub(crate) fn policies(reversed: bool, events: Option<&Trace>) -> UserConfig {
    let names = if reversed {
        ["aaguid", "name"]
    } else {
        ["name", "aaguid"]
    };
    UserConfig {
        additional_fields: Some(
            names
                .into_iter()
                .map(|name| {
                    let transform = events.map(|events| {
                        let input = events.clone();
                        let output = events.clone();
                        FieldTransforms {
                            input: Some(UserFieldTransform::new(move |value| {
                                input
                                    .lock()
                                    .expect("shared display input trace")
                                    .push(json!([
                                        "input",
                                        name,
                                        value
                                            .json()?
                                            .unwrap_or_else(|| json!({"type":"undefined"}))
                                    ]));
                                Ok(value)
                            })),
                            output: Some(UserFieldTransform::new(move |value| {
                                output
                                    .lock()
                                    .expect("shared display output trace")
                                    .push(json!([
                                        "output",
                                        name,
                                        value
                                            .json()?
                                            .unwrap_or_else(|| json!({"type":"undefined"}))
                                    ]));
                                Ok(value)
                            })),
                        }
                    });
                    (
                        name.into(),
                        UserFieldConfig {
                            required: Some(false),
                            field_name: Some("display".into()),
                            transform,
                            ..Default::default()
                        },
                    )
                })
                .collect(),
        ),
    }
}

pub(crate) fn take(events: &Trace) -> Vec<Value> {
    std::mem::take(&mut *events.lock().expect("shared display trace"))
}

struct Fields(UserConfig);

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Fields {
    fn name(&self) -> &'static str {
        "ordinary-passkey-additional-fields"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        context.register_model_fields(EntityRole::Passkey, self.0.clone())
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

pub(crate) async fn run<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    database: Option<&DatabaseConnection>,
    case: &Value,
) -> TestResult {
    let reversed = case["declarationOrder"] == json!(["aaguid", "name"]);
    let events = Trace::default();
    let auth = BetterAuth::new(config())
        .store_arc(raw.clone())
        .plugin(PasskeyPlugin::new())
        .plugin(Fields(policies(reversed, Some(&events))))
        .build()
        .await?;
    let reader = BetterAuth::new(config())
        .store_arc(raw)
        .plugin(PasskeyPlugin::new())
        .plugin(Fields(policies(reversed, None)))
        .build()
        .await?;
    let owner = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_name("Shared display owner")
                .with_email("owner@passkey-shared-display.test")
                .with_email_verified(true),
        )
        .await?;
    assert_eq!(owner.id().typed()?, OWNER);
    let session = auth
        .store()
        .create_session(CreateSession {
            inherited_fields: Default::default(),
            user_id: OWNER.into(),
            expires_at: (chrono::Utc::now() + auth.config().session.expires_in()).into(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            additional_fields: Default::default(),
        })
        .await?;
    let cookie = format!(
        "better-auth.session_token={}",
        sign_cookie_value(session.token(), auth.config().signing_secret())
    );
    assert!(take(&events).is_empty());
    let check = Check {
        started: chrono::Utc::now().timestamp_millis(),
        created: OnceLock::new(),
    };
    if let Some(database) = database {
        let columns = database
            .query_all_raw(Statement::from_string(
                DbBackend::Sqlite,
                "PRAGMA table_info(shared_display_passkey)".to_owned(),
            ))
            .await?;
        let actual = columns
            .iter()
            .map(|row| row.try_get::<String>("", "name"))
            .collect::<Result<Vec<_>, _>>()?;
        let expected = case["catalog"]["catalog"]["columns"]
            .as_array()
            .ok_or("Captured columns")?
            .iter()
            .map(|column| column["name"].as_str().ok_or("Captured column name"))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(actual, expected);
    }
    let operations = case["operations"].as_array().ok_or("Captured operations")?;
    assert_eq!(
        operations
            .iter()
            .map(|operation| operation["name"].as_str())
            .collect::<Vec<_>>(),
        [
            "create",
            "get-id",
            "get-credential",
            "list",
            "update-name",
            "update-auth"
        ]
        .map(Some)
    );
    for expected in operations {
        let name = expected["name"].as_str().ok_or("Captured operation name")?;
        let result = if name == "update-name" {
            let http = &case["http"][0];
            let body = http["request"]["body"]
                .as_str()
                .ok_or("Captured HTTP body")?;
            let headers = [
                ("accept".into(), "application/json".into()),
                ("content-type".into(), "application/json".into()),
                ("cookie".into(), cookie.clone()),
                ("origin".into(), ORIGIN.into()),
            ]
            .into();
            let request = AuthRequest::from_parts(
                HttpMethod::Post,
                "/api/auth/passkey/update-passkey".into(),
                headers,
                Some(body.as_bytes().to_vec()),
                None,
            )
            .with_url(
                http["request"]["url"]
                    .as_str()
                    .ok_or("Captured HTTP URL")?
                    .parse()?,
            );
            let mut request_headers = request
                .headers
                .iter()
                .map(|(name, value)| {
                    (
                        name.clone(),
                        if name == "cookie" {
                            assert_eq!(value, &cookie);
                            "better-auth.session_token=<owner-session-cookie>".into()
                        } else {
                            value.clone()
                        },
                    )
                })
                .collect::<Vec<_>>();
            request_headers.sort();
            assert_eq!(json!(request_headers), http["request"]["headers"]);
            assert_eq!(http["request"]["method"], "POST");
            let response = auth.handle_request(request).await?;
            assert_eq!(json!(response.status), http["response"]["status"]);
            let mut headers = response
                .headers
                .iter()
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect::<Vec<_>>();
            headers.sort();
            assert_eq!(json!(headers), http["response"]["headers"]);
            assert_eq!(
                json!(response.headers.get_all("set-cookie").collect::<Vec<_>>()),
                http["response"]["cookies"]
            );
            let mut returned: Value = serde_json::from_slice(&response.body.bytes()?)?;
            returned["passkey"] = check.http_row(returned["passkey"].take())?;
            let captured: Value = serde_json::from_str(
                http["response"]["body"]
                    .as_str()
                    .ok_or("Captured response bytes")?,
            )?;
            assert_eq!(returned, normalized(captured));
            json!([observation(returned["passkey"].clone())])
        } else {
            let store = auth.store();
            let rows = match name {
                "create" => vec![
                    store
                        .create_passkey(CreatePasskey {
                            user_id: OWNER.into(),
                            name: Some("Desk".into()).into(),
                            aaguid: Some(AAGUID.into()).into(),
                            credential_id: "ordinary-shared-display-credential".into(),
                            public_key: "ordinary-public-key".into(),
                            counter: 0,
                            device_type: "singleDevice".into(),
                            backed_up: false,
                            transports: None,
                            credential: match store.passkey_storage() {
                                PasskeyStorage::Native => PasskeyCredentialState::Native,
                                PasskeyStorage::Legacy => "ordinary-private-record".into(),
                            },
                            additional_fields: Default::default(),
                        })
                        .await?,
                ],
                "get-id" => store.get_passkey_by_id(ID).await?.into_iter().collect(),
                "get-credential" => store
                    .get_passkey_by_credential_id("ordinary-shared-display-credential")
                    .await?
                    .into_iter()
                    .collect(),
                "list" => store.list_passkeys_by_user(OWNER).await?,
                "update-auth" => vec![
                    store
                        .update_passkey_authentication(
                            &ID.to_owned().into(),
                            match store.passkey_storage() {
                                PasskeyStorage::Native => {
                                    UpdatePasskeyAuthentication::Native { counter: 1 }
                                }
                                PasskeyStorage::Legacy => UpdatePasskeyAuthentication::Legacy {
                                    credential: "ordinary-private-record".into(),
                                    counter: 1,
                                    backed_up: false,
                                    device_type: "singleDevice".into(),
                                },
                            },
                        )
                        .await?,
                ],
                _ => return Err(format!("Unknown captured operation: {name}").into()),
            };
            assert_eq!(rows.len(), 1);
            json!(
                rows.iter()
                    .map(|row| check.visible(row))
                    .collect::<AuthResult<Vec<_>>>()?
            )
        };
        let observed = json!({"name": name, "result":result, "events":take(&events),
            "stored":check.stored(reader.store().as_ref(), database).await?});
        assert_eq!(
            normalized(observed),
            normalized(expected.clone()),
            "{} {name} reversed={reversed}",
            case["backend"]
        );
    }
    let row = auth
        .store()
        .get_passkey_by_id(ID)
        .await?
        .ok_or("Final Passkey read")?;
    let final_read = json!({"name":"read-updated", "result":check.visible(&row)?, "events":take(&events),
        "stored":check.stored(reader.store().as_ref(), database).await?});
    assert_eq!(
        normalized(final_read),
        normalized(case["finalRead"].clone())
    );
    assert!(take(&events).is_empty());
    eprintln!(
        "Passkey shared display boundaries: compare complete field sets without JavaScript key order; compare HTTP JSON without byte order or statusText; verify real creation timestamps and storage equality before normalization; Memory retains its verified legacy credential and updatedAt envelope; CLI acceptance owns catalog types, indexes, foreign keys, and DDL"
    );
    Ok(())
}

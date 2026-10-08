use super::*;
use better_auth::{middleware::RateLimitConfig, server_api::EndpointInput};
use better_auth_core::{
    AuthStore, HttpMethod,
    user_fields::{FieldTransforms, UserFieldTransform},
};
use chrono::Utc;
use serde_json::{Value, json};
use std::sync::Mutex;

const DEVICE: &str = "native-route-device";
const OWNER: &str = "native-route-owner";
const FUTURE: f64 = 4_102_444_800_000.0;

struct Projection(UserConfig);

#[async_trait::async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Projection {
    fn name(&self) -> &'static str {
        "native-device-route-projection"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        context.register_model_fields(EntityRole::DeviceCode, self.0.clone())
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

#[derive(Clone, Copy, Debug)]
enum Outcome {
    Success,
    ClientMismatch,
    InvalidStatus,
    UserNotFound,
    SlowDown,
    Expired,
    Pending,
    Denied,
}

impl Outcome {
    fn error(self) -> Option<(u16, &'static str, &'static str)> {
        match self {
            Self::Success => None,
            Self::ClientMismatch => Some((400, "invalid_grant", "Client ID mismatch")),
            Self::InvalidStatus => Some((500, "server_error", "Invalid device code status")),
            Self::UserNotFound => Some((500, "server_error", "User not found")),
            Self::SlowDown => Some((400, "slow_down", "Polling too frequently")),
            Self::Expired => Some((400, "expired_token", "Device code has expired")),
            Self::Pending => Some((400, "authorization_pending", "Authorization pending")),
            Self::Denied => Some((400, "access_denied", "Access denied")),
        }
    }

    fn outputs(self) -> usize {
        match self {
            Self::Success => 3,
            Self::ClientMismatch | Self::SlowDown => 1,
            _ => 2,
        }
    }

    fn deleted(self) -> bool {
        matches!(self, Self::Success | Self::Expired | Self::Denied)
    }
}

fn lock<T>(value: &Mutex<T>) -> AuthResult<std::sync::MutexGuard<'_, T>> {
    value
        .lock()
        .map_err(|_| AuthError::internal("Device route trace mutex is poisoned"))
}

struct Fixture {
    auth: BetterAuth<StatelessSchema>,
    raw: Arc<EphemeralStore>,
    before: Vec<FieldMap>,
    polls: Arc<Mutex<Vec<FieldValue>>>,
}

impl Fixture {
    async fn new(overrides: FieldMap) -> AuthResult<Self> {
        let mut config = AuthConfig::new("native-device-route-secret-at-least-32-characters")
            .base_url("http://native-device-route.test");
        config.logger.disabled = Some(true);
        config.telemetry.enabled = false;
        let raw = Arc::new(EphemeralStore::new(Arc::new(config.clone())));
        let store: Arc<dyn AuthStore<StatelessSchema>> = raw.clone();
        let mut owner = CreateUser::new()
            .with_name("Device owner")
            .with_email("owner@native-device-route.test");
        owner.id = Some(OWNER.into());
        let _ = store.create_user(owner).await?;
        let _ = store
            .create_device_code(CreateDeviceCode {
                device_code: DEVICE.into(),
                user_code: "NATV2345".into(),
                user_id: Some(OWNER.into()),
                expires_at: FieldDate::from_milliseconds(FUTURE),
                status: "approved".into(),
                last_polled_at: None,
                polling_interval: None,
                client_id: Some("client".into()),
                scope: Some("read".into()).into(),
                additional_fields: FieldMap::new(),
            })
            .await?;
        let before = raw.plugin_storage_rows(EntityRole::DeviceCode)?;
        let polls = Arc::new(Mutex::new(Vec::new()));
        let mut names = overrides.keys().cloned().collect::<Vec<_>>();
        if !names.iter().any(|name| name == "lastPolledAt") {
            names.push("lastPolledAt".into());
        }
        let fields = names
            .into_iter()
            .map(|name| {
                let replacement = overrides.get(&name).cloned();
                let trace = polls.clone();
                let polling = name == "lastPolledAt";
                let field_type = match name.as_str() {
                    "lastPolledAt" | "expiresAt" => UserFieldType::Date,
                    "pollingInterval" => UserFieldType::Number,
                    _ => UserFieldType::String,
                };
                (
                    name,
                    UserFieldConfig {
                        field_type,
                        required: Some(false),
                        transform: Some(FieldTransforms {
                            output: Some(UserFieldTransform::new(move |value| {
                                if polling {
                                    lock(&trace)?.push(value.clone());
                                }
                                Ok(replacement.clone().unwrap_or(value))
                            })),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                )
            })
            .collect();
        let auth = BetterAuth::new(config)
            .store_arc(raw.clone())
            .rate_limit(RateLimitConfig::new().enabled(false))
            .plugin(DeviceAuthorizationPlugin::new())
            .plugin(Projection(UserConfig {
                additional_fields: Some(fields),
            }))
            .build()
            .await?;
        Ok(Self {
            auth,
            raw,
            before,
            polls,
        })
    }

    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions compare route errors, complete storage, session issuance, and ordered callback observations"
    )]
    async fn check(self, outcome: Outcome) -> AuthResult<()> {
        let start = Utc::now().timestamp_millis() as f64;
        let returned = self.auth.call_endpoint(HttpMethod::Post, "/device/token", EndpointInput {
            body: Some(json!({"grant_type":"urn:ietf:params:oauth:grant-type:device_code","device_code":DEVICE,"client_id":"client"})),
            ..Default::default()
        }).await;
        let response = match returned {
            Ok(response) => {
                assert!(
                    outcome.error().is_none(),
                    "{outcome:?} must reject native dispatch"
                );
                response
            }
            Err(error @ AuthError::Response(_)) => {
                assert!(
                    outcome.error().is_some(),
                    "{outcome:?} must complete native dispatch"
                );
                error.to_auth_response()
            }
            Err(error) => return Err(error),
        };
        let end = Utc::now().timestamp_millis() as f64;
        let body: Value = serde_json::from_slice(&response.body.bytes()?)?;
        let sessions = self.auth.store().get_user_sessions(OWNER).await?;
        if let Some((status, error, description)) = outcome.error() {
            assert_eq!(response.status, status, "{outcome:?}");
            assert_eq!(body, json!({"error":error,"error_description":description}));
            assert!(sessions.is_empty());
        } else {
            assert_eq!(response.status, 200);
            assert_eq!(sessions.len(), 1);
            let session = sessions
                .first()
                .ok_or_else(|| AuthError::internal("Expected one issued session"))?;
            let expiry = session.expires_at.date_milliseconds().unwrap();
            let ttl = body
                .get("expires_in")
                .and_then(Value::as_f64)
                .ok_or_else(|| AuthError::internal("Expected numeric session expiry"))?;
            assert!(
                ttl >= ((expiry - end) / 1000.0).floor()
                    && ttl <= ((expiry - start) / 1000.0).floor()
            );
            assert_eq!(
                body,
                json!({"access_token":session.token,"token_type":"Bearer","expires_in":FieldValue::Number(ttl).json()?,"scope":"read"})
            );
            assert_eq!(
                response.headers.get("Cache-Control").map(String::as_str),
                Some("no-store")
            );
            assert_eq!(
                response.headers.get("Pragma").map(String::as_str),
                Some("no-cache")
            );
        }
        let polls = lock(&self.polls)?.clone();
        assert_eq!(polls.len(), outcome.outputs(), "{outcome:?}");
        assert_eq!(polls.first(), Some(&FieldValue::Null));
        if polls.len() > 1 {
            let Some(FieldValue::Date(timestamp)) = polls.get(1) else {
                return Err(AuthError::internal("Polling must write a native Date"));
            };
            assert!(timestamp.milliseconds() >= start && timestamp.milliseconds() <= end);
            if polls.len() > 2 {
                assert_eq!(polls.get(2), polls.get(1));
            }
        }
        let after = self.raw.plugin_storage_rows(EntityRole::DeviceCode)?;
        if outcome.deleted() {
            assert!(after.is_empty());
        } else {
            let mut expected = self.before;
            if let Some(polled) = polls.get(1) {
                let row = expected
                    .first_mut()
                    .ok_or_else(|| AuthError::internal("Expected the original Device row"))?;
                let _ = row.insert("lastPolledAt".into(), polled.clone());
            }
            assert_eq!(after, expected);
        }
        Ok(())
    }
}

// Source-derived contract: Better Auth 1.7.6 device-authorization/routes.mjs uses strict status comparisons and JavaScript truthiness.
#[tokio::test]
async fn native_status_client_and_owner_values_follow_device_route_branches() -> AuthResult<()> {
    for (value, outcome) in [
        ("approved".into(), Outcome::Success),
        ("pending".into(), Outcome::Pending),
        ("denied".into(), Outcome::Denied),
        (
            vec![FieldValue::from("approved")].into(),
            Outcome::InvalidStatus,
        ),
        (FieldValue::Number(1.0), Outcome::InvalidStatus),
        (FieldValue::Bool(true), Outcome::InvalidStatus),
        (FieldValue::Null, Outcome::InvalidStatus),
        (FieldValue::Undefined, Outcome::InvalidStatus),
    ] {
        Fixture::new([("status".into(), value)].into())
            .await?
            .check(outcome)
            .await?;
    }
    for value in [
        FieldValue::Null,
        FieldValue::Undefined,
        false.into(),
        0.0.into(),
        f64::NAN.into(),
        "".into(),
    ] {
        Fixture::new([("clientId".into(), value.clone())].into())
            .await?
            .check(Outcome::Success)
            .await?;
        Fixture::new([("userId".into(), value)].into())
            .await?
            .check(Outcome::InvalidStatus)
            .await?;
    }
    for value in [
        true.into(),
        7.0.into(),
        vec![FieldValue::from("client")].into(),
        FieldMap::new().into(),
    ] {
        Fixture::new([("clientId".into(), value)].into())
            .await?
            .check(Outcome::ClientMismatch)
            .await?;
    }
    Fixture::new([("userId".into(), "missing-owner".into())].into())
        .await?
        .check(Outcome::UserNotFound)
        .await
}

// Source-derived contract: polling constructs a Date, while expiresAt uses relational coercion without a Date constructor.
#[tokio::test]
async fn polling_constructs_dates_and_preserves_truthy_interval_coercion() -> AuthResult<()> {
    let iso = FieldValue::from("2100-01-01T00:00:00.000Z");
    for (last_polled, interval, outcome) in [
        (iso.clone(), "5000".into(), Outcome::SlowDown),
        (FUTURE.into(), 5000.0.into(), Outcome::SlowDown),
        (vec![iso].into(), 5000.0.into(), Outcome::SlowDown),
        (FUTURE.into(), "0".into(), Outcome::SlowDown),
        ("not-a-date".into(), 5000.0.into(), Outcome::Success),
        (FieldDate::invalid().into(), 5000.0.into(), Outcome::Success),
        (FUTURE.into(), "not-a-number".into(), Outcome::Success),
        (FUTURE.into(), f64::NAN.into(), Outcome::Success),
        (FieldValue::Null, 5000.0.into(), Outcome::Success),
        (false.into(), 5000.0.into(), Outcome::Success),
    ] {
        Fixture::new(
            [
                ("lastPolledAt".into(), last_polled),
                ("pollingInterval".into(), interval),
            ]
            .into(),
        )
        .await?
        .check(outcome)
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn expiry_uses_relational_conversion_and_preserves_poll_before_delete() -> AuthResult<()> {
    for (value, outcome) in [
        (FieldDate::from_milliseconds(0.0).into(), Outcome::Expired),
        (0.0.into(), Outcome::Expired),
        ("0".into(), Outcome::Expired),
        (FieldValue::Null, Outcome::Expired),
        (false.into(), Outcome::Expired),
        (vec![FieldValue::Number(0.0)].into(), Outcome::Expired),
        ("2000-01-01T00:00:00.000Z".into(), Outcome::Success),
        (FieldValue::Undefined, Outcome::Success),
        (FieldDate::invalid().into(), Outcome::Success),
    ] {
        Fixture::new([("expiresAt".into(), value)].into())
            .await?
            .check(outcome)
            .await?;
    }
    Ok(())
}

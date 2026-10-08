#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "The route contract requires complete snapshots and immediate failures for invalid fixture state."
)]

use super::{
    tests::{device_token_request, json_body},
    *,
};
use crate::plugins::test_helpers::create_test_config;
use better_auth_core::{
    AuthConfig, AuthInitContext, AuthPlugin, CreateDeviceCode, CreateUser, FieldDate,
    session::NativeSessionData,
    store::{
        AuthStore, EphemeralStore, MemoryCacheAdapter, SecondaryStorage, StatelessSchema,
        database_hooks::{DatabaseHookContext, DatabaseHookUpdate, DatabaseHooks},
        secondary::SecondaryStore,
    },
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform, UserFieldType},
    wire::SessionView,
};
use std::sync::Mutex;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Copy, Default)]
enum SessionOutcome {
    #[default]
    Continue,
    Cancel,
    Error,
}

#[derive(Default)]
struct Trace {
    outcome: SessionOutcome,
    users: Mutex<Vec<FieldValue>>,
    id_transforms: Mutex<Vec<FieldValue>>,
    owners: Mutex<Vec<FieldValue>>,
    after: Mutex<Vec<SessionView>>,
}

#[better_auth_core::database_hooks()]
impl DatabaseHooks<StatelessSchema> for Trace {
    async fn before_create_session(
        &self,
        fields: &mut FieldMap,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        self.owners
            .lock()
            .unwrap()
            .push(fields.get("userId").cloned().unwrap_or_default());
        match self.outcome {
            SessionOutcome::Continue => Ok(DatabaseHookUpdate::Continue),
            SessionOutcome::Cancel => Ok(DatabaseHookUpdate::Cancel),
            SessionOutcome::Error => Err(AuthError::bad_request("device session hook rejected")),
        }
    }

    async fn after_create_session(
        &self,
        session: &SessionView,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        self.after.lock().unwrap().push(session.clone());
        Ok(())
    }
}

struct Write {
    key: FieldValue,
    value: String,
    ttl: Option<f64>,
    published: Option<NativeSessionData>,
}

#[derive(Default)]
struct Storage {
    inner: MemoryCacheAdapter,
    request: Mutex<Option<AuthRequest>>,
    writes: Mutex<Vec<Write>>,
    fail_published: bool,
}

#[async_trait::async_trait]
impl SecondaryStorage for Storage {
    async fn get(&self, key: &str) -> AuthResult<Option<serde_json::Value>> {
        self.inner.get(key).await
    }

    async fn set_native(&self, key: &FieldValue, value: &str, ttl: Option<f64>) -> AuthResult<()> {
        let published = self
            .request
            .lock()
            .unwrap()
            .as_ref()
            .map(AuthRequest::new_session)
            .transpose()?
            .flatten();
        let fail = self.fail_published && published.is_some();
        self.writes.lock().unwrap().push(Write {
            key: key.clone(),
            value: value.into(),
            ttl,
            published,
        });
        if fail {
            return Err(AuthError::bad_request("device secondary write rejected"));
        }
        self.inner.set_native(key, value, ttl).await
    }

    async fn delete(&self, key: &str) -> AuthResult<()> {
        self.inner.delete(key).await
    }

    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<serde_json::Value>> {
        self.inner.get_and_delete(key).await
    }
}

fn output(field_type: UserFieldType, callback: UserFieldTransform) -> UserFieldConfig {
    UserFieldConfig {
        field_type,
        transform: Some(FieldTransforms {
            input: None,
            output: Some(callback),
        }),
        ..Default::default()
    }
}

struct Fixture {
    ctx: AuthContext<StatelessSchema>,
    raw: Arc<dyn AuthStore<StatelessSchema>>,
    trace: Arc<Trace>,
    storage: Arc<Storage>,
    request: AuthRequest,
}

impl Fixture {
    async fn new(
        token: FieldValue,
        expiration: FieldValue,
        outcome: SessionOutcome,
        fail_published: bool,
    ) -> TestResult<Self> {
        let mut config = create_test_config();
        config.telemetry.enabled = false;
        config.session.store_session_in_database = Some(true);
        let config = Arc::new(config);
        let raw: Arc<dyn AuthStore<StatelessSchema>> =
            Arc::new(EphemeralStore::new(config.clone()));
        let mut init = AuthInitContext::new(config.clone(), raw.clone());
        AuthPlugin::on_init(&DeviceAuthorizationPlugin::new(), &mut init).await?;
        let fields = init.into_parts().plugin_fields;
        let raw = raw.with_runtime(config.clone(), Vec::new(), fields.clone())?;
        for (id, name) in [("user-a", "Selected User"), ("user-b", "Other User")] {
            raw.create_user(CreateUser {
                id: Some(id.into()),
                ..CreateUser::new()
                    .with_name(name)
                    .with_email(format!("{id}@device.test"))
            })
            .await?;
        }
        raw.create_device_code(CreateDeviceCode {
            additional_fields: Default::default(),
            device_code: "native-device".into(),
            user_code: "NATV2345".into(),
            user_id: Some("user-a".into()),
            expires_at: (Utc::now() + Duration::hours(1)).into(),
            status: DEVICE_STATUS_APPROVED.into(),
            last_polled_at: None,
            polling_interval: None,
            client_id: Some("client".into()),
            scope: Some("read".into()).into(),
        })
        .await?;
        let trace = Arc::new(Trace {
            outcome,
            ..Default::default()
        });
        let mut config: AuthConfig = config.as_ref().clone();
        let observed = trace.clone();
        let _ = config.user.fields_mut().insert(
            "id".into(),
            output(
                UserFieldType::String,
                UserFieldTransform::new(move |id| {
                    observed.id_transforms.lock().unwrap().push(id);
                    Ok("user-b".into())
                }),
            ),
        );
        let observed = trace.clone();
        let _ = config.user.fields_mut().insert(
            "name".into(),
            output(
                UserFieldType::String,
                UserFieldTransform::new(move |name| {
                    observed.users.lock().unwrap().push(name.clone());
                    Ok(name)
                }),
            ),
        );
        let _ = config.session.fields_mut().insert(
            "token".into(),
            output(
                UserFieldType::String,
                UserFieldTransform::new(move |_| Ok(token.clone())),
            ),
        );
        let _ = config.session.fields_mut().insert(
            "expiresAt".into(),
            output(
                UserFieldType::Date,
                UserFieldTransform::new(move |_| Ok(expiration.clone())),
            ),
        );
        let config = Arc::new(config);
        let database = raw.with_runtime(config.clone(), vec![trace.clone()], fields)?;
        let storage = Arc::new(Storage {
            fail_published,
            ..Default::default()
        });
        let database = Arc::new(SecondaryStore::new(
            database,
            storage.clone(),
            config.clone(),
            Default::default(),
        )?);
        let mut ctx = AuthContext::new(config, database);
        ctx.secondary_storage = Some(storage.clone());
        let request = device_token_request("native-device", "client");
        *storage.request.lock().unwrap() = Some(request.clone());
        Ok(Self {
            ctx,
            raw,
            trace,
            storage,
            request,
        })
    }

    async fn redeem(&self) -> AuthResult<AuthResponse> {
        DeviceAuthorizationPlugin::new()
            .handle_device_token(&self.request, &self.ctx)
            .await
    }

    async fn assert_consumed(&self, sessions: usize) -> TestResult {
        assert!(
            self.raw
                .get_device_code_by_device_code("native-device")
                .await?
                .is_none()
        );
        assert_eq!(self.raw.get_user_sessions("user-a").await?.len(), sessions);
        assert!(self.raw.get_user_sessions("user-b").await?.is_empty());
        assert_eq!(
            *self.trace.owners.lock().unwrap(),
            [FieldValue::from("user-a")]
        );
        assert!(self.trace.id_transforms.lock().unwrap().is_empty());
        assert_eq!(self.trace.after.lock().unwrap().len(), sessions);
        assert!(
            !self
                .request
                .take_response_headers()?
                .contains_key("set-cookie")
        );
        Ok(())
    }
}

// Better Auth 1.7.6 device-authorization/routes.mjs:455–476 retains the selected User and publishes before the explicit cache write.
#[tokio::test]
async fn native_session_values_reach_publication_cache_and_response_without_coercion() -> TestResult
{
    let future = FieldDate::from(Utc::now() + Duration::minutes(2));
    let past = FieldDate::from(Utc::now() - Duration::minutes(2));
    for (token, expiration, expiry) in [
        (7.0.into(), future.clone().into(), future.milliseconds()),
        (FieldValue::Null, past.clone().into(), past.milliseconds()),
        (FieldValue::Undefined, FieldDate::invalid().into(), f64::NAN),
        (
            FieldMap::from([("credential".into(), true.into())]).into(),
            FieldValue::Null,
            0.0,
        ),
        (
            "iso-minute-token".into(),
            "2100-01-01T00:00Z".into(),
            4_102_444_800_000.0,
        ),
        (
            "iso-offset-token".into(),
            "2100-01-01T00:00+08:00".into(),
            4_102_416_000_000.0,
        ),
    ] {
        let fixture = Fixture::new(
            token.clone(),
            expiration.clone(),
            SessionOutcome::Continue,
            false,
        )
        .await?;
        let started = Utc::now().timestamp_millis() as f64;
        let response = fixture.redeem().await?;
        let ended = Utc::now().timestamp_millis() as f64;
        assert_eq!(response.status, 200);
        let native = response.body.field_value()?;
        let native = native.as_object().ok_or("Missing native response object")?;
        assert!(native["access_token"].strict_equals(&token));
        let body = json_body(&response);
        assert_eq!(body.get("access_token").cloned(), token.json()?);
        assert_eq!(body["token_type"], "Bearer");
        assert_eq!(body["scope"], "read");
        assert_eq!(
            response.headers.get("Cache-Control").map(String::as_str),
            Some("no-store")
        );
        assert_eq!(
            response.headers.get("Pragma").map(String::as_str),
            Some("no-cache")
        );
        fixture.assert_consumed(1).await?;
        assert_eq!(
            *fixture.trace.users.lock().unwrap(),
            [
                FieldValue::from("Selected User"),
                FieldValue::from("Selected User")
            ]
        );
        let published = fixture
            .request
            .new_session()?
            .ok_or("Missing published session")?;
        assert_eq!(published.user_field("id"), &FieldValue::from("user-a"));
        assert_eq!(
            published.user_field("name"),
            &FieldValue::from("Selected User")
        );
        let session = FieldMap::from(published.session.clone());
        assert!(session["token"].strict_equals(&token));
        let writes = fixture.storage.writes.lock().unwrap();
        assert_eq!(writes.len(), 3);
        assert!(writes[..2].iter().all(|write| write.published.is_none()));
        let write = writes.last().ok_or("Missing explicit device cache write")?;
        assert!(write.key.strict_equals(&token));
        let at_write = write
            .published
            .as_ref()
            .ok_or("Cache write preceded session publication")?;
        assert_eq!(
            FieldMap::from(at_write.clone()),
            FieldMap::from(published.clone())
        );
        let expected = FieldValue::from(FieldMap::from([
            ("user".into(), published.user),
            ("session".into(), session.into()),
        ]))
        .stringify()?
        .ok_or("Missing cache JSON")?;
        assert_eq!(write.value, expected);
        let ttl = write.ttl.ok_or("Missing device TTL")?;
        if expiry.is_nan() {
            assert!(ttl.is_nan());
            assert!(body["expires_in"].is_null());
        } else {
            let lower = ((expiry - ended) / 1_000.0).floor();
            let upper = ((expiry - started) / 1_000.0).floor();
            assert!(ttl >= lower && ttl <= upper);
            let response_ttl = body["expires_in"]
                .as_f64()
                .ok_or("Missing numeric expiry")?;
            assert!(response_ttl >= lower && response_ttl <= upper);
        }
    }
    Ok(())
}

#[tokio::test]
async fn cache_failure_keeps_consumption_session_and_published_snapshot() -> TestResult {
    let fixture = Fixture::new(
        7.0.into(),
        FieldDate::invalid().into(),
        SessionOutcome::Continue,
        true,
    )
    .await?;
    assert!(
        matches!(fixture.redeem().await, Err(AuthError::BadRequest(message)) if message == "device secondary write rejected")
    );
    fixture.assert_consumed(1).await?;
    let published = fixture
        .request
        .new_session()?
        .ok_or("Missing published snapshot after cache failure")?;
    assert_eq!(
        published.user_field("name"),
        &FieldValue::from("Selected User")
    );
    let writes = fixture.storage.writes.lock().unwrap();
    assert_eq!(writes.len(), 3);
    assert!(writes[2].published.is_some());
    assert!(writes[2].ttl.is_some_and(f64::is_nan));
    Ok(())
}

#[tokio::test]
async fn cancelled_session_has_device_error_while_hook_error_propagates() -> TestResult {
    for outcome in [SessionOutcome::Cancel, SessionOutcome::Error] {
        let fixture =
            Fixture::new("token".into(), FieldDate::invalid().into(), outcome, false).await?;
        let result = fixture.redeem().await;
        match outcome {
            SessionOutcome::Cancel => {
                let response = result?;
                assert_eq!(response.status, 500);
                assert_eq!(
                    json_body(&response),
                    serde_json::json!({"error":"server_error","error_description":FAILED_TO_CREATE_SESSION})
                );
            }
            SessionOutcome::Error => assert!(
                matches!(result, Err(AuthError::BadRequest(message)) if message == "device session hook rejected")
            ),
            SessionOutcome::Continue => return Err("Expected cancellation or rejection".into()),
        }
        fixture.assert_consumed(0).await?;
        assert!(fixture.request.new_session()?.is_none());
        assert!(fixture.storage.writes.lock().unwrap().is_empty());
        assert_eq!(
            *fixture.trace.users.lock().unwrap(),
            [FieldValue::from("Selected User")]
        );
    }
    Ok(())
}

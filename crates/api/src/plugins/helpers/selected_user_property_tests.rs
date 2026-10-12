#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    clippy::indexing_slicing,
    reason = "The paired native property scenarios require exact callback order, original failures, and complete storage assertions."
)]

use super::{SessionIssueError, issue_selected_user_session_optional};
use crate::plugins::{
    email_password::EmailPasswordPlugin,
    password_management::{
        PasswordManagementConfig, handlers::change_password_core, types::ChangePasswordRequest,
    },
    test_helpers,
};
use better_auth_core::{
    AuthError, AuthRequest, AuthResult, FieldArray, FieldDate, FieldFunction, FieldMap,
    FieldObject, FieldValue, FromFieldMap, HttpMethod, RequestMeta,
    field_value::{
        FieldObjectSource, FieldProperty, FieldPropertyDefinition, FieldPropertyDescriptor,
    },
    session::NativeSessionData,
    store::{
        EphemeralStore, StatelessSchema,
        database_hooks::{
            DatabaseHookContext, DatabaseHookControl, DatabaseHookUpdate, DatabaseHooks,
        },
        schema::EntityRole,
    },
    user_fields::{UserFieldConfig, UserFieldFactory, UserFieldType},
    utils::password::PasswordHasher,
    wire::SessionView,
};
use std::sync::{
    Arc, Mutex, OnceLock, Weak,
    atomic::{AtomicUsize, Ordering},
};
use test_helpers::native_observation::NativeObservation;

const NOW: f64 = 2_000_000_000_000.0;
const PASSWORD: &str = "CorrectHorseBattery1!";

#[path = "selected_user_property_tests/fixture_replay.rs"]
mod fixture_replay;

struct Trace {
    events: Mutex<Vec<String>>,
    native: Mutex<NativeObservation>,
    reads: AtomicUsize,
    throws_at: usize,
    changing: bool,
    changed: FieldValue,
    original: FieldValue,
    cancel_create: bool,
}

impl Trace {
    fn new(shape: &str, throws_at: usize, changing: bool, cancel_create: bool) -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            native: Mutex::new(NativeObservation::default()),
            reads: AtomicUsize::new(0),
            throws_at,
            changing,
            changed: FieldMap::from([("marker".into(), "third-read-owner".into())]).into(),
            original: FieldMap::from([
                ("kind".into(), "selected-user-id-error".into()),
                ("shape".into(), shape.into()),
                ("throwsAt".into(), (throws_at as f64).into()),
            ])
            .into(),
            cancel_create,
        }
    }

    fn record(&self, phase: impl Into<String>) {
        self.events.lock().unwrap().push(phase.into());
    }

    fn observe_event(&self, phase: &str, name: &str, value: FieldValue) -> AuthResult<()> {
        let mut native = self.native.lock().unwrap();
        let value = native.observe(&value)?;
        native.record(phase, [(name.into(), value)]);
        Ok(())
    }
}

struct Properties {
    getter: FieldFunction,
}

impl FieldObjectSource for Properties {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        Ok(vec!["id".into()])
    }
    fn own_property_descriptor(&self, name: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        Ok((name == "id").then(|| FieldPropertyDescriptor {
            enumerable: true,
            configurable: true,
            property: FieldProperty::Accessor {
                get: Some(self.getter.clone()),
                set: None,
            },
        }))
    }

    fn get_with_receiver(
        &self,
        name: &str,
        receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        if name != "id" {
            return Ok(None);
        }
        self.getter.call_with(receiver, &[]).map(Some)
    }
    fn set_with_receiver(&self, _: String, _: FieldValue, _: &FieldValue) -> AuthResult<bool> {
        Err(AuthError::internal(
            "The route must not overwrite its selected User",
        ))
    }
    fn define_own_property(&self, _: String, _: FieldPropertyDefinition) -> AuthResult<bool> {
        Err(AuthError::internal(
            "The route must not overwrite its selected User",
        ))
    }

    fn delete(&self, _: &str) -> AuthResult<bool> {
        Err(AuthError::internal(
            "The route must not delete selected User properties",
        ))
    }
    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Err(AuthError::internal(
            "Session issuance must not snapshot the selected User",
        ))
    }
    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }
}

struct SelectedUser {
    value: FieldValue,
    properties: FieldObject,
    getter: FieldFunction,
    _receiver: Arc<OnceLock<FieldValue>>,
}

fn user(shape: &str, trace: &Arc<Trace>) -> SelectedUser {
    let receiver = Arc::new(OnceLock::<FieldValue>::new());
    let expected: Weak<OnceLock<FieldValue>> = Arc::downgrade(&receiver);
    let trace = Arc::downgrade(trace);
    let getter = FieldFunction::contextual(move |receiver, arguments| {
        let trace = trace.upgrade().unwrap();
        assert!(arguments.is_empty());
        let same_receiver = receiver.strict_equals(expected.upgrade().unwrap().get().unwrap());
        assert!(same_receiver);
        let read = trace.reads.fetch_add(1, Ordering::SeqCst) + 1;
        trace.record(format!("user-id-{read}"));
        trace.native.lock().unwrap().record(
            "user-id",
            [
                ("read".into(), read.into()),
                ("sameReceiver".into(), same_receiver.into()),
            ],
        );
        if read == trace.throws_at {
            return Err(AuthError::from_thrown(trace.original.clone()));
        }
        Ok(if trace.changing && read == 3 {
            trace.changed.clone()
        } else {
            7.into()
        })
    });
    let properties = FieldObject::from_source(Arc::new(Properties {
        getter: getter.clone(),
    }));
    let user: FieldValue = match shape {
        "array" => FieldArray::with_length_and_properties(0, properties.clone()).into(),
        "function" => FieldFunction::contextual_with_properties(
            |_, _| Err(AuthError::internal("The User function must not be called")),
            properties.clone(),
        )
        .into(),
        "date" => FieldDate::from_milliseconds_with_properties(NOW, properties.clone()).into(),
        _ => properties.clone().into(),
    };
    receiver.set(user.clone()).unwrap();
    SelectedUser {
        value: user,
        properties,
        getter,
        _receiver: receiver,
    }
}

#[async_trait::async_trait]
impl PasswordHasher for Trace {
    async fn hash(&self, password: &str) -> AuthResult<String> {
        assert_eq!(password, PASSWORD);
        self.record("hash");
        self.observe_event("hash", "value", password.into())?;
        Ok("new-hash".into())
    }
    async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
        assert_eq!((hash, password), ("stored-hash", PASSWORD));
        self.record("verify");
        self.observe_event(
            "verify",
            "arguments",
            FieldMap::from([
                ("hash".into(), hash.into()),
                ("password".into(), password.into()),
            ])
            .into(),
        )?;
        Ok(true)
    }
}

#[better_auth_core::database_hooks()]
impl DatabaseHooks<StatelessSchema> for Trace {
    async fn before_create_session(
        &self,
        fields: &mut FieldMap,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        self.record("create");
        let expected = if self.changing {
            self.changed.clone()
        } else {
            7.into()
        };
        let same_owner = fields.get("userId").unwrap().strict_equals(&expected);
        assert!(same_owner);
        {
            let mut native = self.native.lock().unwrap();
            let arguments = native.observe(&vec![FieldValue::from(fields.clone())].into())?;
            native.record(
                if self.cancel_create {
                    "create-cancel"
                } else {
                    "create"
                },
                [
                    ("arguments".into(), arguments),
                    ("sameOwner".into(), same_owner.into()),
                ],
            );
        }
        Ok(if self.cancel_create {
            DatabaseHookUpdate::Cancel
        } else {
            DatabaseHookUpdate::Continue
        })
    }
    async fn before_delete_session(
        &self,
        session: &SessionView,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookControl> {
        self.record("delete-before");
        self.observe_event(
            "delete-before",
            "arguments",
            vec![FieldValue::from(FieldMap::from(session.clone()))].into(),
        )?;
        Ok(DatabaseHookControl::Continue)
    }
    async fn after_delete_session(
        &self,
        session: &SessionView,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        self.record("delete-after");
        self.observe_event(
            "delete-after",
            "arguments",
            vec![FieldValue::from(FieldMap::from(session.clone()))].into(),
        )?;
        Ok(())
    }
}

fn session() -> FieldMap {
    FieldMap::from([
        ("id".into(), "current".into()),
        ("token".into(), "current".into()),
        ("userId".into(), 7.into()),
        (
            "expiresAt".into(),
            FieldDate::from_milliseconds(NOW + 3_600_000.0).into(),
        ),
        ("createdAt".into(), FieldDate::from_milliseconds(NOW).into()),
        ("updatedAt".into(), FieldDate::from_milliseconds(NOW).into()),
        ("ipAddress".into(), FieldValue::Null),
        ("userAgent".into(), FieldValue::Null),
    ])
}

fn account() -> FieldMap {
    FieldMap::from([
        ("id".into(), "credential".into()),
        ("userId".into(), 7.into()),
        ("accountId".into(), 7.into()),
        ("providerId".into(), "credential".into()),
        ("password".into(), "stored-hash".into()),
        ("createdAt".into(), FieldDate::from_milliseconds(NOW).into()),
        ("updatedAt".into(), FieldDate::from_milliseconds(NOW).into()),
    ])
}

#[tokio::test]
async fn selected_user_property_reads_reach_password_session_replacement() -> AuthResult<()> {
    for shape in ["object", "array", "function", "date"] {
        for (throws_at, changing) in [(0, false), (1, false), (2, false), (3, false), (0, true)] {
            run_case(shape, throws_at, changing, None).await?;
        }
    }
    Ok(())
}

async fn run_case(
    shape: &str,
    throws_at: usize,
    changing: bool,
    case: Option<&serde_json::Value>,
) -> AuthResult<()> {
    let trace = Arc::new(Trace::new(shape, throws_at, changing, true));
    let user = user(shape, &trace);
    let mut config = test_helpers::create_test_config();
    let _ = config
        .session
        .fields_mut()
        .insert("userId".into(), UserFieldConfig::default());
    let _ = config
        .account
        .additional_fields
        .insert("userId".into(), UserFieldConfig::default());
    let _ = config.account.additional_fields.insert(
        "updatedAt".into(),
        UserFieldConfig {
            field_type: UserFieldType::Date,
            on_update: Some(UserFieldFactory::new(|| {
                Ok(FieldDate::from_milliseconds(NOW).into())
            })),
            ..Default::default()
        },
    );
    if case.is_some() {
        fixture_replay::fixed_creation_fields(&mut config);
    }
    let config = Arc::new(config);
    let store = Arc::new(
        EphemeralStore::from_storage(
            config.clone(),
            [
                ("user".into(), Vec::new()),
                ("session".into(), vec![session()]),
                ("account".into(), vec![account()]),
                ("verification".into(), Vec::new()),
            ],
        )?
        .with_hooks(vec![trace.clone()]),
    );
    let email = EmailPasswordPlugin::new().password_hasher(trace.clone());
    let context = test_helpers::initialize_test_context(config, store.clone(), &[&email]).await?;
    let observed = match case {
        Some(_) => Some(fixture_replay::before(&context, &store, &trace, &user).await?),
        None => None,
    };
    let request = AuthRequest::new(HttpMethod::Post, "/change-password");
    let result = change_password_core(
        &ChangePasswordRequest {
            current_password: PASSWORD.into(),
            new_password: PASSWORD.into(),
            revoke_other_sessions: Some(true),
        },
        &NativeSessionData::new(
            SessionView::from_field_values(session())?,
            user.value.clone(),
        ),
        &PasswordManagementConfig::default(),
        &request,
        &RequestMeta::default(),
        &context,
    )
    .await;
    let error = result.unwrap_err();
    if throws_at == 0 {
        test_helpers::assert_coded_api_error(
            &error,
            "INTERNAL_SERVER_ERROR",
            500,
            "FAILED_TO_GET_SESSION",
            "Failed to get session",
        );
    }
    let thrown = error.into_thrown_value()?;
    if throws_at != 0 {
        assert!(thrown.strict_equals(&trace.original));
    }
    let mut expected_events = vec!["user-id-1"];
    if throws_at != 1 {
        expected_events.extend(["hash", "verify", "user-id-2"]);
    }
    if throws_at == 0 || throws_at == 3 {
        expected_events.extend(["delete-before", "delete-after", "user-id-3"]);
    }
    if throws_at == 0 {
        expected_events.push("create");
    }
    assert_eq!(
        *trace.events.lock().unwrap(),
        expected_events,
        "{shape}/{throws_at}/{changing}"
    );
    let mut expected_account = account();
    if throws_at != 1 {
        let _ = expected_account.insert("password".into(), "new-hash".into());
    }
    assert_eq!(store.storage_rows(EntityRole::Account)?, [expected_account]);
    assert_eq!(
        store.storage_rows(EntityRole::Session)?,
        if throws_at == 0 || throws_at == 3 {
            Vec::new()
        } else {
            vec![session()]
        }
    );
    assert!(store.storage_rows(EntityRole::User)?.is_empty());
    assert!(store.storage_rows(EntityRole::Verification)?.is_empty());
    if let (Some(case), Some(before)) = (case, observed) {
        before.assert_case(case, thrown).await?;
    }
    Ok(())
}

#[tokio::test]
async fn selected_user_property_success_retains_the_user_handle() -> AuthResult<()> {
    for shape in ["object", "array", "function", "date"] {
        let trace = Arc::new(Trace::new(shape, 0, false, false));
        let user = user(shape, &trace);
        let mut config = test_helpers::create_test_config();
        let _ = config
            .session
            .fields_mut()
            .insert("userId".into(), UserFieldConfig::default());
        let config = Arc::new(config);
        let store = Arc::new(EphemeralStore::new(config.clone()).with_hooks(vec![trace.clone()]));
        let context = test_helpers::initialize_test_context(config, store.clone(), &[]).await?;
        let issued = issue_selected_user_session_optional(
            &context,
            user.value.clone(),
            &RequestMeta::default(),
            context.config.session.expires_in(),
        )
        .await
        .map_err(SessionIssueError::into_auth_error)?
        .unwrap();
        assert!(issued.user_value()?.strict_equals(&user.value));
        assert_eq!(*trace.events.lock().unwrap(), ["user-id-1", "create"]);
        let rows = store.storage_rows(EntityRole::Session)?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("id"), Some(&issued.session_property("id")?));
        assert_eq!(
            rows[0].get("token"),
            Some(&issued.session_property("token")?)
        );
        assert_eq!(rows[0].get("userId"), Some(&7.into()));
    }
    Ok(())
}

use super::*;
use better_auth_core::user_fields::{
    FieldTransforms, UserFieldConfig, UserFieldTransform, UserFieldType,
};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scenario {
    SharedAlias,
    DeletedToken,
    OutputToken,
    OutputNativeValues,
    NativeCollision,
    ChainedNativeAliases,
    Defaults,
    CallerOverrides,
}

const SCENARIOS: [Scenario; 8] = [
    Scenario::SharedAlias,
    Scenario::DeletedToken,
    Scenario::OutputToken,
    Scenario::OutputNativeValues,
    Scenario::NativeCollision,
    Scenario::ChainedNativeAliases,
    Scenario::Defaults,
    Scenario::CallerOverrides,
];

struct DeclaredHooks {
    scenario: Scenario,
    events: Sender<Event>,
}

#[better_auth_core::database_hooks()]
impl DatabaseHooks<StatelessSchema> for DeclaredHooks {
    async fn before_create_session(
        &self,
        fields: &mut FieldMap,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        emit(&self.events, Event::Before(1, fields.clone()))?;
        if self.scenario == Scenario::DeletedToken {
            let _ = fields.remove("token");
        }
        Ok(DatabaseHookUpdate::Continue)
    }

    async fn after_create_session(
        &self,
        session: &SessionView,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        emit(&self.events, Event::After(1, session.clone().into()))
    }
}

fn native_defaults() -> AuthResult<FieldMap> {
    Ok([
        ("token".into(), "configured-token".into()),
        ("createdAt".into(), date("2031-01-02T03:04:10Z")?.into()),
        ("updatedAt".into(), date("2031-01-02T03:04:11Z")?.into()),
    ]
    .into())
}

fn caller_overrides() -> AuthResult<FieldMap> {
    Ok([
        ("token".into(), "caller-token".into()),
        ("createdAt".into(), date("2031-01-02T03:04:12Z")?.into()),
        ("updatedAt".into(), date("2031-01-02T03:04:13Z")?.into()),
    ]
    .into())
}

fn configure(
    scenario: Scenario,
    config: &mut AuthConfig,
    events: &Sender<Event>,
) -> AuthResult<()> {
    let mut token = UserFieldConfig::default();
    match scenario {
        Scenario::SharedAlias => {
            token.field_name = Some("storedToken".into());
            let _ = config.session.fields_mut().insert(
                "echo".into(),
                UserFieldConfig {
                    field_name: Some("storedToken".into()),
                    required: Some(false),
                    ..Default::default()
                },
            );
        }
        Scenario::DeletedToken => {
            token.field_name = Some("storedToken".into());
            let events = events.clone();
            let calls = AtomicUsize::new(0);
            token.default_value_fn = Some(Arc::new(move || {
                let value =
                    FieldValue::from(format!("D{}", calls.fetch_add(1, Ordering::SeqCst) + 1));
                assert!(events.send(Event::Default("token", value.clone())).is_ok());
                value
            }));
        }
        Scenario::OutputToken => {
            token.transform = Some(FieldTransforms {
                output: Some(UserFieldTransform::new(|value| {
                    let token = value
                        .as_str()
                        .ok_or_else(|| AuthError::internal("Token output must receive a string"))?;
                    Ok(format!("out:{token}").into())
                })),
                ..Default::default()
            });
        }
        Scenario::OutputNativeValues => {
            token.transform = Some(FieldTransforms {
                output: Some(UserFieldTransform::new(|_| Ok(7.into()))),
                ..Default::default()
            });
            let _ = config.session.fields_mut().insert(
                "createdAt".into(),
                UserFieldConfig {
                    field_type: UserFieldType::Date,
                    transform: Some(FieldTransforms {
                        output: Some(UserFieldTransform::new(|_| Ok(FieldValue::Null))),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            );
        }
        Scenario::NativeCollision => token.field_name = Some("userAgent".into()),
        Scenario::ChainedNativeAliases => {
            token.field_name = Some("userAgent".into());
            let _ = config.session.fields_mut().insert(
                "userAgent".into(),
                UserFieldConfig {
                    field_name: Some("storedAgent".into()),
                    required: Some(false),
                    ..Default::default()
                },
            );
        }
        Scenario::Defaults | Scenario::CallerOverrides => {
            for (name, value) in native_defaults()? {
                let events = events.clone();
                let event_name = match name.as_str() {
                    "token" => "token",
                    "createdAt" => "createdAt",
                    "updatedAt" => "updatedAt",
                    _ => return Err(AuthError::internal("Unknown native default fixture field")),
                };
                let field = UserFieldConfig {
                    field_type: if matches!(value, FieldValue::Date(_)) {
                        UserFieldType::Date
                    } else {
                        UserFieldType::String
                    },
                    default_value_fn: Some(Arc::new(move || {
                        assert!(
                            events
                                .send(Event::Default(event_name, value.clone()))
                                .is_ok()
                        );
                        value.clone()
                    })),
                    ..Default::default()
                };
                let _ = config.session.fields_mut().insert(name, field);
            }
            return Ok(());
        }
    }
    let _ = config.session.fields_mut().insert("token".into(), token);
    Ok(())
}

#[tokio::test]
async fn memory_native_declarations_preserve_storage_and_public_values() -> TestResult {
    for scenario in SCENARIOS {
        let mode = if matches!(
            scenario,
            Scenario::OutputToken | Scenario::OutputNativeValues | Scenario::CallerOverrides
        ) {
            Mode::Mirrored
        } else {
            Mode::Database
        };
        let (events, receiver) = mpsc::channel();
        let mut config = config(mode, &events);
        configure(scenario, &mut config, &events)?;
        let raw: Arc<dyn AuthStore<StatelessSchema>> = Arc::new(
            EphemeralStore::new(Arc::new(config.clone())).with_hooks(vec![Arc::new(
                DeclaredHooks {
                    scenario,
                    events: events.clone(),
                },
            )]),
        );
        seed_users(raw.as_ref()).await?;
        assert!(receiver.try_iter().next().is_none());
        let cache = Arc::new(RecordingStorage {
            inner: MemoryCacheAdapter::new(),
            events,
        });
        let store: Arc<dyn AuthStore<StatelessSchema>> = if mode == Mode::Mirrored {
            Arc::new(SecondaryStore::new(
                raw.clone(),
                cache.clone(),
                Arc::new(config),
                Default::default(),
            )?)
        } else {
            raw.clone()
        };
        let mut create = input()?;
        if scenario == Scenario::CallerOverrides {
            create.additional_fields.extend(caller_overrides()?);
        }
        let started = Utc::now().timestamp_millis();
        let created = store
            .create_session_optional(create)
            .await?
            .ok_or("Unexpected cancellation")?;
        let finished = Utc::now().timestamp_millis();
        let observed: Vec<_> = receiver.try_iter().collect();
        let initial = observed
            .iter()
            .find_map(|event| match event {
                Event::Before(1, fields) => Some(fields),
                _ => None,
            })
            .ok_or("Session before hook is missing")?;
        let initial_token = initial
            .get("token")
            .and_then(FieldValue::as_str)
            .ok_or("Native token is missing")?;
        let created_at = initial
            .get("createdAt")
            .and_then(FieldValue::as_date)
            .ok_or("Native createdAt is missing")?;
        let updated_at = initial
            .get("updatedAt")
            .and_then(FieldValue::as_date)
            .ok_or("Native updatedAt is missing")?;
        if !matches!(scenario, Scenario::Defaults | Scenario::CallerOverrides) {
            assert!(!created_at.same_object(updated_at));
            for value in [created_at, updated_at] {
                assert!((started as f64..=finished as f64).contains(&value.milliseconds()));
            }
        }
        if matches!(
            scenario,
            Scenario::SharedAlias
                | Scenario::OutputToken
                | Scenario::OutputNativeValues
                | Scenario::NativeCollision
                | Scenario::ChainedNativeAliases
        ) {
            assert_eq!(initial_token.len(), 32);
            assert!(
                initial_token
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric())
            );
        }
        let mut expected_initial: FieldMap = [
            ("token".into(), initial_token.into()),
            ("userId".into(), "owner".into()),
            ("expiresAt".into(), date(EXPIRY)?.into()),
            ("createdAt".into(), created_at.clone().into()),
            ("updatedAt".into(), updated_at.clone().into()),
            ("ipAddress".into(), "192.0.2.10".into()),
            ("userAgent".into(), "session-payload-contract".into()),
        ]
        .into();
        let mut expected_events = Vec::new();
        if scenario == Scenario::DeletedToken {
            let _ = expected_initial.insert("token".into(), "D1".into());
            expected_events.push(Event::Default("token", "D1".into()));
        } else if matches!(scenario, Scenario::Defaults | Scenario::CallerOverrides) {
            for (name, value) in native_defaults()? {
                let event_name = match name.as_str() {
                    "token" => "token",
                    "createdAt" => "createdAt",
                    "updatedAt" => "updatedAt",
                    _ => return Err("Unknown native default fixture field".into()),
                };
                expected_events.push(Event::Default(event_name, value));
            }
            expected_initial.extend(if scenario == Scenario::CallerOverrides {
                caller_overrides()?
            } else {
                native_defaults()?
            });
        }
        assert_eq!(*initial, expected_initial, "{scenario:?}");
        expected_events.push(Event::Before(1, expected_initial.clone()));
        let mut expected = expected_initial.clone();
        let stored_token = match scenario {
            Scenario::SharedAlias => {
                let _ = expected.insert("echo".into(), initial_token.into());
                initial_token
            }
            Scenario::DeletedToken => {
                let _ = expected.insert("token".into(), "D2".into());
                expected_events.push(Event::Default("token", "D2".into()));
                "D2"
            }
            Scenario::OutputToken => {
                let _ = expected.insert("token".into(), format!("out:{initial_token}").into());
                initial_token
            }
            Scenario::OutputNativeValues => {
                let _ = expected.insert("token".into(), 7.into());
                let _ = expected.insert("createdAt".into(), FieldValue::Null);
                initial_token
            }
            Scenario::NativeCollision => {
                let _ = expected.insert("token".into(), "session-payload-contract".into());
                "session-payload-contract"
            }
            Scenario::Defaults | Scenario::CallerOverrides | Scenario::ChainedNativeAliases => {
                initial_token
            }
        };
        let _ = expected.insert("id".into(), SESSION_ID.into());
        expected_events.push(Event::Generate("session".into(), None));
        assert_eq!(FieldMap::from(created.clone()), expected, "{scenario:?}");
        if scenario == Scenario::OutputNativeValues {
            assert_eq!(created.token, initial_token);
            assert_eq!(&created.created_at, created_at);
            assert_eq!(created.additional_fields.get("token"), Some(&7.into()));
            assert_eq!(
                created.additional_fields.get("createdAt"),
                Some(&FieldValue::Null)
            );
        } else {
            assert_eq!(
                expected.get("token").and_then(FieldValue::as_str),
                Some(created.token.as_str())
            );
            assert_eq!(
                expected.get("createdAt").and_then(FieldValue::as_date),
                Some(&created.created_at)
            );
        }
        assert_eq!(
            expected.get("updatedAt").and_then(FieldValue::as_date),
            Some(&created.updated_at)
        );
        if mode == Mode::Mirrored {
            let ttl = observed
                .iter()
                .find_map(|event| match event {
                    Event::Set(key, _, Some(ttl)) if key == initial_token => Some(*ttl),
                    _ => None,
                })
                .ok_or("Original token cache write is missing")?;
            let expires = date(EXPIRY)?.milliseconds() as i64;
            assert!(
                (u64::try_from((expires - finished).div_euclid(1000))?
                    ..=u64::try_from((expires - started).div_euclid(1000))?)
                    .contains(&ttl)
            );
            let references = json!([{"token": initial_token, "expiresAt": expires}]);
            let payload = json!({"session": expected.json()?, "user": owner_json()});
            expected_events.extend([
                Event::Get("active-sessions-owner".into(), None),
                Event::Set(
                    "active-sessions-owner".into(),
                    references.clone(),
                    Some(ttl),
                ),
                Event::Set(initial_token.into(), payload.clone(), Some(ttl)),
            ]);
            for (key, expected) in [
                ("active-sessions-owner", references),
                (initial_token, payload),
            ] {
                let value = cache
                    .inner
                    .get(key)
                    .await?
                    .ok_or("Expected cache value is missing")?;
                let value: JsonValue =
                    serde_json::from_str(value.as_str().ok_or("Cache value is not text")?)?;
                assert_eq!(value, expected);
            }
            if created.token != initial_token {
                assert_eq!(cache.inner.get(&created.token).await?, None);
            }
        }
        expected_events.push(Event::After(1, expected.clone()));
        assert_eq!(observed, expected_events, "{scenario:?}");
        assert_eq!(
            raw.get_session(stored_token).await?.map(FieldMap::from),
            Some(expected)
        );
        assert_eq!(raw.get_user_sessions("owner").await?, [created.clone()]);
        match scenario {
            Scenario::DeletedToken | Scenario::NativeCollision => {
                assert_eq!(raw.get_session(initial_token).await?, None);
            }
            Scenario::OutputToken => assert_eq!(raw.get_session(&created.token).await?, None),
            Scenario::OutputNativeValues => {
                assert_eq!(raw.get_session("7").await?, None);
                assert_eq!(cache.inner.get("7").await?, None);
            }
            Scenario::CallerOverrides => {
                assert_eq!(raw.get_session("configured-token").await?, None)
            }
            Scenario::ChainedNativeAliases => {
                assert_eq!(raw.get_session("session-payload-contract").await?, None);
            }
            Scenario::SharedAlias | Scenario::Defaults => {}
        }
    }
    Ok(())
}

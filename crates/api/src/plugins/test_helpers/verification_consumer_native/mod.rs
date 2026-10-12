#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report exact contract mismatches while Result propagates fixture errors."
)]
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Pinned consumer contracts must fail immediately on invalid setup, fixture shape, or observation state."
)]

use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthPlugin, AuthResult, FieldDate, FieldMap, FieldValue,
    SchemaValue,
    id::{IdGeneration, IdGenerator},
    observability::{LogArgument, LogLevel, LogSink},
    store::{EphemeralStore, StatelessSchema, schema::EntityRole, secondary::SecondaryStore},
};
use serde_json::{Value as Json, json};
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};

use super::native_observation as observation;

pub(crate) mod object;
mod storage;
mod values;

pub(crate) use super::ReplayFailures;
pub(crate) use storage::Storage;

/// Compare business runtime observations. JavaScript APIError stacks remain unpaired host metadata.
pub(crate) fn assert_replay(actual: &Json, expected: &Json, name: &str) {
    let path = "/outcome/error/ownEnumerable/stack";
    let mut expected = expected.clone();
    if let Some(stack) = expected.pointer(path) {
        assert_eq!(expected["outcome"]["error"]["name"], "APIError");
        assert!(stack.as_str().unwrap().starts_with("APIError\n    at "));
        let undefined_stack = json!({"type":"undefined"});
        assert_eq!(
            actual.pointer(path),
            Some(&undefined_stack),
            "{name}: the debug dispatcher must retain the undefined Rust host stack"
        );
        *expected.pointer_mut(path).unwrap() = undefined_stack;
        eprintln!("{name}: the value at {path} remains unpaired JavaScript host metadata");
    }
    observation::assert_replay(actual, &expected, name);
}

pub(crate) const NOW: i64 = 2_000_000_000_000;
pub(crate) const ORIGIN: &str = "http://verification-consumer-native.test";
pub(crate) const SECRET: &str =
    "verification-consumer-native-secret-at-least-thirty-two-characters";
pub(crate) const EMAIL: &str = "owner@verification-consumer-native.test";
pub(crate) const PHONE: &str = "+12025550123";

pub(crate) fn date(milliseconds: f64) -> FieldValue {
    FieldDate::from_milliseconds(milliseconds).into()
}

pub(crate) fn consumer_user() -> FieldMap {
    FieldMap::from([
        ("id".into(), "owner".into()),
        ("name".into(), "Verification consumer".into()),
        ("email".into(), EMAIL.into()),
        ("emailVerified".into(), true.into()),
        ("image".into(), FieldValue::Null),
        ("createdAt".into(), date(NOW as f64)),
        ("updatedAt".into(), date(NOW as f64)),
        ("twoFactorEnabled".into(), true.into()),
    ])
}

#[derive(Default)]
struct Counts {
    expiry: usize,
    value: usize,
    split: usize,
    slice: usize,
    generated: usize,
}

struct State {
    scenario: Json,
    observer: Mutex<observation::NativeObservation>,
    counts: Mutex<Counts>,
    active: AtomicBool,
    original: FieldValue,
    root: OnceLock<FieldValue>,
    roots: Mutex<Vec<object::Root>>,
}

impl State {
    fn record(&self, phase: &str, fields: impl IntoIterator<Item = (String, Json)>) {
        if self.active.load(Ordering::Acquire) {
            self.observer.lock().unwrap().record(phase, fields);
        }
    }

    fn observe(&self, value: &FieldValue) -> AuthResult<Json> {
        self.observer.lock().unwrap().observe(value)
    }

    fn fail<T>(&self, phase: &str) -> AuthResult<T> {
        let mutation = self
            .original
            .model_property("mutation")?
            .decode::<usize>()?
            + 1;
        self.original
            .set_model_property("mutation", mutation.into())?;
        self.record(phase, [("mutation".into(), mutation.into())]);
        Err(AuthError::from_thrown(self.original.clone()))
    }

    fn error_value(&self, value: &FieldValue) -> AuthResult<Json> {
        let name = value.model_property("name")?;
        if name.is_undefined() {
            return self.observe(value);
        }
        let mut output = serde_json::Map::from_iter([
            ("name".into(), self.observe(&name)?),
            (
                "message".into(),
                self.observe(&value.model_property("message")?)?,
            ),
            ("ownEnumerable".into(), self.observe(value)?),
        ]);
        let status = value.model_property("status")?;
        if !status.is_undefined() {
            let headers = value.model_property("headers")?;
            let headers = if headers.is_null() || headers.is_undefined() {
                Vec::new()
            } else {
                headers
                    .enumerable_fields()?
                    .into_iter()
                    .map(|(key, value)| {
                        Ok(json!([
                            key,
                            SchemaValue::<String>::from_field(value).display_string()?
                        ]))
                    })
                    .collect::<AuthResult<Vec<_>>>()?
            };
            output.extend([
                ("status".into(), self.observe(&status)?),
                (
                    "statusCode".into(),
                    self.observe(&value.model_property("statusCode")?)?,
                ),
                ("body".into(), self.observe(&value.model_property("body")?)?),
                ("headers".into(), headers.into()),
            ]);
        }
        Ok(output.into())
    }
}

struct Logger(Arc<State>);

impl LogSink for Logger {
    #[expect(
        clippy::panic,
        reason = "An unexpected logged error category must fail the contract instead of fabricating a native error."
    )]
    fn log(
        &self,
        level: LogLevel,
        message: LogArgument<'_>,
        arguments: &[LogArgument<'_>],
    ) -> better_auth_core::AuthResult<()> {
        let arguments = arguments
            .iter()
            .map(|argument| match argument {
                LogArgument::Native(value) => self.0.error_value(value),
                LogArgument::Error(error) => {
                    let error = error.downcast_ref::<AuthError>().unwrap();
                    if let Some(value) = error.raw_value() {
                        self.0.error_value(value)
                    } else {
                        let owned = match error {
                            AuthError::TypeError(message) => AuthError::TypeError(message.clone()),
                            AuthError::RangeError(message) => {
                                AuthError::RangeError(message.clone())
                            }
                            AuthError::Internal(message) => AuthError::Internal(message.clone()),
                            _ => panic!("Unexpected consumer log error category: {error:?}"),
                        };
                        self.0.error_value(&owned.into_thrown_value().unwrap())
                    }
                }
                _ => Err(AuthError::internal(
                    "Consumer logs must retain native arguments",
                )),
            })
            .collect::<AuthResult<Vec<_>>>()
            .unwrap();
        self.0.record(
            &format!("logger:{}", level.as_str()),
            [
                ("message".into(), message.to_string().into()),
                ("arguments".into(), arguments.into()),
            ],
        );
        Ok(())
    }
}

pub(crate) struct Harness {
    pub(crate) scenario: Json,
    pub(crate) root: FieldValue,
    pub(crate) value: FieldValue,
    pub(crate) original: FieldValue,
    pub(crate) cache: Arc<Storage>,
    pub(crate) target_key: String,
    state: Arc<State>,
    retained: FieldValue,
    model_rows: Vec<(&'static str, EntityRole, Vec<FieldMap>)>,
}

impl Harness {
    pub(crate) fn new(scenario: &Json, identifier: &str) -> AuthResult<Self> {
        let original: FieldValue = FieldMap::from([
            ("code".into(), "CONSUMER_ORIGINAL_FAILURE".into()),
            ("mutation".into(), 0.into()),
            ("ownUndefined".into(), FieldValue::Undefined),
        ])
        .into();
        let state = Arc::new(State {
            scenario: scenario.clone(),
            observer: Mutex::default(),
            counts: Mutex::default(),
            active: AtomicBool::new(false),
            original: original.clone(),
            root: OnceLock::new(),
            roots: Mutex::default(),
        });
        let (root, value) = values::input(&state, identifier)?;
        state.root.set(root.clone()).unwrap();
        let retained: FieldValue = FieldMap::from([
            ("value".into(), "unchanged".into()),
            ("ownUndefined".into(), FieldValue::Undefined),
        ])
        .into();
        let target_key = format!("verification:{identifier}");
        let cache = Arc::new(Storage::new(state.clone()));
        cache.insert(
            &target_key,
            if scenario["root"] == "missing" {
                FieldValue::Undefined
            } else {
                root.clone()
            },
        )?;
        cache.insert("verification:retained", retained.clone())?;
        Ok(Self {
            scenario: scenario.clone(),
            root,
            value,
            original,
            cache,
            target_key,
            state,
            retained,
            model_rows: Vec::new(),
        })
    }

    pub(crate) fn with_model_rows(
        mut self,
        name: &'static str,
        role: EntityRole,
        rows: Vec<FieldMap>,
    ) -> Self {
        self.model_rows.push((name, role, rows));
        self
    }

    pub(crate) fn config(&self) -> AuthResult<AuthConfig> {
        let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
        config.verification.store_in_database = false;
        config.logger = better_auth_core::LoggerConfig {
            level: Some(LogLevel::Debug),
            log: Some(Arc::new(Logger(self.state.clone()))),
            ..Default::default()
        }
        .into();
        let state = self.state.clone();
        config.advanced.database.generate_id =
            Some(IdGeneration::Custom(IdGenerator::new(move |request| {
                let count = {
                    let mut counts = state.counts.lock().unwrap();
                    counts.generated += 1;
                    counts.generated
                };
                let id = format!("{}-generated-{count}", request.model);
                state.record(
                    "generate-id",
                    [
                        ("model".into(), request.model.into()),
                        ("id".into(), id.clone().into()),
                    ],
                );
                Ok(Some(id))
            })));
        Ok(config)
    }

    pub(crate) async fn context(
        &self,
        plugins: &[&dyn AuthPlugin<StatelessSchema>],
    ) -> AuthResult<(AuthContext<StatelessSchema>, Arc<EphemeralStore>)> {
        let config = Arc::new(self.config()?);
        let mut tables = vec![
            ("user".into(), vec![consumer_user()]),
            ("session".into(), Vec::new()),
            ("account".into(), Vec::new()),
            ("verification".into(), Vec::new()),
        ];
        tables.extend(
            self.model_rows
                .iter()
                .map(|(name, _, rows)| ((*name).into(), rows.clone())),
        );
        let inner = Arc::new(EphemeralStore::from_storage(config.clone(), tables)?);
        let store = SecondaryStore::new(
            inner.clone(),
            self.cache.clone(),
            config.clone(),
            Default::default(),
        )?
        .with_clock(|| chrono::DateTime::from_timestamp_millis(NOW).unwrap());
        let mut context = super::initialize_test_context(config, Arc::new(store), plugins)
            .await?
            .with_clock(|| chrono::DateTime::from_timestamp_millis(NOW).unwrap());
        context.extensions.insert(Arc::new(
            better_auth_core::endpoint_dispatch::EndpointDispatcher::<StatelessSchema>::new(
                Arc::new(Vec::new()),
                Default::default(),
                [],
            ),
        ));
        context.secondary_storage = Some(self.cache.clone());
        Ok((context, inner))
    }

    pub(crate) fn activate(&self) {
        self.state.active.store(true, Ordering::Release);
    }

    pub(crate) fn observe(&self, value: &FieldValue) -> AuthResult<Json> {
        self.state.observe(value)
    }

    pub(crate) fn record(&self, phase: &str, fields: impl IntoIterator<Item = (String, Json)>) {
        self.state.record(phase, fields);
    }

    pub(crate) fn fail<T>(&self, phase: &str) -> AuthResult<T> {
        self.state.fail(phase)
    }

    pub(crate) fn state(&self, inner: &EphemeralStore) -> AuthResult<Json> {
        let database: FieldValue = [
            ("user", EntityRole::User),
            ("session", EntityRole::Session),
            ("account", EntityRole::Account),
            ("verification", EntityRole::Verification),
        ]
        .into_iter()
        .chain(self.model_rows.iter().map(|(name, role, _)| (*name, *role)))
        .map(|(name, role)| {
            Ok((
                name.into(),
                inner
                    .storage_rows(role)?
                    .into_iter()
                    .map(FieldValue::from)
                    .collect::<Vec<_>>()
                    .into(),
            ))
        })
        .collect::<AuthResult<FieldMap>>()?
        .into();
        let counts = self.state.counts.lock().unwrap();
        let state: FieldValue = FieldMap::from([
            ("database".into(), database),
            ("cache".into(), self.cache.snapshot()?),
            (
                "targetPresent".into(),
                self.cache.contains(&self.target_key)?.into(),
            ),
            (
                "targetSameRoot".into(),
                self.cache
                    .get(&self.target_key)?
                    .is_some_and(|value| value.strict_equals(&self.root))
                    .into(),
            ),
            (
                "retainedSameObject".into(),
                self.cache
                    .get("verification:retained")?
                    .is_some_and(|value| value.strict_equals(&self.retained))
                    .into(),
            ),
            (
                "counts".into(),
                FieldMap::from([
                    ("expiry".into(), counts.expiry.into()),
                    ("value".into(), counts.value.into()),
                    ("split".into(), counts.split.into()),
                    ("slice".into(), counts.slice.into()),
                    ("generated".into(), counts.generated.into()),
                ])
                .into(),
            ),
            ("original".into(), self.original.clone()),
        ])
        .into();
        drop(counts);
        self.observe(&state)
    }

    pub(crate) fn outcome(&self, result: AuthResult<FieldValue>) -> AuthResult<Json> {
        match result {
            Ok(value) => Ok(json!({"returned":true,"result":self.observe(&value)?})),
            Err(error) => {
                let value = error.into_thrown_value()?;
                Ok(
                    json!({"returned":false,"sameOriginal":value.strict_equals(&self.original),
                    "error":self.state.error_value(&value)?}),
                )
            }
        }
    }

    pub(crate) fn finish(
        &self,
        before: Json,
        outcome: Json,
        inner: &EphemeralStore,
    ) -> AuthResult<Json> {
        let after = self.state(inner)?;
        let observer = self.state.observer.lock().unwrap();
        Ok(
            json!({"before":before,"outcome":outcome,"events":observer.events,
            "after":after,"functionIds":observer.function_ids()}),
        )
    }
}

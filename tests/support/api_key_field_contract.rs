#[path = "api_key_field_policies.rs"]
mod policies;
#[path = "api_key_usage_date_contract.rs"]
pub(crate) mod usage_dates;

pub(crate) use policies::{Fields, Trace, config, policies, take};

use better_auth::seaorm::sea_orm::entity::prelude::DateTimeUtc;
use better_auth::{
    __private_core::{
        ApiKey, AuthError, AuthResult, AuthSchema, AuthStore, CreateApiKey, FieldDate, FieldMap,
        UpdateApiKey, store::ApiKeyUsageWrite, user_fields::UserConfig, wire::ApiKeyView,
    },
    BetterAuth,
};
use serde_json::{Value, json};
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicU8, Ordering},
};

pub(crate) const OPERATIONS: [&str; 16] = [
    "create",
    "get-id",
    "get-hash",
    "list",
    "decrement-input-ignored",
    "update",
    "refill",
    "refill-miss",
    "decrement",
    "start-window",
    "start-window-miss",
    "reset-window",
    "increment-window",
    "increment-window-miss",
    "last-request",
    "updated-at",
];
const FAILURE_OPERATIONS: [&str; 8] = [
    "create",
    "update",
    "refill",
    "decrement",
    "start-window",
    "increment-window",
    "last-request",
    "updated-at",
];
const TIMES: [&str; 6] = [
    "2031-02-03T04:05:00.000Z",
    "2031-02-03T04:05:01.000Z",
    "2031-02-03T04:05:02.000Z",
    "2031-02-03T04:05:03.000Z",
    "2031-02-03T04:05:04.000Z",
    "2031-02-03T04:05:05.000Z",
];

#[derive(Clone, Copy)]
pub(crate) enum Scenario {
    Operations,
    Failure { operation: &'static str, phase: u8 },
}

impl Scenario {
    pub(crate) fn all() -> impl Iterator<Item = Self> {
        std::iter::once(Self::Operations).chain(FAILURE_OPERATIONS.into_iter().flat_map(
            |operation| {
                (1..=2)
                    .filter(move |phase| operation != "decrement" || *phase == 2)
                    .map(move |phase| Self::Failure { operation, phase })
            },
        ))
    }
}

pub(super) struct Fixture<S: AuthSchema> {
    store: Arc<dyn AuthStore<S>>,
    reader: Arc<dyn AuthStore<S>>,
    identity: OnceLock<(String, FieldDate)>,
    ordinary_update: OnceLock<FieldDate>,
    update_phase: AtomicU8,
    events: Trace,
    failure: Arc<AtomicU8>,
    mapped_name: bool,
}

#[expect(
    clippy::expect_used,
    clippy::panic_in_result_fn,
    reason = "The contract asserts complete API Key serialization and propagates serialization errors"
)]
pub(crate) fn adapter_value(row: &ApiKey) -> AuthResult<Value> {
    let public = serde_json::to_value(ApiKeyView::from(row))?;
    let mut value = serde_json::to_value(row)?;
    let object = value.as_object_mut().expect("flattened API Key record");
    // JavaScript represents integral f64 values as integer JSON numbers.
    for name in [
        "refillInterval",
        "refillAmount",
        "rateLimitTimeWindow",
        "rateLimitMax",
        "requestCount",
        "remaining",
    ] {
        let stored = object.get(name).expect("stored API Key numeric field");
        let projected = public.get(name).expect("public API Key numeric field");
        assert_eq!(stored.as_f64(), projected.as_f64());
        let _ = object.insert(name.into(), projected.clone());
    }
    let mut view_fields = object.clone();
    assert_eq!(
        view_fields.remove("key"),
        Some(json!("ordinary-stored-hash"))
    );
    assert_eq!(
        &view_fields,
        public.as_object().expect("public API Key record")
    );
    let mut keys = object.keys().map(String::as_str).collect::<Vec<_>>();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "activatedAt",
            "configId",
            "createdAt",
            "details",
            "enabled",
            "expiresAt",
            "id",
            "key",
            "label",
            "lastRefillAt",
            "lastRequest",
            "metadata",
            "name",
            "permissions",
            "prefix",
            "rateLimitEnabled",
            "rateLimitMax",
            "rateLimitTimeWindow",
            "referenceId",
            "refillAmount",
            "refillInterval",
            "remaining",
            "requestCount",
            "revision",
            "start",
            "updatedAt",
        ]
    );
    Ok(value)
}

pub(crate) fn input() -> CreateApiKey {
    CreateApiKey {
        reference_id: "ordinary-owner".into(),
        config_id: "default".into(),
        name: Some("Desk".into()).into(),
        prefix: None,
        key_hash: "ordinary-stored-hash".into(),
        start: None,
        expires_at: None,
        remaining: Some(10.0),
        rate_limit_enabled: true,
        rate_limit_time_window: Some(60_000.0),
        rate_limit_max: Some(3.0),
        refill_interval: Some(60_000.0),
        refill_amount: Some(10.0),
        permissions: None,
        metadata: None,
        enabled: true,
        additional_fields: [
            ("activatedAt".into(), "2029-01-02T03:04:05.000Z".into()),
            (
                "details".into(),
                FieldMap::from_iter([
                    ("channel".into(), "ordinary".into()),
                    ("enabled".into(), true.into()),
                ])
                .into(),
            ),
        ]
        .into_iter()
        .collect(),
    }
}

impl<S: AuthSchema> Fixture<S> {
    pub(super) async fn new(
        raw: Arc<dyn AuthStore<S>>,
        mapped_name: bool,
        fields: impl Fn(Option<Trace>, Arc<AtomicU8>) -> UserConfig,
    ) -> AuthResult<Self> {
        let failure = Arc::new(AtomicU8::new(0));
        let fields = |events| fields(events, failure.clone());
        let reader = BetterAuth::new(config())
            .store_arc(raw.clone())
            .plugin(Fields(fields(None)))
            .build()
            .await?;
        let events = Trace::default();
        let auth = BetterAuth::new(config())
            .store_arc(raw)
            .plugin(Fields(fields(Some(events.clone()))))
            .build()
            .await?;
        Ok(Self {
            store: auth.store().clone(),
            reader: reader.store().clone(),
            identity: OnceLock::new(),
            ordinary_update: OnceLock::new(),
            update_phase: AtomicU8::new(0),
            events,
            failure,
            mapped_name,
        })
    }

    #[expect(
        clippy::expect_used,
        clippy::panic_in_result_fn,
        reason = "The contract asserts API Key identity and timestamps before propagating serialization errors"
    )]
    fn visible(&self, row: &ApiKey) -> AuthResult<Value> {
        let id = row.id.typed()?;
        assert!(!id.is_empty());
        assert_eq!(row.reference_id, "ordinary-owner");
        assert_eq!(row.key_hash, "ordinary-stored-hash");
        assert_eq!(row.config_id, "default");
        let created = row
            .created_at
            .to_datetime()?
            .expect("stored creation timestamp");
        let updated = row
            .updated_at
            .to_datetime()?
            .expect("stored update timestamp");
        let identity = self
            .identity
            .get_or_init(|| (id.clone(), row.created_at.clone()));
        assert_eq!(id, &identity.0);
        assert_eq!(row.created_at, identity.1);
        let normalized_update = match self.update_phase.load(Ordering::SeqCst) {
            0 => {
                assert_eq!(row.updated_at, identity.1);
                "<created-at>"
            }
            1 => {
                assert!(updated >= created);
                assert_eq!(
                    &row.updated_at,
                    self.ordinary_update.get_or_init(|| row.updated_at.clone())
                );
                "<ordinary-updated-at>"
            }
            2 => {
                assert_eq!(
                    updated,
                    TIMES[5]
                        .parse::<DateTimeUtc>()
                        .expect("fixed usage timestamp")
                );
                TIMES[5]
            }
            _ => return Err(AuthError::internal("Unknown API Key timestamp phase")),
        };
        let mut value = adapter_value(row)?;
        let object = value.as_object_mut().expect("flattened API Key record");
        let _ = object.insert("id".into(), json!("<api-key-id>"));
        let _ = object.insert("createdAt".into(), json!("<created-at>"));
        let _ = object.insert("updatedAt".into(), json!(normalized_update));
        Ok(value)
    }

    async fn stored(&self) -> AuthResult<Value> {
        let rows = self
            .reader
            .find_api_keys_by_reference("ordinary-owner", None)
            .await?;
        assert!(rows.len() <= 1);
        Ok(json!(
            rows.iter()
                .map(|row| self.visible(row))
                .collect::<AuthResult<Vec<_>>>()?
        ))
    }

    async fn observe(&self, name: &str, result: Value) -> AuthResult<Value> {
        let events = take(&self.events);
        let stored = self.stored().await?;
        Ok(json!({"name":name, "events":events, "result":result, "stored":stored}))
    }

    #[expect(
        clippy::expect_used,
        reason = "Usage timestamps are fixed valid RFC 3339 contract data"
    )]
    async fn execute(&self, operation: &str, seeded: Option<&ApiKey>) -> AuthResult<Vec<ApiKey>> {
        if operation == "create" {
            let mut input = input();
            if self.mapped_name {
                input.name = Some(" Desk ".into()).into();
            }
            return self.store.create_api_key(input).await.map(|row| vec![row]);
        }
        let seed =
            seeded.ok_or_else(|| AuthError::internal("API Key operation requires a seed"))?;
        let date = |index: usize| {
            TIMES
                .get(index)
                .expect("configured usage timestamp")
                .parse::<DateTimeUtc>()
                .expect("fixed usage timestamp")
        };
        let row = match operation {
            "get-id" => self.store.get_api_key_by_id(seed.id.typed()?).await?,
            "get-hash" => self.store.get_api_key_by_hash(&seed.key_hash).await?,
            "list" => {
                return self
                    .store
                    .find_api_keys_by_reference("ordinary-owner", None)
                    .await;
            }
            "update" => {
                if self.failure.load(Ordering::SeqCst) != 1 {
                    self.update_phase.store(1, Ordering::SeqCst);
                }
                Some(
                    self.store
                        .update_api_key(
                            &seed.id,
                            UpdateApiKey {
                                name: Some(
                                    Some(
                                        if self.mapped_name {
                                            " Desk-renamed "
                                        } else {
                                            "Desk-renamed"
                                        }
                                        .to_owned(),
                                    )
                                    .into(),
                                ),
                                additional_fields: [("label".into(), " Revised ".into())]
                                    .into_iter()
                                    .collect(),
                                ..Default::default()
                            },
                        )
                        .await?,
                )
            }
            operation => {
                let write = match operation {
                    "decrement" | "decrement-input-ignored" => ApiKeyUsageWrite::Decrement,
                    "refill" | "refill-miss" => ApiKeyUsageWrite::Refill {
                        previous: None,
                        remaining: 8.0,
                        at: date(0),
                    },
                    "start-window" | "start-window-miss" => ApiKeyUsageWrite::StartWindow {
                        previous_before: None,
                        at: date(1),
                    },
                    "reset-window" => ApiKeyUsageWrite::StartWindow {
                        previous_before: Some(date(1)),
                        at: date(2),
                    },
                    "increment-window" | "increment-window-miss" => {
                        ApiKeyUsageWrite::IncrementWindow {
                            previous_after: date(0),
                            maximum: if operation.ends_with("-miss") {
                                2.0
                            } else {
                                3.0
                            },
                            at: date(3),
                        }
                    }
                    "last-request" => ApiKeyUsageWrite::LastRequest(date(4)),
                    "updated-at" => {
                        if self.failure.load(Ordering::SeqCst) != 1 {
                            self.update_phase.store(2, Ordering::SeqCst);
                        }
                        ApiKeyUsageWrite::UpdatedAt(date(5))
                    }
                    _ => return Err(AuthError::internal("Unknown API Key field operation")),
                };
                self.store.write_api_key_usage(&seed.id, write).await?
            }
        };
        Ok(row.into_iter().collect())
    }

    #[expect(
        clippy::expect_used,
        reason = "Create must return the selected API Key before later operations"
    )]
    pub(super) async fn operations(&self) -> AuthResult<Value> {
        let mut seed = None;
        let mut observations = Vec::new();
        for operation in OPERATIONS {
            if operation == "decrement-input-ignored" {
                self.failure.store(1, Ordering::SeqCst);
            }
            let rows = self.execute(operation, seed.as_ref()).await?;
            self.failure.store(0, Ordering::SeqCst);
            assert_eq!(rows.len(), usize::from(!operation.ends_with("-miss")));
            let result = rows
                .iter()
                .map(|row| self.visible(row))
                .collect::<AuthResult<Vec<_>>>()?;
            if operation == "create" {
                seed = Some(rows.first().expect("created API Key").clone());
            }
            observations.push(self.observe(operation, json!(result)).await?);
        }
        Ok(json!(observations))
    }

    pub(super) async fn error(&self, operation: &str, mode: u8) -> AuthResult<Value> {
        let seed = if operation == "create" {
            None
        } else {
            let mut input = input();
            if self.mapped_name {
                input.name = Some(" Desk ".into()).into();
            }
            Some(self.store.create_api_key(input).await?)
        };
        if operation == "increment-window" {
            let _ = self.execute("start-window", seed.as_ref()).await?;
        }
        let before = self.stored().await?;
        let _ = take(&self.events);
        self.failure.store(mode, Ordering::SeqCst);
        let result = self.execute(operation, seed.as_ref()).await;
        self.failure.store(0, Ordering::SeqCst);
        let phase = if mode == 1 { "input" } else { "output" };
        let message = format!("ordinary API Key {phase} error");
        match result {
            Err(AuthError::Internal(ref actual)) if actual == &message => {}
            Err(error) => return Err(error),
            Ok(_) => {
                return Err(AuthError::internal(
                    "API Key callback did not reject the operation",
                ));
            }
        }
        let observation = self
            .observe(
                &format!("{operation}-{phase}-error"),
                json!({"sameError":true, "message":message}),
            )
            .await?;
        if mode == 1 {
            assert_eq!(observation.get("stored"), Some(&before));
        }
        Ok(observation)
    }
}

#[expect(
    clippy::expect_used,
    reason = "The paired contract requires all captured backends and scenarios"
)]
pub(crate) async fn contract<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    backend: &str,
    scenario: Scenario,
) -> AuthResult<()> {
    let fixture: Value =
        serde_json::from_str(include_str!("../fixtures/api-key-fields-1.7.6.json"))?;
    assert_eq!(
        fixture.get("version").and_then(Value::as_str),
        Some("1.7.6")
    );
    let backends = fixture
        .get("backends")
        .and_then(Value::as_array)
        .expect("captured backends");
    assert_eq!(
        backends
            .iter()
            .map(|case| case.get("backend").and_then(Value::as_str))
            .collect::<Vec<_>>(),
        [Some("memory"), Some("sqlite")]
    );
    let expected = backends
        .iter()
        .find(|case| case.get("backend").and_then(Value::as_str) == Some(backend))
        .expect("captured backend");
    let operations = expected.get("operations").expect("captured operations");
    assert_eq!(
        operations
            .as_array()
            .expect("captured operations")
            .iter()
            .map(|operation| operation.get("name").and_then(Value::as_str))
            .collect::<Vec<_>>(),
        OPERATIONS.map(Some)
    );
    let failures = expected
        .get("failures")
        .and_then(Value::as_array)
        .expect("captured failures");
    assert_eq!(failures.len(), 15);
    let fixture = Fixture::new(raw, false, policies).await?;
    match scenario {
        Scenario::Operations => assert_eq!(&fixture.operations().await?, operations),
        Scenario::Failure { operation, phase } => {
            let actual = fixture.error(operation, phase).await?;
            let name = actual.get("name").expect("observed error name");
            let expected = failures
                .iter()
                .find(|failure| failure.get("name") == Some(name))
                .expect("captured error scenario");
            assert_eq!(&actual, expected);
        }
    }
    Ok(())
}

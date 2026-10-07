#[path = "two_factor_field_policies.rs"]
mod policies;

pub(crate) use policies::{Fields, config};

use better_auth::{
    __private_core::{
        AuthError, AuthResult, AuthSchema, AuthStore, CreateTwoFactor, CreateUser, FieldMap,
        TwoFactor, UpdateTwoFactor,
    },
    BetterAuth,
    plugins::TwoFactorPlugin,
};
use policies::{Trace, policies, take};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};

#[derive(Clone, Copy)]
pub(crate) enum Scenario {
    Operations,
    CreateInputError,
    CreateOutputError,
    UpdateInputError,
    UpdateOutputError,
    CasInputError,
    CasOutputError,
    LockInputError,
    ResetNullLockBeforeEpoch,
    ResetNullLock,
}

impl Scenario {
    pub(crate) const ALL: [Self; 10] = [
        Self::Operations,
        Self::CreateInputError,
        Self::CreateOutputError,
        Self::UpdateInputError,
        Self::UpdateOutputError,
        Self::CasInputError,
        Self::CasOutputError,
        Self::LockInputError,
        Self::ResetNullLockBeforeEpoch,
        Self::ResetNullLock,
    ];

    fn failure(self) -> Option<(&'static str, u8, usize)> {
        match self {
            Self::Operations
            | Self::LockInputError
            | Self::ResetNullLockBeforeEpoch
            | Self::ResetNullLock => None,
            Self::CreateInputError => Some(("create", 1, 0)),
            Self::CreateOutputError => Some(("create", 2, 1)),
            Self::UpdateInputError => Some(("update", 1, 2)),
            Self::UpdateOutputError => Some(("update", 2, 3)),
            Self::CasInputError => Some(("cas", 1, 4)),
            Self::CasOutputError => Some(("cas", 2, 5)),
        }
    }
}

#[expect(
    clippy::expect_used,
    reason = "The fixture requires a fixed valid Date before adapter input callbacks run"
)]
fn input(owner: &str) -> CreateTwoFactor {
    CreateTwoFactor {
        user_id: owner.into(),
        secret: "ordinary-encrypted-secret".into(),
        backup_codes: "ordinary-encrypted-codes".into(),
        verified: false,
        additional_fields: [
            (
                "activatedAt".into(),
                "2029-01-02T03:04:05.000Z"
                    .parse::<chrono::DateTime<chrono::Utc>>()
                    .expect("fixed activation date parses")
                    .into(),
            ),
            (
                "details".into(),
                FieldMap::from([
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

#[expect(
    clippy::expect_used,
    reason = "The fixture requires a fixed valid Date before adapter input callbacks run"
)]
fn update() -> UpdateTwoFactor {
    UpdateTwoFactor {
        verified: Some(true),
        additional_fields: [
            ("label".into(), " Changed ".into()),
            (
                "activatedAt".into(),
                "2029-02-03T04:05:06.789Z"
                    .parse::<chrono::DateTime<chrono::Utc>>()
                    .expect("fixed activation date parses")
                    .into(),
            ),
            (
                "details".into(),
                FieldMap::from([
                    ("channel".into(), "updated".into()),
                    ("enabled".into(), false.into()),
                ])
                .into(),
            ),
        ]
        .into_iter()
        .collect(),
        ..Default::default()
    }
}

struct Fixture<S: AuthSchema> {
    store: Arc<dyn AuthStore<S>>,
    reader: Arc<dyn AuthStore<S>>,
    owner: String,
    events: Trace,
    failure: Arc<AtomicU8>,
}

impl<S: AuthSchema> Fixture<S> {
    async fn new(raw: Arc<dyn AuthStore<S>>) -> AuthResult<Self> {
        let failure = Arc::new(AtomicU8::new(0));
        let reader = BetterAuth::new(config())
            .store_arc(raw.clone())
            .plugin(TwoFactorPlugin::new())
            .plugin(Fields(policies(None, failure.clone())))
            .build()
            .await?;
        let owner = reader
            .store()
            .create_user(
                CreateUser::new()
                    .with_name("TwoFactor field owner")
                    .with_email("owner@two-factor-fields.test")
                    .with_email_verified(false),
            )
            .await?
            .id
            .typed()?
            .clone();
        let events = Trace::default();
        let auth = BetterAuth::new(config())
            .store_arc(raw)
            .plugin(TwoFactorPlugin::new())
            .plugin(Fields(policies(Some(events.clone()), failure.clone())))
            .build()
            .await?;
        Ok(Self {
            store: auth.store().clone(),
            reader: reader.store().clone(),
            owner,
            events,
            failure,
        })
    }

    #[expect(
        clippy::expect_used,
        reason = "The contract requires a complete flattened record with only the declared native and additional fields"
    )]
    fn visible(&self, row: Option<&TwoFactor>) -> AuthResult<Value> {
        let Some(row) = row else {
            return Ok(Value::Null);
        };
        assert!(!row.id.typed()?.is_empty());
        assert_eq!(row.user_id, self.owner);
        assert!(row.created_at.is_undefined());
        assert!(row.updated_at.is_undefined());
        let mut value = serde_json::to_value(row)?;
        let object = value.as_object_mut().expect("flattened TwoFactor record");
        let mut keys = object.keys().map(String::as_str).collect::<Vec<_>>();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "activatedAt",
                "backupCodes",
                "details",
                "failedVerificationCount",
                "id",
                "label",
                "lockedUntil",
                "revision",
                "secret",
                "userId",
                "verified",
            ]
        );
        let _ = object.insert("id".into(), json!("<two-factor-id>"));
        let _ = object.insert("userId".into(), json!("<owner-id>"));
        Ok(value)
    }

    async fn stored(&self) -> AuthResult<Value> {
        self.visible(
            self.reader
                .get_two_factor_by_user_id(&self.owner)
                .await?
                .as_ref(),
        )
    }

    async fn observe(&self, name: &str, result: Value) -> AuthResult<Value> {
        let events = take(&self.events);
        let stored = self.stored().await?;
        Ok(json!({"name":name, "events":events, "result":result, "stored":stored}))
    }

    #[expect(
        clippy::expect_used,
        reason = "The fixed fixture dates must parse before the corresponding store operations"
    )]
    async fn operations(&self) -> AuthResult<Value> {
        let created = self.store.create_two_factor(input(&self.owner)).await?;
        let mut operations = vec![
            self.observe("create", self.visible(Some(&created))?)
                .await?,
        ];
        let read = self.store.get_two_factor_by_user_id(&self.owner).await?;
        operations.push(self.observe("read", self.visible(read.as_ref())?).await?);
        let updated = self.store.update_two_factor(&created.id, update()).await?;
        operations.push(
            self.observe("update", self.visible(Some(&updated))?)
                .await?,
        );
        let updated = self
            .store
            .update_two_factor_backup_codes(&self.owner, "ordinary-updated-codes")
            .await?;
        operations.push(
            self.observe("update-backup-codes", self.visible(Some(&updated))?)
                .await?,
        );
        for (name, replacement) in [
            ("cas-success", "ordinary-cas-codes"),
            ("cas-mismatch", "must-not-replace"),
        ] {
            let exchanged = self
                .store
                .compare_exchange_two_factor_backup_codes(
                    &created.id,
                    "ordinary-updated-codes",
                    replacement,
                )
                .await?;
            operations.push(self.observe(name, json!(exchanged)).await?);
        }
        let deadline = "2030-01-02T03:04:05.123Z"
            .parse()
            .expect("fixed fixture deadline parses");
        for name in ["failure-increment", "failure-lock"] {
            self.store
                .record_two_factor_failure(&created.id, 2, &|| Ok(deadline))
                .await?;
            operations.push(self.observe(name, Value::Null).await?);
        }
        for (name, cutoff) in [
            ("reset-guard-mismatch", "2030-01-01T00:00:00.000Z"),
            ("reset-guard-success", "2030-01-03T00:00:00.000Z"),
        ] {
            self.store
                .reset_two_factor_failures(
                    &created.id,
                    Some(cutoff.parse().expect("fixed fixture cutoff parses")),
                )
                .await?;
            operations.push(self.observe(name, Value::Null).await?);
        }
        self.store
            .record_two_factor_failure(&created.id, 2, &|| Ok(deadline))
            .await?;
        operations.push(
            self.observe("failure-increment-after-reset", Value::Null)
                .await?,
        );
        self.store
            .reset_two_factor_failures(&created.id, None)
            .await?;
        operations.push(self.observe("reset-unconditional", Value::Null).await?);
        Ok(json!(operations))
    }

    #[expect(
        clippy::expect_used,
        reason = "Update and CAS failure cases require the seeded record before arming the callback error"
    )]
    async fn error(&self, operation: &str, mode: u8) -> AuthResult<Value> {
        let seeded = if operation == "create" {
            None
        } else {
            Some(self.store.create_two_factor(input(&self.owner)).await?)
        };
        let before = self.stored().await?;
        let _ = take(&self.events);
        self.failure.store(mode, Ordering::SeqCst);
        let result = match operation {
            "create" => self
                .store
                .create_two_factor(input(&self.owner))
                .await
                .map(|_| ()),
            "update" => self
                .store
                .update_two_factor(&seeded.as_ref().expect("seeded factor").id, update())
                .await
                .map(|_| ()),
            "cas" => self
                .store
                .compare_exchange_two_factor_backup_codes(
                    &seeded.as_ref().expect("seeded factor").id,
                    "ordinary-encrypted-codes",
                    "ordinary-error-cas-codes",
                )
                .await
                .map(|_| ()),
            _ => return Err(AuthError::internal("Unknown TwoFactor error operation")),
        };
        self.failure.store(0, Ordering::SeqCst);
        let phase = if mode == 1 { "input" } else { "output" };
        let message = format!("ordinary TwoFactor {phase} error");
        let same_error = match result {
            Err(AuthError::Internal(actual)) if actual == message => true,
            Err(error) => return Err(error),
            Ok(()) => false,
        };
        let observation = self
            .observe(
                &format!("{operation}-{phase}-error"),
                json!({"sameError":same_error,"message":message}),
            )
            .await?;
        if mode == 1 {
            assert_eq!(observation["stored"], before);
        }
        Ok(observation)
    }

    #[expect(
        clippy::expect_used,
        reason = "The fixed fixture dates must parse before the corresponding store operations"
    )]
    async fn boundary(&self, scenario: Scenario) -> AuthResult<Value> {
        let created = self.store.create_two_factor(input(&self.owner)).await?;
        let deadline = "2030-01-02T03:04:05.123Z"
            .parse()
            .expect("fixed fixture deadline parses");
        self.store
            .record_two_factor_failure(&created.id, 2, &|| Ok(deadline))
            .await?;
        let before = self.stored().await?;
        assert_eq!(before["failedVerificationCount"], 1);
        assert!(before["lockedUntil"].is_null());
        let _ = take(&self.events);

        match scenario {
            Scenario::LockInputError => {
                self.failure.store(1, Ordering::SeqCst);
                let result = self
                    .store
                    .record_two_factor_failure(&created.id, 2, &|| Ok(deadline))
                    .await;
                self.failure.store(0, Ordering::SeqCst);
                let message = "ordinary TwoFactor input error";
                let same_error = match result {
                    Err(AuthError::Internal(actual)) if actual == message => true,
                    Err(error) => return Err(error),
                    Ok(()) => false,
                };
                let observation = self
                    .observe(
                        "failure-lock-input-error",
                        json!({"sameError":same_error,"message":message}),
                    )
                    .await?;
                let mut expected_stored = before;
                expected_stored["failedVerificationCount"] = json!(2);
                assert_eq!(observation["stored"], expected_stored);
                Ok(observation)
            }
            Scenario::ResetNullLockBeforeEpoch | Scenario::ResetNullLock => {
                let before_epoch = matches!(scenario, Scenario::ResetNullLockBeforeEpoch);
                let (name, cutoff) = if before_epoch {
                    ("reset-guard-null-before-epoch", "1969-12-31T23:59:59.999Z")
                } else {
                    ("reset-guard-null", "2030-01-03T00:00:00.000Z")
                };
                self.store
                    .reset_two_factor_failures(
                        &created.id,
                        Some(cutoff.parse().expect("fixed fixture cutoff parses")),
                    )
                    .await?;
                let observation = self.observe(name, Value::Null).await?;
                if before_epoch {
                    assert_eq!(observation["stored"], before);
                }
                Ok(observation)
            }
            _ => Err(AuthError::internal("Unknown TwoFactor boundary scenario")),
        }
    }
}

#[expect(
    clippy::expect_used,
    reason = "The paired contract requires the complete pinned backend, operation sequence, and error sequence"
)]
pub(crate) async fn contract<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    backend: &str,
    scenario: Scenario,
) -> AuthResult<()> {
    let expected: Value =
        serde_json::from_str(include_str!("../fixtures/two-factor-fields-1.7.6.json"))?;
    assert_eq!(expected["version"], "1.7.6");
    let backends = expected["backends"].as_array().expect("captured backends");
    assert_eq!(
        backends
            .iter()
            .map(|case| case["backend"].as_str())
            .collect::<Vec<_>>(),
        [Some("memory"), Some("sqlite")]
    );
    let expected = backends
        .iter()
        .find(|case| case["backend"] == backend)
        .expect("captured TwoFactor backend");
    assert_eq!(expected["failures"].as_array().expect("failures").len(), 6);
    assert_eq!(
        expected["boundaries"].as_array().expect("boundaries").len(),
        3
    );
    let fixture = Fixture::new(raw).await?;
    let boundary_index = match scenario {
        Scenario::LockInputError => Some(0),
        Scenario::ResetNullLockBeforeEpoch => Some(1),
        Scenario::ResetNullLock => Some(2),
        _ => None,
    };
    if let Some(index) = boundary_index {
        assert_eq!(
            fixture.boundary(scenario).await?,
            expected["boundaries"][index]
        );
    } else if let Some((operation, mode, index)) = scenario.failure() {
        assert_eq!(
            fixture.error(operation, mode).await?,
            expected["failures"][index]
        );
    } else {
        assert_eq!(fixture.operations().await?, expected["operations"]);
    }
    Ok(())
}

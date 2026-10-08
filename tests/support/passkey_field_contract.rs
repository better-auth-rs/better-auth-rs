#[path = "passkey_field_policies.rs"]
mod policies;

pub(crate) use policies::{Fields, config};

use better_auth::{
    __private_core::{
        AuthError, AuthResult, AuthSchema, AuthStore, CreatePasskey, CreateUser, FieldMap, Passkey,
        PasskeyCredentialState, PasskeyStorage, UpdatePasskeyAuthentication, wire::PasskeyView,
    },
    BetterAuth,
};
use policies::{Trace, policies, take};
use serde_json::{Value, json};
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicU8, Ordering},
};

const OPERATIONS: [&str; 6] = [
    "create",
    "get-id",
    "get-credential",
    "list",
    "update-name",
    "update-auth",
];

#[derive(Clone, Copy)]
pub(crate) enum Scenario {
    Operations,
    Failure { operation: &'static str, phase: u8 },
}

impl Scenario {
    pub(crate) const ALL: [Self; 7] = [
        Self::Operations,
        Self::Failure {
            operation: "create",
            phase: 1,
        },
        Self::Failure {
            operation: "create",
            phase: 2,
        },
        Self::Failure {
            operation: "update-name",
            phase: 1,
        },
        Self::Failure {
            operation: "update-name",
            phase: 2,
        },
        Self::Failure {
            operation: "update-auth",
            phase: 1,
        },
        Self::Failure {
            operation: "update-auth",
            phase: 2,
        },
    ];
}

struct Fixture<S: AuthSchema> {
    store: Arc<dyn AuthStore<S>>,
    reader: Arc<dyn AuthStore<S>>,
    owner: String,
    identity: OnceLock<(String, Value)>,
    events: Trace,
    failure: Arc<AtomicU8>,
}

impl<S: AuthSchema> Fixture<S> {
    async fn new(raw: Arc<dyn AuthStore<S>>) -> AuthResult<Self> {
        let failure = Arc::new(AtomicU8::new(0));
        let reader = BetterAuth::new(config())
            .store_arc(raw.clone())
            .plugin(Fields(policies(None, failure.clone())))
            .build()
            .await?;
        let owner = reader
            .store()
            .create_user(
                CreateUser::new()
                    .with_name("Passkey field owner")
                    .with_email("owner@passkey-fields.test")
                    .with_email_verified(false),
            )
            .await?
            .id
            .typed()?
            .clone();
        let events = Trace::default();
        let auth = BetterAuth::new(config())
            .store_arc(raw)
            .plugin(Fields(policies(Some(events.clone()), failure.clone())))
            .build()
            .await?;
        Ok(Self {
            store: auth.store().clone(),
            reader: reader.store().clone(),
            owner,
            identity: OnceLock::new(),
            events,
            failure,
        })
    }

    fn input(&self) -> CreatePasskey {
        CreatePasskey {
            user_id: self.owner.clone().into(),
            name: Some("Desk".into()).into(),
            credential_id: "ordinary-credential".into(),
            public_key: "ordinary-public-key".into(),
            counter: 0,
            device_type: "singleDevice".into(),
            backed_up: false,
            transports: None,
            credential: match self.store.passkey_storage() {
                PasskeyStorage::Native => PasskeyCredentialState::Native,
                PasskeyStorage::Legacy => "ordinary-private-record".into(),
            },
            aaguid: Some("ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4".into()).into(),
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

    #[expect(
        clippy::expect_used,
        clippy::panic_in_result_fn,
        reason = "The paired record must contain every native and additional field and satisfy all credential invariants"
    )]
    fn visible(&self, row: &Passkey) -> AuthResult<Value> {
        let id = row.id.typed()?;
        assert!(!id.is_empty());
        assert_eq!(row.user_id, self.owner);
        assert_eq!(row.credential_id, "ordinary-credential");
        assert_eq!(row.public_key, "ordinary-public-key");
        assert_eq!(row.device_type, "singleDevice");
        assert!(!*row.backed_up.typed()?);
        assert_eq!(row.transports, None);
        assert_eq!(
            row.aaguid.typed()?.as_deref(),
            Some("ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4")
        );
        assert!(row.created_at.typed()?.is_some());
        let timestamp = serde_json::to_value(&row.created_at)?;
        let identity = self
            .identity
            .get_or_init(|| (id.clone(), timestamp.clone()));
        assert_eq!(id, &identity.0);
        assert_eq!(timestamp, identity.1);
        match self.store.passkey_storage() {
            PasskeyStorage::Native => {
                assert!(row.credential.is_undefined());
                assert!(row.updated_at.is_undefined());
            }
            PasskeyStorage::Legacy => {
                assert_eq!(row.credential.typed()?, "ordinary-private-record");
                let _ = row.updated_at.typed()?;
            }
        }
        let public = serde_json::to_value(PasskeyView::from(row))?;
        let mut value = serde_json::to_value(row)?;
        let object = value.as_object_mut().expect("flattened Passkey record");
        // The upstream adapter has no Rust legacy update timestamp or credential envelope.
        let _ = object.remove("updatedAt");
        assert_eq!(&*object, public.as_object().expect("public Passkey record"));
        let mut keys = object.keys().map(String::as_str).collect::<Vec<_>>();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "aaguid",
                "activatedAt",
                "backedUp",
                "counter",
                "createdAt",
                "credentialID",
                "details",
                "deviceType",
                "id",
                "label",
                "name",
                "publicKey",
                "revision",
                "transports",
                "userId",
            ]
        );
        let _ = object.insert("id".into(), json!("<passkey-id>"));
        let _ = object.insert("userId".into(), json!("<owner-id>"));
        let _ = object.insert("createdAt".into(), json!("<created-at>"));
        Ok(value)
    }

    async fn stored(&self) -> AuthResult<Value> {
        let rows = self.reader.list_passkeys_by_user(&self.owner).await?;
        assert!(rows.len() <= 1);
        let rows = rows
            .iter()
            .map(|row| self.visible(row))
            .collect::<AuthResult<Vec<_>>>()?;
        Ok(json!(rows))
    }

    async fn observe(&self, name: &str, result: Value) -> AuthResult<Value> {
        let events = take(&self.events);
        let stored = self.stored().await?;
        Ok(json!({"name":name, "events":events, "result":result, "stored":stored}))
    }

    async fn execute(&self, operation: &str, seeded: Option<&Passkey>) -> AuthResult<Vec<Passkey>> {
        if operation == "create" {
            return self
                .store
                .create_passkey(self.input())
                .await
                .map(|row| vec![row]);
        }
        let seeded =
            seeded.ok_or_else(|| AuthError::internal("Passkey operation requires a seed"))?;
        let row = match operation {
            "get-id" => self.store.get_passkey_by_id(seeded.id.typed()?).await?,
            "get-credential" => {
                self.store
                    .get_passkey_by_credential_id(seeded.credential_id.typed()?)
                    .await?
            }
            "list" => return self.store.list_passkeys_by_user(&self.owner).await,
            "update-name" => Some(
                self.store
                    .update_passkey_name(seeded.id.typed()?, "Desk-renamed")
                    .await?,
            ),
            "update-auth" => {
                let update = match self.store.passkey_storage() {
                    PasskeyStorage::Native => UpdatePasskeyAuthentication::Native { counter: 1 },
                    PasskeyStorage::Legacy => UpdatePasskeyAuthentication::Legacy {
                        credential: seeded.credential.typed()?.clone(),
                        counter: 1,
                        backed_up: *seeded.backed_up.typed()?,
                        device_type: seeded.device_type.typed()?.clone(),
                    },
                };
                Some(
                    self.store
                        .update_passkey_authentication(&seeded.id, update)
                        .await?,
                )
            }
            _ => return Err(AuthError::internal("Unknown Passkey field operation")),
        };
        Ok(vec![row.ok_or_else(|| {
            AuthError::internal("Selected Passkey does not exist")
        })?])
    }

    #[expect(
        clippy::expect_used,
        reason = "Create must return the selected Passkey before later operations"
    )]
    async fn operations(&self) -> AuthResult<Value> {
        let mut seed = None;
        let mut observations = Vec::new();
        for operation in OPERATIONS {
            let rows = self.execute(operation, seed.as_ref()).await?;
            assert_eq!(rows.len(), 1);
            let result = rows
                .iter()
                .map(|row| self.visible(row))
                .collect::<AuthResult<Vec<_>>>()?;
            if operation == "create" {
                seed = Some(rows.first().expect("created Passkey").clone());
            }
            observations.push(self.observe(operation, json!(result)).await?);
        }
        Ok(json!(observations))
    }

    async fn error(&self, operation: &str, mode: u8) -> AuthResult<Value> {
        let seed = if operation == "create" {
            None
        } else {
            Some(self.store.create_passkey(self.input()).await?)
        };
        let before = self.stored().await?;
        let _ = take(&self.events);
        self.failure.store(mode, Ordering::SeqCst);
        let result = self.execute(operation, seed.as_ref()).await;
        self.failure.store(0, Ordering::SeqCst);
        let phase = if mode == 1 { "input" } else { "output" };
        let message = format!("ordinary Passkey {phase} error");
        match result {
            Err(AuthError::Internal(ref actual)) if actual == &message => {}
            Err(error) => return Err(error),
            Ok(_) => {
                return Err(AuthError::internal(
                    "Passkey callback did not reject the operation",
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
            assert_eq!(
                observation
                    .get("stored")
                    .ok_or_else(|| AuthError::internal("Passkey observation has no stored rows"))?,
                &before
            );
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
        serde_json::from_str(include_str!("../fixtures/passkey-fields-1.7.6.json"))?;
    assert_eq!(fixture.get("version").expect("captured version"), "1.7.6");
    let backends = fixture
        .get("backends")
        .and_then(Value::as_array)
        .expect("captured backends");
    assert_eq!(
        backends
            .iter()
            .map(|case| case.get("backend").expect("captured backend name").as_str())
            .collect::<Vec<_>>(),
        [Some("memory"), Some("sqlite")]
    );
    let expected = backends
        .iter()
        .find(|case| case.get("backend").expect("captured backend name") == backend)
        .expect("captured backend");
    let operations = expected.get("operations").expect("captured operations");
    let failures = expected
        .get("failures")
        .and_then(Value::as_array)
        .expect("captured failures");
    assert_eq!(
        operations
            .as_array()
            .expect("captured operations")
            .iter()
            .map(|operation| operation
                .get("name")
                .expect("captured operation name")
                .as_str())
            .collect::<Vec<_>>(),
        OPERATIONS.map(Some)
    );
    assert_eq!(failures.len(), 6);
    let fixture = Fixture::new(raw).await?;
    match scenario {
        Scenario::Operations => assert_eq!(&fixture.operations().await?, operations),
        Scenario::Failure { operation, phase } => {
            let actual = fixture.error(operation, phase).await?;
            let name = actual.get("name").expect("observed operation name");
            let expected = failures
                .iter()
                .find(|failure| failure.get("name").expect("captured failure name") == name)
                .expect("captured error scenario");
            assert_eq!(&actual, expected);
        }
    }
    Ok(())
}

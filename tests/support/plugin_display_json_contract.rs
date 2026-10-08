#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "The fixture contract asserts complete protocol shapes and fails immediately on invalid observations"
)]

use better_auth::{
    __private_core::{
        ApiKey, AuthError, AuthResult, AuthSchema, AuthStore, CreateApiKey, CreatePasskey,
        CreateUser, FieldMap, FieldValue, Passkey, PasskeyCredentialState, PasskeyStorage,
        SchemaValue, UpdateApiKey, UpdatePasskey, entity::AuthUser, store::schema::EntityRole,
    },
    BetterAuth,
};
use serde_json::{Value, json};
use std::{future::Future, sync::Arc};

#[path = "plugin_display_json_observation.rs"]
mod observation;
#[path = "plugin_display_json_policies.rs"]
mod policies;
#[path = "plugin_primary_key_update.rs"]
mod primary_key_update;
pub(crate) use observation::{api_key_value, passkey_value};
pub(crate) use policies::config;

mod values {
    use better_auth::__private_core as better_auth_core;
    use better_auth::seaorm::__private_chrono as chrono;
    include!("device_where_values.rs");
}

pub(crate) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub(crate) const OWNER: &str = "display-json-owner";
pub(crate) const ID: &str = "display-json-row";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Target {
    ApiKeyName,
    PasskeyName,
    PasskeyAaguid,
}

impl Target {
    pub(crate) const ALL: [Self; 3] = [Self::ApiKeyName, Self::PasskeyName, Self::PasskeyAaguid];
    pub(crate) fn field(self) -> &'static str {
        match self {
            Self::PasskeyAaguid => "aaguid",
            _ => "name",
        }
    }
    pub(crate) fn model(self) -> &'static str {
        match self {
            Self::ApiKeyName => "apikey",
            _ => "passkey",
        }
    }
    pub(crate) fn role(self) -> EntityRole {
        match self {
            Self::ApiKeyName => EntityRole::ApiKey,
            _ => EntityRole::Passkey,
        }
    }
    pub(crate) fn table(self) -> String {
        format!("display_json_{}_{}", self.model(), self.field())
    }
}

pub(crate) fn fixture(path: &std::path::Path, backend: &str, target: Target) -> TestResult<Value> {
    let value: Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    assert_eq!(value["version"], "1.7.6");
    assert_eq!(value["backend"], backend);
    let models = value["models"].as_array().ok_or("Missing display models")?;
    assert_eq!(models.len(), Target::ALL.len());
    for (model, target) in models.iter().zip(Target::ALL) {
        assert_eq!(model["model"], target.model());
        assert_eq!(model["field"], target.field());
        assert_eq!(model["table"], target.table());
        assert_eq!(model["column"], "stored_display");
    }
    models
        .iter()
        .find(|model| model["model"] == target.model() && model["field"] == target.field())
        .cloned()
        .ok_or_else(|| "Missing display target".into())
}

fn api_input(name: FieldValue) -> CreateApiKey {
    CreateApiKey {
        additional_fields: Default::default(),
        reference_id: OWNER.into(),
        config_id: "default".into(),
        name: SchemaValue::from_field(name),
        start: None,
        prefix: None,
        key_hash: "ordinary-display-key".into(),
        refill_interval: None,
        refill_amount: None,
        enabled: true.into(),
        rate_limit_enabled: true,
        rate_limit_time_window: Some(60_000.0),
        rate_limit_max: Some(3.0),
        remaining: Some(10.0),
        expires_at: None,
        permissions: None,
        metadata: Some("null".into()),
    }
}

async fn create<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    target: Target,
    value: FieldValue,
) -> AuthResult<Option<Value>> {
    if target == Target::ApiKeyName {
        return Ok(Some(api_key_value(
            &store.create_api_key(api_input(value)).await?,
        )?));
    }
    let mut input = CreatePasskey {
        additional_fields: Default::default(),
        user_id: OWNER.into(),
        name: Some("Desk".into()).into(),
        credential_id: "ordinary-display-credential".into(),
        public_key: "ordinary-public-key".into(),
        counter: 0,
        device_type: "singleDevice".into(),
        backed_up: false,
        transports: None,
        credential: match store.passkey_storage() {
            PasskeyStorage::Native => PasskeyCredentialState::Native,
            PasskeyStorage::Legacy => "ordinary-private-record".into(),
        },
        aaguid: Some("ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4".into()).into(),
    };
    if target == Target::PasskeyName {
        input.name = SchemaValue::from_field(value);
    } else {
        input.aaguid = SchemaValue::from_field(value);
    }
    Ok(Some(passkey_value(&store.create_passkey(input).await?)?))
}

async fn read<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    target: Target,
) -> AuthResult<Option<Value>> {
    if target == Target::ApiKeyName {
        store
            .get_api_key_by_id(ID)
            .await?
            .as_ref()
            .map(api_key_value)
            .transpose()
    } else {
        store
            .get_passkey_by_id(ID)
            .await?
            .as_ref()
            .map(passkey_value)
            .transpose()
    }
}

async fn update<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    target: Target,
    value: FieldValue,
) -> AuthResult<Option<Value>> {
    if target == Target::ApiKeyName {
        let row = store
            .update_api_key(
                &ID.to_owned().into(),
                UpdateApiKey {
                    name: Some(SchemaValue::from_field(value)),
                    request_count: Some(1.0),
                    ..Default::default()
                },
            )
            .await?;
        return Ok(Some(api_key_value(&row)?));
    }
    let mut patch = UpdatePasskey {
        counter: Some(1),
        ..Default::default()
    };
    if target == Target::PasskeyName {
        patch.name = SchemaValue::from_field(value);
    } else {
        patch.aaguid = SchemaValue::from_field(value);
    }
    Ok(Some(passkey_value(
        &store.update_passkey(&ID.to_owned().into(), patch).await?,
    )?))
}

async fn reset<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    target: Target,
    state: &policies::Shared,
) -> TestResult {
    {
        let mut state = state.lock().expect("display reset state");
        assert!(state.events.is_empty());
        *state = Default::default();
    }
    if target == Target::ApiKeyName {
        store.delete_api_key(&ID.to_owned().into()).await?;
    } else {
        store.delete_passkey(ID).await?;
    }
    Ok(())
}

fn display(input: &Value, target: Target) -> AuthResult<FieldValue> {
    input
        .get(target.field())
        .map(values::revive)
        .transpose()
        .map(|value| value.unwrap_or_default())
}

struct Check<'a, F> {
    backend: &'a str,
    target: Target,
    state: policies::Shared,
    raw: F,
    started: f64,
}

impl<F, Fut> Check<'_, F>
where
    F: Fn() -> Fut,
    Fut: Future<Output = TestResult<Value>>,
{
    async fn observe(
        &self,
        expected: &Value,
        action: impl Future<Output = AuthResult<Option<Value>>>,
    ) -> TestResult {
        let before = (self.raw)().await?;
        let result = action.await;
        let events =
            std::mem::take(&mut self.state.lock().expect("display observation state").events);
        let stored = (self.raw)().await?;
        observation::verify_write_boundary(&before, &stored, &result, expected)?;
        observation::compare(
            self.backend,
            self.target,
            self.started,
            &result,
            events,
            &stored,
            expected,
        )?;
        Ok(())
    }
}

pub(crate) async fn contract<S, F, Fut>(
    raw: Arc<dyn AuthStore<S>>,
    backend: &str,
    target: Target,
    expected: Value,
    observe_raw: F,
) -> TestResult
where
    S: AuthSchema,
    F: Fn() -> Fut,
    Fut: Future<Output = TestResult<Value>>,
{
    let state = policies::Shared::default();
    let build = |defaults| {
        BetterAuth::new(config())
            .store_arc(raw.clone())
            .plugin(policies::Policy {
                target,
                defaults,
                state: state.clone(),
            })
            .build()
    };
    let auth = build(false).await?;
    let defaults = build(true).await?;
    let store = auth.store();
    let default_store = defaults.store();
    let owner = store
        .create_user(
            CreateUser::new()
                .with_name("Display owner")
                .with_email("owner@display-json.test")
                .with_email_verified(false),
        )
        .await?;
    assert_eq!(owner.id().typed()?, OWNER);
    let check = Check {
        backend,
        target,
        state: state.clone(),
        raw: observe_raw,
        started: now(),
    };
    let cases = expected["cases"]
        .as_array()
        .ok_or("Missing display value cases")?;
    assert_eq!(
        cases
            .iter()
            .map(|case| case["name"].as_str())
            .collect::<Vec<_>>(),
        [
            "omitted",
            "undefined",
            "null",
            "object",
            "array",
            "object-text",
            "array-text",
            "string-text",
            "null-text",
            "invalid-text",
            "invalid-json-text"
        ]
        .map(Some)
    );
    for case in cases {
        reset(store.as_ref(), target, &state).await?;
        let value = display(&case["input"], target)?;
        let operations = case["operations"]
            .as_array()
            .ok_or("Missing display operations")?;
        assert_eq!(
            operations
                .iter()
                .map(|operation| operation["name"].as_str())
                .collect::<Vec<_>>(),
            ["create", "read-created", "seed", "update", "read-updated"].map(Some)
        );
        check
            .observe(
                &operations[0],
                create(store.as_ref(), target, value.clone()),
            )
            .await?;
        check
            .observe(&operations[1], read(store.as_ref(), target))
            .await?;
        reset(store.as_ref(), target, &state).await?;
        check
            .observe(
                &operations[2],
                create(store.as_ref(), target, object("seed")),
            )
            .await?;
        check
            .observe(&operations[3], update(store.as_ref(), target, value))
            .await?;
        check
            .observe(&operations[4], read(store.as_ref(), target))
            .await?;
    }
    for case in expected["defaults"]
        .as_array()
        .ok_or("Missing default cases")?
    {
        reset(store.as_ref(), target, &state).await?;
        let operations = case["operations"]
            .as_array()
            .ok_or("Missing default operations")?;
        check
            .observe(
                &operations[0],
                create(
                    default_store.as_ref(),
                    target,
                    display(&case["input"], target)?,
                ),
            )
            .await?;
        check
            .observe(
                &operations[1],
                update(default_store.as_ref(), target, FieldValue::Undefined),
            )
            .await?;
        check
            .observe(&operations[2], read(default_store.as_ref(), target))
            .await?;
    }
    reset(store.as_ref(), target, &state).await?;
    {
        let mut state = state.lock().expect("display wrapping state");
        state.wrap_input = true;
        state.wrap_output = true;
    }
    let transformations = expected["transformations"]
        .as_array()
        .ok_or("Missing transformations")?;
    check
        .observe(
            &transformations[0],
            create(store.as_ref(), target, object("request")),
        )
        .await?;
    check
        .observe(
            &transformations[1],
            update(
                store.as_ref(),
                target,
                vec!["request".into(), 2.into()].into(),
            ),
        )
        .await?;
    check
        .observe(&transformations[2], read(store.as_ref(), target))
        .await?;
    reset(store.as_ref(), target, &state).await?;
    check
        .observe(
            &expected["projectionSeed"],
            create(store.as_ref(), target, object("seed")),
        )
        .await?;
    for projection in expected["projections"]
        .as_array()
        .ok_or("Missing projections")?
    {
        let name = projection["name"]
            .as_str()
            .ok_or("Missing projection name")?;
        let case = cases
            .iter()
            .find(|case| case["name"] == name)
            .ok_or("Missing projection input")?;
        state.lock().expect("display projection state").projection =
            Some(display(&case["input"], target)?);
        check
            .observe(projection, read(store.as_ref(), target))
            .await?;
    }
    for failure in expected["failures"].as_array().ok_or("Missing failures")? {
        reset(store.as_ref(), target, &state).await?;
        if !failure["seed"].is_null() {
            check
                .observe(
                    &failure["seed"],
                    create(default_store.as_ref(), target, FieldValue::Undefined),
                )
                .await?;
        }
        let (operation, phase) = failure["name"]
            .as_str()
            .ok_or("Missing failure name")?
            .split_once('-')
            .ok_or("Invalid failure name")?;
        observation::compare_storage(backend, target, &(check.raw)().await?, &failure["before"])?;
        state.lock().expect("display failure state").failure = Some(phase.into());
        let action = async {
            match operation {
                "create" => create(default_store.as_ref(), target, FieldValue::Undefined).await,
                "update" => update(default_store.as_ref(), target, FieldValue::Undefined).await,
                "read" => read(default_store.as_ref(), target).await,
                _ => Err(AuthError::internal("Unknown display failure operation")),
            }
        };
        check.observe(&failure["result"], action).await?;
    }
    eprintln!(
        "display JSON contract boundaries: generated ID policy replaces forceAllowId; timestamps are checked against the real clock and storage; Memory Passkey retains its verified legacy credential and updatedAt envelope; field sets are compared without key order; JavaScript Error identity and driver diagnostic text/properties remain unpaired; backend={backend}, target={target:?}"
    );
    if backend == "mysql" && target != Target::PasskeyAaguid {
        primary_key_update::check(raw, target).await?;
    }
    Ok(())
}

fn object(source: &str) -> FieldValue {
    FieldMap::from_iter([("source".into(), source.into())]).into()
}
fn now() -> f64 {
    better_auth::seaorm::__private_chrono::Utc::now().timestamp_millis() as f64
}

#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report exact contract mismatches while Result propagates fixture errors."
)]
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Pinned native contracts must fail immediately when the fixture shape or setup changes."
)]

use super::*;
use crate::field_value::{FieldObjectSource, FieldPropertyDescriptor};
use crate::store::database_hooks::{
    DatabaseHookContext, DatabaseHookControl, DatabaseHookUpdate, DatabaseHooks,
};
use crate::store::schema::EntityRole;
use crate::store::{EphemeralStore, SecondaryStorage, SessionStore, StatelessSchema};
use crate::{AuthConfig, FieldArray, FieldFunction, FieldObject, FromFieldMap};
use serde_json::{Value as Json, json};
use std::sync::{Arc, Mutex};

use crate::native_test_observation as observation;
mod storage;
mod undefined_writes;
mod values;

use observation::{NativeObservation, assert_replay};
use storage::Storage;

const NOW: i64 = 2_000_000_000_000;
const INDEX: &str = "active-sessions-owner";
type Observer = Arc<Mutex<NativeObservation>>;

fn date(offset: i64) -> FieldValue {
    FieldDate::from_milliseconds((NOW + offset) as f64).into()
}

fn user() -> FieldMap {
    FieldMap::from([
        ("id".into(), "owner".into()),
        ("name".into(), "Owner".into()),
        ("email".into(), "owner@secondary-native.test".into()),
        ("emailVerified".into(), true.into()),
        ("image".into(), FieldValue::Null),
        ("createdAt".into(), date(-2_000)),
        ("updatedAt".into(), date(-1_000)),
    ])
}

fn session(token: &str, expiration: i64) -> FieldMap {
    FieldMap::from([
        ("id".into(), format!("session-{token}").into()),
        ("token".into(), token.into()),
        ("userId".into(), "owner".into()),
        ("expiresAt".into(), date(expiration)),
        ("createdAt".into(), date(-2_000)),
        ("updatedAt".into(), date(-1_000)),
        ("ipAddress".into(), "stored-ip".into()),
        ("userAgent".into(), "stored-agent".into()),
    ])
}

fn record(observer: &Observer, phase: &str, data: FieldValue) -> AuthResult<()> {
    let mut observer = observer.lock().unwrap();
    let data = observer.observe(&data)?;
    observer.record(phase, [("data".into(), data)]);
    Ok(())
}

struct Hooks(Observer);

#[crate::database_hooks()]
impl DatabaseHooks<StatelessSchema> for Hooks {
    async fn before_create_session(
        &self,
        data: &mut FieldMap,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        record(&self.0, "hook:create:before", data.clone().into())?;
        Ok(DatabaseHookUpdate::Continue)
    }

    async fn after_create_session(
        &self,
        data: Option<&crate::SessionView>,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        record(
            &self.0,
            "hook:create:after",
            data.map_or(FieldValue::Null, |value| {
                FieldMap::from(value.clone()).into()
            }),
        )
    }

    async fn before_update_session(
        &self,
        data: &mut FieldMap,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        record(&self.0, "hook:update:before", data.clone().into())?;
        Ok(DatabaseHookUpdate::Continue)
    }

    async fn after_update_session(
        &self,
        data: Option<&crate::SessionView>,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        record(
            &self.0,
            "hook:update:after",
            data.map_or(FieldValue::Null, |value| {
                FieldMap::from(value.clone()).into()
            }),
        )
    }

    async fn before_delete_session(
        &self,
        data: &crate::SessionView,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookControl> {
        record(
            &self.0,
            "hook:delete:before",
            FieldMap::from(data.clone()).into(),
        )?;
        Ok(DatabaseHookControl::Continue)
    }

    async fn after_delete_session(
        &self,
        data: &crate::SessionView,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        record(
            &self.0,
            "hook:delete:after",
            FieldMap::from(data.clone()).into(),
        )
    }
}

fn database_rows(inner: &EphemeralStore) -> AuthResult<FieldValue> {
    Ok([
        ("user", EntityRole::User),
        ("session", EntityRole::Session),
        ("account", EntityRole::Account),
        ("verification", EntityRole::Verification),
    ]
    .into_iter()
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
    .into())
}

fn snapshot(
    inner: &EphemeralStore,
    cache: &Storage,
    values: &values::Values,
    observer: &Observer,
) -> AuthResult<Json> {
    let database = database_rows(inner)?;
    let cache = cache.snapshot();
    let mut observer = observer.lock().unwrap();
    let _ = observer.observe(
        &FieldMap::from([
            ("database".into(), database.clone()),
            ("cache".into(), cache.clone()),
            ("roots".into(), values.roots.clone().into()),
        ])
        .into(),
    )?;
    let database = observer.observe(&database)?;
    let cache = observer.observe(&cache)?;
    let root_data = values
        .roots
        .iter()
        .map(|(name, value)| {
            Ok((
                name.clone(),
                observer.observe(&value.enumerable_fields()?.into())?,
            ))
        })
        .collect::<AuthResult<serde_json::Map<_, _>>>()?;
    Ok(json!({"database": database, "cache": cache, "rootData": root_data}))
}

async fn capture(scenario: &Json, synchronous_storage: bool) -> AuthResult<Json> {
    let observer = Observer::default();
    let values = values::Values::new(scenario, observer.clone())?;
    let cache = Arc::new(Storage::new(
        scenario,
        &values,
        observer.clone(),
        synchronous_storage,
    )?);
    let initial_index = cache.value(INDEX);
    let mut config = AuthConfig::default();
    config.session.store_session_in_database = Some(scenario["storeInDatabase"] == true);
    config.advanced.database.generate_id = Some(crate::id::IdGeneration::Custom(
        crate::id::IdGenerator::new(|request| Ok(Some(format!("{}-generated", request.model)))),
    ));
    let config = Arc::new(config);
    let inner = Arc::new(
        EphemeralStore::from_storage(
            config.clone(),
            [
                ("user".into(), vec![user()]),
                (
                    "session".into(),
                    vec![session("target", 60_000), session("retained", 90_000)],
                ),
                ("account".into(), Vec::new()),
                ("verification".into(), Vec::new()),
            ],
        )?
        .with_hooks(vec![Arc::new(Hooks(observer.clone()))]),
    );
    let store = SecondaryStore::new(inner.clone(), cache.clone(), config, Default::default())?
        .with_clock(|| chrono::DateTime::from_timestamp_millis(NOW).unwrap());
    let before = snapshot(&inner, &cache, &values, &observer)?;
    let input = values.input(scenario);
    let result = match scenario["operation"].as_str().unwrap() {
        "create" => store
            .create_session(crate::CreateSession {
                inherited_fields: FieldMap::new(),
                additional_fields: session("created", 30_000),
                user_id: "owner".into(),
                expires_at: FieldDate::from_milliseconds((NOW + 30_000) as f64),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await
            .map(|value| FieldMap::from(value).into()),
        "update" => store
            .update_session_fields("target", values::patch())
            .await
            .map(|value| value.map_or(FieldValue::Null, |value| FieldMap::from(value).into())),
        "delete" => store
            .delete_session("target")
            .await
            .map(|()| FieldValue::Undefined),
        "batch-delete" => store
            .delete_user_sessions("owner")
            .await
            .map(|()| FieldValue::Undefined),
        "refresh" => {
            let user =
                UserView::from_field_values(input.model_property("user")?.enumerable_fields()?)?;
            store
                .refresh_user_sessions(Some(&user))
                .await
                .map(|()| FieldValue::Undefined)
        }
        _ => {
            return Err(AuthError::internal(
                "Unknown secondary Session contract operation",
            ));
        }
    };
    let outcome = observer.lock().unwrap().outcome(result, &values.original)?;
    let mut after = snapshot(&inner, &cache, &values, &observer)?;
    let _ = after.as_object_mut().unwrap().insert(
        "indexSameOriginal".into(),
        cache.value(INDEX).strict_equals(&initial_index).into(),
    );
    let mut observer = observer.lock().unwrap();
    let input = observer.observe(&input)?;
    Ok(json!({
        "input": input, "before": before, "outcome": outcome, "events": observer.events,
        "after": after, "functionIds": observer.function_ids(),
    }))
}

#[tokio::test]
async fn session_secondary_native_runtime_matches_complete_upstream_observations() -> AuthResult<()>
{
    let fixture: Json = serde_json::from_str(include_str!(
        "../../../../../../tests/fixtures/session-secondary-native-1.7.6.json"
    ))?;
    assert_eq!(fixture["version"], "1.7.6");
    assert_eq!(fixture["cases"].as_array().unwrap().len(), 16);
    for case in fixture["cases"].as_array().unwrap() {
        for synchronous_storage in [false, true] {
            let actual = capture(&case["scenario"], synchronous_storage).await?;
            let label = format!(
                "{}/synchronous={synchronous_storage}",
                case["scenario"]["name"].as_str().unwrap()
            );
            assert_replay(&actual, &case["runtime"], &label);
        }
    }
    Ok(())
}

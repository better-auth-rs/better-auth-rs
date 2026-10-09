#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "The paired input contract fails immediately on missing records or malformed shared cases"
)]

use crate::{
    AuthConfig, AuthError, AuthResult, AuthSchema, FieldMap, FieldValue, UserView,
    store::database_hooks::{DatabaseHookContext, DatabaseHookUpdate, DatabaseHooks},
    store::{EphemeralStore, RuntimeStore, UserStore},
    user_fields::{FieldTransforms, UserFieldTransform},
};
use std::sync::{Arc, Mutex};

#[expect(
    dead_code,
    reason = "The shared contract also supplies output callback and integration setup helpers"
)]
mod contract {
    use crate as better_auth_core;
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/support/user_runtime_output_contract.rs"
    ));
}

use contract::write;

#[tokio::test]
async fn user_list_binds_native_boolean_queries_from_the_complete_schema() -> AuthResult<()> {
    let store = EphemeralStore::new(Arc::new(AuthConfig::default()));
    let mut expected = Vec::new();
    for (id, verified) in [("verified", true), ("unverified", false)] {
        expected.push(
            store
                .create_user(crate::CreateUser {
                    id: Some(id.into()),
                    ..crate::CreateUser::new()
                        .with_name(id)
                        .with_email(format!("{id}@native-query.test"))
                        .with_email_verified(verified)
                })
                .await?,
        );
    }
    let before = store.storage_rows(crate::store::schema::EntityRole::User)?;
    for (value, index) in [("true", 0), ("false", 1), ("TRUE", 1), ("", 1)] {
        let (returned, count) = store
            .list_users(crate::ListUsersParams {
                filter_field: Some("emailVerified".into()),
                filter_value: Some(value.into()),
                ..Default::default()
            })
            .await?;
        assert_eq!(returned, [expected[index].clone()], "{value:?}");
        assert_eq!(count, 1, "{value:?}");
        assert_eq!(
            store.storage_rows(crate::store::schema::EntityRole::User)?,
            before
        );
    }
    Ok(())
}

type Events = Arc<Mutex<Vec<(&'static str, FieldMap)>>>;

struct Hook {
    name: &'static str,
    events: Events,
    patch: FieldMap,
}

impl Hook {
    fn before(&self, fields: &FieldMap) -> DatabaseHookUpdate<FieldMap> {
        self.events
            .lock()
            .unwrap()
            .push((self.name, fields.clone()));
        DatabaseHookUpdate::Patch(self.patch.clone())
    }

    fn after(&self, user: Option<&UserView>) {
        self.events
            .lock()
            .unwrap()
            .push(("after", FieldMap::from(user.unwrap().clone())));
    }
}

#[better_auth::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for Hook {
    async fn before_create_user(
        &self,
        fields: &mut FieldMap,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        Ok(self.before(fields))
    }

    async fn before_update_user(
        &self,
        fields: &mut FieldMap,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        Ok(self.before(fields))
    }

    async fn after_create_user(
        &self,
        user: Option<&UserView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.after(user);
        Ok(())
    }

    async fn after_update_user(
        &self,
        user: Option<&UserView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.after(user);
        Ok(())
    }
}

fn raw(config: &AuthConfig, create: bool) -> AuthResult<Arc<EphemeralStore>> {
    let store = Arc::new(EphemeralStore::new(Arc::new(config.clone())));
    if !create {
        store
            .lock()?
            .users
            .push(UserView::try_from(contract::native_user())?);
    }
    Ok(store)
}

fn stored_user(store: &EphemeralStore) -> AuthResult<Option<FieldMap>> {
    let rows = store.lock()?.users.snapshot()?;
    assert!(rows.len() <= 1);
    Ok(rows.into_iter().next().map(FieldMap::from))
}

#[tokio::test]
async fn native_user_input_replacements_reach_storage_and_after_hooks_once() -> AuthResult<()> {
    for create in [true, false] {
        for field in contract::cases()?["fields"].as_array().unwrap() {
            let mut config = contract::config()?;
            let raw = raw(&config, create)?;
            let name = field["name"].as_str().unwrap();
            let replacement = contract::revive(&field["replacement"])?;
            let selected = replacement.clone();
            let calls = contract::Calls::default();
            let observed = calls.clone();
            config.user.fields_mut().get_mut(name).unwrap().transform = Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    observed.lock().unwrap().push(value);
                    Ok(selected.clone())
                })),
                ..Default::default()
            });
            let events = Events::default();
            let store = raw.with_runtime(
                Arc::new(config),
                vec![Arc::new(Hook {
                    name: "before",
                    events: events.clone(),
                    patch: FieldMap::new(),
                })],
                Default::default(),
            )?;
            let input = contract::native_user();
            let result = write(store.as_ref(), create, input.clone()).await?;
            let count = field["calls"].as_u64().unwrap_or(1) as usize;
            assert_eq!(
                calls.lock().unwrap().len(),
                count,
                "create={create}, {name}"
            );
            if count != 0 {
                assert_eq!(
                    contract::observe(&calls.lock().unwrap()[0])?,
                    contract::observe(&input[name])?
                );
            }
            let expected = if count == 0 || !create && replacement.is_undefined() {
                &input[name]
            } else {
                &replacement
            };
            let result = FieldMap::from(result);
            let stored = stored_user(&raw)?.unwrap();
            let readback = FieldMap::from(raw.get_user_by_id(contract::OWNER).await?.unwrap());
            assert_eq!(
                contract::observe(&result[name])?,
                contract::observe(expected)?,
                "create={create}, {name}"
            );
            assert_eq!(
                contract::observe(stored.get(name).unwrap_or(&FieldValue::Undefined))?,
                contract::observe(expected)?,
                "create={create}, {name}"
            );
            let events = events.lock().unwrap();
            assert_eq!(
                events.iter().map(|event| event.0).collect::<Vec<_>>(),
                ["before", "after"]
            );
            assert_eq!(
                contract::observe(&events[0].1[name])?,
                contract::observe(&input[name])?
            );
            assert_eq!(
                contract::observe(&events[1].1[name])?,
                contract::observe(expected)?
            );
            let mut expected_record = input.clone();
            let _ = expected_record.insert(name.into(), expected.clone());
            let mut expected_storage = expected_record.clone();
            // Memory stores JSON text and omits undefined writes before adapter output.
            if name != "metadata" {
                let _ = expected_storage.insert("metadata".into(), r#"{"seed":true}"#.into());
            } else if create && expected.is_undefined() {
                let _ = expected_storage.remove("metadata");
            }
            assert_eq!(
                contract::observe(&stored.into())?,
                contract::observe(&expected_storage.into())?,
                "complete storage: create={create}, {name}"
            );
            let expected_record = contract::observe(&expected_record.into())?;
            for record in [&result, &readback, &events[1].1] {
                assert_eq!(
                    contract::observe(&record.clone().into())?,
                    expected_record,
                    "complete record: create={create}, {name}"
                );
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn user_hooks_merge_native_patches_without_revalidating_cross_type_fields() -> AuthResult<()>
{
    for create in [true, false] {
        let config = contract::config()?;
        let raw = raw(&config, create)?;
        let events = Events::default();
        let first = FieldMap::from([
            (
                "email".into(),
                FieldMap::from([("source".into(), "hook".into())]).into(),
            ),
            ("emailVerified".into(), Vec::<FieldValue>::new().into()),
        ]);
        let second = FieldMap::from([("role".into(), vec![FieldValue::from("admin")].into())]);
        let store = raw.with_runtime(
            Arc::new(config),
            vec![
                Arc::new(Hook {
                    name: "first",
                    events: events.clone(),
                    patch: first.clone(),
                }),
                Arc::new(Hook {
                    name: "second",
                    events: events.clone(),
                    patch: second.clone(),
                }),
            ],
            Default::default(),
        )?;
        let input = contract::native_user();
        let returned = FieldMap::from(write(store.as_ref(), create, input.clone()).await?);
        let stored = stored_user(&raw)?.unwrap();
        let readback = FieldMap::from(raw.get_user_by_id(contract::OWNER).await?.unwrap());
        let events = events.lock().unwrap();
        assert_eq!(
            events.iter().map(|event| event.0).collect::<Vec<_>>(),
            ["first", "second", "after", "after"]
        );
        for (name, value) in first.iter().chain(second.iter()) {
            assert_eq!(
                contract::observe(&returned[name])?,
                contract::observe(value)?
            );
            assert_eq!(contract::observe(&stored[name])?, contract::observe(value)?);
            assert_eq!(
                contract::observe(&events[2].1[name])?,
                contract::observe(value)?
            );
            assert_eq!(
                contract::observe(&events[3].1[name])?,
                contract::observe(value)?
            );
        }
        let mut expected_record = input.clone();
        expected_record.extend(first.clone());
        expected_record.extend(second.clone());
        let mut expected_storage = expected_record.clone();
        let _ = expected_storage.insert("metadata".into(), r#"{"seed":true}"#.into());
        assert_eq!(
            contract::observe(&stored.into())?,
            contract::observe(&expected_storage.into())?
        );
        let expected_record = contract::observe(&expected_record.into())?;
        for record in [&returned, &readback, &events[2].1, &events[3].1] {
            assert_eq!(contract::observe(&record.clone().into())?, expected_record);
        }
        assert_eq!(
            contract::observe(&events[0].1["email"])?,
            contract::observe(&input["email"])?
        );
        let second_email = if create {
            &first["email"]
        } else {
            &input["email"]
        };
        assert_eq!(
            contract::observe(&events[1].1["email"])?,
            contract::observe(second_email)?
        );
    }
    Ok(())
}

#[tokio::test]
async fn later_user_input_errors_stop_writes_and_after_hooks() -> AuthResult<()> {
    for create in [true, false] {
        let mut config = contract::config()?;
        let raw = raw(&config, create)?;
        let before = stored_user(&raw)?;
        let calls = Arc::new(Mutex::new(Vec::new()));
        for name in ["emailVerified", "createdAt"] {
            let calls = calls.clone();
            config.user.fields_mut().get_mut(name).unwrap().transform = Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    calls.lock().unwrap().push(name);
                    if name == "createdAt" {
                        Err(AuthError::internal("user-input-stop"))
                    } else {
                        Ok(value)
                    }
                })),
                ..Default::default()
            });
        }
        let events = Events::default();
        let store = raw.with_runtime(
            Arc::new(config),
            vec![Arc::new(Hook {
                name: "before",
                events: events.clone(),
                patch: FieldMap::new(),
            })],
            Default::default(),
        )?;
        let error = write(store.as_ref(), create, contract::native_user())
            .await
            .unwrap_err();
        assert_eq!(error.instrumentation_message(), "user-input-stop");
        assert_eq!(*calls.lock().unwrap(), ["emailVerified", "createdAt"]);
        assert_eq!(
            events
                .lock()
                .unwrap()
                .iter()
                .map(|event| event.0)
                .collect::<Vec<_>>(),
            ["before"]
        );
        assert_eq!(stored_user(&raw)?, before);
    }
    Ok(())
}

#[tokio::test]
async fn user_email_normalization_runs_before_hooks_with_operation_specific_truthiness()
-> AuthResult<()> {
    let cases: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/user-runtime-input-cases.json"
    )))?;
    for create in [true, false] {
        let operation = if create { "create" } else { "update" };
        for case in cases["emails"].as_array().unwrap() {
            let config = contract::config()?;
            let raw = raw(&config, create)?;
            let before = stored_user(&raw)?;
            let events = Events::default();
            let store = raw.with_runtime(
                Arc::new(config),
                vec![Arc::new(Hook {
                    name: "before",
                    events: events.clone(),
                    patch: FieldMap::new(),
                })],
                Default::default(),
            )?;
            let mut input = contract::native_user();
            let _ = input.insert("email".into(), contract::revive(&case["value"])?);
            let result = write(store.as_ref(), create, input).await;
            let events = events.lock().unwrap().clone();
            if case.get(format!("{operation}Error")).is_some() {
                assert!(result.is_err(), "{operation}: {}", case["name"]);
                assert!(events.is_empty());
                assert_eq!(stored_user(&raw)?, before);
            } else {
                let returned = FieldMap::from(result?);
                assert_eq!(
                    events.iter().map(|event| event.0).collect::<Vec<_>>(),
                    ["before", "after"]
                );
                assert_eq!(contract::observe(&events[0].1["email"])?, case[operation]);
                let selected = contract::revive(&case[operation])?;
                let expected = if !create && selected.is_undefined() {
                    FieldValue::from(contract::EMAIL)
                } else {
                    selected
                };
                assert_eq!(
                    contract::observe(&returned["email"])?,
                    contract::observe(&expected)?
                );
                let stored = stored_user(&raw)?.unwrap();
                assert_eq!(
                    contract::observe(stored.get("email").unwrap_or(&FieldValue::Undefined))?,
                    contract::observe(&expected)?
                );
            }
        }
    }
    Ok(())
}

#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "The paired input contract fails immediately on missing records or malformed shared cases"
)]

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, CreateUser, FieldMap, FieldValue, UpdateUser,
    UserView,
    store::database_hooks::{DatabaseHookContext, DatabaseHookUpdate, DatabaseHooks},
    store::{EphemeralStore, RuntimeStore, UserStore},
    user_fields::{FieldTransforms, UserFieldTransform},
};
use std::sync::{Arc, Mutex};

#[path = "support/user_runtime_output_contract.rs"]
#[expect(
    dead_code,
    reason = "The shared contract also supplies output callback helpers"
)]
mod contract;

#[path = "support/username_native_input.rs"]
mod username_native_input;

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

async fn write(
    store: &dyn UserStore<better_auth_core::store::StatelessSchema>,
    create: bool,
    fields: FieldMap,
) -> AuthResult<UserView> {
    if create {
        store
            .create_user(CreateUser {
                additional_fields: fields,
                ..Default::default()
            })
            .await
    } else {
        store
            .update_user(
                contract::OWNER,
                UpdateUser {
                    additional_fields: fields,
                    ..Default::default()
                },
            )
            .await
    }
}

async fn raw(config: &AuthConfig, create: bool) -> AuthResult<Arc<EphemeralStore>> {
    if create {
        Ok(Arc::new(EphemeralStore::new(Arc::new(config.clone()))))
    } else {
        Ok(contract::seed(config).await?.0)
    }
}

#[tokio::test]
async fn native_user_input_replacements_reach_storage_and_after_hooks_once() -> AuthResult<()> {
    for create in [true, false] {
        for field in contract::cases()?["fields"].as_array().unwrap() {
            let mut config = contract::config()?;
            let raw = raw(&config, create).await?;
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
            let stored = FieldMap::from(raw.get_user_by_id(contract::OWNER).await?.unwrap());
            assert_eq!(
                contract::observe(&result[name])?,
                contract::observe(expected)?,
                "create={create}, {name}"
            );
            assert_eq!(
                contract::observe(&stored[name])?,
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
        }
    }
    Ok(())
}

#[tokio::test]
async fn user_hooks_merge_native_patches_without_revalidating_cross_type_fields() -> AuthResult<()>
{
    for create in [true, false] {
        let config = contract::config()?;
        let raw = raw(&config, create).await?;
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
        let stored = FieldMap::from(raw.get_user_by_id(contract::OWNER).await?.unwrap());
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
        let raw = raw(&config, create).await?;
        let before = raw
            .get_user_by_id(contract::OWNER)
            .await?
            .map(FieldMap::from);
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
        assert_eq!(
            raw.get_user_by_id(contract::OWNER)
                .await?
                .map(FieldMap::from),
            before
        );
    }
    Ok(())
}

#[tokio::test]
async fn user_email_normalization_runs_before_hooks_with_operation_specific_truthiness()
-> AuthResult<()> {
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/user-runtime-input-cases.json"))?;
    for create in [true, false] {
        let operation = if create { "create" } else { "update" };
        for case in cases["emails"].as_array().unwrap() {
            let config = contract::config()?;
            let raw = raw(&config, create).await?;
            let before = raw
                .get_user_by_id(contract::OWNER)
                .await?
                .map(FieldMap::from);
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
                assert_eq!(
                    raw.get_user_by_id(contract::OWNER)
                        .await?
                        .map(FieldMap::from),
                    before
                );
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
                let stored = FieldMap::from(raw.get_user_by_id(contract::OWNER).await?.unwrap());
                assert_eq!(
                    contract::observe(&stored["email"])?,
                    contract::observe(&expected)?
                );
            }
        }
    }
    Ok(())
}

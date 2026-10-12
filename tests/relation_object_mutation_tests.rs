#![cfg(feature = "seaorm2")]

use better_auth_core::{
    AuthConfig, AuthError, AuthRecordFields, AuthResult, AuthSchema, AuthStore, CreateAccount,
    CreateTeam, CreateUser, FieldDate, FieldMap, FieldObject, FieldProperty, FieldValue,
    StructuredCloneContext,
    organization_fields::OrganizationFields,
    plugin_runtime::ModelFields,
    store::{EphemeralStore, JoinValue, RuntimeStore, StatelessSchema, schema::EntityRole},
    user_fields::{
        FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
    },
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Schema, Statement},
    store::entities,
};
use std::sync::{Arc, Mutex};

#[path = "sql_relation_property_tests/models.rs"]
mod core_models;
#[path = "relation_object_mutation_tests/models.rs"]
mod models;
#[path = "relation_object_mutation_tests/support.rs"]
mod support;
use support::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
type Events = Arc<Mutex<Vec<(&'static str, FieldValue)>>>;
const COLLISION: &str = "stored-parent-property";

fn data_property(object: &FieldObject, name: &str) -> AuthResult<Option<FieldValue>> {
    object
        .own_property_descriptor(name)?
        .map(|descriptor| match descriptor.property {
            FieldProperty::Data { value, .. } => Ok(value),
            FieldProperty::Accessor { .. } => Err(AuthError::internal(
                "Relation mutation requires a stored data property",
            )),
        })
        .transpose()
}

#[derive(Clone, Copy, Debug)]
enum Target {
    User,
    Account,
    Team,
}

impl Target {
    fn roles(self) -> (EntityRole, EntityRole) {
        match self {
            Self::User => (EntityRole::User, EntityRole::Account),
            Self::Account => (EntityRole::Account, EntityRole::User),
            Self::Team => (EntityRole::Team, EntityRole::TeamMember),
        }
    }
    fn physical(self) -> &'static str {
        match self {
            Self::User => "linked_account",
            Self::Account => "linked_user",
            Self::Team => "linked_team_member",
        }
    }
    fn changed(self) -> &'static str {
        match self {
            Self::User => "accessToken",
            Self::Account => "name",
            Self::Team => "userId",
        }
    }
    fn deleted(self) -> &'static str {
        match self {
            Self::User => "refreshToken",
            Self::Account => "image",
            Self::Team => "createdAt",
        }
    }
    fn many(self) -> bool {
        !matches!(self, Self::Account)
    }
}

#[derive(Clone, Copy)]
struct Run {
    target: Target,
    joins: bool,
    reject: bool,
}

fn policy(output: UserFieldTransform) -> UserFieldConfig {
    UserFieldConfig {
        transform: Some(FieldTransforms {
            output: Some(output),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn event(events: &Events, name: &'static str, value: &FieldValue) -> AuthResult<()> {
    events
        .lock()
        .map_err(|_| AuthError::internal("Trace lock poisoned"))?
        .push((name, snapshot(value)?));
    Ok(())
}

fn snapshot(value: &FieldValue) -> AuthResult<FieldValue> {
    fn plain_tree(value: &FieldValue) -> AuthResult<FieldValue> {
        Ok(match value {
            FieldValue::Array(values) => values
                .iter()?
                .map(|value| plain_tree(&value?))
                .collect::<AuthResult<Vec<_>>>()?
                .into(),
            FieldValue::Object(object) => object
                .snapshot_fields()?
                .into_iter()
                .map(|(name, value)| Ok((name, plain_tree(&value)?)))
                .collect::<AuthResult<FieldMap>>()?
                .into(),
            value => value.clone(),
        })
    }

    // These acyclic fixture trees need structural comparisons; identity assertions use the original live handles.
    plain_tree(&StructuredCloneContext::new().clone_value(value)?)
}

fn mutate(target: Target, row: &mut FieldMap) {
    let _ = row.insert("id".into(), 9.into());
    let _ = row.insert(target.changed().into(), 7.into());
    let _ = row.remove(target.deleted());
    let _ = row.insert("mutationOwn".into(), FieldValue::Undefined);
    let _ = row.insert("mutationTail".into(), "last".into());
}

async fn check<S: AuthSchema>(
    run: Run,
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
) -> TestResult {
    let Run {
        target,
        joins,
        reject,
    } = run;
    let plain = configured(raw.as_ref(), target, false, None, UserConfig::default())?;
    let (baseline, visible_before) = observe(plain.as_ref(), target).await?;
    let (parent_role, child_role) = target.roles();
    let before_parent = storage.rows(parent_role).await?;
    let before_children = storage.rows(child_role).await?;
    let raw_children = match &storage {
        Storage::Memory(_) => before_children.clone(),
        Storage::Sqlite { children, .. } => children.clone(),
    };
    let raw_before = if joins {
        relation(target, &raw_children)
    } else {
        COLLISION.into()
    };
    let mut changed = raw_children.clone();
    if joins {
        mutate(target, changed.first_mut().ok_or("Missing first child")?);
    }
    let raw_after = if joins {
        relation(target, &changed)
    } else {
        COLLISION.into()
    };
    let events = Events::default();
    let captured = Arc::new(Mutex::new(FieldValue::Undefined));
    let collision = {
        let (events, captured, before, after) = (
            events.clone(),
            captured.clone(),
            raw_before.clone(),
            raw_after.clone(),
        );
        UserFieldTransform::new(move |value| {
            assert_eq!(snapshot(&value)?, before);
            *captured
                .lock()
                .map_err(|_| AuthError::internal("Capture lock poisoned"))? = value.clone();
            event(&events, "collision", &value)?;
            if joins {
                let child = first(target, &value)?;
                let object = child
                    .as_object()
                    .ok_or_else(|| AuthError::internal("Expected child object"))?;
                let initial = object.snapshot_fields()?;
                assert_eq!(data_property(object, "id")?, initial.get("id").cloned());
                object.set("id", 9.into())?;
                assert_eq!(
                    data_property(object, target.changed())?,
                    initial.get(target.changed()).cloned()
                );
                object.set(target.changed(), 7.into())?;
                assert_eq!(
                    data_property(object, target.deleted())?,
                    initial.get(target.deleted()).cloned()
                );
                assert!(object.delete(target.deleted())?);
                assert_eq!(data_property(object, "mutationTail")?, None);
                object.set("mutationTail", "first".into())?;
                assert_eq!(data_property(object, "mutationOwn")?, None);
                object.set("mutationOwn", FieldValue::Undefined)?;
                assert_eq!(data_property(object, "mutationTail")?, Some("first".into()));
                assert!(object.delete("mutationTail")?);
                assert_eq!(data_property(object, "mutationTail")?, None);
                object.set("mutationTail", "last".into())?;
                assert_eq!(object.get(target.deleted())?, None);
                assert_eq!(object.get("mutationOwn")?, Some(FieldValue::Undefined));
                let expected_keys = initial
                    .keys()
                    .filter(|name| name.as_str() != target.deleted())
                    .map(String::as_str)
                    .chain(["mutationOwn", "mutationTail"])
                    .collect::<Vec<_>>();
                assert_eq!(
                    object
                        .snapshot_fields()?
                        .keys()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                    expected_keys
                );
                assert!(first(target, &value)?.strict_equals(&child));
            }
            assert_eq!(snapshot(&value)?, after);
            event(&events, "mutation", &value)?;
            if reject {
                return Err(AuthError::type_error("relation-object-mutation-rejected"));
            }
            Ok(value)
        })
    };
    let mirror = {
        let (events, captured, after) = (events.clone(), captured.clone(), raw_after.clone());
        UserFieldTransform::new(move |value| {
            let held = captured
                .lock()
                .map_err(|_| AuthError::internal("Capture lock poisoned"))?;
            assert!(value.strict_equals(&held));
            if joins {
                assert!(first(target, &value)?.strict_equals(&first(target, &held)?));
            }
            assert_eq!(snapshot(&value)?, after);
            event(&events, "mirror", &value)?;
            Ok(value)
        })
    };
    let parent_fields = UserConfig {
        additional_fields: Some(
            [
                (target.physical().into(), policy(collision)),
                (
                    "relationMirror".into(),
                    UserFieldConfig {
                        field_name: Some(target.physical().into()),
                        ..policy(mirror)
                    },
                ),
            ]
            .into(),
        ),
    };
    let mut child_fields = UserConfig::default();
    for (name, phase) in [(target.changed(), "value"), (target.deleted(), "deleted")] {
        let (input, output, update) = (events.clone(), events.clone(), events.clone());
        let _ = child_fields.fields_mut().insert(
            name.into(),
            UserFieldConfig {
                field_type: if name == "createdAt" {
                    UserFieldType::Date
                } else {
                    UserFieldType::String
                },
                on_update: Some(better_auth_core::user_fields::UserFieldFactory::new(
                    move || {
                        event(&update, "unexpected-onUpdate", &name.into())?;
                        Ok(FieldValue::Undefined)
                    },
                )),
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(move |value| {
                        event(&input, "unexpected-input", &value)?;
                        Ok(value)
                    })),
                    output: Some(UserFieldTransform::new(move |value| {
                        event(&output, phase, &value)?;
                        Ok(value)
                    })),
                }),
                ..Default::default()
            },
        );
    }
    let reader = configured(
        raw.as_ref(),
        target,
        joins,
        Some(parent_fields),
        child_fields,
    )?;
    let result = observe(reader.as_ref(), target).await;
    let mut expected_events = vec![("collision", raw_before), ("mutation", raw_after.clone())];
    if reject {
        let error = result
            .err()
            .ok_or("The parent output callback must reject the query")?;
        assert!(
            matches!(error.downcast_ref::<AuthError>(), Some(AuthError::TypeError(message))
            if message == "relation-object-mutation-rejected")
        );
    } else {
        let (output, children) = result?;
        let mut expected = baseline.clone();
        let _ = expected.insert(target.physical().into(), raw_after.clone());
        let _ = expected.insert("relationMirror".into(), raw_after.clone());
        assert_eq!(
            snapshot(&output.clone().into())?,
            FieldValue::from(expected)
        );
        assert_eq!(
            output.keys().collect::<Vec<_>>(),
            baseline.keys().collect::<Vec<_>>()
        );
        let held = captured.lock().map_err(|_| "Capture lock poisoned")?;
        for name in [target.physical(), "relationMirror"] {
            assert!(
                output
                    .get(name)
                    .ok_or("Missing relation alias")?
                    .strict_equals(&held)
            );
        }
        let mut visible = visible_before.clone();
        if joins {
            let first = visible.first_mut().ok_or("Missing visible child")?;
            let _ = first.insert("id".into(), "9".into());
            let _ = first.insert(target.changed().into(), 7.into());
            let _ = first.insert(target.deleted().into(), FieldValue::Undefined);
        }
        assert_eq!(children, visible);
        for (child, original) in children.iter().zip(&visible_before) {
            assert_eq!(
                child.keys().collect::<Vec<_>>(),
                original.keys().collect::<Vec<_>>()
            );
            assert!(child.contains_key(target.deleted()));
            assert!(!child.contains_key("mutationOwn"));
        }
        if joins && storage.is_memory() && !matches!(target, Target::Team) {
            let projected_date = children
                .first()
                .and_then(|row| row.get("createdAt"))
                .ok_or("Missing child date")?;
            assert!(
                projected_date.strict_equals(&first(target, &held)?.model_property("createdAt")?)
            );
        }
        expected_events.push(("mirror", raw_after));
        for row in &changed {
            expected_events.push((
                "value",
                row.get(target.changed()).cloned().unwrap_or_default(),
            ));
            expected_events.push((
                "deleted",
                row.get(target.deleted()).cloned().unwrap_or_default(),
            ));
        }
    }
    assert_eq!(
        *events.lock().map_err(|_| "Trace lock poisoned")?,
        expected_events
    );
    assert_eq!(storage.rows(parent_role).await?, before_parent);
    let expected_storage = if storage.is_memory() {
        changed
    } else {
        before_children
    };
    let stored = storage.rows(child_role).await?;
    assert_eq!(stored, expected_storage);
    for (row, expected) in stored.iter().zip(&expected_storage) {
        assert_eq!(
            row.keys().collect::<Vec<_>>(),
            expected.keys().collect::<Vec<_>>()
        );
    }
    Ok(())
}

#[tokio::test]
async fn direct_relation_object_mutation_matches_memory_and_sqlite() -> TestResult {
    for target in [Target::User, Target::Account, Target::Team] {
        for joins in [false, true] {
            for reject in [false, true] {
                let run = Run {
                    target,
                    joins,
                    reject,
                };
                let raw = Arc::new(memory_store(target)?);
                let writer = configured::<StatelessSchema>(
                    raw.as_ref(),
                    target,
                    false,
                    None,
                    UserConfig::default(),
                )?;
                seed_memory(writer.as_ref(), target).await?;
                check::<StatelessSchema>(run, raw.clone(), Storage::Memory(raw)).await?;
                let (raw, storage) = sql_fixture(target).await?;
                check::<core_models::Core>(run, raw, storage).await?;
            }
        }
    }
    Ok(())
}

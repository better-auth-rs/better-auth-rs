//! Paired with the pinned native-join-property-collision upstream contract.
#![expect(
    clippy::panic_in_result_fn,
    reason = "The paired contract propagates setup errors and asserts full output, identity, callbacks, and durable storage."
)]

use super::*;
use crate::store::{JoinValue, RuntimeStore, schema::EntityRole};
use crate::user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform};
use crate::{FieldDate, FieldValue, StructuredCloneContext};

fn date(offset: u32) -> FieldDate {
    FieldDate::from_milliseconds(1_893_456_000_000.0 + f64::from(offset) * 1_000.0)
}

fn account(id: &str, subject: &str, token: &str, owner: &str) -> CreateAccount {
    CreateAccount {
        id: id.into(),
        account_id: subject.into(),
        provider_id: "provider".into(),
        user_id: owner.into(),
        access_token: Some(token.to_owned()).into(),
        refresh_token: Some("refresh".to_owned()).into(),
        id_token: Some("id-token".to_owned()).into(),
        access_token_expires_at: Some(date(10)).into(),
        refresh_token_expires_at: Some(date(20)).into(),
        scope: Some("read".to_owned()).into(),
        password: Some("password".to_owned()).into(),
        created_at: date(0).into(),
        updated_at: date(0).into(),
        ..Default::default()
    }
}

fn user(id: &str, name: &str, extra: FieldMap) -> CreateUser {
    CreateUser {
        id: Some(id.into()),
        email: Some(format!("{id}@native-join-property-collision.test")),
        name: Some(name.to_owned()).into(),
        email_verified: Some(true),
        image: None::<String>.into(),
        created_at: Some(date(0)),
        updated_at: Some(date(0)),
        additional_fields: extra,
        ..Default::default()
    }
}

fn snapshot(value: &FieldValue) -> AuthResult<FieldValue> {
    StructuredCloneContext::new().clone_value(value)
}

fn joined(many: bool, rows: &[FieldMap]) -> FieldValue {
    if many {
        rows.iter()
            .cloned()
            .map(FieldValue::from)
            .collect::<Vec<_>>()
            .into()
    } else {
        rows.first()
            .cloned()
            .map_or(FieldValue::Null, FieldValue::from)
    }
}

type Events = Arc<Mutex<Vec<(String, FieldValue)>>>;

fn event(events: &Events, name: &str, value: &FieldValue) -> AuthResult<()> {
    events
        .lock()
        .map_err(|_| AuthError::internal("Relation trace lock poisoned"))?
        .push((name.to_owned(), snapshot(value)?));
    Ok(())
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

async fn check(
    many: bool,
    alias: bool,
    joins: bool,
    reject: bool,
    missing: bool,
) -> AuthResult<()> {
    let child_model = if many { "account" } else { "user" };
    let physical = if alias {
        format!("linked_{child_model}")
    } else {
        child_model.to_owned()
    };
    let child_role = if many {
        EntityRole::Account
    } else {
        EntityRole::User
    };
    let parent_id = if many {
        "joined-owner"
    } else {
        "parent-account"
    };
    let child_id = if many {
        "child-account"
    } else {
        "joined-owner"
    };
    let value_field = if many { "accessToken" } else { "name" };
    let mut config = AuthConfig::default();
    config.advanced.database.joins = Some(joins);
    let fields = if many {
        config.user.fields_mut()
    } else {
        &mut config.account.additional_fields
    };
    let _ = fields.insert(physical.clone(), UserFieldConfig::default());
    let _ = fields.insert(
        "relationMirror".into(),
        UserFieldConfig {
            field_name: Some(physical.clone()),
            ..Default::default()
        },
    );
    let writer = EphemeralStore::new(Arc::new(config.clone()));
    if many {
        let _ = writer
            .create_account(account(
                "unrelated-account",
                "unrelated",
                "Unrelated",
                "owner",
            ))
            .await?;
    } else {
        let _ = writer
            .create_user(user("unrelated-user", "Unrelated", FieldMap::new()))
            .await?;
    }
    let extra = [(physical.clone(), "stored-parent-property".into())].into();
    let before_parent = if many {
        writer
            .create_user(user(parent_id, "Parent", extra))
            .await?
            .field_values()?
    } else {
        let mut input = account(parent_id, "subject", "before", child_id);
        input.additional_fields = extra;
        writer.create_account(input).await?.internal_fields()?
    };
    let mut before_children = Vec::new();
    if !missing {
        if many {
            for (id, subject, token) in [
                (child_id, "first", "Before"),
                ("second-account", "second", "Second"),
            ] {
                before_children.push(
                    writer
                        .create_account(account(id, subject, token, parent_id))
                        .await?
                        .internal_fields()?,
                );
            }
        } else {
            before_children.push(
                writer
                    .create_user(user(child_id, "Before", FieldMap::new()))
                    .await?
                    .field_values()?,
            );
        }
    }
    let before_storage = writer.storage_rows(child_role)?;
    let before_parent_storage = writer.storage_rows(if many {
        EntityRole::User
    } else {
        EntityRole::Account
    })?;
    let mut after_children = before_children.clone();
    if let Some(first) = after_children.first_mut() {
        let _ = first.insert(value_field.into(), "After".into());
        let _ = first.insert("updatedAt".into(), date(1).into());
    }
    let raw_before = if joins {
        joined(many, &before_children)
    } else {
        "stored-parent-property".into()
    };
    let raw_after = if joins {
        joined(many, &after_children)
    } else {
        "stored-parent-property".into()
    };
    let events = Events::default();
    let captured = Arc::new(Mutex::new(FieldValue::Undefined));
    let output = {
        let (events, captured, writer, raw_before, raw_after) = (
            events.clone(),
            captured.clone(),
            writer.clone(),
            raw_before.clone(),
            raw_after.clone(),
        );
        UserFieldTransform::new_async(move |value| {
            let (events, captured, writer, raw_before, raw_after) = (
                events.clone(),
                captured.clone(),
                writer.clone(),
                raw_before.clone(),
                raw_after.clone(),
            );
            async move {
                assert_eq!(snapshot(&value)?, raw_before);
                *captured
                    .lock()
                    .map_err(|_| AuthError::internal("Captured relation lock poisoned"))? =
                    value.clone();
                let raw_child = if joins && !missing {
                    Some(if many {
                        value
                            .as_array()
                            .and_then(|rows| rows.first())
                            .cloned()
                            .ok_or_else(|| AuthError::internal("Expected selected child"))?
                    } else {
                        value.clone()
                    })
                } else {
                    None
                };
                event(&events, "collision", &value)?;
                if !missing {
                    let written = if many {
                        writer
                            .update_account(
                                child_id,
                                UpdateAccount {
                                    access_token: Some("After".to_owned()).into(),
                                    updated_at: date(1).into(),
                                    ..Default::default()
                                },
                            )
                            .await?
                            .internal_fields()?
                    } else {
                        writer
                            .update_user(
                                child_id,
                                UpdateUser {
                                    name: Some("After".to_owned()).into(),
                                    additional_fields: [("updatedAt".into(), date(1).into())]
                                        .into(),
                                    ..Default::default()
                                },
                            )
                            .await?
                            .field_values()?
                    };
                    event(&events, "write", &written.into())?;
                    assert_eq!(snapshot(&value)?, raw_after);
                    if let Some(child) = raw_child {
                        let current = if many {
                            value
                                .as_array()
                                .and_then(|rows| rows.first())
                                .ok_or_else(|| AuthError::internal("Expected retained child"))?
                        } else {
                            &value
                        };
                        assert!(current.strict_equals(&child));
                    }
                    event(&events, "collision-after-write", &value)?;
                }
                if reject {
                    return Err(AuthError::type_error("raw-relation-output-rejected"));
                }
                Ok(value)
            }
        })
    };
    let mirror = {
        let (events, captured, raw_after) = (events.clone(), captured.clone(), raw_after.clone());
        UserFieldTransform::new(move |value| {
            assert!(
                value.strict_equals(
                    &*captured
                        .lock()
                        .map_err(|_| AuthError::internal("Captured relation lock poisoned"))?
                )
            );
            assert_eq!(snapshot(&value)?, raw_after);
            event(&events, "mirror", &value)?;
            Ok(value)
        })
    };
    let fields = if many {
        config.user.fields_mut()
    } else {
        &mut config.account.additional_fields
    };
    let _ = fields.insert(physical.clone(), policy(output));
    let _ = fields.insert(
        "relationMirror".into(),
        UserFieldConfig {
            field_name: Some(physical.clone()),
            ..policy(mirror)
        },
    );
    let child_policy = {
        let events = events.clone();
        policy(UserFieldTransform::new(move |value| {
            event(&events, "child", &value)?;
            Ok(format!(
                "visible:{}",
                value
                    .display_utf16()?
                    .to_utf8()
                    .map_err(|error| AuthError::internal(error.to_string()))?
            )
            .into())
        }))
    };
    let child_fields = if many {
        &mut config.account.additional_fields
    } else {
        config.user.fields_mut()
    };
    let _ = child_fields.insert(value_field.into(), child_policy);
    let mut models = crate::plugin_runtime::ModelFields::default();
    models.set_model_name(child_role, Some(&physical))?;
    let reader = writer.with_runtime(Arc::new(config), Vec::new(), models)?;
    let result = async {
        if many {
            let output = reader
                .get_user_with_accounts(&format!("{parent_id}@native-join-property-collision.test"))
                .await?
                .ok_or_else(|| AuthError::internal("Expected parent User"))?;
            let mut parent = output.user.field_values()?;
            let children = match output.accounts {
                JoinValue::Many(rows) => rows
                    .into_iter()
                    .map(|row| row.internal_fields())
                    .collect::<AuthResult<Vec<_>>>()?,
                _ => return Err(AuthError::internal("Expected Account page")),
            };
            let _ = parent.insert("account".into(), joined(true, &children));
            Ok(parent)
        } else {
            let output = reader
                .get_account_owner("provider", "subject")
                .await?
                .ok_or_else(|| AuthError::internal("Expected parent Account"))?;
            let mut parent = output.account.internal_fields()?;
            let child = match output.user {
                JoinValue::One(user) => user.map(|user| user.field_values()).transpose()?,
                _ => return Err(AuthError::internal("Expected one User")),
            };
            let _ = parent.insert(
                "user".into(),
                child.map_or(FieldValue::Null, FieldValue::from),
            );
            Ok(parent)
        }
    }
    .await;
    if reject {
        assert!(
            matches!(result, Err(AuthError::TypeError(message)) if message == "raw-relation-output-rejected")
        );
    } else {
        let output = result?;
        let held = captured
            .lock()
            .map_err(|_| AuthError::internal("Captured relation lock poisoned"))?
            .clone();
        assert!(
            output
                .get("relationMirror")
                .is_some_and(|value| value.strict_equals(&held))
        );
        if alias {
            assert!(
                output
                    .get(&physical)
                    .is_some_and(|value| value.strict_equals(&held))
            );
        }
        if joins && !missing {
            let projected = output
                .get(child_model)
                .ok_or_else(|| AuthError::internal("Expected projected relationship"))?;
            let (raw_child, projected_child) = if many {
                assert!(!projected.strict_equals(&held));
                (
                    held.as_array().and_then(|rows| rows.first()),
                    projected.as_array().and_then(|rows| rows.first()),
                )
            } else {
                (Some(&held), Some(projected))
            };
            let raw_child = raw_child.ok_or_else(|| AuthError::internal("Expected raw child"))?;
            let projected_child =
                projected_child.ok_or_else(|| AuthError::internal("Expected projected child"))?;
            assert!(!projected_child.strict_equals(raw_child));
            assert!(
                projected_child
                    .model_property("createdAt")?
                    .strict_equals(&raw_child.model_property("createdAt")?)
            );
        }
        let mut expected = before_parent;
        let _ = expected.insert(physical.clone(), raw_after.clone());
        let _ = expected.insert("relationMirror".into(), raw_after.clone());
        let mut projected = after_children.clone();
        for child in &mut projected {
            let value = child
                .get(value_field)
                .and_then(FieldValue::as_str)
                .ok_or_else(|| AuthError::internal("Expected child label"))?;
            let value = format!("visible:{value}");
            let _ = child.insert(value_field.into(), value.into());
        }
        let _ = expected.insert(child_model.into(), joined(many, &projected));
        assert_eq!(StructuredCloneContext::new().clone_map(&output)?, expected);
    }
    let mut expected_events = vec![("collision".to_owned(), raw_before)];
    if !missing {
        expected_events.push((
            "write".into(),
            after_children
                .first()
                .cloned()
                .ok_or_else(|| AuthError::internal("Expected written child"))?
                .into(),
        ));
        expected_events.push(("collision-after-write".into(), raw_after.clone()));
    }
    if !reject {
        expected_events.push(("mirror".into(), raw_after));
        expected_events.extend(after_children.iter().map(|row| {
            (
                "child".into(),
                row.get(value_field).cloned().unwrap_or_default(),
            )
        }));
    }
    assert_eq!(
        *events
            .lock()
            .map_err(|_| AuthError::internal("Relation trace lock poisoned"))?,
        expected_events
    );
    assert_eq!(
        writer.storage_rows(if many {
            EntityRole::User
        } else {
            EntityRole::Account
        })?,
        before_parent_storage
    );
    let mut expected_storage = before_storage;
    if let Some(first) = expected_storage
        .iter_mut()
        .find(|row| row.get("id") == Some(&child_id.into()))
    {
        let _ = first.insert(value_field.into(), "After".into());
        let _ = first.insert("updatedAt".into(), date(1).into());
    }
    assert_eq!(writer.storage_rows(child_role)?, expected_storage);
    Ok(())
}

#[tokio::test]
async fn native_and_fallback_raw_relations_preserve_collision_identity_and_committed_writes()
-> AuthResult<()> {
    for many in [false, true] {
        for alias in [false, true] {
            for joins in [false, true] {
                for reject in [false, true] {
                    check(many, alias, joins, reject, false).await?;
                }
            }
            check(many, alias, true, false, true).await?;
        }
    }
    Ok(())
}

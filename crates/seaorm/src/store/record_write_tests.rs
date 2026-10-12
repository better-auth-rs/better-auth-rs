use super::*;
use crate::store::mysql_query::materialize_for_test;
use crate::store::query_compile::Compile;
use crate::{
    SeaOrmPluginModel,
    store::entities::{passkey, user},
};
use better_auth_core::{
    AuthError, FieldFunction, FieldMap, FieldObject,
    id::IdGeneration,
    user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform},
};
use sea_orm::{DbBackend, sea_query::Values};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn rejecting_callback(
    name: &'static str,
    calls: &Arc<AtomicUsize>,
    allocation: &Arc<AtomicUsize>,
) -> FieldValue {
    let calls = calls.clone();
    let allocation = allocation.clone();
    FieldFunction::contextual(move |_, _| {
        let _ = calls.fetch_add(1, Ordering::SeqCst);
        let message = name.to_owned();
        allocation.store(message.as_ptr() as usize, Ordering::SeqCst);
        Err(AuthError::Internal(message))
    })
    .into()
}

fn assert_original_error<T>(
    result: AuthResult<T>,
    name: &str,
    allocation: &AtomicUsize,
) -> AuthResult<()> {
    let Err(AuthError::Internal(message)) = result else {
        return Err(AuthError::internal(
            "Expected the original UPDATE phase error",
        ));
    };
    assert_eq!(message, name);
    assert_eq!(message.as_ptr() as usize, allocation.load(Ordering::SeqCst));
    Ok(())
}

#[test]
fn set_expressions_parse_before_where_expressions_and_any_driver_encoding() -> AuthResult<()> {
    for backend in [DbBackend::Sqlite, DbBackend::Postgres, DbBackend::MySql] {
        let set_calls = Arc::new(AtomicUsize::new(0));
        let where_calls = Arc::new(AtomicUsize::new(0));
        let nested_calls = Arc::new(AtomicUsize::new(0));
        let allocation = Arc::new(AtomicUsize::new(0));
        let mut write = RecordWrite::<user::Entity>::default();
        write.field(
            user::Column::Name,
            vec![rejecting_callback(
                "nested-driver",
                &nested_calls,
                &allocation,
            )]
            .into(),
        );
        write.field(
            user::Column::Email,
            rejecting_callback("set-expression", &set_calls, &allocation),
        );
        let predicate = QueryPredicate::equals(
            user::Column::Id,
            rejecting_callback("where-expression", &where_calls, &allocation),
        );
        assert_original_error(
            write.update_where_returning(backend, [predicate]),
            "set-expression",
            &allocation,
        )?;
        assert_eq!(set_calls.load(Ordering::SeqCst), 1);
        assert_eq!(where_calls.load(Ordering::SeqCst), 0);
        assert_eq!(nested_calls.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[test]
fn all_where_expressions_parse_before_set_or_where_driver_encoding() -> AuthResult<()> {
    for backend in [DbBackend::Sqlite, DbBackend::Postgres, DbBackend::MySql] {
        let where_calls = Arc::new(AtomicUsize::new(0));
        let later_calls = Arc::new(AtomicUsize::new(0));
        let nested_calls = Arc::new(AtomicUsize::new(0));
        let allocation = Arc::new(AtomicUsize::new(0));
        let nested: FieldValue = vec![rejecting_callback(
            "nested-driver",
            &nested_calls,
            &allocation,
        )]
        .into();
        let mut write = RecordWrite::<user::Entity>::default();
        write.field(user::Column::Name, nested.clone());
        let predicates = [
            QueryPredicate::equals(user::Column::Name, vec![nested].into()),
            QueryPredicate::equals(
                user::Column::Email,
                rejecting_callback("where-expression", &where_calls, &allocation),
            ),
            QueryPredicate::equals(
                user::Column::Id,
                rejecting_callback("later-expression", &later_calls, &allocation),
            ),
        ];
        assert_original_error(
            write.update_where_returning(backend, predicates),
            "where-expression",
            &allocation,
        )?;
        assert_eq!(where_calls.load(Ordering::SeqCst), 1);
        assert_eq!(later_calls.load(Ordering::SeqCst), 0);
        assert_eq!(nested_calls.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[test]
fn set_driver_encoding_precedes_where_driver_encoding() -> AuthResult<()> {
    for backend in [DbBackend::Sqlite, DbBackend::Postgres, DbBackend::MySql] {
        let calls = Arc::new(AtomicUsize::new(0));
        let allocation = Arc::new(AtomicUsize::new(0));
        let object = FieldObject::from(FieldMap::from([("toString".into(), FieldValue::Null)]));
        if backend == DbBackend::Postgres {
            let _ = object.set("self", FieldValue::Object(object.clone()))?;
        }
        let mut write = RecordWrite::<user::Entity>::default();
        if backend == DbBackend::Sqlite {
            write.native_field(
                user::Column::Name,
                better_auth_core::FieldDate::invalid().into(),
            );
        } else {
            write.field(
                user::Column::Name,
                vec![rejecting_callback("nested-driver", &calls, &allocation)].into(),
            );
        }
        let result = write
            .update_where_returning(
                backend,
                [QueryPredicate::equals(
                    user::Column::Id,
                    FieldValue::Object(object.clone()),
                )],
            )
            .and_then(|(update, _)| update.query.compile(backend))
            .and_then(materialize_for_test);
        let _ = object.delete("self")?;
        let error = result
            .err()
            .ok_or_else(|| AuthError::internal("Invalid SET driver value must fail"))?;
        assert_eq!(
            error.instrumentation_message()?,
            if backend == DbBackend::Sqlite {
                "Invalid Date"
            } else {
                "JavaScript function source is unavailable for this Rust field callback"
            }
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[test]
fn returning_update_keeps_all_conditions_and_reuses_only_the_first_selector() -> AuthResult<()> {
    for backend in [DbBackend::Sqlite, DbBackend::Postgres, DbBackend::MySql] {
        let mut write = RecordWrite::<user::Entity>::default();
        write.field(user::Column::Name, "after".into());
        write.field(user::Column::Image, FieldValue::Null);
        let (update, reselect) = write.update_where_returning(
            backend,
            [
                QueryPredicate::equals(user::Column::Id, "selected".into()),
                QueryPredicate::equals(user::Column::Name, "before".into()),
                QueryPredicate::equals(user::Column::Image, FieldValue::Null),
            ],
        )?;
        assert!(update.source_is_null(user::Column::Image));
        assert!(!update.source_is_null(user::Column::Name));
        let actual = update
            .query
            .compile(backend)
            .and_then(materialize_for_test)?;
        let selected = crate::store::query_compile::build(backend, Query::select().expr(reselect))
            .and_then(materialize_for_test)?;
        let quote = if backend == DbBackend::MySql {
            '`'
        } else {
            '"'
        };
        let table = format!("{quote}users{quote}");
        let name = format!("{quote}name{quote}");
        let image = format!("{quote}image{quote}");
        let id = format!("{quote}id{quote}");
        if backend == DbBackend::Postgres {
            assert_eq!(
                actual.sql,
                format!(
                    "UPDATE {table} SET {name} = $1, {image} = $2 WHERE {table}.{id} = $3 AND {table}.{name} = $4 AND {table}.{image} IS NULL"
                )
            );
            assert_eq!(
                actual.values,
                Some(Values(vec![
                    Value::PostgresUnspecifiedText(Some("after".into())),
                    Value::PostgresUnspecifiedText(None),
                    Value::PostgresUnspecifiedText(Some("selected".into())),
                    Value::PostgresUnspecifiedText(Some("before".into())),
                ]))
            );
            assert_eq!(selected.sql, format!("SELECT {table}.{id} = $1"));
            assert_eq!(
                selected.values,
                Some(Values(vec![Value::PostgresUnspecifiedText(Some(
                    "selected".into()
                ))]))
            );
        } else if backend == DbBackend::MySql {
            assert_eq!(
                actual.sql,
                "update `users` set `name` = 'after', `image` = NULL where `users`.`id` = 'selected' and `users`.`name` = 'before' and `users`.`image` is null"
            );
            assert_eq!(actual.values, None);
            assert_eq!(selected.sql, "select `users`.`id` = 'selected'");
            assert_eq!(selected.values, None);
        } else {
            assert_eq!(
                actual.sql,
                format!(
                    "UPDATE {table} SET {name} = ?, {image} = ? WHERE {table}.{id} = ? AND {table}.{name} = ? AND {table}.{image} IS NULL"
                )
            );
            assert_eq!(
                actual.values,
                Some(Values(vec![
                    Value::String(Some("after".into())),
                    Value::String(None),
                    Value::String(Some("selected".into())),
                    Value::String(Some("before".into())),
                ]))
            );
            assert_eq!(selected.sql, format!("SELECT {table}.{id} = ?"));
            assert_eq!(
                selected.values,
                Some(Values(vec![Value::String(Some("selected".into()))]))
            );
        }
    }
    Ok(())
}

#[expect(
    unreachable_pub,
    reason = "SeaORM derives require public fixture entity types"
)]
mod mapped {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "mapped_assignments")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(save_as = "integer")]
        pub remaining: i32,
        pub label: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[test]
fn increment_expression_keeps_assignment_position_and_bypasses_column_casts() -> AuthResult<()> {
    use sea_orm::sea_query::{Expr, ExprTrait};

    for backend in [DbBackend::Sqlite, DbBackend::Postgres, DbBackend::MySql] {
        for expression in [false, true] {
            let mut write = RecordWrite::<mapped::Entity>::default();
            write.field(mapped::Column::Remaining, FieldValue::Null);
            write.field(mapped::Column::Label, "after".into());
            if expression {
                write.expression(
                    mapped::Column::Remaining,
                    Expr::col(mapped::Column::Remaining).add(1),
                );
            } else {
                write.set(mapped::Column::Remaining, Value::Int(Some(2)));
            }
            let update = write.update_where(
                backend,
                [QueryPredicate::equals(
                    mapped::Column::Id,
                    "selected".into(),
                )],
            )?;
            assert!(!update.source_is_null(mapped::Column::Remaining));
            let quote = if backend == DbBackend::MySql {
                '`'
            } else {
                '"'
            };
            let remaining = format!("{quote}remaining{quote}");
            let assigned = if expression {
                format!("{remaining} + 1")
            } else {
                if backend == DbBackend::MySql {
                    "cast(2 as integer)"
                } else {
                    "CAST(2 AS integer)"
                }
                .into()
            };
            let expected = if backend == DbBackend::MySql {
                format!(
                    "update `mapped_assignments` set {remaining} = {assigned}, `label` = 'after' where `mapped_assignments`.`id` = 'selected'"
                )
            } else {
                format!(
                    "UPDATE {quote}mapped_assignments{quote} SET {remaining} = {assigned}, {quote}label{quote} = 'after' WHERE {quote}mapped_assignments{quote}.{quote}id{quote} = 'selected'"
                )
            };
            assert_eq!(
                update
                    .query
                    .compile(backend)
                    .and_then(materialize_for_test)?
                    .to_string(),
                expected
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn declared_undefined_keeps_database_default_instead_of_legacy_initializer() -> AuthResult<()>
{
    let db = sea_orm::Database::connect("sqlite::memory:")
        .await
        .map_err(map_db_err)?;
    let _ = db.execute_unprepared(
        "CREATE TABLE passkeys (id TEXT PRIMARY KEY, updated_at TEXT DEFAULT 'database-default')",
    ).await.map_err(map_db_err)?;
    let mut schema = UserConfig::default();
    let _ = schema.fields_mut().insert(
        "label".into(),
        UserFieldConfig {
            field_name: Some("updatedAt".into()),
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(|_| Ok(FieldValue::Undefined))),
                output: None,
            }),
            ..Default::default()
        },
    );
    let input = prepare_fields(
        &schema,
        FieldMap::from([
            ("id".into(), "row".into()),
            ("label".into(), "supplied".into()),
        ]),
        Some("passkey"),
        (&ModelFields::default(), EntityRole::Passkey),
        &IdGeneration::Database,
        DbBackend::Sqlite,
        |_, _, value| Ok(value),
    )
    .await?;
    let write = RecordWrite::<passkey::Entity>::from_initialized_fields::<passkey::ActiveModel>(
        &schema,
        input,
        passkey::Model::column,
        vec![passkey::Column::UpdatedAt],
        |_| {
            Err(AuthError::internal(
                "A declared column must not call the legacy initializer",
            ))
        },
    )?;
    let row = write
        .insert_raw(
            &db,
            CreateReadback {
                schema: &schema,
                policy: &IdGeneration::Database,
                scope: super::super::create_readback::ReadbackScope::Direct(&db),
                column: passkey::Model::column,
            },
        )
        .await?
        .ok_or_else(|| AuthError::internal("Created row was not returned"))?;
    assert_eq!(row.try_get::<String>("", "id").map_err(map_db_err)?, "row");
    assert_eq!(
        row.try_get::<String>("", "updated_at")
            .map_err(map_db_err)?,
        "database-default"
    );
    Ok(())
}

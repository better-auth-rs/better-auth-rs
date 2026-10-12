use super::*;
use crate::store::mysql_query::materialize_for_test;
use crate::store::{
    SeaOrmStore, bundled_schema::BundledSchema, entities::user, map_db_err,
    migrator::run_migrations, record_write::RecordWrite,
};
use better_auth_core::{
    AuthConfig, CreateUser, FieldFunction, FieldMap, UpdateUser, WhereMode, WhereOperator,
    store::UserStore, user_fields::UserFieldFactory,
};
use sea_orm::{Database, EntityTrait};
use serde_json::Value as JsonValue;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn function(result: &str, calls: &Arc<AtomicUsize>, returned: &Arc<AtomicUsize>) -> FieldValue {
    let result = result.to_owned();
    let calls = calls.clone();
    let returned = returned.clone();
    let factory: UserFieldFactory = UserFieldFactory::new(move || {
        let _ = calls.fetch_add(1, Ordering::SeqCst);
        Ok(match result.as_str() {
            "string" => "factory-value".into(),
            "undefined" => FieldValue::Undefined,
            "null" => FieldValue::Null,
            "date" => chrono::DateTime::parse_from_rfc3339("2030-01-02T03:04:05.000Z")
                .map_err(|error| AuthError::internal(error.to_string()))?
                .with_timezone(&chrono::Utc)
                .into(),
            "object" => FieldMap::from([
                ("source".into(), "factory".into()),
                ("ownUndefined".into(), FieldValue::Undefined),
            ])
            .into(),
            "function" => {
                let returned = returned.clone();
                let returned_factory: UserFieldFactory = UserFieldFactory::new(move || {
                    let _ = returned.fetch_add(1, Ordering::SeqCst);
                    Ok("returned-function-value".into())
                });
                FieldValue::Function(FieldFunction::from(returned_factory))
            }
            "throws" => return Err(AuthError::internal("protected-default-failed")),
            _ => return Err(AuthError::internal("Unknown captured function result")),
        })
    });
    FieldValue::Function(FieldFunction::from(factory))
}

fn captured(backend: &str) -> AuthResult<JsonValue> {
    let path = format!(
        "{}/../../tests/fixtures/protected-function-{backend}-1.7.6.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let source = std::fs::read_to_string(&path)
        .map_err(|error| AuthError::internal(format!("Cannot read {path}: {error}")))?;
    Ok(serde_json::from_str(&source)?)
}

fn raw_cases(fixture: &JsonValue) -> impl Iterator<Item = &JsonValue> {
    fixture["cases"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|case| &case["observation"])
        .filter(|case| {
            case["scenario"]["name"]
                .as_str()
                .is_some_and(|name| name.starts_with("raw-"))
        })
}

fn operation<'a>(case: &'a JsonValue, name: &str) -> AuthResult<&'a JsonValue> {
    case["operations"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|operation| operation["name"] == name)
        .ok_or_else(|| AuthError::internal(format!("Captured operation {name} is missing")))
}

fn assert_rejection<T>(result: AuthResult<T>, expected: &JsonValue) -> AuthResult<()> {
    let error = result
        .err()
        .ok_or_else(|| AuthError::internal("Function expression unexpectedly succeeded"))?;
    assert_eq!(
        error.instrumentation_message()?,
        expected["error"]["message"]
    );
    assert_eq!(expected["returned"], false);
    assert_eq!(expected["storage"], expected["before"]["storage"]);
    assert_eq!(
        expected["counts"]["factory"]
            .as_u64()
            .zip(expected["before"]["counts"]["factory"].as_u64())
            .map(|(after, before)| after - before),
        Some(1)
    );
    Ok(())
}

#[test]
fn captured_expression_failures_run_once_before_parameter_encoding() -> AuthResult<()> {
    for (name, backend) in [
        ("sqlite", DbBackend::Sqlite),
        ("postgres", DbBackend::Postgres),
        ("mysql", DbBackend::MySql),
    ] {
        let fixture = captured(name)?;
        let cases = raw_cases(&fixture).collect::<Vec<_>>();
        assert_eq!(cases.len(), 6);
        for case in cases {
            let result = case["scenario"]["result"]
                .as_str()
                .ok_or_else(|| AuthError::internal("Captured function result is missing"))?;
            for json_column in [false, true] {
                let calls = Arc::new(AtomicUsize::new(0));
                let returned = Arc::new(AtomicUsize::new(0));
                let later = Arc::new(AtomicUsize::new(0));
                let field = function(result, &calls, &returned);
                let binding = if json_column {
                    Binding::Json(field)
                } else {
                    Binding::Raw(field)
                };
                assert_rejection(
                    bind(
                        backend,
                        vec![
                            Binding::Raw(FieldMap::from([("driver".into(), true.into())]).into()),
                            binding,
                            Binding::Raw(function("string", &later, &returned)),
                        ],
                    ),
                    operation(case, "direct:create")?,
                )?;
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                assert_eq!(returned.load(Ordering::SeqCst), 0);
                assert_eq!(later.load(Ordering::SeqCst), 0);

                for operator in [WhereOperator::Eq, WhereOperator::In] {
                    calls.store(0, Ordering::SeqCst);
                    assert_rejection(
                        crate::store::value_filter::predicate(
                            user::Column::Name,
                            operator,
                            WhereMode::Sensitive,
                            vec![
                                FieldMap::from([("driver".into(), true.into())]).into(),
                                function(result, &calls, &returned),
                                function("string", &later, &returned),
                            ]
                            .into(),
                            backend,
                        ),
                        operation(case, "direct:create")?,
                    )?;
                    assert_eq!(calls.load(Ordering::SeqCst), 1);
                    assert_eq!(returned.load(Ordering::SeqCst), 0);
                    assert_eq!(later.load(Ordering::SeqCst), 0);
                }

                calls.store(0, Ordering::SeqCst);
                let mut write = RecordWrite::<user::Entity>::default();
                write.field(
                    user::Column::Name,
                    FieldMap::from([("driver".into(), true.into())]).into(),
                );
                write.field(
                    if json_column {
                        user::Column::Metadata
                    } else {
                        user::Column::Image
                    },
                    function(result, &calls, &returned),
                );
                write.field(user::Column::Email, function("string", &later, &returned));
                assert_rejection(
                    write.update_where(
                        backend,
                        [crate::store::value_filter::QueryPredicate::equals(
                            user::Column::Id,
                            "selected".into(),
                        )],
                    ),
                    operation(case, "update:function")?,
                )?;
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                assert_eq!(returned.load(Ordering::SeqCst), 0);
                assert_eq!(later.load(Ordering::SeqCst), 0);
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn captured_functions_preserve_complete_sqlite_rows_on_insert_and_update() -> AuthResult<()> {
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(map_db_err)?;
    run_migrations(&database).await.map_err(map_db_err)?;
    let store = SeaOrmStore::<BundledSchema>::new(AuthConfig::default(), database.clone());
    let owner = store
        .create_user(
            CreateUser::new()
                .with_name("Original")
                .with_email("original@function.test"),
        )
        .await?;
    let original = user::Entity::find()
        .all(&database)
        .await
        .map_err(map_db_err)?;
    let fixture = captured("sqlite")?;
    let cases = raw_cases(&fixture).collect::<Vec<_>>();
    assert_eq!(cases.len(), 6);
    for case in cases {
        let result = case["scenario"]["result"]
            .as_str()
            .ok_or_else(|| AuthError::internal("Captured function result is missing"))?;
        let calls = Arc::new(AtomicUsize::new(0));
        let returned = Arc::new(AtomicUsize::new(0));
        let mut input = CreateUser::new()
            .with_name("Rejected")
            .with_email("rejected@function.test");
        input.additional_fields = [("image".into(), function(result, &calls, &returned))].into();
        assert_rejection(
            store.create_user(input).await,
            operation(case, "direct:create")?,
        )?;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            user::Entity::find()
                .all(&database)
                .await
                .map_err(map_db_err)?,
            original
        );
        calls.store(0, Ordering::SeqCst);
        assert_rejection(
            store
                .update_user(
                    owner.id.typed()?,
                    UpdateUser {
                        name: Some("Rejected".into()).into(),
                        additional_fields: [("image".into(), function(result, &calls, &returned))]
                            .into(),
                        ..Default::default()
                    },
                )
                .await,
            operation(case, "update:function")?,
        )?;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(returned.load(Ordering::SeqCst), 0);
        assert_eq!(
            user::Entity::find()
                .all(&database)
                .await
                .map_err(map_db_err)?,
            original
        );
    }
    Ok(())
}

#[test]
fn null_results_fail_after_invocation_and_nested_driver_functions_are_not_called() -> AuthResult<()>
{
    for backend in [DbBackend::Sqlite, DbBackend::Postgres, DbBackend::MySql] {
        let calls = Arc::new(AtomicUsize::new(0));
        let returned = Arc::new(AtomicUsize::new(0));
        let error = parameter(function("null", &calls, &returned), backend)
            .err()
            .ok_or_else(|| AuthError::internal("Null expression result unexpectedly succeeded"))?;
        assert_eq!(
            error.instrumentation_message()?,
            "null is not an object (evaluating 'exp(expressionBuilder()).toOperationNode')"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        calls.store(0, Ordering::SeqCst);
        assert!(
            parameter(vec![function("throws", &calls, &returned)].into(), backend)
                .and_then(|value| crate::store::query_compile::build(
                    backend,
                    sea_orm::sea_query::Query::select().expr(value)
                ))
                .and_then(materialize_for_test)
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        for operator in [WhereOperator::Eq, WhereOperator::In] {
            let result = crate::store::value_filter::predicate(
                user::Column::Name,
                operator,
                WhereMode::Sensitive,
                vec![FieldValue::from(vec![function(
                    "throws", &calls, &returned,
                )])]
                .into(),
                backend,
            )
            .and_then(|value| {
                crate::store::query_compile::build(
                    backend,
                    sea_orm::sea_query::Query::select().expr(value),
                )
            })
            .and_then(materialize_for_test);
            let error = result.err().ok_or_else(|| {
                AuthError::internal("Nested driver function unexpectedly encoded")
            })?;
            assert_eq!(
                error.instrumentation_message()?,
                if backend == DbBackend::Sqlite {
                    "Binding expected string, TypedArray, boolean, number, bigint or null"
                } else {
                    "JavaScript function source is unavailable for this Rust field callback"
                },
            );
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(returned.load(Ordering::SeqCst), 0);
        }
    }
    Ok(())
}

#[test]
fn candidate_expression_errors_retain_the_original_allocation() -> AuthResult<()> {
    for backend in [DbBackend::Sqlite, DbBackend::Postgres, DbBackend::MySql] {
        for operator in [WhereOperator::Eq, WhereOperator::In] {
            let allocation = Arc::new(AtomicUsize::new(0));
            let original = allocation.clone();
            let factory: UserFieldFactory = UserFieldFactory::new(move || {
                let message = "original-candidate-error".to_owned();
                original.store(message.as_ptr() as usize, Ordering::SeqCst);
                Err(AuthError::Internal(message))
            });
            let result = crate::store::value_filter::predicate(
                user::Column::Name,
                operator,
                WhereMode::Sensitive,
                vec![
                    FieldMap::from([("driver".into(), true.into())]).into(),
                    FieldFunction::from(factory).into(),
                ]
                .into(),
                backend,
            );
            match result {
                Err(AuthError::Internal(message)) => {
                    assert_eq!(message, "original-candidate-error");
                    assert_eq!(message.as_ptr() as usize, allocation.load(Ordering::SeqCst));
                }
                Err(error) => return Err(error),
                Ok(_) => return Err(AuthError::internal("Candidate expression must fail")),
            }
        }
    }
    Ok(())
}

#[test]
fn all_condition_expressions_parse_before_any_driver_parameter_is_encoded() -> AuthResult<()> {
    use crate::store::value_filter::{self, QueryPredicate};

    for backend in [DbBackend::Sqlite, DbBackend::Postgres, DbBackend::MySql] {
        for operator in [WhereOperator::Eq, WhereOperator::In] {
            let allocation = Arc::new(AtomicUsize::new(0));
            let calls = Arc::new(AtomicUsize::new(0));
            let driver_calls = Arc::new(AtomicUsize::new(0));
            let later = Arc::new(AtomicUsize::new(0));
            let returned = Arc::new(AtomicUsize::new(0));
            let original = allocation.clone();
            let called = calls.clone();
            let factory: UserFieldFactory = UserFieldFactory::new(move || {
                let _ = called.fetch_add(1, Ordering::SeqCst);
                let message = "original-condition-error".to_owned();
                original.store(message.as_ptr() as usize, Ordering::SeqCst);
                Err(AuthError::Internal(message))
            });
            let rejecting = FieldValue::from(FieldFunction::from(factory));
            // The nested function is a driver value; expression parsing must not invoke its body.
            let invalid_driver = vec![FieldValue::from(vec![function(
                "string",
                &driver_calls,
                &returned,
            )])]
            .into();
            let result = value_filter::all(
                [
                    QueryPredicate::equals(user::Column::Name, invalid_driver),
                    QueryPredicate::new(
                        user::Column::Email,
                        operator,
                        WhereMode::Sensitive,
                        if operator == WhereOperator::In {
                            vec![rejecting].into()
                        } else {
                            rejecting
                        },
                    ),
                    QueryPredicate::equals(
                        user::Column::Image,
                        function("string", &later, &returned),
                    ),
                ],
                backend,
            );
            let Err(AuthError::Internal(message)) = result else {
                return Err(AuthError::internal("Expected the original condition error"));
            };
            assert_eq!(message, "original-condition-error");
            assert_eq!(message.as_ptr() as usize, allocation.load(Ordering::SeqCst));
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(driver_calls.load(Ordering::SeqCst), 0);
            assert_eq!(later.load(Ordering::SeqCst), 0);
            assert_eq!(returned.load(Ordering::SeqCst), 0);
        }
    }
    Ok(())
}

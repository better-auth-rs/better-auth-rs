use super::*;
use crate::store::entities::user;
use crate::store::mysql_query::materialize_for_test;
use better_auth_core::AuthError;
use sea_orm::sea_query::{Query, Value, Values};

#[test]
fn insensitive_mode_depends_on_the_operator_and_original_operand_shape() -> AuthResult<()> {
    for backend in [DbBackend::Sqlite, DbBackend::Postgres, DbBackend::MySql] {
        let quote = if backend == DbBackend::MySql {
            '`'
        } else {
            '"'
        };
        let column = format!("{quote}users{quote}.{quote}name{quote}");
        for (operator, sql_operator, pattern) in [
            (WhereOperator::Eq, "=", "UPPER"),
            (WhereOperator::Ne, "<>", "UPPER"),
            (WhereOperator::In, "IN", "UPPER"),
            (WhereOperator::NotIn, "NOT IN", "UPPER"),
            (WhereOperator::Contains, "LIKE", "%UPPER%"),
            (WhereOperator::StartsWith, "LIKE", "UPPER%"),
            (WhereOperator::EndsWith, "LIKE", "%UPPER"),
            (WhereOperator::Lt, "<", "UPPER"),
            (WhereOperator::Lte, "<=", "UPPER"),
            (WhereOperator::Gt, ">", "UPPER"),
            (WhereOperator::Gte, ">=", "UPPER"),
        ] {
            for array in [false, true] {
                let value = if array {
                    FieldValue::from(vec![FieldValue::from("UPPER")])
                } else {
                    FieldValue::from("UPPER")
                };
                let predicate = QueryPredicate::new(
                    user::Column::Name,
                    operator,
                    WhereMode::Insensitive,
                    value,
                )
                .bind(backend)?;
                let statement =
                    crate::store::query_compile::build(backend, Query::select().expr(predicate))
                        .and_then(materialize_for_test)?;
                let membership = matches!(operator, WhereOperator::In | WhereOperator::NotIn);
                let equality = matches!(operator, WhereOperator::Eq | WhereOperator::Ne);
                let like = matches!(
                    operator,
                    WhereOperator::Contains | WhereOperator::StartsWith | WhereOperator::EndsWith
                );
                let folded = membership || !array && (equality || like);
                let value = if folded && !like {
                    pattern.to_lowercase()
                } else {
                    pattern.into()
                };
                let select = if backend == DbBackend::MySql {
                    "select"
                } else {
                    "SELECT"
                };
                let sql_operator = if backend == DbBackend::MySql {
                    sql_operator.to_lowercase()
                } else {
                    sql_operator.into()
                };
                let parameter = if backend == DbBackend::MySql {
                    format!("'{value}'")
                } else if backend == DbBackend::Postgres {
                    "$1".into()
                } else {
                    "?".into()
                };
                let expected = if like && folded && backend == DbBackend::Postgres {
                    format!("{select} {column} ILIKE {parameter}")
                } else if like && folded {
                    format!("{select} LOWER({column}) LIKE LOWER({parameter})")
                } else {
                    let lhs = if folded {
                        format!("LOWER({column})")
                    } else {
                        column.clone()
                    };
                    let rhs = if membership || array && !like {
                        format!("({parameter})")
                    } else {
                        parameter
                    };
                    format!("{select} {lhs} {sql_operator} {rhs}")
                };
                assert_eq!(
                    statement.sql, expected,
                    "{backend:?}: {operator:?}, array={array}"
                );
                if backend == DbBackend::MySql {
                    assert_eq!(statement.values, None);
                    assert_eq!(
                        statement.mysql_text_sql(),
                        Some(statement.sql.encode_utf16().collect::<Vec<_>>().as_slice())
                    );
                    continue;
                }
                let values = if backend == DbBackend::Postgres {
                    vec![Value::PostgresUnspecifiedText(Some(value))]
                } else {
                    vec![Value::String(Some(value))]
                };
                assert_eq!(
                    statement.values,
                    Some(Values(values)),
                    "{backend:?}: {operator:?}, array={array}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn empty_membership_preserves_the_pinned_mysql_compiler_and_other_backends() -> AuthResult<()> {
    use sea_orm::sea_query::{Asterisk, Expr};

    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/mysql-text-1.7.6.json"
    ))?;
    let captured = fixture["compiled"]
        .as_array()
        .and_then(|cases| cases.iter().find(|case| case["name"] == "empty-in"))
        .ok_or_else(|| {
            AuthError::internal("Pinned MySQL empty-in compiler observation is missing")
        })?;
    assert_eq!(captured["parameters"], serde_json::json!([]));
    for backend in [DbBackend::MySql, DbBackend::Postgres, DbBackend::Sqlite] {
        for negated in [false, true] {
            let predicate =
                super::super::membership(Expr::col(("MiX`ed", "id")), Vec::new(), negated, backend);
            let command = crate::store::query_compile::build(
                backend,
                Query::select()
                    .column(Asterisk)
                    .from("MiX`ed")
                    .and_where(predicate),
            )
            .and_then(materialize_for_test)?;
            let expected = match (backend, negated) {
                (DbBackend::MySql, false) => captured["sql"]
                    .as_str()
                    .ok_or_else(|| AuthError::internal("Pinned MySQL empty-in SQL is missing"))?,
                (DbBackend::MySql, true) => {
                    "select * from `MiX``ed` where `MiX``ed`.`id` not in ()"
                }
                (_, false) => "SELECT * FROM \"MiX`ed\" WHERE \"MiX`ed\".\"id\" IN ()",
                (_, true) => "SELECT * FROM \"MiX`ed\" WHERE \"MiX`ed\".\"id\" NOT IN ()",
            };
            assert_eq!(command.sql, expected, "{backend:?}, negated={negated}");
            if backend == DbBackend::MySql {
                assert_eq!(command.values, None);
            } else {
                assert_eq!(command.values, Some(Values(vec![])));
            }
        }
    }
    Ok(())
}

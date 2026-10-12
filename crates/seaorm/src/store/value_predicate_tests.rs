use super::*;
use crate::store::entities::user;
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
                let statement = backend.build(&Query::select().expr(predicate).to_owned());
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
                let parameter = if backend == DbBackend::Postgres {
                    "$1".into()
                } else {
                    "?".into()
                };
                let expected = if like && folded && backend == DbBackend::Postgres {
                    format!("SELECT {column} ILIKE {parameter}")
                } else if like && folded {
                    format!("SELECT LOWER({column}) LIKE LOWER({parameter})")
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
                    format!("SELECT {lhs} {sql_operator} {rhs}")
                };
                assert_eq!(
                    statement.sql, expected,
                    "{backend:?}: {operator:?}, array={array}"
                );
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

use super::*;

#[test]
fn protocol_values_preserve_identity_without_becoming_model_strings() {
    let raw = Value::PostgresUnspecifiedText(Some("17".into()));
    assert_ne!(raw, Value::String(Some("17".into())));
    assert_eq!(raw.as_null(), Value::PostgresUnspecifiedText(None));
    assert_ne!(raw.as_null(), Value::String(None));
    assert_eq!(
        raw.dummy_value(),
        Value::PostgresUnspecifiedText(Some(String::new()))
    );
    assert!(<String as ValueType>::try_from(raw.clone()).is_err());
    assert!(<Option<String> as ValueType>::try_from(raw.as_null()).is_err());

    #[cfg(feature = "hashable-value")]
    {
        let values =
            std::collections::HashSet::from([raw.clone(), Value::String(Some("17".into()))]);
        assert_eq!(values.len(), 2);
        assert!(values.contains(&raw));
    }
}

#[test]
#[should_panic(expected = "PostgresUnspecifiedText is a protocol parameter, not an array type")]
fn protocol_values_reject_array_type_inference() {
    Value::PostgresUnspecifiedText(None).array_type();
}

#[test]
#[cfg(feature = "with-json")]
#[should_panic(expected = "PostgresUnspecifiedText is a protocol parameter, not a JSON value")]
fn protocol_values_reject_lossy_json_conversion() {
    sea_value_to_json_value(&Value::PostgresUnspecifiedText(None));
}

#[test]
#[cfg(feature = "backend-postgres")]
fn postgres_parameters_follow_expression_occurrence_order() {
    let raw = Value::PostgresUnspecifiedText(Some("17".into()));
    let expr = Expr::val(raw.clone());
    let query = Query::update()
        .table("credential")
        .value("raw", expr.clone().cast_as("integer"))
        .value("native", "17")
        .value(
            "repeated",
            Expr::cust_with_expr("COALESCE($1, $1)", expr.clone()),
        )
        .value("nullable", Value::PostgresUnspecifiedText(None))
        .and_where(Expr::col("id").eq(expr.cast_as("integer")))
        .returning_col("raw")
        .to_owned();
    let expected = (
        r#"UPDATE "credential" SET "raw" = CAST($1 AS integer), "native" = $2, "repeated" = COALESCE($3, $4), "nullable" = $5 WHERE "id" = CAST($6 AS integer) RETURNING "raw""#.to_owned(),
        Values(vec![
            raw.clone(),
            Value::String(Some("17".into())),
            raw.clone(),
            raw.clone(),
            Value::PostgresUnspecifiedText(None),
            raw,
        ]),
    );
    assert_eq!(query.build(PostgresQueryBuilder), expected);
    assert_eq!(query.clone().build(PostgresQueryBuilder), expected);
}

#[test]
#[cfg(feature = "backend-postgres")]
fn postgres_diagnostic_literals_escape_text_and_preserve_null() {
    let values = [
        Value::PostgresUnspecifiedText(Some("O'Reilly\\path".into())),
        Value::PostgresUnspecifiedText(None),
        Value::String(Some("17".into())),
    ];
    let query = Query::select()
        .expr(values[0].clone())
        .expr(values[1].clone())
        .expr(values[2].clone())
        .to_owned();
    let expected = r#"SELECT E'O\'Reilly\\path', NULL, '17'"#;
    assert_eq!(query.to_string(PostgresQueryBuilder), expected);
    assert_eq!(
        inject_parameters("SELECT $1, $2, $3", &values, &PostgresQueryBuilder),
        expected
    );
}

#[test]
fn common_builder_rejects_protocol_values() {
    for text in [Some("17"), None] {
        assert!(
            std::panic::catch_unwind(|| {
                Query::select()
                    .expr(Value::PostgresUnspecifiedText(text.map(str::to_owned)))
                    .build(CommonSqlQueryBuilder)
            })
            .is_err()
        );
    }
}

#[test]
#[cfg(feature = "backend-mysql")]
fn mysql_builder_rejects_protocol_values() {
    for text in [Some("17"), None] {
        assert!(
            std::panic::catch_unwind(|| {
                Query::select()
                    .expr(Value::PostgresUnspecifiedText(text.map(str::to_owned)))
                    .build(MysqlQueryBuilder)
            })
            .is_err()
        );
    }
}

#[test]
#[cfg(feature = "backend-sqlite")]
fn sqlite_builder_rejects_protocol_values() {
    for text in [Some("17"), None] {
        assert!(
            std::panic::catch_unwind(|| {
                Query::select()
                    .expr(Value::PostgresUnspecifiedText(text.map(str::to_owned)))
                    .build(SqliteQueryBuilder)
            })
            .is_err()
        );
    }
}

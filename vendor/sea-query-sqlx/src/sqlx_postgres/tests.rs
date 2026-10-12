use super::*;
use sea_query::Values;
use sqlx::{Arguments, Execute, IntoArguments, Postgres};
use std::num::TryFromIntError;

#[test]
fn shared_binder_keeps_native_and_protocol_parameter_occurrences() {
    let values = SqlxValues(Values(vec![
        Value::String(Some("17".into())),
        Value::PostgresUnspecifiedText(Some("17".into())),
        Value::PostgresUnspecifiedText(None),
        Value::Int(Some(17)),
        Value::String(None),
    ]));
    let args = values.clone().try_into_pg_arguments().unwrap();
    assert_eq!(args.len(), 5);
    let args = <SqlxValues as IntoArguments<'_, Postgres>>::into_arguments(values);
    assert_eq!(args.len(), 5);
}

#[test]
fn oversized_unsigned_value_returns_original_conversion_error() {
    let result = SqlxValues(Values(vec![
        Value::Int(Some(1)),
        Value::BigUnsigned(Some(u64::MAX)),
        Value::PostgresUnspecifiedText(Some("tail".into())),
    ]))
    .try_into_pg_arguments();
    let mut query = sqlx::query_with_result::<Postgres, _>("SELECT $1, $2, $3", result);
    let error = query.take_arguments().unwrap_err();
    assert!(error.is::<TryFromIntError>());
}

#[test]
#[should_panic(expected = "failed to encode PostgreSQL arguments")]
fn infallible_entry_point_rejects_failed_conversion() {
    let _ = <SqlxValues as IntoArguments<'_, Postgres>>::into_arguments(SqlxValues(Values(vec![
        Value::BigUnsigned(Some(u64::MAX)),
    ])));
}

#[test]
#[cfg(feature = "with-bigdecimal")]
fn native_encoder_error_is_not_discarded() {
    let decimal: BigDecimal = "1e-32768".parse().unwrap();
    let error = SqlxValues(Values(vec![
        Value::Int(Some(1)),
        Value::BigDecimal(Some(Box::new(decimal))),
        Value::Int(Some(2)),
    ]))
    .try_into_pg_arguments()
    .unwrap_err();
    assert!(error.is::<TryFromIntError>());
}

#[test]
#[cfg(feature = "postgres-array")]
fn malformed_array_elements_return_conversion_errors() {
    for element in [
        Value::String(Some("1".into())),
        Value::PostgresUnspecifiedText(Some("1".into())),
        Value::Int(None),
    ] {
        let error = SqlxValues(Values(vec![Value::Array(
            ArrayType::Int,
            Some(Box::new(vec![Value::Int(Some(1)), element])),
        )]))
        .try_into_pg_arguments()
        .unwrap_err();
        assert!(error.is::<ValueTypeErr>());
    }
    assert!(array_values::<i32>(ArrayType::String, None).is_err());
}

#[test]
#[cfg(feature = "postgres-array")]
fn oversized_unsigned_array_returns_original_conversion_error() {
    let error = SqlxValues(Values(vec![Value::Array(
        ArrayType::BigUnsigned,
        Some(Box::new(vec![Value::BigUnsigned(Some(u64::MAX))])),
    )]))
    .try_into_pg_arguments()
    .unwrap_err();
    assert!(error.is::<TryFromIntError>());
}

#[test]
#[cfg(feature = "postgres-array")]
fn array_conversion_keeps_null_arrays_and_unsigned_byte_arrays() {
    let values = SqlxValues(Values(vec![
        Value::Array(ArrayType::Int, None),
        Value::Array(
            ArrayType::TinyUnsigned,
            Some(Box::new(vec![Value::TinyUnsigned(Some(255))])),
        ),
        Value::Bytes(Some(vec![255])),
    ]));
    assert_eq!(values.try_into_pg_arguments().unwrap().len(), 3);
}

#![expect(
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "Tests intentionally panic when fixture setup or adapter contract assertions fail."
)]

use super::*;
use better_auth_core::{FieldFunction, FieldMap, FieldObject};
use sea_orm::{
    DbBackend,
    sea_query::{Expr, Query},
};
use std::sync::atomic::{AtomicUsize, Ordering};

fn format(query: &impl QueryStatementBuilder) -> AuthResult<Utf16String> {
    let statement = materialize_for_test(statement(query)?)?;
    let sql = statement
        .mysql_text_sql()
        .ok_or_else(|| AuthError::internal("Materialized native statement has no logical SQL"))?;
    Ok(Utf16String::from_units(sql.to_vec()))
}

fn raw(callback: impl Fn() -> AuthResult<FieldValue> + Send + Sync + 'static) -> FieldValue {
    FieldMap::from([(
        "toSqlString".into(),
        FieldFunction::contextual(move |_, _| callback()).into(),
    )])
    .into()
}

#[test]
fn ast_parameter_order_includes_reused_native_nodes_and_compiler_parameters() -> AuthResult<()> {
    let first = Binding::Raw("first".into()).bind(DbBackend::MySql)?;
    let second = Binding::Raw("second".into()).bind(DbBackend::MySql)?;
    let query = Query::select()
        .expr(second)
        .expr(7)
        .expr(first.clone())
        .expr(first)
        .to_owned();
    assert_eq!(
        format(&query)?,
        Utf16String::from("select 'second', 7, 'first', 'first'")
    );
    Ok(())
}

#[test]
fn parse_failure_prevents_all_native_formatting_and_preserves_the_thrown_value() -> AuthResult<()> {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let value = raw(move || {
        let _ = counted.fetch_add(1, Ordering::SeqCst);
        Ok("CURRENT_TIMESTAMP".into())
    });
    let thrown = FieldValue::from(FieldMap::from([("marker".into(), "parse".into())]));
    let rejected = thrown.clone();
    let factory =
        FieldFunction::contextual(move |_, _| Err(AuthError::from_thrown(rejected.clone())));
    let error = super::super::record_bindings::bind(
        DbBackend::MySql,
        vec![Binding::Raw(value), Binding::Raw(factory.into())],
    )
    .err()
    .ok_or_else(|| AuthError::internal("Function expression unexpectedly parsed"))?;
    assert!(
        error
            .raw_value()
            .is_some_and(|value| value.strict_equals(&thrown))
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn unknown_payload_rejects_the_complete_ast_before_native_callbacks() -> AuthResult<()> {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let value = raw(move || {
        let _ = counted.fetch_add(1, Ordering::SeqCst);
        Ok("CURRENT_TIMESTAMP".into())
    });
    let native = Binding::Raw(value).bind(DbBackend::MySql)?;
    let unknown = Expr::ExternalParameter(ExternalParameter::new(17_u32));
    let query = Query::select().expr(native).expr(unknown).to_owned();
    let error = statement(&query)
        .err()
        .ok_or_else(|| AuthError::internal("Unknown payload unexpectedly compiled"))?;
    assert_eq!(
        error.instrumentation_message()?,
        "MySQL query contains an unrecognized native parameter payload"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn formatter_failure_preserves_identity_and_stops_later_parameter_callbacks() -> AuthResult<()> {
    let before = Arc::new(AtomicUsize::new(0));
    let after = Arc::new(AtomicUsize::new(0));
    let counted_before = before.clone();
    let counted_after = after.clone();
    let thrown = FieldValue::from(FieldMap::from([("marker".into(), "render".into())]));
    let rejected = thrown.clone();
    let values = vec![
        Binding::Raw(raw(move || {
            let _ = counted_before.fetch_add(1, Ordering::SeqCst);
            Ok("FIRST".into())
        })),
        Binding::Raw(raw(move || Err(AuthError::from_thrown(rejected.clone())))),
        Binding::Raw(raw(move || {
            let _ = counted_after.fetch_add(1, Ordering::SeqCst);
            Ok("LAST".into())
        })),
    ];
    let expressions = super::super::record_bindings::bind(DbBackend::MySql, values)?;
    let query = Query::select().exprs(expressions).to_owned();
    let error = format(&query)
        .err()
        .ok_or_else(|| AuthError::internal("Native formatter unexpectedly succeeded"))?;
    assert!(
        error
            .raw_value()
            .is_some_and(|value| value.strict_equals(&thrown))
    );
    assert_eq!(before.load(Ordering::SeqCst), 1);
    assert_eq!(after.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn unused_parameters_do_not_materialize() -> AuthResult<()> {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let value = raw(move || {
        let _ = counted.fetch_add(1, Ordering::SeqCst);
        Err(AuthError::internal("Unused native value was formatted"))
    });
    let extra = Binding::Raw(value).bind(DbBackend::MySql)?;
    let query = Query::select()
        .expr(Expr::cust_with_exprs("'?'", [extra]))
        .to_owned();
    assert_eq!(format(&query)?, Utf16String::from("select '?'"));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let never_resolve = |_: &()| Err(AuthError::internal("Extra parameter was resolved"));
    assert_eq!(
        mysql_text::format_parameters("select '?'", &[()], never_resolve)?,
        Utf16String::from("select '?'")
    );
    Ok(())
}

#[test]
fn text_statement_retains_logical_utf16_before_wire_conversion() -> AuthResult<()> {
    let text = Utf16String::from_units(vec![0x41, 0xd800, 0x42]);
    let value = Binding::Raw(text.into()).bind(DbBackend::MySql)?;
    let query = Query::select().expr(value).to_owned();
    let statement = materialize_for_test(statement(&query)?)?;
    let expected: Vec<_> = "select '"
        .encode_utf16()
        .chain([0x41, 0xd800, 0x42])
        .chain("'".encode_utf16())
        .collect();
    assert_eq!(statement.mysql_text_sql(), Some(expected.as_slice()));
    assert_eq!(statement.sql, "select 'A\u{fffd}B'");
    assert_eq!(statement.values, None);
    Ok(())
}

#[test]
#[ignore = "requires the pinned mysql2 source observation from GitHub Actions"]
fn pinned_mysql_native_bindings_preserve_callback_traces() -> AuthResult<()> {
    let fixture = std::env::var("BETTER_AUTH_MYSQL_TEXT_FIXTURE")
        .map_err(|cause| AuthError::internal(cause.to_string()))?;
    let expected: serde_json::Value = serde_json::from_slice(
        &std::fs::read(fixture).map_err(|cause| AuthError::internal(cause.to_string()))?,
    )
    .map_err(|cause| AuthError::internal(cause.to_string()))?;
    let mut observations = Vec::new();
    for throw_on_read in [0, 2] {
        observations.push(super::super::mysql_text::tests::native_with(
            throw_on_read,
            |value| {
                let value = Binding::Raw(value).bind(DbBackend::MySql)?;
                format(&Query::select().expr(value).to_owned())
            },
        )?);
    }
    assert_eq!(serde_json::json!(observations), expected["native"]);
    Ok(())
}

#[test]
fn statement_construction_inspection_and_clone_do_not_materialize_native_values() -> AuthResult<()>
{
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let value = Binding::Raw(raw(move || {
        let _ = counted.fetch_add(1, Ordering::SeqCst);
        Ok("NATIVE".into())
    }))
    .bind(DbBackend::MySql)?;
    let command = statement(Query::select().expr(value))?;
    assert_eq!(command.sql, "select ?");
    assert_eq!(command.to_string(), "select ?");
    assert!(format!("{command:?}").contains("select ?"));
    assert_eq!(command.mysql_text_sql(), None);
    assert_eq!(command.values, None);
    let cloned = command.clone();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(materialize_for_test(command)?.sql, "select NATIVE");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(materialize_for_test(cloned)?.sql, "select NATIVE");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[test]
fn deferred_statements_retain_live_objects_between_executions() -> AuthResult<()> {
    let object = FieldObject::from(FieldMap::new());
    let value = Binding::Raw(FieldValue::Object(object.clone())).bind(DbBackend::MySql)?;
    let command = statement(Query::select().expr(value))?;
    let calls = Arc::new(AtomicUsize::new(0));
    for output in ["FIRST", "SECOND"] {
        let counted = calls.clone();
        object.set(
            "toSqlString",
            FieldFunction::contextual(move |_, _| {
                let _ = counted.fetch_add(1, Ordering::SeqCst);
                Ok(output.into())
            })
            .into(),
        )?;
        let materialized = materialize_for_test(command.clone())?;
        assert_eq!(materialized.sql, format!("select {output}"));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(command.sql, "select ?");
    assert_eq!(command.mysql_text_sql(), None);
    Ok(())
}

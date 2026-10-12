use super::*;
use crate::store::entities::user;
use better_auth_core::{
    FieldFunction, FieldMap, FieldObject, FieldValue, WhereMode, WhereOperator,
};
use sea_orm::{
    Database, DbBackend, DbErr, ExecResult, Statement,
    sea_query::{Value, Values},
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

fn rejecting(
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

fn original_error<T>(result: AuthResult<T>, expected: &str, allocation: &AtomicUsize) {
    let error = result.err();
    let message = match &error {
        Some(AuthError::Internal(message)) => Some(message),
        _ => None,
    };
    assert_eq!(message.map(String::as_str), Some(expected));
    assert_eq!(
        message.map(|value| value.as_ptr() as usize),
        Some(allocation.load(Ordering::SeqCst))
    );
}

#[test]
fn target_expression_parsing_precedes_set_parsing_but_target_encoding_does_not() {
    for backend in [DbBackend::Sqlite, DbBackend::Postgres] {
        for target_expression in [false, true] {
            let set_calls = Arc::new(AtomicUsize::new(0));
            let target_calls = Arc::new(AtomicUsize::new(0));
            let allocation = Arc::new(AtomicUsize::new(0));
            let mut write = RecordWrite::<user::Entity>::default();
            write.field(
                user::Column::Name,
                rejecting("set-expression", &set_calls, &allocation),
            );
            let target = rejecting("target-expression", &target_calls, &allocation);
            let target = if target_expression {
                target
            } else {
                // A nested function remains driver data during WHERE expression parsing.
                vec![FieldValue::from(vec![target])].into()
            };
            original_error(
                compile_increment(
                    user::Column::Id,
                    write,
                    vec![QueryPredicate::equals(user::Column::Id, target)],
                    backend,
                ),
                if target_expression {
                    "target-expression"
                } else {
                    "set-expression"
                },
                &allocation,
            );
            assert_eq!(
                set_calls.load(Ordering::SeqCst),
                usize::from(!target_expression)
            );
            assert_eq!(
                target_calls.load(Ordering::SeqCst),
                usize::from(target_expression)
            );
        }
    }
}

#[test]
fn increment_sql_keeps_outer_guards_and_orders_set_before_both_where_bindings() -> AuthResult<()> {
    for backend in [DbBackend::Sqlite, DbBackend::Postgres] {
        let mut write = RecordWrite::<user::Entity>::default();
        write.field(user::Column::Name, "after".into());
        let statement = compile_increment(
            user::Column::Id,
            write,
            vec![QueryPredicate::equals(user::Column::Name, "before".into())],
            backend,
        )?
        .build(backend);
        if backend == DbBackend::Sqlite {
            assert_eq!(
                statement.sql,
                "UPDATE \"users\" SET \"name\" = ? WHERE \"users\".\"name\" = ? AND \"users\".\"id\" IN (SELECT \"users\".\"id\" FROM \"users\" WHERE \"users\".\"name\" = ? LIMIT ?)"
            );
            assert_eq!(
                statement.values,
                Some(Values(vec![
                    Value::String(Some("after".into())),
                    Value::String(Some("before".into())),
                    Value::String(Some("before".into())),
                    Value::BigUnsigned(Some(1))
                ]))
            );
        } else {
            assert_eq!(
                statement.sql,
                "UPDATE \"users\" SET \"name\" = $1 WHERE \"users\".\"name\" = $2 AND \"users\".\"id\" IN (SELECT \"users\".\"id\" FROM \"users\" WHERE \"users\".\"name\" = $3 LIMIT $4)"
            );
            assert_eq!(
                statement.values,
                Some(Values(vec![
                    Value::PostgresUnspecifiedText(Some("after".into())),
                    Value::PostgresUnspecifiedText(Some("before".into())),
                    Value::PostgresUnspecifiedText(Some("before".into())),
                    Value::BigUnsigned(Some(1))
                ]))
            );
        }
    }
    Ok(())
}

struct LockConnection {
    target: Mutex<Option<QueryResult>>,
    mutate_after_lock: Option<FieldObject>,
    statements: Mutex<Vec<Statement>>,
}

#[async_trait::async_trait]
impl ConnectionTrait for LockConnection {
    fn get_database_backend(&self) -> DbBackend {
        DbBackend::MySql
    }

    async fn execute_raw(&self, _: Statement) -> Result<ExecResult, DbErr> {
        Err(DbErr::Custom(
            "UPDATE must not execute in the lock-phase fixture".into(),
        ))
    }

    async fn execute_unprepared(&self, _: &str) -> Result<ExecResult, DbErr> {
        Err(DbErr::Custom(
            "Unprepared SQL is not supported by the lock-phase fixture".into(),
        ))
    }

    async fn query_one_raw(&self, statement: Statement) -> Result<Option<QueryResult>, DbErr> {
        self.statements
            .lock()
            .map_err(|_| DbErr::Custom("Statement log lock is poisoned".into()))?
            .push(statement);
        if let Some(object) = &self.mutate_after_lock {
            let _ = object
                .set("toString", FieldValue::Null)
                .map_err(|error| DbErr::Custom(error.to_string()))?;
        }
        Ok(self
            .target
            .lock()
            .map_err(|_| DbErr::Custom("Target lock is poisoned".into()))?
            .take())
    }

    async fn query_all_raw(&self, _: Statement) -> Result<Vec<QueryResult>, DbErr> {
        Err(DbErr::Custom(
            "Bulk reads must not execute in the lock-phase fixture".into(),
        ))
    }
}

impl LockConnection {
    fn statements(&self) -> AuthResult<Vec<String>> {
        Ok(self
            .statements
            .lock()
            .map_err(|_| AuthError::internal("Statement log lock is poisoned"))?
            .iter()
            .map(ToString::to_string)
            .collect())
    }
}

#[tokio::test]
async fn mysql_parses_set_only_after_locking_a_non_null_target_id() -> AuthResult<()> {
    let rows = Database::connect("sqlite::memory:")
        .await
        .map_err(map_db_err)?;
    let null = rows
        .query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT NULL AS id",
        ))
        .await
        .map_err(map_db_err)?;
    let matched = rows
        .query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT 'selected' AS id",
        ))
        .await
        .map_err(map_db_err)?;
    assert!(null.is_some());
    assert!(matched.is_some());
    for (target, calls_expected) in [(None, 0), (null, 0), (matched, 1)] {
        let connection = LockConnection {
            target: Mutex::new(target),
            mutate_after_lock: None,
            statements: Mutex::new(Vec::new()),
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let allocation = Arc::new(AtomicUsize::new(0));
        let mut write = RecordWrite::<user::Entity>::default();
        write.field(
            user::Column::Name,
            rejecting("set-expression", &calls, &allocation),
        );
        let result = increment_returning_raw_with_connection(
            &connection,
            write,
            vec![QueryPredicate::equals(user::Column::Id, "selected".into())],
        )
        .await;
        if calls_expected == 0 {
            assert!(result?.is_none());
        } else {
            original_error(result, "set-expression", &allocation);
        }
        assert_eq!(calls.load(Ordering::SeqCst), calls_expected);
        assert_eq!(
            connection.statements()?,
            ["SELECT `users`.`id` FROM `users` WHERE `users`.`id` = 'selected' LIMIT 1 FOR UPDATE"]
        );
    }
    Ok(())
}

#[tokio::test]
async fn mysql_reparses_where_from_the_same_object_after_target_locking() -> AuthResult<()> {
    let rows = Database::connect("sqlite::memory:")
        .await
        .map_err(map_db_err)?;
    let target = rows
        .query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT 'selected' AS id",
        ))
        .await
        .map_err(map_db_err)?;
    assert!(target.is_some());
    let object = FieldObject::from(FieldMap::new());
    let connection = LockConnection {
        target: Mutex::new(target),
        mutate_after_lock: Some(object.clone()),
        statements: Mutex::new(Vec::new()),
    };
    let mut write = RecordWrite::<user::Entity>::default();
    write.field(user::Column::Name, "after".into());
    let result = increment_returning_raw_with_connection(
        &connection,
        write,
        vec![QueryPredicate::new(
            user::Column::Name,
            WhereOperator::Contains,
            WhereMode::Sensitive,
            FieldValue::Object(object.clone()),
        )],
    )
    .await;
    assert!(matches!(result, Err(AuthError::TypeError(message)) if message == "No default value"));
    assert_eq!(object.get("toString")?, Some(FieldValue::Null));
    assert_eq!(
        connection.statements()?,
        [
            "SELECT `users`.`id` FROM `users` WHERE `users`.`name` LIKE '%[object Object]%' LIMIT 1 FOR UPDATE"
        ]
    );
    Ok(())
}

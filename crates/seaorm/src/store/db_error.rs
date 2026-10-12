use better_auth_core::{AuthError, DatabaseError, DatabaseErrorCause, FieldMap, FieldValue};
use sea_orm::{DbErr, RuntimeErr, SqlErr, sqlx};

mod mysql_codes;

pub(crate) fn map_db_err(error: DbErr) -> AuthError {
    let (category, message): (fn(DatabaseErrorCause) -> DatabaseError, String) =
        match error.sql_err() {
            Some(SqlErr::UniqueConstraintViolation(message)) => {
                (DatabaseError::UniqueConstraint, message)
            }
            Some(SqlErr::ForeignKeyConstraintViolation(message)) => {
                (DatabaseError::Constraint, message)
            }
            Some(_) | None => (
                DatabaseError::Query,
                match &error {
                    DbErr::Custom(message) => message.clone(),
                    _ => error.to_string(),
                },
            ),
        };
    let properties = driver_properties(&error);
    category(DatabaseErrorCause::from_source(message, error, properties)).into()
}

fn driver_properties(error: &DbErr) -> Option<FieldMap> {
    let (DbErr::Conn(RuntimeErr::SqlxError(error))
    | DbErr::Exec(RuntimeErr::SqlxError(error))
    | DbErr::Query(RuntimeErr::SqlxError(error))) = error
    else {
        return None;
    };
    let sqlx::Error::Database(error) = error.as_ref() else {
        return None;
    };
    if let Some(error) = error.try_downcast_ref::<sqlx::postgres::PgDatabaseError>() {
        return Some(postgres_properties(error));
    }
    error
        .try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>()
        .map(mysql_properties)
}

fn postgres_properties(error: &sqlx::postgres::PgDatabaseError) -> FieldMap {
    FieldMap::from([
        ("message".into(), error.message().into()),
        ("length".into(), error.response_length().into()),
        ("name".into(), "error".into()),
        ("severity".into(), optional_text(error.field(b'S'))),
        ("code".into(), error.code().into()),
        ("detail".into(), optional_text(error.detail())),
        ("hint".into(), optional_text(error.hint())),
        ("position".into(), optional_text(error.field(b'P'))),
        ("internalPosition".into(), optional_text(error.field(b'p'))),
        ("internalQuery".into(), optional_text(error.field(b'q'))),
        ("where".into(), optional_text(error.r#where())),
        ("schema".into(), optional_text(error.schema())),
        ("table".into(), optional_text(error.table())),
        ("column".into(), optional_text(error.column())),
        ("dataType".into(), optional_text(error.data_type())),
        ("constraint".into(), optional_text(error.constraint())),
        ("file".into(), optional_text(error.file())),
        ("line".into(), optional_text(error.field(b'L'))),
        ("routine".into(), optional_text(error.routine())),
    ])
}

fn mysql_properties(error: &sqlx::mysql::MySqlDatabaseError) -> FieldMap {
    FieldMap::from([
        ("message".into(), error.message().into()),
        (
            "code".into(),
            optional_text(mysql_codes::name(error.number())),
        ),
        ("errno".into(), f64::from(error.number()).into()),
        ("sqlState".into(), error.code().unwrap_or("").into()),
        ("sqlMessage".into(), error.message().into()),
        // mysql2 assigns command.sql || command.query, so an empty SQL string is undefined.
        (
            "sql".into(),
            optional_text(error.sql().filter(|sql| !sql.is_empty())),
        ),
    ])
}

fn optional_text(value: Option<&str>) -> FieldValue {
    value.map(FieldValue::from).unwrap_or_default()
}

#[cfg(test)]
mod tests;

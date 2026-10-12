use crate::DbBackend;
#[cfg(feature = "rbac")]
pub use sea_query::audit::{AuditTrait, Error as AuditError, QueryAccessAudit};
use sea_query::{MysqlQueryBuilder, PostgresQueryBuilder, SqliteQueryBuilder, inject_parameters};
pub use sea_query::{Value, Values};
use std::fmt;

/// Defines an SQL statement
#[derive(Debug, Clone, PartialEq)]
pub struct Statement {
    /// The SQL query
    pub sql: String,
    /// The values for the SQL statement's parameters
    pub values: Option<Values>,
    /// The database backend this statement is constructed for.
    /// The SQL dialect and values should be valid for the DbBackend.
    pub db_backend: DbBackend,
    #[cfg(feature = "sqlx-mysql")]
    mysql_text: Option<sqlx::mysql::MySqlTextCommand>,
}

/// Any type that can build a [Statement]
pub trait StatementBuilder: Sync {
    /// Method to build a [Statement]
    fn build(&self, db_backend: &DbBackend) -> Statement;

    #[cfg(feature = "rbac")]
    /// Method to audit access request of query
    fn audit(&self) -> Result<QueryAccessAudit, AuditError>;
}

impl Statement {
    /// Construct an explicit MySQL text command from complete logical UTF-16 SQL.
    ///
    /// The immutable command owns protocol selection and error provenance. Later changes
    /// to the legacy `sql` or `values` views do not change this command.
    #[cfg(feature = "sqlx-mysql")]
    pub fn from_mysql_text(logical_sql: Vec<u16>) -> Self {
        let command = sqlx::mysql::MySqlTextCommand::new(logical_sql);
        Self {
            sql: command.sql().to_owned(),
            values: None,
            db_backend: DbBackend::MySql,
            mysql_text: Some(command),
        }
    }

    /// Inspect the logical SQL of an explicit MySQL text command.
    #[cfg(feature = "sqlx-mysql")]
    pub fn mysql_text_sql(&self) -> Option<&[u16]> {
        self.mysql_text
            .as_ref()
            .map(sqlx::mysql::MySqlTextCommand::logical_sql)
    }

    #[cfg(feature = "sqlx-mysql")]
    pub(crate) fn mysql_text_command(&self) -> Option<&sqlx::mysql::MySqlTextCommand> {
        self.mysql_text.as_ref()
    }

    /// Create a [Statement] from a [crate::DatabaseBackend] and a raw SQL statement
    pub fn from_string<T>(db_backend: DbBackend, stmt: T) -> Statement
    where
        T: Into<String>,
    {
        Statement {
            sql: stmt.into(),
            values: None,
            db_backend,
            #[cfg(feature = "sqlx-mysql")]
            mysql_text: None,
        }
    }

    /// Create a SQL statement from a [crate::DatabaseBackend], a
    /// raw SQL statement and param values
    pub fn from_sql_and_values<I, T>(db_backend: DbBackend, sql: T, values: I) -> Self
    where
        I: IntoIterator<Item = Value>,
        T: Into<String>,
    {
        Self::from_string_values_tuple(db_backend, (sql, Values(values.into_iter().collect())))
    }

    pub(crate) fn from_string_values_tuple<T>(db_backend: DbBackend, stmt: (T, Values)) -> Statement
    where
        T: Into<String>,
    {
        Statement {
            sql: stmt.0.into(),
            values: Some(stmt.1),
            db_backend,
            #[cfg(feature = "sqlx-mysql")]
            mysql_text: None,
        }
    }
}

impl fmt::Display for Statement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        #[cfg(feature = "sqlx-mysql")]
        if let Some(command) = &self.mysql_text {
            return f.write_str(command.sql());
        }
        match &self.values {
            Some(values) => {
                let string = match self.db_backend {
                    DbBackend::MySql => inject_parameters(&self.sql, &values.0, &MysqlQueryBuilder),
                    DbBackend::Postgres => {
                        inject_parameters(&self.sql, &values.0, &PostgresQueryBuilder)
                    }
                    DbBackend::Sqlite => {
                        inject_parameters(&self.sql, &values.0, &SqliteQueryBuilder)
                    }
                };
                write!(f, "{}", &string)
            }
            None => {
                write!(f, "{}", &self.sql)
            }
        }
    }
}

macro_rules! build_any_stmt {
    ($stmt: expr, $db_backend: expr) => {
        match $db_backend {
            DbBackend::MySql => $stmt.build(MysqlQueryBuilder),
            DbBackend::Postgres => $stmt.build(PostgresQueryBuilder),
            DbBackend::Sqlite => $stmt.build(SqliteQueryBuilder),
        }
    };
}

macro_rules! build_postgres_stmt {
    ($stmt: expr, $db_backend: expr) => {
        match $db_backend {
            DbBackend::Postgres => $stmt.to_string(PostgresQueryBuilder),
            DbBackend::MySql | DbBackend::Sqlite => unimplemented!(),
        }
    };
}

macro_rules! build_query_stmt {
    ($stmt: ty) => {
        impl StatementBuilder for $stmt {
            fn build(&self, db_backend: &DbBackend) -> Statement {
                let stmt = build_any_stmt!(self, db_backend);
                Statement::from_string_values_tuple(*db_backend, stmt)
            }

            #[cfg(feature = "rbac")]
            fn audit(&self) -> Result<QueryAccessAudit, AuditError> {
                AuditTrait::audit(self)
            }
        }
    };
}

build_query_stmt!(sea_query::InsertStatement);
build_query_stmt!(sea_query::SelectStatement);
build_query_stmt!(sea_query::UpdateStatement);
build_query_stmt!(sea_query::DeleteStatement);
build_query_stmt!(sea_query::WithQuery);

macro_rules! build_schema_stmt {
    ($stmt: ty) => {
        impl StatementBuilder for $stmt {
            fn build(&self, db_backend: &DbBackend) -> Statement {
                let stmt = build_any_stmt!(self, db_backend);
                Statement::from_string(*db_backend, stmt)
            }

            #[cfg(feature = "rbac")]
            fn audit(&self) -> Result<QueryAccessAudit, AuditError> {
                todo!("Audit not supported for {} yet", stringify!($stmt))
            }
        }
    };
}

build_schema_stmt!(sea_query::TableCreateStatement);
build_schema_stmt!(sea_query::TableDropStatement);
build_schema_stmt!(sea_query::TableAlterStatement);
build_schema_stmt!(sea_query::TableRenameStatement);
build_schema_stmt!(sea_query::TableTruncateStatement);
build_schema_stmt!(sea_query::IndexCreateStatement);
build_schema_stmt!(sea_query::IndexDropStatement);
build_schema_stmt!(sea_query::ForeignKeyCreateStatement);
build_schema_stmt!(sea_query::ForeignKeyDropStatement);

macro_rules! build_type_stmt {
    ($stmt: ty) => {
        impl StatementBuilder for $stmt {
            fn build(&self, db_backend: &DbBackend) -> Statement {
                let stmt = build_postgres_stmt!(self, db_backend);
                Statement::from_string(*db_backend, stmt)
            }

            #[cfg(feature = "rbac")]
            fn audit(&self) -> Result<QueryAccessAudit, AuditError> {
                Err(AuditError::UnsupportedQuery)
            }
        }
    };
}

build_type_stmt!(sea_query::extension::postgres::TypeAlterStatement);
build_type_stmt!(sea_query::extension::postgres::TypeCreateStatement);
build_type_stmt!(sea_query::extension::postgres::TypeDropStatement);

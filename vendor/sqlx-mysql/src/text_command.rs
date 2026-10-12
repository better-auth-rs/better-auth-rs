use std::sync::Arc;

use crate::arguments::IntoArguments;
use crate::{MySql, MySqlArguments};

/// An explicit COM_QUERY command with its logical UTF-16 text retained.
///
/// MySQL receives UTF-8 with replacement characters for unpaired surrogates.
/// Error metadata retains the original code units independently of those bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MySqlTextCommand {
    sql: Arc<str>,
    logical_sql: Arc<[u16]>,
}

impl MySqlTextCommand {
    /// Encode one complete logical SQL command for the MySQL text protocol.
    pub fn new(logical_sql: Vec<u16>) -> Self {
        Self {
            sql: String::from_utf16_lossy(&logical_sql).into(),
            logical_sql: logical_sql.into(),
        }
    }

    /// The UTF-8 SQL sent in the COM_QUERY packet.
    pub fn sql(&self) -> &str {
        &self.sql
    }

    /// The complete logical SQL before UTF-8 encoding.
    pub fn logical_sql(&self) -> &[u16] {
        &self.logical_sql
    }

    /// Execute this command without preparing a binary statement.
    pub fn query(&self) -> sqlx_core::query::Query<'_, MySql, Self> {
        sqlx_core::query::query_with(self.sql(), self.clone())
    }
}

impl IntoArguments<'_, MySql> for MySqlTextCommand {
    fn into_arguments(self) -> MySqlArguments {
        MySqlArguments {
            text_command: Some(self),
            ..MySqlArguments::default()
        }
    }
}

#[derive(Debug)]
pub(crate) enum CommandSql {
    Utf8(Arc<str>),
    Text(MySqlTextCommand),
}

impl CommandSql {
    pub(crate) fn sql(&self) -> &str {
        match self {
            Self::Utf8(sql) => sql,
            Self::Text(command) => command.sql(),
        }
    }

    pub(crate) fn logical_sql(&self) -> Option<&[u16]> {
        match self {
            Self::Utf8(_) => None,
            Self::Text(command) => Some(command.logical_sql()),
        }
    }
}

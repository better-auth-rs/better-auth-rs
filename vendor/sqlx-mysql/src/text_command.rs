use std::sync::Arc;

use crate::arguments::IntoArguments;
use crate::{MySql, MySqlArguments};
use sqlx_core::error::BoxDynError;

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

type Materializer = dyn Fn() -> Result<Vec<u16>, BoxDynError> + Send + Sync;

/// A text command whose native values are resolved after connection acquisition.
///
/// Each execution calls the materializer again. Clones retain the same native handles,
/// not a cached command or a cached failure.
#[derive(Clone)]
pub struct MySqlDeferredTextCommand {
    template: Arc<str>,
    materializer: Arc<Materializer>,
}

impl MySqlDeferredTextCommand {
    /// Retain a validated SQL template and its native command materializer.
    pub fn new(
        template: String,
        materialize: impl Fn() -> Result<Vec<u16>, BoxDynError> + Send + Sync + 'static,
    ) -> Self {
        Self {
            template: template.into(),
            materializer: Arc::new(materialize),
        }
    }

    /// Inspect the template without reading native parameter values.
    pub fn template(&self) -> &str {
        &self.template
    }

    /// Resolve one command after the executor owns the connection or transaction lock.
    pub fn materialize(&self) -> Result<MySqlTextCommand, BoxDynError> {
        (self.materializer)().map(MySqlTextCommand::new)
    }

    /// Execute this command through the existing connection executor.
    pub fn query(&self) -> sqlx_core::query::Query<'_, MySql, Self> {
        sqlx_core::query::query_with(self.template(), self.clone())
    }
}

impl std::fmt::Debug for MySqlDeferredTextCommand {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MySqlDeferredTextCommand")
            .field("template", &self.template)
            .finish_non_exhaustive()
    }
}

impl PartialEq for MySqlDeferredTextCommand {
    fn eq(&self, other: &Self) -> bool {
        self.template == other.template && Arc::ptr_eq(&self.materializer, &other.materializer)
    }
}

impl Eq for MySqlDeferredTextCommand {}

impl IntoArguments<'_, MySql> for MySqlDeferredTextCommand {
    fn into_arguments(self) -> MySqlArguments {
        MySqlArguments {
            deferred_text_command: Some(self),
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

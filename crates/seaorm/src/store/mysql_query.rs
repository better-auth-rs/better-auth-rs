//! Compile one complete MySQL AST before resolving its native parameter sequence.

use std::{fmt, sync::Arc};

use better_auth_core::{AuthError, AuthResult, FieldValue, Utf16String};
use sea_orm::{
    Statement,
    sea_query::{
        ExternalParameter, KyselyMysqlQueryBuilder, QueryBuilder, QueryStatementBuilder, SqlWriter,
        Value,
    },
};

use super::{
    mysql_text,
    record_bindings::{Binding, ParsedBinding},
};

/// Retain native parameter identity until the complete query reaches the text-command boundary.
pub(super) fn statement(query: &impl QueryStatementBuilder) -> AuthResult<Statement> {
    let command = collect(query)?;
    Ok(Statement::from_mysql_text_deferred(
        command.sql.clone(),
        move || {
            command
                .format()
                .map(|sql| sql.as_utf16().to_vec())
                .map_err(|error| {
                    Box::new(error.into_shared()) as Box<dyn std::error::Error + Send + Sync>
                })
        },
    ))
}

fn collect(query: &impl QueryStatementBuilder) -> AuthResult<Command> {
    let mut collector = Collector::default();
    query.build_collect_any_into(&KyselyMysqlQueryBuilder, &mut collector);
    collector.finish()
}

enum Parameter {
    Native(Value),
    Binding(Arc<ParsedBinding>),
}

impl Parameter {
    fn resolve(&self) -> AuthResult<FieldValue> {
        match self {
            Self::Native(value) => native_value(value.clone()),
            Self::Binding(binding) => match binding.binding() {
                Binding::Native(value) => native_value(value.clone()),
                Binding::Raw(value) => Ok(value.clone()),
                Binding::Date(value) => Ok(value.clone().into()),
                Binding::Json(value) => Ok(value
                    .stringify()?
                    .map(FieldValue::String)
                    .unwrap_or(FieldValue::Undefined)),
                Binding::Expression(_) => Err(AuthError::internal(
                    "A MySQL native parameter cannot contain a SQL expression",
                )),
            },
        }
    }
}

fn native_value(value: Value) -> AuthResult<FieldValue> {
    match value {
        Value::PostgresUnspecifiedText(_) => Err(AuthError::internal(
            "A PostgreSQL protocol parameter cannot enter a MySQL text command",
        )),
        Value::Json(Some(value)) => Ok(FieldValue::from_json(*value)?
            .stringify()?
            .map(FieldValue::String)
            .unwrap_or(FieldValue::Undefined)),
        value => crate::field_value::from_column(value),
    }
}

#[derive(Default)]
struct Collector {
    sql: String,
    parameters: Vec<Parameter>,
    error: Option<AuthError>,
}

impl Collector {
    fn finish(self) -> AuthResult<Command> {
        if let Some(error) = self.error {
            return Err(error);
        }
        Ok(Command {
            sql: self.sql,
            parameters: self.parameters,
        })
    }
}

struct Command {
    sql: String,
    parameters: Vec<Parameter>,
}

impl Command {
    fn format(&self) -> AuthResult<Utf16String> {
        mysql_text::format_parameters(&self.sql, &self.parameters, Parameter::resolve)
    }
}

impl fmt::Write for Collector {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.sql.push_str(text);
        Ok(())
    }

    fn write_char(&mut self, character: char) -> fmt::Result {
        self.sql.push(character);
        Ok(())
    }
}

impl fmt::Display for Collector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.sql)
    }
}

impl SqlWriter for Collector {
    fn push_param<T: QueryBuilder>(&mut self, value: Value, _: &T) {
        self.sql.push('?');
        self.parameters.push(Parameter::Native(value));
    }

    fn push_external_parameter(&mut self, parameter: &ExternalParameter) {
        self.sql.push('?');
        match parameter.clone().downcast::<ParsedBinding>() {
            Ok(binding) => self.parameters.push(Parameter::Binding(binding)),
            Err(_) => {
                if self.error.is_none() {
                    self.error = Some(AuthError::internal(
                        "MySQL query contains an unrecognized native parameter payload",
                    ));
                }
            }
        }
    }

    fn as_writer(&mut self) -> &mut dyn fmt::Write {
        self
    }
}

#[cfg(test)]
pub(super) fn materialize_for_test(statement: Statement) -> AuthResult<Statement> {
    statement.materialize_mysql_text().map_err(|error| {
        *error
            .downcast::<AuthError>()
            .expect("The native MySQL bridge preserves the AuthError type")
    })
}

#[cfg(test)]
mod tests;

//! Preserve raw record values until the adapter binds the complete SQL parameter list.

use better_auth_core::{AuthError, AuthResult};
use sea_orm::{ColumnTrait, DbBackend, sea_query::Value};

pub(super) enum Binding {
    Native(Value),
    Raw(serde_json::Value),
}

impl Binding {
    pub(super) fn for_column(column: impl ColumnTrait, value: serde_json::Value) -> Self {
        if matches!(
            column.def().get_column_type(),
            sea_orm::ColumnType::Json | sea_orm::ColumnType::JsonBinary
        ) {
            Self::Native(Value::Json(Some(Box::new(value))))
        } else {
            Self::Raw(value)
        }
    }

    fn bind(self, backend: DbBackend) -> AuthResult<Value> {
        let value = match self {
            Self::Native(value) => return Ok(value),
            Self::Raw(value) => value,
        };
        let value = match value {
            serde_json::Value::Null => Value::String(None),
            serde_json::Value::String(value) => Value::String(Some(value)),
            serde_json::Value::Bool(value) if backend == DbBackend::Sqlite => {
                Value::BigInt(Some(i64::from(value)))
            }
            serde_json::Value::Bool(value) => Value::Bool(Some(value)),
            serde_json::Value::Number(value) => Value::Double(value.as_f64()),
            serde_json::Value::Array(_) | serde_json::Value::Object(_)
                if backend == DbBackend::Sqlite =>
            {
                return Err(AuthError::internal(
                    "SQLite non-JSON fields do not accept arrays or objects",
                ));
            }
            value => Value::Json(Some(Box::new(value))),
        };
        crate::reference_id::binding(value, backend)
    }
}

pub(super) fn bind(backend: DbBackend, values: Vec<Binding>) -> AuthResult<Vec<Value>> {
    values
        .into_iter()
        .map(|value| value.bind(backend))
        .collect()
}

use sea_orm::{ColumnTrait, sea_query::SimpleExpr};

pub(super) fn equals(column: impl ColumnTrait, value: &serde_json::Value) -> SimpleExpr {
    match value {
        serde_json::Value::Null => column.is_null(),
        serde_json::Value::String(value) => column.eq(value),
        serde_json::Value::Bool(value) => column.eq(*value),
        serde_json::Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                column.eq(value)
            } else if let Some(value) = value.as_u64() {
                column.eq(value)
            } else {
                column.eq(value.as_f64())
            }
        }
        value => column.eq(sea_orm::Value::Json(Some(Box::new(value.clone())))),
    }
}

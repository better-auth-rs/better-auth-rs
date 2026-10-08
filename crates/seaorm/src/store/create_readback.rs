//! Identify MySQL inserts without changing their transaction or value semantics.

use better_auth_core::{
    AuthError, AuthResult, FieldValue, id::IdGeneration, store::schema::resolve_field_name,
    user_fields::UserConfig,
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, DbBackend, EntityTrait, Iterable,
    PrimaryKeyToColumn, QueryFilter, QueryResult, QuerySelect, QueryTrait, Statement,
    TransactionTrait,
    sea_query::{ExprTrait, Value},
};

use super::{map_db_err, record_bindings::Binding};

pub(super) enum ReadbackScope<'a> {
    Direct(&'a DatabaseConnection),
    Transaction,
}

pub(super) struct CreateReadback<'a, E: EntityTrait> {
    pub(super) schema: &'a UserConfig,
    pub(super) policy: &'a IdGeneration,
    pub(super) scope: ReadbackScope<'a>,
    pub(super) column: fn(&str) -> AuthResult<E::Column>,
}

impl<E: EntityTrait> CreateReadback<'_, E> {
    pub(super) async fn fetch(
        &self,
        db: &impl ConnectionTrait,
        fields: &[(E::Column, Binding)],
    ) -> AuthResult<Option<QueryResult>> {
        match self.scope {
            ReadbackScope::Transaction => self.fetch_with_connection(db, fields).await,
            ReadbackScope::Direct(pool) => {
                // INSERT has already completed. Only readback belongs to this transaction.
                let transaction = pool.begin().await.map_err(map_db_err)?;
                let result = self.fetch_with_connection(&transaction, fields).await;
                if result.is_ok() {
                    transaction.commit().await.map_err(map_db_err)?;
                } else {
                    transaction.rollback().await.map_err(map_db_err)?;
                }
                result
            }
        }
    }

    async fn fetch_with_connection(
        &self,
        db: &impl ConnectionTrait,
        fields: &[(E::Column, Binding)],
    ) -> AuthResult<Option<QueryResult>> {
        let primary = E::PrimaryKey::iter()
            .next()
            .ok_or_else(|| AuthError::config("An auth model requires a primary key"))?
            .into_column();
        if let Some(value) = field_value(fields, primary).filter(|value| is_truthy(value)) {
            return select_one::<E>(db, primary, value).await;
        }
        if matches!(self.policy, IdGeneration::Serial) {
            let id = db
                .query_one_raw(Statement::from_string(
                    db.get_database_backend(),
                    "SELECT LAST_INSERT_ID() as id",
                ))
                .await
                .map_err(map_db_err)?
                .map(|row| super::plugin_rows::value(&row, "id"))
                .transpose()?;
            if let Some(id) = id.filter(FieldValue::is_truthy) {
                return select_one::<E>(db, primary, &Binding::Raw(id)).await;
            }
        }
        for candidate in self.unique_values(fields) {
            let (column, value) = candidate?;
            if let Some(row) = select_one::<E>(db, column, value).await? {
                return Ok(Some(row));
            }
        }
        if let Some(query) = full_match::<E>(fields, db.get_database_backend())? {
            let mut rows = db
                .query_all_raw(query.build(db.get_database_backend()))
                .await
                .map_err(map_db_err)?;
            if rows.len() == 1 {
                return Ok(rows.pop());
            }
        }
        better_auth_core::observability::logger::current().warn(
            &format!(
                "[Kysely Adapter] Unable to safely identify the inserted \"{}\" row on MySQL. Enable Better Auth ID generation or use generateId: \"serial\" for reliable behavior.",
                E::default().table_name()
            ),
            &[],
        );
        Ok(None)
    }

    fn unique_values<'a>(
        &'a self,
        fields: &'a [(E::Column, Binding)],
    ) -> impl Iterator<Item = AuthResult<(E::Column, &'a Binding)>> + 'a {
        self.schema
            .adapter_fields(&[])
            .additional_fields
            .into_iter()
            .flatten()
            .filter_map(move |(name, field)| {
                if field.unique != Some(true) {
                    return None;
                }
                let column =
                    match (self.column)(resolve_field_name(field.field_name.as_deref(), &name)) {
                        Ok(column) => column,
                        Err(error) => return Some(Err(error)),
                    };
                field_value(fields, column)
                    .filter(|value| !is_null(value) && !is_undefined(value))
                    .map(|value| Ok((column, value)))
            })
    }
}

fn field_value<C: ColumnTrait>(fields: &[(C, Binding)], column: C) -> Option<&Binding> {
    fields
        .iter()
        .find(|(stored, _)| stored.to_string() == column.to_string())
        .map(|(_, value)| value)
}

async fn select_one<E: EntityTrait>(
    db: &impl ConnectionTrait,
    column: E::Column,
    value: &Binding,
) -> AuthResult<Option<QueryResult>> {
    let backend = db.get_database_backend();
    let query = E::find()
        .filter(
            column
                .into_expr()
                .eq(column.save_as(value.clone().bind(backend)?)),
        )
        .limit(1);
    db.query_one_raw(query.build(backend))
        .await
        .map_err(map_db_err)
}

fn full_match<E: EntityTrait>(
    fields: &[(E::Column, Binding)],
    backend: DbBackend,
) -> AuthResult<Option<sea_orm::Select<E>>> {
    let mut query = E::find();
    let mut has_conditions = false;
    for (column, value) in fields {
        if is_undefined(value) {
            continue;
        }
        let filter = if is_null(value) {
            column.is_null()
        } else {
            column
                .into_expr()
                .eq(column.save_as(value.clone().bind(backend)?))
        };
        query = query.filter(filter);
        has_conditions = true;
    }
    Ok(has_conditions.then(|| query.limit(2)))
}

fn is_undefined(value: &Binding) -> bool {
    matches!(
        value,
        Binding::Raw(FieldValue::Undefined) | Binding::Json(FieldValue::Undefined)
    )
}

fn is_null(value: &Binding) -> bool {
    match value {
        Binding::Native(value) => *value == value.as_null(),
        Binding::Raw(value) | Binding::Json(value) => value.is_null(),
        // An invalid Date encodes as SQL NULL but still uses an equality predicate.
        Binding::Date(_) => false,
    }
}

fn is_truthy(value: &Binding) -> bool {
    match value {
        Binding::Raw(value) | Binding::Json(value) => value.is_truthy(),
        Binding::Date(_) => true,
        Binding::Native(value) if *value == value.as_null() => false,
        Binding::Native(value) => match value {
            Value::Bool(Some(value)) => *value,
            Value::TinyInt(Some(value)) => *value != 0,
            Value::SmallInt(Some(value)) => *value != 0,
            Value::Int(Some(value)) => *value != 0,
            Value::BigInt(Some(value)) => *value != 0,
            Value::TinyUnsigned(Some(value)) => *value != 0,
            Value::SmallUnsigned(Some(value)) => *value != 0,
            Value::Unsigned(Some(value)) => *value != 0,
            Value::BigUnsigned(Some(value)) => *value != 0,
            Value::Float(Some(value)) => *value != 0.0 && !value.is_nan(),
            Value::Double(Some(value)) => *value != 0.0 && !value.is_nan(),
            Value::String(Some(value)) => !value.is_empty(),
            Value::Json(Some(value)) => match value.as_ref() {
                serde_json::Value::Null => false,
                serde_json::Value::Bool(value) => *value,
                serde_json::Value::Number(value) => {
                    value.as_f64().is_some_and(|value| value != 0.0)
                }
                serde_json::Value::String(value) => !value.is_empty(),
                serde_json::Value::Array(_) | serde_json::Value::Object(_) => true,
            },
            _ => true,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SeaOrmUserModel, store::entities::user};
    use better_auth_core::{FieldDate, user_fields::UserFieldConfig};

    #[test]
    fn unique_probes_use_declaration_order_and_skip_only_null_or_undefined() -> AuthResult<()> {
        let mut schema = UserConfig::default();
        for (logical, storage) in [
            ("label", "name"),
            ("primaryEmail", "email"),
            ("timestamp", "createdAt"),
            ("absent", "updatedAt"),
        ] {
            let _ = schema.fields_mut().insert(
                logical.into(),
                UserFieldConfig {
                    unique: Some(true),
                    field_name: Some(storage.into()),
                    ..Default::default()
                },
            );
        }
        let readback = CreateReadback::<user::Entity> {
            schema: &schema,
            policy: &IdGeneration::Database,
            scope: ReadbackScope::Transaction,
            column: user::Model::field_column,
        };
        for (label, probed) in [
            (Binding::Raw("".into()), true),
            (Binding::Raw(false.into()), true),
            (Binding::Raw(0.0.into()), true),
            (Binding::Raw(FieldValue::Null), false),
            (Binding::Raw(FieldValue::Undefined), false),
            (Binding::Native(Value::String(None)), false),
        ] {
            let fields = [
                (user::Column::Email, Binding::Raw("mail@example.com".into())),
                (user::Column::CreatedAt, Binding::Date(FieldDate::invalid())),
                (user::Column::Name, label),
            ];
            let columns = readback
                .unique_values(&fields)
                .map(|candidate| candidate.map(|(column, _)| column.to_string()))
                .collect::<AuthResult<Vec<_>>>()?;
            let mut expected = Vec::new();
            if probed {
                expected.push(user::Column::Name.to_string());
            }
            expected.extend([
                user::Column::Email.to_string(),
                user::Column::CreatedAt.to_string(),
            ]);
            assert_eq!(columns, expected);
        }
        Ok(())
    }

    #[test]
    fn readback_uses_the_id_declaration_installed_by_input_conversion() -> AuthResult<()> {
        let mut schema = UserConfig::default();
        let _ = schema.fields_mut().insert(
            "id".into(),
            UserFieldConfig {
                unique: Some(true),
                field_name: Some("name".into()),
                ..Default::default()
            },
        );
        let _ = schema.fields_mut().insert(
            "email".into(),
            UserFieldConfig {
                unique: Some(true),
                ..Default::default()
            },
        );
        let readback = CreateReadback::<user::Entity> {
            schema: &schema,
            policy: &IdGeneration::Database,
            scope: ReadbackScope::Transaction,
            column: user::Model::field_column,
        };
        let fields = [
            (
                user::Column::Name,
                Binding::Raw("replaced-id-mapping".into()),
            ),
            (user::Column::Email, Binding::Raw("mail@example.com".into())),
        ];
        let columns = readback
            .unique_values(&fields)
            .map(|candidate| candidate.map(|(column, _)| column.to_string()))
            .collect::<AuthResult<Vec<_>>>()?;
        assert_eq!(columns, [user::Column::Email.to_string()]);
        Ok(())
    }

    #[test]
    fn full_match_keeps_order_and_distinguishes_null_from_invalid_date() -> AuthResult<()> {
        for invalid_date in [
            Binding::Date(FieldDate::invalid()),
            Binding::Raw(FieldValue::Date(FieldDate::invalid())),
        ] {
            let fields = [
                (user::Column::CreatedAt, invalid_date),
                (user::Column::Image, Binding::Raw(FieldValue::Undefined)),
                (user::Column::Name, Binding::Raw(FieldValue::Null)),
                (user::Column::Email, Binding::Raw("".into())),
            ];
            let query = full_match::<user::Entity>(&fields, DbBackend::MySql)?
                .ok_or_else(|| AuthError::internal("Expected full-match conditions"))?
                .select_only()
                .column(user::Column::Id);
            assert_eq!(
                query.build(DbBackend::MySql).to_string(),
                "SELECT `users`.`id` FROM `users` WHERE `users`.`created_at` = NULL AND `users`.`name` IS NULL AND `users`.`email` = '' LIMIT 2"
            );
        }
        assert!(
            full_match::<user::Entity>(
                &[(user::Column::Image, Binding::Raw(FieldValue::Undefined))],
                DbBackend::MySql,
            )?
            .is_none()
        );
        Ok(())
    }

    #[test]
    fn primary_id_truthiness_uses_values_before_mysql_encoding() -> AuthResult<()> {
        for value in [
            Binding::Date(FieldDate::invalid()),
            Binding::Raw(FieldValue::Date(FieldDate::invalid())),
        ] {
            assert!(is_truthy(&value));
            assert!(!is_null(&value));
            assert_eq!(
                value.bind(DbBackend::MySql)?,
                sea_orm::sea_query::SimpleExpr::Value(Value::String(None))
            );
        }
        for value in [
            Binding::Raw(0.0.into()),
            Binding::Raw("".into()),
            Binding::Native(Value::BigInt(Some(0))),
            Binding::Native(Value::String(Some(String::new()))),
        ] {
            assert!(!is_truthy(&value));
            assert!(!is_null(&value));
        }
        assert!(is_truthy(&Binding::Raw("0".into())));
        Ok(())
    }
}

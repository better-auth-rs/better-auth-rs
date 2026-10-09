use better_auth_core::{AuthError, AuthResult, id::IdGeneration};
use sea_orm::{
    ColumnTrait, ColumnType, DbBackend, Value,
    sea_query::{ExprTrait, SimpleExpr},
};
use std::{fmt::Display, str::FromStr};

pub(super) trait IdColumn: ColumnTrait {
    fn id_value(&self, id: &str, policy: &IdGeneration) -> AuthResult<Value> {
        let id = policy.coerce_id(id)?;
        let id = id.as_ref();
        match self.def().get_column_type() {
            ColumnType::TinyInteger => parse::<i8>(id),
            ColumnType::SmallInteger => parse::<i16>(id),
            ColumnType::Integer => parse::<i32>(id),
            ColumnType::BigInteger => parse::<i64>(id),
            ColumnType::TinyUnsigned => parse::<u8>(id),
            ColumnType::SmallUnsigned => parse::<u16>(id),
            ColumnType::Unsigned => parse::<u32>(id),
            ColumnType::BigUnsigned => parse::<u64>(id),
            ColumnType::Uuid => parse::<uuid::Uuid>(id),
            ColumnType::String(_) | ColumnType::Text | ColumnType::Char(_) => Ok(id.into()),
            column_type => Err(AuthError::config(format!(
                "Unsupported identifier column type: {column_type:?}"
            ))),
        }
    }

    fn id_parameter(
        &self,
        id: &str,
        policy: &IdGeneration,
        backend: DbBackend,
    ) -> AuthResult<SimpleExpr> {
        super::record_bindings::Binding::Native(self.id_value(id, policy)?).bind(backend)
    }

    fn eq_id(
        &self,
        id: impl AsRef<str>,
        policy: &IdGeneration,
        backend: DbBackend,
    ) -> AuthResult<SimpleExpr> {
        Ok(self
            .into_expr()
            .eq(self.save_as(self.id_parameter(id.as_ref(), policy, backend)?)))
    }

    fn is_in_ids(
        &self,
        ids: impl IntoIterator<Item = impl AsRef<str>>,
        policy: &IdGeneration,
        backend: DbBackend,
    ) -> AuthResult<SimpleExpr> {
        let values = ids
            .into_iter()
            .map(|id| {
                self.id_parameter(id.as_ref(), policy, backend)
                    .map(|value| self.save_as(value))
            })
            .collect::<AuthResult<Vec<_>>>()?;
        Ok(self.into_expr().is_in(values))
    }
}

impl<C: ColumnTrait> IdColumn for C {}

fn parse<T: FromStr + Into<Value>>(id: &str) -> AuthResult<Value>
where
    T::Err: Display,
{
    id.parse::<T>()
        .map(Into::into)
        .map_err(|error| AuthError::bad_request(format!("Invalid model identifier: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{entities::member, map_db_err, record_bindings::parameter, value_filter};
    use sea_orm::{ConnectOptions, ConnectionTrait, Database, sea_query::Query};

    #[tokio::test]
    async fn identifiers_and_references_use_the_write_binding_for_queries() -> AuthResult<()> {
        for encoding in ["UTF-8", "UTF-16le", "UTF-16be"] {
            let mut options = ConnectOptions::new("sqlite::memory:");
            let _ = options.max_connections(1);
            let database = Database::connect(options).await.map_err(map_db_err)?;
            let _ = database
                .execute_unprepared(&format!("PRAGMA encoding = '{encoding}'"))
                .await
                .map_err(map_db_err)?;
            let _ = database
                .execute_unprepared("CREATE TABLE member (id TEXT, user_id TEXT)")
                .await
                .map_err(map_db_err)?;
            for (input, expected) in [
                ("\u{feff}node", "node"),
                ("A\u{ffff}B", "A\u{ffff}B"),
                ("42", "42"),
            ] {
                let _ = database
                    .execute_unprepared("DELETE FROM member")
                    .await
                    .map_err(map_db_err)?;
                let value = parameter(input.into(), DbBackend::Sqlite)?;
                let insert = Query::insert()
                    .into_table(member::Entity)
                    .columns([member::Column::Id, member::Column::UserId])
                    .values_panic([value.clone(), value])
                    .to_owned();
                let _ = database
                    .execute_raw(DbBackend::Sqlite.build(&insert))
                    .await
                    .map_err(map_db_err)?;
                for column in [member::Column::Id, member::Column::UserId] {
                    for predicate in [
                        column.eq_id(input, &IdGeneration::Random, DbBackend::Sqlite)?,
                        column.is_in_ids(
                            ["missing", input],
                            &IdGeneration::Random,
                            DbBackend::Sqlite,
                        )?,
                        value_filter::equals_id(
                            column,
                            &input.into(),
                            &IdGeneration::Random,
                            DbBackend::Sqlite,
                        )?,
                    ] {
                        let query = Query::select()
                            .columns([member::Column::Id, member::Column::UserId])
                            .from(member::Entity)
                            .and_where(predicate)
                            .to_owned();
                        let rows = database
                            .query_all_raw(DbBackend::Sqlite.build(&query))
                            .await
                            .map_err(map_db_err)?;
                        assert_eq!(rows.len(), 1, "{encoding}: {input:?}");
                        let row = rows.first().ok_or_else(|| {
                            AuthError::internal("SQLite identifier query did not match")
                        })?;
                        assert_eq!(
                            row.try_get::<String>("", "id").map_err(map_db_err)?,
                            expected
                        );
                        assert_eq!(
                            row.try_get::<String>("", "user_id").map_err(map_db_err)?,
                            expected
                        );
                    }
                }
            }
        }
        Ok(())
    }
}

use better_auth_core::{AuthError, AuthResult, id::IdGeneration};
use sea_orm::{ColumnTrait, ColumnType, Value, sea_query::SimpleExpr};
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

    fn eq_id(&self, id: impl AsRef<str>, policy: &IdGeneration) -> AuthResult<SimpleExpr> {
        Ok(self.eq(self.id_value(id.as_ref(), policy)?))
    }

    fn is_in_ids(
        &self,
        ids: impl IntoIterator<Item = impl AsRef<str>>,
        policy: &IdGeneration,
    ) -> AuthResult<SimpleExpr> {
        let values = ids
            .into_iter()
            .map(|id| self.id_value(id.as_ref(), policy))
            .collect::<AuthResult<Vec<_>>>()?;
        Ok(self.is_in(values))
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

use better_auth_core::AuthResult;
use sea_orm::{DatabaseBackend, DbErr};

/// Convert query pagination at the SQL adapter boundary without truncating input.
pub(super) fn sql_pagination(
    backend: DatabaseBackend,
    limit: Option<f64>,
    offset: Option<f64>,
) -> AuthResult<(Option<u64>, Option<u64>)> {
    let convert = |value: f64, is_limit: bool| {
        if backend == DatabaseBackend::Sqlite
            && value.is_finite()
            && value.fract() == 0.0
            && value < 0.0
        {
            return Ok(if is_limit { None } else { Some(0) });
        }
        let maximum = if backend == DatabaseBackend::Sqlite {
            9_223_372_036_854_775_808.0
        } else {
            18_446_744_073_709_551_616.0
        };
        if !value.is_finite() || value.fract() != 0.0 || value < 0.0 || value >= maximum {
            let message = if backend == DatabaseBackend::Sqlite {
                "datatype mismatch"
            } else {
                "Pagination cannot be represented by this database adapter"
            };
            return Err(super::map_db_err(DbErr::Type(message.into())));
        }
        Ok(Some(value as u64))
    };
    Ok((
        limit
            .map(|value| convert(value, true))
            .transpose()?
            .flatten(),
        offset
            .map(|value| convert(value, false))
            .transpose()?
            .flatten(),
    ))
}

pub(crate) use better_auth_core::error::{AuthError, AuthResult, DatabaseError};
use diesel::result::{DatabaseErrorKind, Error};

pub(crate) fn map_query_err(err: Error) -> AuthError {
    match err {
        Error::DatabaseError(DatabaseErrorKind::UniqueViolation, info) => {
            AuthError::Database(DatabaseError::UniqueConstraint(info.message().to_owned()))
        }
        Error::DatabaseError(DatabaseErrorKind::ForeignKeyViolation, info) => {
            AuthError::Database(DatabaseError::Constraint(info.message().to_owned()))
        }
        other => AuthError::Database(DatabaseError::Query(other.to_string())),
    }
}

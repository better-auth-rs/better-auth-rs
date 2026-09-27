//! Portable SQL types used by the Better Auth tables.
//!
//! Diesel binds each built-in SQL type to one backend representation
//! (`Timestamptz` is PostgreSQL-only, `TimestamptzSqlite` is SQLite-only).
//! These types map to the native representation of each enabled backend, so
//! one `table!` schema and one set of queries serve every backend.
//!
//! Rows load these columns into `DateTime<Utc>` and `serde_json::Value`
//! directly. Coherence rules keep this crate from implementing
//! `AsExpression` for those foreign types, so values bound into a query use
//! the local wrappers [`UtcTimestampValue`], [`NullableUtcTimestampValue`],
//! and [`JsonDocumentValue`]:
//!
//! ```rust,ignore
//! sessions::table.filter(sessions::expires_at.gt(UtcTimestampValue(Utc::now())))
//! ```

use chrono::{DateTime, Utc};
use diesel::expression::AsExpression;
use diesel::query_builder::QueryId;
use diesel::sql_types::SqlType;

/// UTC timestamp: `TIMESTAMPTZ` on PostgreSQL, `TEXT` on SQLite.
///
/// SQLite values are written with a fixed-width, microsecond-precision
/// format so that text comparison matches time order.
#[derive(Debug, Clone, Copy, Default, QueryId, SqlType)]
#[diesel(postgres_type(oid = 1184, array_oid = 1185))]
#[diesel(sqlite_type(name = "Text"))]
pub struct UtcTimestamp;

/// JSON document: `JSONB` on PostgreSQL, `TEXT` on SQLite.
#[derive(Debug, Clone, Copy, Default, QueryId, SqlType)]
#[diesel(postgres_type(oid = 3802, array_oid = 3807))]
#[diesel(sqlite_type(name = "Text"))]
pub struct JsonDocument;

/// A `DateTime<Utc>` bound as [`UtcTimestamp`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, AsExpression)]
#[diesel(sql_type = UtcTimestamp)]
pub struct UtcTimestampValue(pub DateTime<Utc>);

/// An `Option<DateTime<Utc>>` bound as `Nullable<UtcTimestamp>`.
///
/// Bind it only to nullable columns: `None` is written as `NULL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, AsExpression)]
#[diesel(sql_type = UtcTimestamp)]
pub struct NullableUtcTimestampValue(pub Option<DateTime<Utc>>);

/// A `serde_json::Value` bound as [`JsonDocument`].
#[derive(Debug, Clone, PartialEq, Eq, AsExpression)]
#[diesel(sql_type = JsonDocument)]
pub struct JsonDocumentValue(pub serde_json::Value);

impl From<DateTime<Utc>> for UtcTimestampValue {
    fn from(value: DateTime<Utc>) -> Self {
        Self(value)
    }
}

impl From<Option<DateTime<Utc>>> for NullableUtcTimestampValue {
    fn from(value: Option<DateTime<Utc>>) -> Self {
        Self(value)
    }
}

impl From<serde_json::Value> for JsonDocumentValue {
    fn from(value: serde_json::Value) -> Self {
        Self(value)
    }
}

/// Serialize the three wrappers for one backend.
///
/// `NullableUtcTimestampValue` writes `NULL` for `None`; its `AsExpression`
/// derive routes `Nullable<UtcTimestamp>` through this impl.
macro_rules! impl_to_sql {
    ($backend:ty) => {
        impl diesel::serialize::ToSql<UtcTimestamp, $backend> for UtcTimestampValue {
            fn to_sql<'b>(
                &'b self,
                out: &mut diesel::serialize::Output<'b, '_, $backend>,
            ) -> diesel::serialize::Result {
                <DateTime<Utc> as diesel::serialize::ToSql<UtcTimestamp, $backend>>::to_sql(
                    &self.0, out,
                )
            }
        }

        impl diesel::serialize::ToSql<UtcTimestamp, $backend> for NullableUtcTimestampValue {
            fn to_sql<'b>(
                &'b self,
                out: &mut diesel::serialize::Output<'b, '_, $backend>,
            ) -> diesel::serialize::Result {
                match &self.0 {
                    Some(value) => <DateTime<Utc> as diesel::serialize::ToSql<
                        UtcTimestamp,
                        $backend,
                    >>::to_sql(value, out),
                    None => Ok(diesel::serialize::IsNull::Yes),
                }
            }
        }

        impl diesel::serialize::ToSql<JsonDocument, $backend> for JsonDocumentValue {
            fn to_sql<'b>(
                &'b self,
                out: &mut diesel::serialize::Output<'b, '_, $backend>,
            ) -> diesel::serialize::Result {
                <serde_json::Value as diesel::serialize::ToSql<JsonDocument, $backend>>::to_sql(
                    &self.0, out,
                )
            }
        }
    };
}

#[cfg(feature = "postgres")]
mod postgres {
    use chrono::{DateTime, Utc};
    use diesel::deserialize::{self, FromSql};
    use diesel::pg::{Pg, PgValue};
    use diesel::serialize::{self, Output, ToSql};
    use diesel::sql_types::{Jsonb, Timestamptz};

    use super::{
        JsonDocument, JsonDocumentValue, NullableUtcTimestampValue, UtcTimestamp, UtcTimestampValue,
    };

    impl ToSql<UtcTimestamp, Pg> for DateTime<Utc> {
        fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
            <Self as ToSql<Timestamptz, Pg>>::to_sql(self, out)
        }
    }

    impl FromSql<UtcTimestamp, Pg> for DateTime<Utc> {
        fn from_sql(value: PgValue<'_>) -> deserialize::Result<Self> {
            <Self as FromSql<Timestamptz, Pg>>::from_sql(value)
        }
    }

    impl ToSql<JsonDocument, Pg> for serde_json::Value {
        fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
            <Self as ToSql<Jsonb, Pg>>::to_sql(self, out)
        }
    }

    impl FromSql<JsonDocument, Pg> for serde_json::Value {
        fn from_sql(value: PgValue<'_>) -> deserialize::Result<Self> {
            <Self as FromSql<Jsonb, Pg>>::from_sql(value)
        }
    }

    impl_to_sql!(Pg);
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use chrono::{DateTime, Utc};
    use diesel::deserialize::{self, FromSql};
    use diesel::serialize::{self, IsNull, Output, ToSql};
    use diesel::sql_types::{Json, TimestamptzSqlite};
    use diesel::sqlite::{Sqlite, SqliteValue};

    use super::{
        JsonDocument, JsonDocumentValue, NullableUtcTimestampValue, UtcTimestamp, UtcTimestampValue,
    };

    /// Fixed width keeps lexicographic order equal to time order.
    const TIMESTAMP_FORMAT: &str = "%Y-%m-%d %H:%M:%S%.6f+00:00";

    impl ToSql<UtcTimestamp, Sqlite> for DateTime<Utc> {
        fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Sqlite>) -> serialize::Result {
            out.set_value(self.format(TIMESTAMP_FORMAT).to_string());
            Ok(IsNull::No)
        }
    }

    impl FromSql<UtcTimestamp, Sqlite> for DateTime<Utc> {
        fn from_sql(value: SqliteValue<'_, '_, '_>) -> deserialize::Result<Self> {
            <Self as FromSql<TimestamptzSqlite, Sqlite>>::from_sql(value)
        }
    }

    impl ToSql<JsonDocument, Sqlite> for serde_json::Value {
        fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Sqlite>) -> serialize::Result {
            <Self as ToSql<Json, Sqlite>>::to_sql(self, out)
        }
    }

    impl FromSql<JsonDocument, Sqlite> for serde_json::Value {
        fn from_sql(value: SqliteValue<'_, '_, '_>) -> deserialize::Result<Self> {
            <Self as FromSql<Json, Sqlite>>::from_sql(value)
        }
    }

    impl_to_sql!(Sqlite);
}

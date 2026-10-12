#[cfg(feature = "with-bigdecimal")]
use sea_query::prelude::BigDecimal;
#[cfg(feature = "with-rust_decimal")]
use sea_query::prelude::Decimal;
#[cfg(feature = "with-ipnetwork")]
use sea_query::prelude::IpNetwork;
#[cfg(feature = "with-json")]
use sea_query::prelude::Json;
#[cfg(feature = "with-mac_address")]
use sea_query::prelude::MacAddress;
#[cfg(feature = "with-uuid")]
use sea_query::prelude::Uuid;
#[cfg(feature = "with-time")]
use sea_query::prelude::time;
#[cfg(feature = "with-chrono")]
use sea_query::prelude::{DateTime, FixedOffset, Local, NaiveDate, NaiveDateTime, NaiveTime, Utc};

use sea_query::Value;
#[cfg(feature = "postgres-array")]
use sea_query::{ArrayType, ValueType, ValueTypeErr};

use crate::SqlxValues;

#[cfg(test)]
mod tests;

impl SqlxValues {
    /// Encode PostgreSQL parameters without discarding conversion or encoding errors.
    ///
    /// Pass the result to `sqlx::query_with_result` to prevent execution after an error.
    pub fn try_into_pg_arguments(
        self,
    ) -> Result<sqlx::postgres::PgArguments, sqlx::error::BoxDynError> {
        let mut args = sqlx::postgres::PgArguments::default();
        for arg in self.0.into_iter() {
            use sqlx::Arguments;
            match arg {
                Value::Bool(b) => {
                    args.add(b)?;
                }
                Value::TinyInt(i) => {
                    args.add(i)?;
                }
                Value::SmallInt(i) => {
                    args.add(i)?;
                }
                Value::Int(i) => {
                    args.add(i)?;
                }
                Value::BigInt(i) => {
                    args.add(i)?;
                }
                Value::TinyUnsigned(i) => {
                    args.add(i.map(|i| i as i16))?;
                }
                Value::SmallUnsigned(i) => {
                    args.add(i.map(|i| i as i32))?;
                }
                Value::Unsigned(i) => {
                    args.add(i.map(|i| i as i64))?;
                }
                Value::BigUnsigned(i) => {
                    args.add(i.map(<i64 as TryFrom<u64>>::try_from).transpose()?)?;
                }
                Value::Float(f) => {
                    args.add(f)?;
                }
                Value::Double(d) => {
                    args.add(d)?;
                }
                Value::String(s) => {
                    args.add(s.as_deref())?;
                }
                Value::PostgresUnspecifiedText(text) => {
                    args.add_text(text.as_deref())?;
                }
                Value::Char(c) => {
                    args.add(c.map(|c| c.to_string()))?;
                }
                Value::Bytes(b) => {
                    args.add(b.as_deref())?;
                }
                #[cfg(feature = "with-chrono")]
                Value::ChronoDate(d) => {
                    args.add(d)?;
                }
                #[cfg(feature = "with-chrono")]
                Value::ChronoTime(t) => {
                    args.add(t)?;
                }
                #[cfg(feature = "with-chrono")]
                Value::ChronoDateTime(t) => {
                    args.add(t)?;
                }
                #[cfg(feature = "with-chrono")]
                Value::ChronoDateTimeUtc(t) => {
                    args.add(t)?;
                }
                #[cfg(feature = "with-chrono")]
                Value::ChronoDateTimeLocal(t) => {
                    args.add(t)?;
                }
                #[cfg(feature = "with-chrono")]
                Value::ChronoDateTimeWithTimeZone(t) => {
                    args.add(t)?;
                }
                #[cfg(feature = "with-time")]
                Value::TimeDate(t) => {
                    args.add(t)?;
                }
                #[cfg(feature = "with-time")]
                Value::TimeTime(t) => {
                    args.add(t)?;
                }
                #[cfg(feature = "with-time")]
                Value::TimeDateTime(t) => {
                    args.add(t)?;
                }
                #[cfg(feature = "with-time")]
                Value::TimeDateTimeWithTimeZone(t) => {
                    args.add(t)?;
                }
                #[cfg(feature = "with-uuid")]
                Value::Uuid(uuid) => {
                    args.add(uuid)?;
                }
                #[cfg(feature = "with-rust_decimal")]
                Value::Decimal(d) => {
                    args.add(d)?;
                }
                #[cfg(feature = "with-bigdecimal")]
                Value::BigDecimal(d) => {
                    args.add(d.as_deref())?;
                }
                #[cfg(feature = "with-json")]
                Value::Json(j) => {
                    args.add(j.as_deref())?;
                }
                #[cfg(feature = "with-ipnetwork")]
                Value::IpNetwork(ip) => {
                    args.add(ip)?;
                }
                #[cfg(feature = "with-mac_address")]
                Value::MacAddress(mac) => {
                    args.add(mac)?;
                }
                #[cfg(feature = "postgres-array")]
                Value::Array(ty, v) => match ty {
                    ArrayType::Bool => {
                        let value: Option<Vec<bool>> = array_values(ty, v)?;
                        args.add(value)?;
                    }
                    ArrayType::TinyInt => {
                        let value: Option<Vec<i8>> = array_values(ty, v)?;
                        args.add(value)?;
                    }
                    ArrayType::SmallInt => {
                        let value: Option<Vec<i16>> = array_values(ty, v)?;
                        args.add(value)?;
                    }
                    ArrayType::Int => {
                        let value: Option<Vec<i32>> = array_values(ty, v)?;
                        args.add(value)?;
                    }
                    ArrayType::BigInt => {
                        let value: Option<Vec<i64>> = array_values(ty, v)?;
                        args.add(value)?;
                    }
                    ArrayType::TinyUnsigned => {
                        let value: Option<Vec<u8>> = array_values(ty, v)?;
                        let value: Option<Vec<i16>> =
                            value.map(|vec| vec.into_iter().map(|i| i as i16).collect());
                        args.add(value)?;
                    }
                    ArrayType::SmallUnsigned => {
                        let value: Option<Vec<u16>> = array_values(ty, v)?;
                        let value: Option<Vec<i32>> =
                            value.map(|vec| vec.into_iter().map(|i| i as i32).collect());
                        args.add(value)?;
                    }
                    ArrayType::Unsigned => {
                        let value: Option<Vec<u32>> = array_values(ty, v)?;
                        let value: Option<Vec<i64>> =
                            value.map(|vec| vec.into_iter().map(|i| i as i64).collect());
                        args.add(value)?;
                    }
                    ArrayType::BigUnsigned => {
                        let value: Option<Vec<u64>> = array_values(ty, v)?;
                        let value: Option<Vec<i64>> = value
                            .map(|vec| {
                                vec.into_iter()
                                    .map(<i64 as TryFrom<u64>>::try_from)
                                    .collect::<Result<_, _>>()
                            })
                            .transpose()?;
                        args.add(value)?;
                    }
                    ArrayType::Float => {
                        let value: Option<Vec<f32>> = array_values(ty, v)?;
                        args.add(value)?;
                    }
                    ArrayType::Double => {
                        let value: Option<Vec<f64>> = array_values(ty, v)?;
                        args.add(value)?;
                    }
                    ArrayType::String => {
                        let value: Option<Vec<String>> = array_values(ty, v)?;
                        args.add(value)?;
                    }
                    ArrayType::Char => {
                        let value: Option<Vec<char>> = array_values(ty, v)?;
                        let value: Option<Vec<String>> =
                            value.map(|vec| vec.into_iter().map(|c| c.to_string()).collect());
                        args.add(value)?;
                    }
                    ArrayType::Bytes => {
                        let value: Option<Vec<Vec<u8>>> = array_values(ty, v)?;
                        args.add(value)?;
                    }
                    #[cfg(feature = "with-chrono")]
                    ArrayType::ChronoDate => {
                        let value: Option<Vec<NaiveDate>> = array_values(ty, v)?;
                        args.add(value)?;
                    }
                    #[cfg(feature = "with-chrono")]
                    ArrayType::ChronoTime => {
                        let value: Option<Vec<NaiveTime>> = array_values(ty, v)?;
                        args.add(value)?;
                    }
                    #[cfg(feature = "with-chrono")]
                    ArrayType::ChronoDateTime => {
                        let value: Option<Vec<NaiveDateTime>> = array_values(ty, v)?;
                        args.add(value)?;
                    }
                    #[cfg(feature = "with-chrono")]
                    ArrayType::ChronoDateTimeUtc => {
                        let value: Option<Vec<DateTime<Utc>>> = array_values(ty, v)?;
                        args.add(value)?;
                    }
                    #[cfg(feature = "with-chrono")]
                    ArrayType::ChronoDateTimeLocal => {
                        let value: Option<Vec<DateTime<Local>>> = array_values(ty, v)?;
                        args.add(value)?;
                    }
                    #[cfg(feature = "with-chrono")]
                    ArrayType::ChronoDateTimeWithTimeZone => {
                        let value: Option<Vec<DateTime<FixedOffset>>> = array_values(ty, v)?;
                        args.add(value)?;
                    }
                    #[cfg(feature = "with-time")]
                    ArrayType::TimeDate => {
                        let value: Option<Vec<time::Date>> = array_values(ty, v)?;
                        args.add(value)?;
                    }
                    #[cfg(feature = "with-time")]
                    ArrayType::TimeTime => {
                        let value: Option<Vec<time::Time>> = array_values(ty, v)?;
                        args.add(value)?;
                    }
                    #[cfg(feature = "with-time")]
                    ArrayType::TimeDateTime => {
                        let value: Option<Vec<time::PrimitiveDateTime>> = array_values(ty, v)?;
                        args.add(value)?;
                    }
                    #[cfg(feature = "with-time")]
                    ArrayType::TimeDateTimeWithTimeZone => {
                        let value: Option<Vec<time::OffsetDateTime>> = array_values(ty, v)?;
                        args.add(value)?;
                    }
                    #[cfg(feature = "with-uuid")]
                    ArrayType::Uuid => {
                        let value: Option<Vec<Uuid>> = array_values(ty, v)?;
                        args.add(value)?;
                    }
                    #[cfg(feature = "with-rust_decimal")]
                    ArrayType::Decimal => {
                        let value: Option<Vec<Decimal>> = array_values(ty, v)?;
                        args.add(value)?;
                    }
                    #[cfg(feature = "with-bigdecimal")]
                    ArrayType::BigDecimal => {
                        let value: Option<Vec<BigDecimal>> = array_values(ty, v)?;
                        args.add(value)?;
                    }
                    #[cfg(feature = "with-json")]
                    ArrayType::Json => {
                        let value: Option<Vec<Json>> = array_values(ty, v)?;
                        args.add(value)?;
                    }
                    #[cfg(feature = "with-ipnetwork")]
                    ArrayType::IpNetwork => {
                        let value: Option<Vec<IpNetwork>> = array_values(ty, v)?;
                        args.add(value)?;
                    }
                    #[cfg(feature = "with-mac_address")]
                    ArrayType::MacAddress => {
                        let value: Option<Vec<MacAddress>> = array_values(ty, v)?;
                        args.add(value)?;
                    }
                },
                #[cfg(feature = "postgres-vector")]
                Value::Vector(v) => {
                    args.add(v)?;
                } /* #[cfg(feature = "postgres-range")]
                  Value::Range(v) => {
                      args.add(v)?;
                  } */
            }
        }
        Ok(args)
    }
}

impl sqlx::IntoArguments<'_, sqlx::postgres::Postgres> for SqlxValues {
    /// Panics on conversion or encoding errors. Use `try_into_pg_arguments` to propagate errors.
    fn into_arguments(self) -> sqlx::postgres::PgArguments {
        self.try_into_pg_arguments()
            .expect("failed to encode PostgreSQL arguments")
    }
}

#[cfg(feature = "postgres-array")]
fn array_values<T: ValueType>(
    ty: ArrayType,
    values: Option<Box<Vec<Value>>>,
) -> Result<Option<Vec<T>>, ValueTypeErr> {
    if ty != T::array_type() {
        return Err(ValueTypeErr);
    }
    values
        .map(|values| values.into_iter().map(T::try_from).collect())
        .transpose()
}

//! Explicit JSON serializers for DTO and cache boundaries.

use crate::{FieldDate, FieldMap, FieldValue};
use ::serde::{Deserialize, Serialize, de::Error};

pub(crate) struct Json<'a>(pub(crate) &'a FieldValue);

impl Serialize for Json<'_> {
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            FieldValue::Undefined | FieldValue::Null => serializer.serialize_unit(),
            FieldValue::Bool(value) => value.serialize(serializer),
            FieldValue::String(value) => value.serialize(serializer),
            FieldValue::Utf16String(value) => value.serialize(serializer),
            FieldValue::Number(value) if !value.is_finite() => serializer.serialize_unit(),
            FieldValue::Number(value) => ::serde_json::value::RawValue::from_string(
                crate::schema_value::number_string(*value),
            )
            .map_err(::serde::ser::Error::custom)?
            .serialize(serializer),
            FieldValue::Date(_) => self
                .0
                .json()
                .map_err(::serde::ser::Error::custom)?
                .serialize(serializer),
            FieldValue::Array(values) => {
                use ::serde::ser::SerializeSeq;
                let mut sequence = serializer.serialize_seq(Some(values.len()))?;
                for value in values.iter() {
                    sequence.serialize_element(&Json(value))?;
                }
                sequence.end()
            }
            FieldValue::Object(fields) => map::serialize(fields, serializer),
        }
    }
}

pub mod map {
    use super::*;

    pub fn serialize<S: ::serde::Serializer>(
        fields: &FieldMap,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        use ::serde::ser::SerializeMap;
        let mut fields: Vec<_> = fields
            .iter()
            .filter(|(_, value)| !value.is_undefined())
            .collect();
        fields.sort_by_key(|(name, _)| {
            crate::utils::json::array_index(name).map_or((true, 0), |index| (false, index))
        });
        let mut output = serializer.serialize_map(Some(fields.len()))?;
        for (name, value) in fields {
            output.serialize_entry(name, &Json(value))?;
        }
        output.end()
    }

    pub fn deserialize<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<FieldMap, D::Error> {
        let value = ::serde_json::Map::<String, ::serde_json::Value>::deserialize(deserializer)?;
        FieldMap::from_json(value).map_err(D::Error::custom)
    }
}

pub mod value {
    use super::*;

    pub fn serialize<S: ::serde::Serializer>(
        value: &FieldValue,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        Json(value).serialize(serializer)
    }

    pub fn deserialize<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<FieldValue, D::Error> {
        let value = ::serde_json::Value::deserialize(deserializer)?;
        FieldValue::from_json(value).map_err(D::Error::custom)
    }
}

pub mod optional_value {
    use super::*;

    pub fn serialize<S: ::serde::Serializer>(
        value: &Option<FieldValue>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => super::value::serialize(value, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<FieldValue>, D::Error> {
        let value = super::value::deserialize(deserializer)?;
        Ok((!value.is_null()).then_some(value))
    }
}

pub mod schema_date {
    use super::*;

    pub fn serialize<S: ::serde::Serializer>(
        value: &crate::SchemaValue<FieldDate>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        super::value::serialize(&value.field_value(), serializer)
    }

    pub fn deserialize<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<crate::SchemaValue<FieldDate>, D::Error> {
        let value = super::value::deserialize(deserializer)?;
        Ok(crate::SchemaValue::from_field(match value {
            FieldValue::String(text) => FieldValue::Date(
                crate::utils::date::parse_date_constructor(&text)
                    .unwrap_or_else(FieldDate::invalid),
            ),
            value => value,
        }))
    }
}

pub mod optional_schema_date {
    use super::*;

    pub fn serialize<S: ::serde::Serializer>(
        value: &crate::SchemaValue<Option<FieldDate>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        super::value::serialize(&value.field_value(), serializer)
    }

    pub fn deserialize<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<crate::SchemaValue<Option<FieldDate>>, D::Error> {
        let value = schema_date::deserialize(deserializer)?.into_field_value();
        Ok(crate::SchemaValue::from_field(value))
    }
}

pub mod date {
    use super::*;

    pub fn serialize<S: ::serde::Serializer>(
        value: &FieldDate,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        super::value::serialize(&FieldValue::Date(value.clone()), serializer)
    }

    pub fn deserialize<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<FieldDate, D::Error> {
        let value = String::deserialize(deserializer)?;
        Ok(crate::utils::date::parse_date_constructor(&value).unwrap_or_else(FieldDate::invalid))
    }
}

pub mod optional_date {
    use super::*;

    pub fn serialize<S: ::serde::Serializer>(
        value: &Option<FieldDate>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => super::date::serialize(value, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<FieldDate>, D::Error> {
        Ok(Option::<String>::deserialize(deserializer)?.map(|value| {
            crate::utils::date::parse_date_constructor(&value).unwrap_or_else(FieldDate::invalid)
        }))
    }
}

pub mod date_update {
    use super::*;

    pub fn serialize<S: ::serde::Serializer>(
        value: &Option<Option<FieldDate>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => optional_date::serialize(value, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Option<FieldDate>>, D::Error> {
        optional_date::deserialize(deserializer).map(Some)
    }
}

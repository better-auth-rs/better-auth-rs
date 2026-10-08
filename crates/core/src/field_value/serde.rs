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
            FieldValue::String(text) => crate::utils::json::parse_json_date(&text)
                .map_or_else(|| text.into(), |date| FieldDate::from(date).into()),
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

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Regression assertions verify public DTO date decoding and JSON preservation"
)]
mod tests {
    use crate::{
        ApiKey, AuthResult, FieldDate, Passkey,
        wire::{ApiKeyView, PasskeyView},
    };
    use ::serde::{Serialize, de::DeserializeOwned};
    use serde_json::{Value, json};

    fn assert_raw_date_strings<T: DeserializeOwned + Serialize>(fields: &[&str]) -> AuthResult<()> {
        // Upstream safeJSONParse retains strings outside its valid UTC ISO date grammar.
        for text in [
            "hello",
            "2100-01-01T00:00Z",
            "2100-01-01T00:00:00+00:00",
            "2100-13-01T00:00:00Z",
        ] {
            let input = Value::Object(
                fields
                    .iter()
                    .map(|field| ((*field).into(), text.into()))
                    .collect(),
            );
            let decoded: T = serde_json::from_value(input.clone())?;
            assert_eq!(serde_json::to_value(decoded)?, input);
        }
        Ok(())
    }

    #[test]
    fn api_key_and_passkey_date_strings_survive_public_serde() -> AuthResult<()> {
        let fields = [
            "createdAt",
            "updatedAt",
            "expiresAt",
            "lastRefillAt",
            "lastRequest",
        ];
        assert_raw_date_strings::<ApiKey>(&fields)?;
        assert_raw_date_strings::<ApiKeyView>(&fields)?;
        assert_raw_date_strings::<Passkey>(&["createdAt", "updatedAt"])?;
        assert_raw_date_strings::<PasskeyView>(&["createdAt"])?;
        Ok(())
    }

    #[test]
    fn api_key_and_passkey_iso_dates_keep_typed_access() -> AuthResult<()> {
        let text = "2100-01-01T00:00:00.000Z";
        let input = json!({
            "createdAt": text,
            "updatedAt": text,
            "expiresAt": text,
            "lastRefillAt": text,
            "lastRequest": text,
        });
        let key: ApiKey = serde_json::from_value(input.clone())?;
        let key_view: ApiKeyView = serde_json::from_value(input.clone())?;
        let passkey_input = json!({"createdAt": text, "updatedAt": text});
        let passkey: Passkey = serde_json::from_value(passkey_input.clone())?;
        let passkey_view_input = json!({"createdAt": text});
        let passkey_view: PasskeyView = serde_json::from_value(passkey_view_input.clone())?;
        let expected = FieldDate::from_milliseconds(4_102_444_800_000.0);
        for date in [
            &key.created_at,
            &key.updated_at,
            &key_view.created_at,
            &key_view.updated_at,
            &passkey.updated_at,
        ] {
            assert_eq!(date.typed()?, &expected);
        }
        for date in [
            &key.expires_at,
            &key.last_refill_at,
            &key.last_request,
            &key_view.expires_at,
            &key_view.last_refill_at,
            &key_view.last_request,
            &passkey.created_at,
            &passkey_view.created_at,
        ] {
            assert_eq!(date.typed()?, &Some(expected.clone()));
        }
        assert_eq!(serde_json::to_value(key)?, input);
        assert_eq!(serde_json::to_value(key_view)?, input);
        assert_eq!(serde_json::to_value(passkey)?, passkey_input);
        assert_eq!(serde_json::to_value(passkey_view)?, passkey_view_input);
        Ok(())
    }
}

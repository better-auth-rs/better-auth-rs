//! Preserve OAuth extras through JSON without converting UTF-16 strings to UTF-8.

use better_auth_core::{ApiKeyStart as Utf16String, AuthResult};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use serde_json::{Map, Value, value::RawValue};

#[derive(Debug, Clone, Default)]
pub(crate) struct StateExtras(Vec<(Utf16String, Box<RawValue>)>);

impl StateExtras {
    pub(super) fn from_values(values: Map<String, Value>) -> AuthResult<Self> {
        values
            .into_iter()
            .map(|(key, value)| Ok((key.into(), serde_json::value::to_raw_value(&value)?)))
            .collect::<AuthResult<Vec<_>>>()
            .map(Self)
    }

    pub(super) fn retain(&mut self, keep: impl Fn(&str) -> bool) {
        self.0.retain(|(key, _)| match key.to_utf8() {
            Ok(key) => keep(&key),
            Err(_) => true,
        });
    }

    pub(super) fn remove(&mut self, name: &str) -> Option<Box<RawValue>> {
        let name = Utf16String::from(name);
        let index = self.0.iter().position(|(key, _)| key == &name)?;
        Some(self.0.remove(index).1)
    }

    pub(super) fn insert<T: Serialize>(&mut self, name: &str, value: &T) -> serde_json::Result<()> {
        self.set(name.into(), serde_json::value::to_raw_value(value)?);
        Ok(())
    }

    fn set(&mut self, name: Utf16String, value: Box<RawValue>) {
        if let Some((_, previous)) = self.0.iter_mut().find(|(key, _)| key == &name) {
            *previous = value;
        } else {
            self.0.push((name, value));
        }
    }

    pub(super) fn popup_entries(text: Option<&str>) -> Self {
        let Some(text) = text.filter(|text| !text.is_empty()) else {
            return Self::default();
        };
        match Self::parse_popup_entries(text) {
            Ok(value) => value,
            Err(error) => {
                // The upstream safeJSONParse logs invalid JSON and returns null.
                tracing::error!(%error, "Error parsing JSON");
                Self::default()
            }
        }
    }

    fn parse_popup_entries(text: &str) -> serde_json::Result<Self> {
        let value: Box<RawValue> = serde_json::from_str(text)?;
        let mut fields = match value.get().as_bytes().first() {
            Some(b'{') => serde_json::from_str::<Self>(value.get())?,
            Some(b'[') => {
                let values: Vec<Box<RawValue>> = serde_json::from_str(value.get())?;
                Self(
                    values
                        .into_iter()
                        .enumerate()
                        .map(|(index, value)| (index.to_string().into(), value))
                        .collect(),
                )
            }
            Some(b'"') => {
                let text: Utf16String = serde_json::from_str(value.get())?;
                if text
                    .to_utf8()
                    .ok()
                    .as_deref()
                    .and_then(better_auth_core::utils::json::parse_json_date)
                    .is_some()
                {
                    return Ok(Self::default());
                }
                let fields = text
                    .as_utf16()
                    .iter()
                    .enumerate()
                    .map(|(index, unit)| {
                        RawValue::from_string(format!("\"\\u{unit:04x}\""))
                            .map(|value| (index.to_string().into(), value))
                    })
                    .collect::<serde_json::Result<Vec<_>>>()?;
                Self(fields)
            }
            _ => Self::default(),
        };
        for (_, value) in &mut fields.0 {
            *value = revive_dates(value)?;
        }
        fields.retain(|key| !super::state::reserved_state_key(key));
        Ok(fields)
    }
}

impl Serialize for StateExtras {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut output = String::from("{");
        for (index, (key, value)) in self.0.iter().enumerate() {
            if index != 0 {
                output.push(',');
            }
            // Both fragments are validated JSON. Serializing a map key as String
            // would reject lone surrogates before RawValue could preserve them.
            let key = match key.to_utf8() {
                Ok(text) => serde_json::to_string(&text),
                Err(_) => serde_json::to_string(key),
            }
            .map_err(serde::ser::Error::custom)?;
            output.push_str(&key);
            output.push(':');
            output.push_str(value.get());
        }
        output.push('}');
        RawValue::from_string(output)
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for StateExtras {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor;
        impl<'de> de::Visitor<'de> for ObjectVisitor {
            type Value = StateExtras;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an OAuth state object")
            }

            fn visit_map<M: de::MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut result = StateExtras::default();
                while let Some((key, value)) = map.next_entry::<Utf16String, Box<RawValue>>()? {
                    result.set(key, value);
                }
                result.0.sort_by_key(|(key, _)| {
                    let index = key
                        .to_utf8()
                        .ok()
                        .and_then(|key| better_auth_core::utils::json::array_index(&key));
                    index.map_or((true, 0), |index| (false, index))
                });
                Ok(result)
            }
        }
        deserializer.deserialize_map(ObjectVisitor)
    }
}

fn revive_dates(value: &RawValue) -> serde_json::Result<Box<RawValue>> {
    match value.get().as_bytes().first() {
        Some(b'{') => {
            let mut object: StateExtras = serde_json::from_str(value.get())?;
            for (_, value) in &mut object.0 {
                *value = revive_dates(value)?;
            }
            serde_json::value::to_raw_value(&object)
        }
        Some(b'[') => {
            let values: Vec<Box<RawValue>> = serde_json::from_str(value.get())?;
            let values = values
                .iter()
                .map(|value| revive_dates(value))
                .collect::<serde_json::Result<Vec<_>>>()?;
            serde_json::value::to_raw_value(&values)
        }
        Some(b'"') => {
            let text: Utf16String = serde_json::from_str(value.get())?;
            match text
                .to_utf8()
                .ok()
                .as_deref()
                .and_then(better_auth_core::utils::json::parse_json_date)
            {
                Some(date) => serde_json::value::to_raw_value(
                    &date.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                ),
                None => Ok(value.to_owned()),
            }
        }
        _ => Ok(value.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn popup_entries_preserve_utf16_and_revive_only_values() {
        let fields = StateExtras::popup_entries(Some(r#""😀x""#));
        let text = serde_json::to_string(&fields).unwrap();
        let mut fields: StateExtras = serde_json::from_str(&text).unwrap();
        for (key, units) in [("0", vec![0xd83d]), ("1", vec![0xde00]), ("2", vec![120])] {
            let value = fields.remove(key).unwrap();
            let value: Utf16String = serde_json::from_str(value.get()).unwrap();
            assert_eq!(value.as_utf16(), units);
        }

        let mut fields = StateExtras::popup_entries(Some(
            r#"{"oauthState":"forged","\ud800":{"v":"\udc00","day":"2026-02-30T00:00:00Z"},"day":1,"day":2}"#,
        ));
        assert!(fields.remove("oauthState").is_none());
        assert_eq!(fields.remove("day").unwrap().get(), "2");
        let raw = &fields.0.first().unwrap().1;
        let mut nested: StateExtras = serde_json::from_str(raw.get()).unwrap();
        assert_eq!(nested.remove("v").unwrap().get(), r#""\udc00""#);
        assert_eq!(
            nested.remove("day").unwrap().get(),
            r#""2026-03-02T00:00:00.000Z""#
        );
        assert_eq!(fields.0.first().unwrap().0.as_utf16(), &[0xd800]);
        assert_eq!(
            serde_json::to_string(&StateExtras::popup_entries(Some(
                r#""2026-02-30T00:00:00Z""#
            )))
            .unwrap(),
            "{}"
        );
    }
}

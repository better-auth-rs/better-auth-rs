//! Strings retain JavaScript UTF-16 code units, including unpaired surrogates.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// A string that can contain unpaired UTF-16 surrogates.
/// JSON serialization preserves every code unit. UTF-8 conversion is fallible.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Utf16String(Vec<u16>);

impl Utf16String {
    /// Construct a JavaScript string from exact UTF-16 code units.
    pub fn from_units(units: Vec<u16>) -> Self {
        Self(units)
    }

    /// Take the first `length` UTF-16 code units, as JavaScript `substring` does.
    pub fn prefix(value: &str, length: usize) -> Self {
        Self(value.encode_utf16().take(length).collect())
    }

    /// Return the exact code units, including any unpaired surrogate.
    pub fn as_utf16(&self) -> &[u16] {
        &self.0
    }

    /// Convert only when the prefix is a valid Unicode string.
    pub fn to_utf8(&self) -> Result<String, std::string::FromUtf16Error> {
        String::from_utf16(&self.0)
    }

    /// Lowercase Unicode segments without replacing unpaired surrogates.
    pub fn to_lowercase(&self) -> Self {
        let mut units = Vec::new();
        let mut segment = String::new();
        for scalar in char::decode_utf16(self.0.iter().copied()) {
            match scalar {
                Ok(scalar) => segment.push(scalar),
                Err(error) => {
                    units.extend(segment.to_lowercase().encode_utf16());
                    segment.clear();
                    units.push(error.unpaired_surrogate());
                }
            }
        }
        units.extend(segment.to_lowercase().encode_utf16());
        Self(units)
    }

    /// Encode the prefix as WTF-8 for adapters that preserve unpaired surrogates.
    pub fn to_wtf8(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for value in char::decode_utf16(self.0.iter().copied()) {
            match value {
                Ok(value) => bytes.extend_from_slice(value.encode_utf8(&mut [0; 4]).as_bytes()),
                Err(error) => {
                    let value = error.unpaired_surrogate();
                    bytes.extend_from_slice(&[
                        0xe0 | (value >> 12) as u8,
                        0x80 | ((value >> 6) & 0x3f) as u8,
                        0x80 | (value & 0x3f) as u8,
                    ]);
                }
            }
        }
        bytes
    }

    fn from_wtf8(mut bytes: &[u8]) -> Result<Self, &'static str> {
        let mut units = Vec::new();
        loop {
            match std::str::from_utf8(bytes) {
                Ok(value) => {
                    units.extend(value.encode_utf16());
                    return Ok(Self(units));
                }
                Err(error) => {
                    let (valid, invalid) = bytes.split_at(error.valid_up_to());
                    units.extend(
                        std::str::from_utf8(valid)
                            .map_err(|_| "Invalid WTF-8 prefix")?
                            .encode_utf16(),
                    );
                    let [0xed, second @ 0xa0..=0xbf, third @ 0x80..=0xbf, rest @ ..] = invalid
                    else {
                        return Err("API key start must contain valid WTF-8");
                    };
                    units.push(0xd000 | (u16::from(second & 0x3f) << 6) | u16::from(third & 0x3f));
                    bytes = rest;
                }
            }
        }
    }
}

impl From<&str> for Utf16String {
    fn from(value: &str) -> Self {
        Self(value.encode_utf16().collect())
    }
}

impl From<String> for Utf16String {
    fn from(value: String) -> Self {
        Self::from(value.as_str())
    }
}

impl Serialize for Utf16String {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut json = String::from("\"");
        for unit in &self.0 {
            json.push_str(&format!("\\u{unit:04x}"));
        }
        json.push('"');
        serde_json::value::RawValue::from_string(json)
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Utf16String {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl de::Visitor<'_> for Visitor {
            type Value = Utf16String;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an API key prefix encoded as a JSON string")
            }

            fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
                Utf16String::from_wtf8(value).map_err(E::custom)
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(Utf16String::from(value))
            }
        }
        // serde_json supplies WTF-8 here; deserialize_string rejects lone surrogates.
        deserializer.deserialize_bytes(Visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substring_retains_surrogates_through_json_and_wtf8() {
        let start = Utf16String::prefix("😀abcdefgh", 1);
        assert_eq!(start.as_utf16(), &[0xd83d]);
        assert!(start.to_utf8().is_err());
        assert_eq!(start.to_wtf8(), [0xed, 0xa0, 0xbd]);
        let json = serde_json::to_string(&start).unwrap();
        assert_eq!(json, "\"\\ud83d\"");
        assert_eq!(serde_json::from_str::<Utf16String>(&json).unwrap(), start);
        assert_eq!(
            Utf16String::prefix("😀abcdefgh", 2).to_utf8().unwrap(),
            "😀"
        );
        assert_eq!(
            Utf16String::prefix("😀abcdefgh", 6).to_utf8().unwrap(),
            "😀abcd"
        );
        assert_eq!(
            serde_json::from_str::<Utf16String>("\"\\udc00A\\ud800\"")
                .unwrap()
                .as_utf16(),
            &[0xdc00, 65, 0xd800]
        );
        assert!(serde_json::from_str::<Utf16String>("[65]").is_err());
        assert!(Utf16String::from("😀") < Utf16String::from("\u{e000}"));
    }
}

/// API key display prefixes retain their existing public type name.
pub type ApiKeyStart = Utf16String;

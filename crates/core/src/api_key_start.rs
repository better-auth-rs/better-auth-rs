//! API key display prefixes retain JavaScript UTF-16 substring boundaries.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// An API key prefix that can end with an unpaired UTF-16 surrogate.
/// JSON serialization preserves every code unit. UTF-8 conversion is fallible.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct ApiKeyStart(Vec<u16>);

impl ApiKeyStart {
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

impl From<&str> for ApiKeyStart {
    fn from(value: &str) -> Self {
        Self(value.encode_utf16().collect())
    }
}

impl From<String> for ApiKeyStart {
    fn from(value: String) -> Self {
        Self::from(value.as_str())
    }
}

impl Serialize for ApiKeyStart {
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

impl<'de> Deserialize<'de> for ApiKeyStart {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl de::Visitor<'_> for Visitor {
            type Value = ApiKeyStart;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an API key prefix encoded as a JSON string")
            }

            fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
                ApiKeyStart::from_wtf8(value).map_err(E::custom)
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(ApiKeyStart::from(value))
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
        let start = ApiKeyStart::prefix("😀abcdefgh", 1);
        assert_eq!(start.as_utf16(), &[0xd83d]);
        assert!(start.to_utf8().is_err());
        assert_eq!(start.to_wtf8(), [0xed, 0xa0, 0xbd]);
        let json = serde_json::to_string(&start).unwrap();
        assert_eq!(json, "\"\\ud83d\"");
        assert_eq!(serde_json::from_str::<ApiKeyStart>(&json).unwrap(), start);
        assert_eq!(
            ApiKeyStart::prefix("😀abcdefgh", 2).to_utf8().unwrap(),
            "😀"
        );
        assert_eq!(
            ApiKeyStart::prefix("😀abcdefgh", 6).to_utf8().unwrap(),
            "😀abcd"
        );
        assert_eq!(
            serde_json::from_str::<ApiKeyStart>("\"\\udc00A\\ud800\"")
                .unwrap()
                .as_utf16(),
            &[0xdc00, 65, 0xd800]
        );
        assert!(serde_json::from_str::<ApiKeyStart>("[65]").is_err());
        assert!(ApiKeyStart::from("😀") < ApiKeyStart::from("\u{e000}"));
    }
}

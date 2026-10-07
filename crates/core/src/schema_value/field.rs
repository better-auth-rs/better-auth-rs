use crate::{FieldDate, FieldValue, types::InvitationStatus};
use std::borrow::Cow;

/// Convert a schema's default Rust type without crossing a JSON boundary.
pub trait SchemaField: Clone {
    /// Return the original field value when the Rust type does not match.
    fn from_field(value: FieldValue) -> Result<Self, FieldValue>;

    /// Move this Rust value into an adapter field while retaining object handles.
    fn into_field(self) -> FieldValue;
}

impl SchemaField for FieldValue {
    fn from_field(value: FieldValue) -> Result<Self, FieldValue> {
        Ok(value)
    }

    fn into_field(self) -> FieldValue {
        self
    }
}

macro_rules! field {
    ($type:ty, $variant:ident) => {
        impl SchemaField for $type {
            fn from_field(value: FieldValue) -> Result<Self, FieldValue> {
                match value {
                    FieldValue::$variant(value) => Ok(value),
                    value => Err(value),
                }
            }

            fn into_field(self) -> FieldValue {
                FieldValue::$variant(self)
            }
        }
    };
}

field!(String, String);
field!(bool, Bool);
field!(f64, Number);
field!(FieldDate, Date);

impl SchemaField for crate::Utf16String {
    fn from_field(value: FieldValue) -> Result<Self, FieldValue> {
        match value {
            FieldValue::String(value) => Ok(value.into()),
            FieldValue::Utf16String(value) => Ok(value),
            value => Err(value),
        }
    }

    fn into_field(self) -> FieldValue {
        self.into()
    }
}

macro_rules! integer {
    ($($type:ty),+ $(,)?) => {$(
        impl SchemaField for $type {
            fn from_field(value: FieldValue) -> Result<Self, FieldValue> {
                match value {
                    FieldValue::Number(number)
                        if number.fract() == 0.0
                            && number >= <$type>::MIN as f64
                            && number < (<$type>::MAX as f64 + 1.0) => Ok(number as Self),
                    value => Err(value),
                }
            }

            fn into_field(self) -> FieldValue {
                FieldValue::Number(self as f64)
            }
        }

        impl From<$type> for FieldValue {
            fn from(value: $type) -> Self {
                FieldValue::Number(value as f64)
            }
        }
    )+};
}

integer!(i8, i16, i32, i64, isize, u8, u16, u32, u64, usize);

impl<T: SchemaField> SchemaField for Option<T> {
    fn from_field(value: FieldValue) -> Result<Self, FieldValue> {
        match value {
            FieldValue::Null | FieldValue::Undefined => Ok(None),
            value => T::from_field(value).map(Some),
        }
    }

    fn into_field(self) -> FieldValue {
        self.map_or(FieldValue::Null, SchemaField::into_field)
    }
}

impl<T: SchemaField> SchemaField for Vec<T> {
    fn from_field(value: FieldValue) -> Result<Self, FieldValue> {
        let FieldValue::Array(values) = &value else {
            return Err(value);
        };
        values
            .iter()
            .cloned()
            .map(T::from_field)
            .collect::<Result<_, _>>()
            .map_err(|_| value)
    }

    fn into_field(self) -> FieldValue {
        self.into_iter()
            .map(SchemaField::into_field)
            .collect::<Vec<_>>()
            .into()
    }
}

impl SchemaField for Cow<'_, str> {
    fn from_field(value: FieldValue) -> Result<Self, FieldValue> {
        String::from_field(value).map(Cow::Owned)
    }

    fn into_field(self) -> FieldValue {
        self.into_owned().into()
    }
}

impl SchemaField for InvitationStatus {
    fn from_field(value: FieldValue) -> Result<Self, FieldValue> {
        match value.as_str() {
            Some("pending") => Ok(Self::Pending),
            Some("accepted") => Ok(Self::Accepted),
            Some("rejected") => Ok(Self::Rejected),
            Some("canceled") => Ok(Self::Canceled),
            _ => Err(value),
        }
    }

    fn into_field(self) -> FieldValue {
        self.to_string().into()
    }
}

impl<T: SchemaField> SchemaField for &T {
    fn from_field(value: FieldValue) -> Result<Self, FieldValue> {
        Err(value)
    }

    fn into_field(self) -> FieldValue {
        (*self).clone().into_field()
    }
}

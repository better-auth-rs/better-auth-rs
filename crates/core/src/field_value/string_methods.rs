use super::{FieldArray, FieldValue};
use crate::{AuthError, AuthResult, Utf16String, query::field_number};

impl FieldValue {
    /// Read the first `N` values from an intrinsic Array or String iterator.
    /// Missing values become undefined. Symbol-based iterator overrides are not represented.
    pub fn destructure<const N: usize>(&self, expression: &str) -> AuthResult<[Self; N]> {
        let mut values = std::array::from_fn(|_| Self::Undefined);
        match self {
            Self::Array(array) => {
                for (index, output) in values.iter_mut().enumerate() {
                    if index >= array.len()? {
                        break;
                    }
                    *output = array.get(index)?.unwrap_or(Self::Undefined);
                }
            }
            Self::String(_) | Self::Utf16String(_) => {
                let text = self.display_utf16()?;
                for (output, unit) in values
                    .iter_mut()
                    .zip(char::decode_utf16(text.as_utf16().iter().copied()))
                {
                    *output = match unit {
                        Ok(character) => character.to_string().into(),
                        Err(error) => {
                            Utf16String::from_units(vec![error.unpaired_surrogate()]).into()
                        }
                    };
                }
            }
            Self::Object(_) => return Err(AuthError::type_error("{} is not iterable")),
            _ => {
                return Err(AuthError::type_error(format!(
                    "{expression} is not iterable"
                )));
            }
        }
        Ok(values)
    }

    /// Invoke `lastIndexOf(search)` on a string, array, or custom native receiver.
    pub fn last_index_of_method(&self, search: &Self, expression: &str) -> AuthResult<Self> {
        match (self, self.method_property("lastIndexOf")?) {
            (_, Some(Self::Function(method))) => {
                method.call_with(self, std::slice::from_ref(search))
            }
            (Self::String(_) | Self::Utf16String(_), None) => {
                let text = self.display_utf16()?;
                let search = search.display_utf16()?;
                let found = if search.as_utf16().is_empty() {
                    Some(text.as_utf16().len())
                } else {
                    text.as_utf16()
                        .windows(search.as_utf16().len())
                        .rposition(|part| part == search.as_utf16())
                };
                Ok(found.map_or(-1.0, |index| index as f64).into())
            }
            (Self::Array(array), None) => {
                for index in (0..array.len()?).rev() {
                    if array
                        .get(index)?
                        .is_some_and(|value| value.strict_equals(search))
                    {
                        return Ok((index as f64).into());
                    }
                }
                Ok((-1.0).into())
            }
            _ => Err(AuthError::type_error(format!(
                "{expression}.lastIndexOf is not a function"
            ))),
        }
    }

    /// Invoke `slice(start, end)` while retaining custom results and sparse array entries.
    pub fn slice_method(
        &self,
        start: &Self,
        end: Option<&Self>,
        expression: &str,
    ) -> AuthResult<Self> {
        self.slice_method_with(|| Ok((start.clone(), end.cloned())), expression)
    }

    /// Read `slice` before evaluating its arguments and retain the resolved method for the call.
    pub fn slice_method_with(
        &self,
        arguments: impl FnOnce() -> AuthResult<(Self, Option<Self>)>,
        expression: &str,
    ) -> AuthResult<Self> {
        let method = self.method_property("slice")?;
        let (start, end) = arguments()?;
        match (self, method) {
            (_, Some(Self::Function(method))) => {
                let mut arguments = vec![start];
                arguments.extend(end);
                method.call_with(self, &arguments)
            }
            (Self::String(_) | Self::Utf16String(_), None) => {
                let text = self.display_utf16()?;
                let (start, end) = slice_bounds(text.as_utf16().len(), &start, end.as_ref())?;
                Ok(Utf16String::from_units(
                    text.as_utf16()
                        .iter()
                        .skip(start)
                        .take(end - start)
                        .copied()
                        .collect(),
                )
                .into())
            }
            (Self::Array(array), None) => {
                let (start, end) = slice_bounds(array.len()?, &start, end.as_ref())?;
                let result = FieldArray::new();
                result.set_length(end - start)?;
                for (output, input) in (start..end).enumerate() {
                    if let Some(value) = array.get(input)? {
                        result.set(output, value)?;
                    }
                }
                Ok(result.into())
            }
            _ => Err(AuthError::type_error(format!(
                "{expression}.slice is not a function"
            ))),
        }
    }

    /// Invoke `split(separator)` without narrowing a custom method's return value.
    /// `call_source` supplies the source expression without converting the separator for diagnostics.
    pub fn split_method(
        &self,
        separator: &Self,
        expression: &str,
        call_source: &str,
    ) -> AuthResult<Self> {
        match (self, self.method_property("split")?) {
            (_, Some(Self::Function(method))) => {
                method.call_with(self, std::slice::from_ref(separator))
            }
            (Self::String(_) | Self::Utf16String(_), None) => {
                let text = self.display_utf16()?;
                if separator.is_undefined() {
                    return Ok(vec![self.clone()].into());
                }
                let separator = separator.display_utf16()?;
                let units = text.as_utf16();
                if separator.as_utf16().is_empty() {
                    return Ok(units
                        .iter()
                        .map(|unit| Utf16String::from_units(vec![*unit]).into())
                        .collect::<Vec<Self>>()
                        .into());
                }
                let mut parts = Vec::new();
                let mut start = 0;
                while let Some(relative) = units.get(start..).and_then(|remaining| {
                    remaining
                        .windows(separator.as_utf16().len())
                        .position(|part| part == separator.as_utf16())
                }) {
                    let end = start + relative;
                    parts.push(
                        Utf16String::from_units(
                            units
                                .iter()
                                .skip(start)
                                .take(end - start)
                                .copied()
                                .collect(),
                        )
                        .into(),
                    );
                    start = end + separator.as_utf16().len();
                }
                parts.push(
                    Utf16String::from_units(units.iter().skip(start).copied().collect()).into(),
                );
                Ok(Self::from(parts))
            }
            (_, method) => Err(method
                .unwrap_or_default()
                .not_callable(&format!("{expression}.split"), call_source)),
        }
    }
}

fn slice_bounds(
    length: usize,
    start: &FieldValue,
    end: Option<&FieldValue>,
) -> AuthResult<(usize, usize)> {
    let position = |value: &FieldValue| -> AuthResult<usize> {
        let value = field_number(value)?;
        let value = if value.is_nan() { 0.0 } else { value.trunc() };
        Ok(if value < 0.0 {
            (length as f64 + value).max(0.0)
        } else {
            value.min(length as f64)
        } as usize)
    };
    let start = position(start)?;
    let end = match end {
        Some(value) if !value.is_undefined() => position(value)?,
        _ => length,
    };
    Ok((start, end.max(start)))
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Native method tests assert sparse entries, UTF-16 iteration, and callback identity."
)]
mod tests {
    use super::*;
    use crate::{FieldFunction, FieldMap};

    #[test]
    fn slice_resolves_method_before_arguments_and_preserves_error_order() -> AuthResult<()> {
        let input: FieldValue = FieldMap::from([(
            "slice".into(),
            FieldFunction::contextual(|receiver, arguments| {
                assert!(receiver.model_property("slice")?.is_null());
                Ok(arguments.to_vec().into())
            })
            .into(),
        )])
        .into();
        let sliced = input.slice_method_with(
            || {
                input.set_model_property("slice", FieldValue::Null)?;
                Ok((1.into(), Some(3.into())))
            },
            "input",
        )?;
        assert_eq!(sliced, vec![1.into(), 3.into()].into());

        let original: FieldValue = FieldMap::from([("original".into(), true.into())]).into();
        let failed_arguments =
            input.slice_method_with(|| Err(AuthError::from_thrown(original.clone())), "input");
        assert!(matches!(failed_arguments,
            Err(error) if error.raw_value().is_some_and(|value| value.strict_equals(&original))));

        let mut evaluated = false;
        let failed_lookup = FieldValue::Null.slice_method_with(
            || {
                evaluated = true;
                Ok((0.into(), None))
            },
            "input",
        );
        assert!(matches!(failed_lookup, Err(AuthError::TypeError(_))));
        assert!(!evaluated);
        Ok(())
    }

    #[test]
    fn methods_preserve_utf16_holes_and_custom_results() -> AuthResult<()> {
        let text: FieldValue = Utf16String::from_units(vec![0xd800, 58, 0xdc00, 58, 51]).into();
        assert_eq!(text.last_index_of_method(&":".into(), "input")?, 3.into());
        assert_eq!(
            text.slice_method(&1.into(), Some(&(-1).into()), "input")?,
            Utf16String::from_units(vec![58, 0xdc00, 58]).into()
        );
        assert_eq!(
            text.split_method(&":".into(), "input", "input.split(\":\")")?
                .model_property("0")?,
            Utf16String::from_units(vec![0xd800]).into()
        );
        let array = FieldArray::with_length(3);
        array.set(1, FieldValue::Undefined)?;
        let input: FieldValue = array.into();
        assert_eq!(
            input.last_index_of_method(&FieldValue::Undefined, "input")?,
            1.into()
        );
        let sliced = input.slice_method(&0.into(), None, "input")?;
        assert!(!sliced.has_property("0")?);
        assert!(sliced.has_property("1")?);
        assert_eq!(
            input.destructure::<4>("input")?,
            std::array::from_fn(|_| FieldValue::Undefined)
        );
        assert_eq!(
            FieldValue::from("😀x").destructure::<3>("input")?,
            ["😀".into(), "x".into(), FieldValue::Undefined]
        );
        assert!(matches!(
            FieldValue::from(FieldMap::from([
                ("0".into(), "x".into()),
                ("length".into(), 1.into())
            ]))
            .destructure::<2>("input"),
            Err(AuthError::TypeError(message)) if message == "{} is not iterable"
        ));
        let result: FieldValue = FieldMap::new().into();
        for name in ["lastIndexOf", "slice", "split"] {
            let returned = result.clone();
            let input: FieldValue = FieldMap::from([(
                name.into(),
                FieldFunction::contextual(move |receiver, arguments| {
                    assert!(!receiver.is_undefined());
                    assert_eq!(arguments.len(), 1);
                    Ok(returned.clone())
                })
                .into(),
            )])
            .into();
            let actual = match name {
                "lastIndexOf" => input.last_index_of_method(&":".into(), "input")?,
                "slice" => input.slice_method(&0.into(), None, "input")?,
                _ => input.split_method(&":".into(), "input", "input.split(\":\")")?,
            };
            assert!(actual.strict_equals(&result));
        }
        Ok(())
    }
}

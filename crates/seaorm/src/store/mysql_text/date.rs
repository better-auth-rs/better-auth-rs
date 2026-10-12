use super::{AuthResult, FieldValue, Utf16String, append, quoted};
use better_auth_core::query::{field_add, field_number};

fn pad(value: &FieldValue, prefixes: &[(f64, &str)]) -> AuthResult<Utf16String> {
    for (bound, prefix) in prefixes {
        if field_number(value)? < *bound {
            return field_add(&(*prefix).into(), value)?.display_utf16();
        }
    }
    field_add(&"".into(), value)?.display_utf16()
}

pub(super) fn format(value: &FieldValue, output: &mut Vec<u16>) -> AuthResult<()> {
    if matches!(value.date_getter_method("getTime", "date")?, FieldValue::Number(number) if number.is_nan())
    {
        append(output, "NULL");
        return Ok(());
    }

    let year = value.date_getter_method("getFullYear", "date")?;
    let month = field_add(&value.date_getter_method("getMonth", "date")?, &1.into())?;
    let day = value.date_getter_method("getDate", "date")?;
    let hour = value.date_getter_method("getHours", "date")?;
    let minute = value.date_getter_method("getMinutes", "date")?;
    let second = value.date_getter_method("getSeconds", "date")?;
    let millisecond = value.date_getter_method("getMilliseconds", "date")?;

    // Component methods run before padding; each comparison and concatenation can invoke coercion callbacks.
    let mut units = pad(&year, &[(10.0, "000"), (100.0, "00"), (1000.0, "0")])?
        .as_utf16()
        .to_vec();
    for (separator, component) in [
        (b'-', month),
        (b'-', day),
        (b' ', hour),
        (b':', minute),
        (b':', second),
    ] {
        units.push(u16::from(separator));
        units.extend_from_slice(pad(&component, &[(10.0, "0")])?.as_utf16());
    }
    units.push(u16::from(b'.'));
    units.extend_from_slice(pad(&millisecond, &[(10.0, "00"), (100.0, "0")])?.as_utf16());
    quoted(&Utf16String::from_units(units), output);
    Ok(())
}

#[cfg(test)]
mod tests;

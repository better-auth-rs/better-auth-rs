use crate::{AuthError, AuthResult, FieldDate, FieldMap, FieldValue, FromFieldMap};

#[cfg(test)]
mod tests;

pub(super) fn decode(value: Option<FieldValue>) -> AuthResult<Option<FieldValue>> {
    value
        .map(|value| crate::utils::json::safe_parse_field(&value))
        .transpose()
        .map(|value| value.filter(FieldValue::is_truthy))
}

pub(super) fn parse(value: Option<FieldValue>) -> AuthResult<Option<FieldValue>> {
    value
        .map(|value| match value {
            FieldValue::String(_) | FieldValue::Utf16String(_) => {
                crate::utils::json::parse_native_json(&value)
            }
            value => Ok(value),
        })
        .transpose()
        .map(|value| value.filter(FieldValue::is_truthy))
}

pub(super) fn object(value: &FieldValue) -> AuthResult<FieldMap> {
    value
        .as_object()
        .ok_or_else(|| AuthError::internal("Secondary storage record must be an object"))?
        .snapshot_fields()
}

pub(super) fn stringify(value: &FieldValue) -> AuthResult<String> {
    value
        .stringify()?
        .ok_or_else(|| AuthError::internal("Secondary storage record cannot be undefined"))
}

fn revive_dates(fields: &mut FieldMap) {
    for name in ["expiresAt", "createdAt", "updatedAt"] {
        if let Some(FieldValue::String(text)) = fields.get(name)
            && let Some(date) = crate::utils::json::parse_json_date(text)
        {
            let _ = fields.insert(name.into(), FieldDate::from(date).into());
        }
    }
}

fn convert_dates(fields: &mut FieldMap, dates: &[&str]) -> AuthResult<()> {
    for name in dates {
        let date = crate::query::field_date(fields.get(*name).unwrap_or(&FieldValue::Undefined))?;
        let _ = fields.insert((*name).into(), date.into());
    }
    Ok(())
}

pub(super) fn session(mut fields: FieldMap, dates: &[&str]) -> AuthResult<crate::SessionView> {
    convert_dates(&mut fields, dates)?;
    let mut session = crate::SessionView::from_field_values(fields)?;
    session.active = true;
    Ok(session)
}

pub(super) fn user(value: &FieldValue) -> AuthResult<crate::UserView> {
    let mut fields = object(value)?;
    convert_dates(&mut fields, &["createdAt", "updatedAt"])?;
    crate::UserView::from_field_values(fields)
}

pub(super) fn verification(value: &FieldValue) -> AuthResult<crate::VerificationView> {
    let mut fields = object(value)?;
    revive_dates(&mut fields);
    crate::VerificationView::from_fields(fields)
}

pub(super) fn session_envelope(session: FieldMap, user: Option<crate::UserView>) -> FieldValue {
    FieldMap::from([
        ("session".into(), session.into()),
        (
            "user".into(),
            user.map_or(FieldValue::Null, |user| FieldMap::from(user).into()),
        ),
    ])
    .into()
}

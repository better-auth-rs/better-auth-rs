use crate::{AuthError, AuthResult, FieldDate, FieldMap, FieldValue, FromFieldMap};

#[cfg(test)]
mod tests;

pub(super) fn decode(value: Option<FieldValue>) -> Option<FieldValue> {
    value
        .map(|value| crate::utils::json::safe_parse_field(&value))
        .filter(FieldValue::is_truthy)
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
        .cloned()
        .ok_or_else(|| AuthError::internal("Secondary storage record must be an object"))
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

pub(super) fn session(mut fields: FieldMap) -> AuthResult<crate::SessionView> {
    revive_dates(&mut fields);
    let mut session = crate::SessionView::from_field_values(fields)?;
    session.active = true;
    Ok(session)
}

pub(super) fn user(value: &FieldValue) -> AuthResult<crate::UserView> {
    let mut fields = object(value)?;
    for name in ["createdAt", "updatedAt", "banExpires"] {
        if let Some(FieldValue::String(text)) = fields.get(name) {
            let date = crate::utils::date::parse_date_constructor(text)
                .ok_or_else(|| AuthError::internal(format!("Invalid user date field `{name}`")))?;
            let _ = fields.insert(name.into(), date.into());
        }
    }
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

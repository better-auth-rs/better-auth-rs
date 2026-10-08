use super::{AuthError, AuthResult, AuthSchema, FieldValue, SecondaryStore, Utc};
use crate::utils::json::safe_parse_field;

fn property<'a>(value: &'a FieldValue, name: &str) -> AuthResult<&'a FieldValue> {
    if value.is_null() || value.is_undefined() {
        return Err(AuthError::internal(format!(
            "Cannot read properties of {} (reading '{name}')",
            if value.is_null() { "null" } else { "undefined" }
        )));
    }
    Ok(value
        .as_object()
        .and_then(|fields| fields.get(name))
        .unwrap_or(&FieldValue::Undefined))
}

impl<S: AuthSchema> SecondaryStore<S> {
    pub(super) async fn delete_runtime_session(&self, token: &FieldValue) -> AuthResult<()> {
        let Some(storage) = &self.storage else {
            return self.inner.delete_session_by_token_value(token).await;
        };
        if let Some(cached) = storage
            .get_native(token)
            .await?
            .filter(FieldValue::is_truthy)
        {
            let cached = safe_parse_field(&cached);
            let session = cached
                .as_object()
                .and_then(|fields| fields.get("session"))
                .unwrap_or(&FieldValue::Undefined);
            if !session.is_truthy() {
                crate::observability::logger::current()
                    .error("Session not found in secondary storage", &[]);
                return Ok(());
            }
            let user_id = property(session, "userId")?.display_utf16()?;
            let mut units: Vec<_> = "active-sessions-".encode_utf16().collect();
            units.extend_from_slice(user_id.as_utf16());
            let key = FieldValue::from(crate::Utf16String::from_units(units));
            if let Some(current) = storage
                .get_native(&key)
                .await?
                .filter(FieldValue::is_truthy)
            {
                let current = safe_parse_field(&current);
                let list = if current.is_truthy() {
                    current
                        .as_array()
                        .ok_or_else(|| AuthError::internal("list.filter is not a function"))?
                } else {
                    &[]
                };
                let now = Utc::now();
                let mut filtered = Vec::new();
                for session in list {
                    let expires_at = crate::query::field_number(property(session, "expiresAt")?)?;
                    if expires_at > now.timestamp_millis() as f64
                        && !property(session, "token")?.strict_equals(token)
                    {
                        filtered.push((session.clone(), expires_at));
                    }
                }
                // The filter excludes NaN; retained values have stable numeric conversions during sorting.
                filtered.sort_by(|(_, left), (_, right)| left.total_cmp(right));
                let furthest = filtered
                    .last()
                    .map(|(session, _)| property(session, "expiresAt"))
                    .transpose()?
                    .unwrap_or(&FieldValue::Undefined);
                if !filtered.is_empty()
                    && furthest.is_truthy()
                    && crate::query::field_number(furthest)? > Utc::now().timestamp_millis() as f64
                {
                    let furthest = furthest.clone();
                    let value = FieldValue::from(
                        filtered
                            .into_iter()
                            .map(|(session, _)| session)
                            .collect::<Vec<_>>(),
                    );
                    let value = value.stringify()?.ok_or_else(|| {
                        AuthError::internal("Session reference array cannot be undefined")
                    })?;
                    let ttl = crate::SchemaValue::<crate::FieldDate>::from_field(furthest)
                        .cache_ttl(now)?;
                    storage.set_native(&key, &value, Some(ttl)).await?;
                } else {
                    storage.delete_native(&key).await?;
                }
            } else {
                crate::observability::logger::current()
                    .error("Active sessions list not found in secondary storage", &[]);
            }
        }
        storage.delete_native(token).await?;
        if !self.database_sessions() {
            return Ok(());
        }
        if self.config.session.preserve_session_in_database() {
            self.inner.end_session_by_token_value(token).await
        } else {
            self.inner.delete_session_by_token_value(token).await
        }
    }
}

#[cfg(test)]
mod tests;

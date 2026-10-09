use super::rows::Rows;
use super::*;
use crate::user_fields::UserConfig;

pub(super) fn value(fields: &FieldMap, schema: &UserConfig, name: &str) -> Value {
    fields
        .get(schema.record_storage_key(name))
        .cloned()
        .unwrap_or_default()
}

pub(super) fn id(fields: &FieldMap) -> crate::SchemaValue<String> {
    crate::SchemaValue::from_field(fields.get("id").cloned().unwrap_or_default())
}

pub(super) fn view<T: FromFieldMap>(fields: &FieldMap, schema: &UserConfig) -> AuthResult<T> {
    let mut logical: FieldMap = schema
        .fields()
        .keys()
        .map(|name| (name.clone(), value(fields, schema, name)))
        .collect();
    if let Some(id) = fields.get("id") {
        let _ = logical.insert("id".into(), id.clone());
    }
    T::from_field_values(logical)
}

/// Organization tables store physical fields. Typed values are read-only business views.
pub(super) trait OrganizationRows {
    fn get<Q: ?Sized>(&self, id: &Q) -> AuthResult<Option<FieldMap>>
    where
        crate::SchemaValue<String>: PartialEq<Q>;

    fn get_mut<Q: ?Sized>(&self, id: &Q) -> AuthResult<Option<MutexGuard<'_, FieldMap>>>
    where
        crate::SchemaValue<String>: PartialEq<Q>;

    fn replace<Q: ?Sized>(&mut self, id: &Q, fields: FieldMap) -> AuthResult<bool>
    where
        crate::SchemaValue<String>: PartialEq<Q>;

    fn remove<Q: ?Sized>(&mut self, id: &Q) -> AuthResult<Option<FieldMap>>
    where
        crate::SchemaValue<String>: PartialEq<Q>;
}

impl OrganizationRows for Rows<FieldMap> {
    fn get<Q: ?Sized>(&self, id: &Q) -> AuthResult<Option<FieldMap>>
    where
        crate::SchemaValue<String>: PartialEq<Q>,
    {
        self.find(|row| self::id(row) == *id)
    }

    fn get_mut<Q: ?Sized>(&self, id: &Q) -> AuthResult<Option<MutexGuard<'_, FieldMap>>>
    where
        crate::SchemaValue<String>: PartialEq<Q>,
    {
        self.find_mut(|row| self::id(row) == *id)
    }

    fn replace<Q: ?Sized>(&mut self, id: &Q, fields: FieldMap) -> AuthResult<bool>
    where
        crate::SchemaValue<String>: PartialEq<Q>,
    {
        if let Some(mut row) = OrganizationRows::get_mut(self, id)? {
            *row = fields;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn remove<Q: ?Sized>(&mut self, id: &Q) -> AuthResult<Option<FieldMap>>
    where
        crate::SchemaValue<String>: PartialEq<Q>,
    {
        self.remove_first(|row| self::id(row) == *id)
    }
}

use super::MemberUserView;
use crate::{AuthRecordFields, AuthResult, FieldMap, FromFieldMap, SchemaValue};

impl AuthRecordFields for MemberUserView {
    fn field_values(&self) -> AuthResult<FieldMap> {
        Ok([
            ("id".into(), self.id.field_value()),
            ("name".into(), self.name.field_value()),
            ("email".into(), self.email.field_value()),
            ("image".into(), self.image.field_value()),
        ]
        .into())
    }

    fn structured_clone(&self, context: &mut crate::StructuredCloneContext) -> AuthResult<Self> {
        let mut user = self.clone();
        user.id = context.clone_field(&self.id)?;
        user.email = context.clone_field(&self.email)?;
        user.name = context.clone_field(&self.name)?;
        user.image = context.clone_field(&self.image)?;
        Ok(user)
    }
}

impl FromFieldMap for MemberUserView {
    fn from_field_values(mut fields: FieldMap) -> AuthResult<Self> {
        Ok(Self {
            id: SchemaValue::from_field(fields.remove("id").unwrap_or_default()),
            email: SchemaValue::from_field(fields.remove("email").unwrap_or_default()),
            name: SchemaValue::from_field(fields.remove("name").unwrap_or_default()),
            image: SchemaValue::from_field(fields.remove("image").unwrap_or_default()),
        })
    }
}

impl serde::Serialize for MemberUserView {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        crate::field_value::serde::map::serialize(
            &self.field_values().map_err(serde::ser::Error::custom)?,
            serializer,
        )
    }
}

impl<'de> serde::Deserialize<'de> for MemberUserView {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::from_field_values(crate::field_value::serde::map::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}

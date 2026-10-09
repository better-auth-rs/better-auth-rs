use super::{BasicMemberResponse, CreateOrganizationResponse, CreatedOrganizationResponse};
use better_auth_core::{AuthRecordFields, AuthResult, FieldMap, FieldValue};
use serde::Serialize;

macro_rules! record {
    ($record:ty, [$($field:ident => $name:literal),* $(,)?]) => {
        impl AuthRecordFields for $record {
            fn field_values(&self) -> AuthResult<FieldMap> {
                let mut fields = FieldMap::from_iter([
                    $(($name.into(), self.$field.field_value())),*
                ]);
                fields.extend(self.additional_fields.clone());
                Ok(fields)
            }
        }
    };
}

record!(CreatedOrganizationResponse, [
    id => "id",
    name => "name",
    slug => "slug",
    logo => "logo",
    metadata => "metadata",
    created_at => "createdAt",
]);

record!(BasicMemberResponse, [
    id => "id",
    organization_id => "organizationId",
    user_id => "userId",
    role => "role",
    created_at => "createdAt",
]);

impl<O: Serialize + AuthRecordFields, M: Serialize + AuthRecordFields> AuthRecordFields
    for CreateOrganizationResponse<O, M>
{
    fn field_values(&self) -> AuthResult<FieldMap> {
        let mut fields = self.organization.field_values()?;
        let members = self
            .members
            .iter()
            .map(|member| member.field_values().map(FieldValue::from))
            .collect::<AuthResult<Vec<_>>>()?;
        let _ = fields.insert("members".into(), members.into());
        Ok(fields)
    }
}

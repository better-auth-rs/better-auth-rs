use super::{
    AcceptInvitationResponse, BasicMemberResponse, CreateOrganizationResponse,
    CreatedOrganizationResponse, GetInvitationResponse, UserInvitationResponse,
};
use better_auth_core::wire::InvitationView;
use better_auth_core::{AuthRecordFields, AuthResult, FieldMap, FieldValue};
use serde::Serialize;

macro_rules! record {
    ($record:ty, [$($field:ident => $name:literal),* $(,)?] $(; order: $order:ident)?) => {
        impl AuthRecordFields for $record {
            fn field_values(&self) -> AuthResult<FieldMap> {
                let mut fields = FieldMap::from_iter([
                    $(($name.into(), self.$field.field_value())),*
                ]);
                $(fields.retain(|name, value| !value.is_undefined() || self.$order.contains(name));)?
                fields.extend(self.additional_fields.clone());
                $(let fields = fields.in_field_order(&self.$order);)?
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
]; order: field_order);

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

impl<I: Serialize + AuthRecordFields> AuthRecordFields for GetInvitationResponse<I> {
    fn field_values(&self) -> AuthResult<FieldMap> {
        let mut fields = self.invitation.field_values()?;
        let _ = fields.insert(
            "organizationName".into(),
            self.organization_name.field_value(),
        );
        let _ = fields.insert(
            "organizationSlug".into(),
            self.organization_slug.field_value(),
        );
        let _ = fields.insert("inviterEmail".into(), self.inviter_email.field_value());
        Ok(fields)
    }
}

impl<I: Serialize + AuthRecordFields> AuthRecordFields for UserInvitationResponse<I> {
    fn field_values(&self) -> AuthResult<FieldMap> {
        let mut fields = self.invitation.field_values()?;
        let _ = fields.insert(
            "organizationName".into(),
            self.organization_name.field_value(),
        );
        Ok(fields)
    }
}

impl AuthRecordFields for AcceptInvitationResponse<InvitationView, BasicMemberResponse> {
    fn field_values(&self) -> AuthResult<FieldMap> {
        Ok([
            ("invitation".into(), self.invitation.field_values()?.into()),
            ("member".into(), self.member.field_values()?.into()),
        ]
        .into())
    }
}

impl AuthRecordFields for AcceptInvitationResponse<InvitationView, Option<BasicMemberResponse>> {
    fn field_values(&self) -> AuthResult<FieldMap> {
        let member = self
            .member
            .as_ref()
            .map(AuthRecordFields::field_values)
            .transpose()?;
        Ok([
            ("invitation".into(), self.invitation.field_values()?.into()),
            (
                "member".into(),
                member.map(FieldValue::from).unwrap_or(FieldValue::Null),
            ),
        ]
        .into())
    }
}

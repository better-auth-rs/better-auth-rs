use super::*;
use crate::plugins::organization::request::{from_fields, object, take};
use better_auth_core::{AuthResult, FieldMap, FieldValue, FromFieldMap};

impl SchemaField for NullableStringField {
    fn from_field(value: FieldValue) -> Result<Self, FieldValue> {
        match value {
            FieldValue::Undefined => Ok(Self::Missing),
            FieldValue::Null => Ok(Self::Null),
            FieldValue::String(value) => Ok(Self::Value(value)),
            value => Err(value),
        }
    }

    fn into_field(self) -> FieldValue {
        match self {
            Self::Missing => FieldValue::Undefined,
            Self::Null => FieldValue::Null,
            Self::Value(value) => value.into(),
        }
    }
}

from_fields!(CreateOrganizationRequest {
    name: "name", slug: "slug", logo: "logo", metadata: "metadata",
    user_id: "userId", keep_current_active_organization: "keepCurrentActiveOrganization",
}; additional_fields);
from_fields!(InviteMemberRequest {
    email: "email", role: "role", organization_id: "organizationId", team_id: "teamId", resend: "resend",
}; additional_fields);
from_fields!(DeleteOrganizationRequest {
    organization_id: "organizationId"
});
from_fields!(LeaveOrganizationRequest {
    organization_id: "organizationId"
});
from_fields!(CheckSlugRequest { slug: "slug" });
from_fields!(SetActiveOrganizationRequest {
    organization_id: "organizationId",
    organization_slug: "organizationSlug",
});
from_fields!(RemoveMemberRequest {
    member_id_or_email: "memberIdOrEmail",
    organization_id: "organizationId",
});
from_fields!(UpdateMemberRoleRequest {
    member_id: "memberId",
    role: "role",
    organization_id: "organizationId",
});
from_fields!(AcceptInvitationRequest {
    invitation_id: "invitationId"
});
from_fields!(RejectInvitationRequest {
    invitation_id: "invitationId"
});
from_fields!(CancelInvitationRequest {
    invitation_id: "invitationId"
});

impl FromFieldMap for UpdateOrganizationData {
    fn from_field_values(mut fields: FieldMap) -> AuthResult<Self> {
        Ok(Self {
            name: take(&mut fields, "name")?,
            slug: take(&mut fields, "slug")?,
            logo: take(&mut fields, "logo")?,
            metadata: fields.remove("metadata"),
            additional_fields: fields,
        })
    }
}

impl FromFieldMap for UpdateOrganizationRequest {
    fn from_field_values(mut fields: FieldMap) -> AuthResult<Self> {
        Ok(Self {
            organization_id: take(&mut fields, "organizationId")?,
            data: UpdateOrganizationData::from_field_values(object(&mut fields, "data")?)?,
        })
    }
}

impl FromFieldMap for HasPermissionRequest {
    fn from_field_values(mut fields: FieldMap) -> AuthResult<Self> {
        let permissions = fields
            .remove("permissions")
            .map(|value| {
                let values = value.as_object().ok_or_else(|| {
                    better_auth_core::AuthError::internal("Validated permissions is not an object")
                })?;
                values
                    .iter()
                    .map(|(name, value)| Ok((name.clone(), value.decode()?)))
                    .collect::<AuthResult<HashMap<String, Vec<String>>>>()
            })
            .transpose()?;
        Ok(Self {
            permissions,
            organization_id: take(&mut fields, "organizationId")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_creation_retains_runtime_values_after_validation() -> AuthResult<()> {
        let shared: FieldValue = FieldMap::from([
            ("date".into(), better_auth_core::FieldDate::invalid().into()),
            ("number".into(), FieldValue::Number(f64::INFINITY)),
            ("missing".into(), FieldValue::Undefined),
        ])
        .into();
        let fields = FieldMap::from([
            ("name".into(), "example".into()),
            ("slug".into(), "example".into()),
            ("metadata".into(), shared.clone()),
            ("custom".into(), shared.clone()),
        ]);
        let body =
            crate::plugins::organization::request::typed::<CreateOrganizationRequest>(fields)?;
        let input = body.get::<CreateOrganizationRequest>().unwrap();
        assert!(input.metadata.field_value().strict_equals(&shared));
        assert!(input.additional_fields["custom"].strict_equals(&shared));
        let metadata = input.metadata.field_value();
        let fields = metadata.as_object().unwrap();
        assert!(fields["date"].as_date().unwrap().milliseconds().is_nan());
        assert_eq!(fields["number"].as_f64(), Some(f64::INFINITY));
        assert!(fields.contains_key("missing"));
        Ok(())
    }
}

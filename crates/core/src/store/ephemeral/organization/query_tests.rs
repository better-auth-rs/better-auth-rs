use super::*;
use crate::organization_fields::OrganizationFields;
use crate::user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform, UserFieldType};
use serde_json::json;

#[tokio::test]
async fn native_json_policies_transform_raw_text_without_reencoding_reads() -> AuthResult<()> {
    use crate::store::OrganizationRoleStore;
    let store = EphemeralStore::default();
    let replace =
        |from: &'static str, to: &'static str| -> crate::user_fields::UserFieldTransform {
            UserFieldTransform::new(move |value| {
                Ok(match value {
                    Value::String(value) => Value::from(value.replace(from, to)),
                    value => value,
                })
            })
        };
    let policy = UserFieldConfig {
        required: Some(false),
        transform: Some(FieldTransforms {
            input: Some(replace("source", "stored")),
            output: Some(replace("stored", "visible")),
        }),
        ..Default::default()
    };
    let mut fields = OrganizationFields::default();
    let _ = fields
        .organization
        .fields_mut()
        .insert("metadata".into(), policy.clone());
    let _ = fields
        .organization_role
        .fields_mut()
        .insert("permission".into(), policy);
    store.configure_organization_fields(fields)?;
    let organization = store
        .create_organization(
            CreateOrganization::new("Native", "native")
                .with_metadata(Value::from_json(json!({"source":1}))?),
        )
        .await?;
    assert_eq!(
        organization.metadata.json()?,
        Some(json!(r#"{"visible":1}"#))
    );
    assert_eq!(
        store
            .lock()
            .unwrap()
            .organizations
            .get(&organization.id)?
            .unwrap()
            .metadata
            .json()?,
        Some(json!(r#"{"stored":1}"#))
    );
    assert_eq!(
        store
            .get_organization_by_id(organization.id.typed().unwrap())
            .await?
            .unwrap()
            .metadata,
        organization.metadata
    );
    let updated = store
        .update_organization(
            organization.id.typed().unwrap(),
            UpdateOrganization {
                metadata: Some(Value::Null),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(updated.metadata.json()?, Some(json!("null")));
    let role = store
        .create_organization_role(crate::CreateOrganizationRole {
            organization_id: organization.id.typed().unwrap().clone(),
            role: "native".into(),
            permission: Value::from_json(json!({"ignored":["original"]}))?,
            additional_fields: [("permission".into(), Value::from(r#"{"source":["read"]}"#))]
                .into_iter()
                .collect(),
        })
        .await?;
    assert_eq!(
        role.permission.json()?,
        Some(json!(r#"{"visible":["read"]}"#))
    );
    assert_eq!(
        store
            .lock()
            .unwrap()
            .organization_roles
            .get(&role.id)?
            .unwrap()
            .permission
            .json()?,
        Some(json!(r#"{"stored":["read"]}"#))
    );
    assert_eq!(
        store
            .get_organization_role(role.id.typed().unwrap())
            .await?
            .unwrap()
            .permission,
        role.permission
    );
    Ok(())
}

#[tokio::test]
async fn member_queries_use_typed_storage_before_output_transforms() -> AuthResult<()> {
    let store = EphemeralStore::default();
    let mut fields = OrganizationFields::default();
    fields.member.additional_fields = Some(
        [
            (
                "label".into(),
                UserFieldConfig {
                    field_name: Some("stored_label".into()),
                    transform: Some(FieldTransforms {
                        input: Some(UserFieldTransform::new(|value| {
                            Ok(if value.is_undefined() {
                                value
                            } else {
                                Value::from(format!("{}:in", value.as_str().unwrap_or_default()))
                            })
                        })),
                        output: Some(UserFieldTransform::new(|value| {
                            Ok(if value.is_undefined() {
                                value
                            } else {
                                Value::from(format!("{}:out", value.as_str().unwrap_or_default()))
                            })
                        })),
                    }),
                    ..Default::default()
                },
            ),
            (
                "score".into(),
                UserFieldConfig {
                    field_type: UserFieldType::Number,
                    ..Default::default()
                },
            ),
            (
                "enabled".into(),
                UserFieldConfig {
                    field_type: UserFieldType::Boolean,
                    ..Default::default()
                },
            ),
        ]
        .into_iter()
        .collect(),
    );
    store.configure_organization_fields(fields)?;
    for (user, score, enabled) in [("first", 2, false), ("second", 10, true)] {
        let mut member = CreateMember::new("organization", user, "member");
        member.additional_fields = [
            ("label".into(), Value::from(user)),
            ("score".into(), Value::from(f64::from(score))),
            ("enabled".into(), Value::from(enabled)),
        ]
        .into_iter()
        .collect();
        let _ = store.create_member(member).await?;
    }
    let mut params = ListOrganizationMembersParams {
        organization_id: "organization".into(),
        filter_field: Some("label".into()),
        filter_value: Some("first:in".into()),
        ..Default::default()
    };
    let (members, total) = store.query_organization_members(&params).await?;
    assert_eq!(total, 1);
    assert_eq!(members[0].user_id, "first");
    assert_eq!(
        members[0].additional_fields["label"],
        Value::String("first:in:out".into())
    );
    params.filter_value = Some("first".into());
    assert_eq!(store.query_organization_members(&params).await?.1, 0);
    params.filter_field = Some("score".into());
    params.filter_value = Some(" 0x2 ".into());
    params.filter_operator = Some("gt".into());
    let (members, total) = store.query_organization_members(&params).await?;
    assert_eq!(total, 1);
    assert_eq!(members[0].user_id, "second");
    params.filter_operator = Some("contains".into());
    for filter in ["0xa", "1e1"] {
        params.filter_value = Some(filter.into());
        let (members, total) = store.query_organization_members(&params).await?;
        assert_eq!(total, 1);
        assert_eq!(members[0].user_id, "second");
    }
    params.filter_field = Some("enabled".into());
    params.filter_value = Some("false".into());
    params.filter_operator = Some("eq".into());
    let (members, total) = store.query_organization_members(&params).await?;
    assert_eq!(total, 1);
    assert_eq!(members[0].user_id, "first");
    params.filter_operator = Some("contains".into());
    params.filter_value = Some("not-true".into());
    let (members, total) = store.query_organization_members(&params).await?;
    assert_eq!(total, 1);
    assert_eq!(members[0].user_id, "first");
    params.filter_field = None;
    params.filter_value = None;
    params.sort_by = Some("score".into());
    params.sort_direction = Some("desc".into());
    params.limit = Some(1.0);
    let (members, total) = store.query_organization_members(&params).await?;
    assert_eq!(total, 2);
    assert_eq!(members[0].user_id, "second");
    Ok(())
}

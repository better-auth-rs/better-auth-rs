use super::*;
use better_auth_schema_registry::{EntityRole, core_fields};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Map, Value};

fn public_name(name: &str) -> String {
    let mut parts = name.split('_');
    let mut result = parts.next().unwrap_or_default().to_owned();
    for part in parts {
        let mut characters = part.chars();
        if let Some(first) = characters.next() {
            result.extend(first.to_uppercase());
            result.extend(characters);
        }
    }
    result
}

fn object(value: &impl Serialize) -> AuthResult<Map<String, Value>> {
    match serde_json::to_value(value)? {
        Value::Object(value) => Ok(value),
        _ => Err(AuthError::config(
            "Organization records must serialize as objects",
        )),
    }
}

fn decode_record<T: DeserializeOwned>(
    role: EntityRole,
    mut fields: Map<String, Value>,
) -> AuthResult<T> {
    if role == EntityRole::Organization {
        // Organization's custom deserializer requires the key; callers restore native JSON afterward.
        fields.entry("metadata".to_owned()).or_insert(Value::Null);
    }
    serde_json::from_value(Value::Object(fields)).map_err(Into::into)
}

impl MemoryStore {
    fn field_config(&self, role: EntityRole) -> AuthResult<crate::user_fields::UserConfig> {
        let fields = self.organization_fields();
        match role {
            EntityRole::Organization => Ok(fields.organization),
            EntityRole::Member => Ok(fields.member),
            EntityRole::Invitation => Ok(fields.invitation),
            EntityRole::Team => Ok(fields.team),
            EntityRole::OrganizationRole => Ok(fields.organization_role),
            _ => Err(AuthError::config("Expected an organization entity role")),
        }
    }

    pub(super) fn store_record<T: Serialize + DeserializeOwned>(
        &self,
        role: EntityRole,
        value: T,
        patch: Option<Map<String, Value>>,
        extras: Map<String, Value>,
    ) -> AuthResult<T> {
        let schema = self.field_config(role)?;
        let mut record = object(&value)?;
        let core_names: Vec<_> = core_fields(role)
            .iter()
            .map(|field| public_name(field.name))
            .collect();
        let create = patch.is_none();
        let mut core = patch.unwrap_or_else(|| {
            record
                .iter()
                .filter(|(name, _)| core_names.contains(name))
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect()
        });
        if create {
            record.retain(|name, _| core_names.contains(name));
            for name in ["logo", "updatedAt"] {
                if core.get(name) == Some(&Value::Null) {
                    let _ = core.remove(name);
                }
            }
            if role == EntityRole::Invitation {
                core.entry("teamId".to_owned()).or_insert(Value::Null);
            }
            for name in schema.additional_fields.keys().filter(|name| *name != "id") {
                let _ = record.remove(name);
            }
        }
        let mut stored = schema.organization_storage_fields(core, extras, create)?;
        for (name, field) in &schema.additional_fields {
            if name == "id" {
                continue;
            }
            let storage_name = field.field_name.as_ref().unwrap_or(name);
            if core_names.contains(name) {
                if let Some(value) = stored.remove(storage_name) {
                    let _ = record.insert(name.clone(), value);
                }
            } else if create {
                stored.entry(storage_name.clone()).or_insert(Value::Null);
            }
        }
        record.extend(stored);
        decode_record(role, record)
    }

    pub(super) fn output_record<T: Serialize + DeserializeOwned>(
        &self,
        role: EntityRole,
        value: T,
    ) -> AuthResult<T> {
        let schema = self.field_config(role)?;
        if schema.additional_fields.is_empty() {
            return Ok(value);
        }
        let raw = object(&value)?;
        let mut core: Map<_, _> = core_fields(role)
            .iter()
            .map(|field| public_name(field.name))
            .filter_map(|name| raw.get(&name).cloned().map(|value| (name, value)))
            .collect();
        if role == EntityRole::Invitation {
            core.entry("teamId".to_owned()).or_insert(Value::Null);
        }
        let mut storage = raw;
        for (name, field) in &schema.additional_fields {
            if let Some(value) = core.get(name) {
                let _ = storage.insert(
                    field.field_name.as_ref().unwrap_or(name).clone(),
                    value.clone(),
                );
            }
        }
        decode_record(role, schema.organization_output_fields(core, &storage)?)
    }
}

#[tokio::test]
async fn builtin_policies_transform_typed_records_once_and_preserve_adapter_id() {
    use crate::{
        CreateOrganizationRole, CreateTeam, UpdateTeam,
        organization_fields::OrganizationFields,
        store::{OrganizationRoleStore, TeamStore},
        user_fields::{UserConfig, UserFieldConfig, UserFieldType},
    };
    use serde_json::json;

    let policy = UserFieldConfig {
        input_transform: Some(Arc::new(|value| {
            Ok(value.map(|value| json!(format!("{}:in", value.as_str().unwrap()))))
        })),
        output_transform: Some(Arc::new(|value| {
            Ok(value.map(|value| json!(format!("{}:out", value.as_str().unwrap()))))
        })),
        ..Default::default()
    };
    let fields = |name: &str| UserConfig {
        additional_fields: [(name.into(), policy.clone())].into(),
    };
    let mut config = OrganizationFields {
        organization: fields("name"),
        member: fields("role"),
        invitation: fields("email"),
        team: fields("name"),
        organization_role: fields("role"),
    };
    let _ = config.organization.additional_fields.insert(
        "id".into(),
        UserFieldConfig {
            required: Some(false),
            field_name: Some("ignored_id".into()),
            default_value: Some(json!("ignored")),
            input_transform: Some(Arc::new(|_| {
                Err(AuthError::bad_request("id input must not run"))
            })),
            output_transform: Some(Arc::new(|_| {
                Err(AuthError::bad_request("id output must not run"))
            })),
            ..Default::default()
        },
    );
    let _ = config.organization.additional_fields.insert(
        "logo".into(),
        UserFieldConfig {
            required: Some(false),
            default_value: Some(json!("default-logo")),
            ..Default::default()
        },
    );
    let _ = config.invitation.additional_fields.insert(
        "teamId".into(),
        UserFieldConfig {
            required: Some(false),
            output_transform: Some(Arc::new(|value| {
                assert_eq!(value, Some(Value::Null));
                Ok(value)
            })),
            ..Default::default()
        },
    );
    for schema in [&mut config.team, &mut config.organization_role] {
        let _ = schema.additional_fields.insert(
            "updatedAt".into(),
            UserFieldConfig {
                required: Some(false),
                field_type: UserFieldType::Date,
                ..Default::default()
            },
        );
    }
    let store = MemoryStore::new(test_config());
    store.configure_organization_fields(config).unwrap();
    let mut create = CreateOrganization::new("original", "original");
    create.id = Some("chosen-id".into());
    create.metadata = Some(Value::Null);
    let organization = store.create_organization(create).await.unwrap();
    assert_eq!(organization.id, "chosen-id");
    assert_eq!(organization.name, "original:in:out");
    assert_eq!(organization.logo.as_deref(), Some("default-logo"));
    assert_eq!(organization.metadata, Some(Value::Null));
    assert!(organization.additional_fields.is_empty());
    assert_eq!(
        store.lock().organizations[&organization.id].name,
        "original:in"
    );
    let updated = store
        .update_organization(
            &organization.id,
            UpdateOrganization {
                name: Some("changed".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.name, "changed:in:out");
    assert_eq!(updated.metadata, Some(Value::Null));
    let updated = store
        .update_organization(
            &organization.id,
            UpdateOrganization {
                metadata: Some(json!({"literal":"value"})),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.metadata, Some(json!({"literal":"value"})));
    assert_eq!(
        store
            .get_organization_by_id(&organization.id)
            .await
            .unwrap()
            .unwrap()
            .metadata,
        Some(json!({"literal":"value"}))
    );

    let mut create = CreateOrganization::new("null-logo", "null-logo");
    let _ = create.additional_fields.insert("logo".into(), Value::Null);
    assert!(
        store
            .create_organization(create)
            .await
            .unwrap()
            .logo
            .is_none()
    );
    let member = store
        .create_member(CreateMember::new(&organization.id, "recipient", "member"))
        .await
        .unwrap();
    assert_eq!(member.role, "member:in:out");
    assert!(member.additional_fields.is_empty());
    let invitation = store
        .create_invitation(CreateInvitation::new(
            &organization.id,
            "target@example.com",
            "member",
            "owner",
            Utc::now() + chrono::Duration::days(1),
        ))
        .await
        .unwrap();
    assert_eq!(invitation.email, "target@example.com:in:out");
    assert!(invitation.additional_fields.is_empty());
    let team = store
        .create_team(CreateTeam {
            name: "team".into(),
            organization_id: organization.id.clone(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(team.name, "team:in:out");
    let team = store
        .update_team(
            &team.id,
            UpdateTeam {
                name: Some("updated".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(team.name, "updated:in:out");
    assert_eq!(team.updated_at, None);
    let role = store
        .create_organization_role(CreateOrganizationRole {
            additional_fields: Default::default(),
            organization_id: organization.id,
            role: "editor".into(),
            permission: json!({"member":["read"]}),
        })
        .await
        .unwrap();
    assert_eq!(role.role, "editor:in:out");
    assert_eq!(role.updated_at, None);
    assert!(role.additional_fields.is_empty());
}

#[tokio::test]
async fn invalid_builtin_transform_cannot_partially_update_a_memory_record() {
    use crate::{
        organization_fields::OrganizationFields,
        user_fields::{UserConfig, UserFieldConfig},
    };
    use serde_json::json;
    let store = MemoryStore::new(test_config());
    let organization = store
        .create_organization(CreateOrganization::new("original", "original"))
        .await
        .unwrap();
    store
        .configure_organization_fields(OrganizationFields {
            organization: UserConfig {
                additional_fields: [(
                    "name".into(),
                    UserFieldConfig {
                        input_transform: Some(Arc::new(|_| Ok(Some(json!(12))))),
                        ..Default::default()
                    },
                )]
                .into(),
            },
            ..Default::default()
        })
        .unwrap();
    assert!(
        store
            .update_organization(
                &organization.id,
                UpdateOrganization {
                    name: Some("changed".into()),
                    slug: Some("changed".into()),
                    ..Default::default()
                }
            )
            .await
            .is_err()
    );
    let state = store.lock();
    assert_eq!(state.organizations[&organization.id].name, "original");
    assert_eq!(state.organizations[&organization.id].slug, "original");
}

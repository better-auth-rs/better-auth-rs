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

pub(super) trait MemoryOrganizationRecord: Serialize + DeserializeOwned {
    fn preserve_schema_values(
        &mut self,
        fields: &crate::user_fields::UserConfig,
        raw: &Map<String, Value>,
    );
}

macro_rules! record_values {
    ($record:ty, dates [$($date:ident => $date_name:literal),*], json [$($json:ident => $json_name:literal),*]) => {
        impl MemoryOrganizationRecord for $record {
            fn preserve_schema_values(&mut self, fields: &crate::user_fields::UserConfig, raw: &Map<String, Value>) {
                $(if fields.additional_fields.get($date_name).is_some_and(|field| !matches!(field.field_type, crate::user_fields::UserFieldType::Date)) {
                    self.$date = raw.get($date_name).cloned().map(crate::SchemaValue::Dynamic).unwrap_or_default();
                })*
                $(if fields.additional_fields.contains_key($json_name) {
                    self.$json = raw.get($json_name).cloned().map(crate::SchemaValue::Dynamic).unwrap_or_default();
                })*
            }
        }
    };
}
record_values!(Organization, dates [created_at => "createdAt"], json [metadata => "metadata"]);
record_values!(Member, dates [created_at => "createdAt"], json []);
record_values!(Invitation, dates [created_at => "createdAt", expires_at => "expiresAt"], json []);
record_values!(crate::Team, dates [created_at => "createdAt", updated_at => "updatedAt"], json []);
record_values!(crate::OrganizationRole, dates [created_at => "createdAt", updated_at => "updatedAt"], json [permission => "permission"]);

fn decode_record<T: MemoryOrganizationRecord>(
    schema: &crate::user_fields::UserConfig,
    fields: Map<String, Value>,
) -> AuthResult<T> {
    let mut record: T = serde_json::from_value(Value::Object(fields.clone()))?;
    record.preserve_schema_values(schema, &fields);
    Ok(record)
}

#[tokio::test]
async fn memory_team_preserves_replaced_date_values_and_durable_capacity() {
    use crate::{
        CreateTeam,
        organization_fields::OrganizationFields,
        store::TeamStore,
        user_fields::{UserFieldConfig, UserFieldType},
    };
    use serde_json::json;
    let mut fields = OrganizationFields::default();
    let _ = fields.team.additional_fields.insert(
        "createdAt".into(),
        UserFieldConfig {
            input_transform: Some(Arc::new(|_| Ok(Some(json!("2000-01-02T03:04:05+02:00"))))),
            ..Default::default()
        },
    );
    let _ = fields.team.additional_fields.insert(
        "memberCount".into(),
        UserFieldConfig {
            field_type: UserFieldType::Number,
            default_value: Some(json!(17)),
            input_transform: Some(Arc::new(|value| {
                assert_eq!(value, Some(json!(0)));
                Ok(Some(json!(2)))
            })),
            ..Default::default()
        },
    );
    let store = EphemeralStore::new(test_config());
    store.configure_organization_fields(fields).unwrap();
    let team = store
        .create_team(CreateTeam {
            name: "Team".into(),
            organization_id: "org".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        team.created_at.json().unwrap(),
        Some(json!("2000-01-02T03:04:05+02:00"))
    );
    assert_eq!(
        store.list_organization_teams("org").await.unwrap()[0].created_at,
        team.created_at
    );
    assert_eq!(team.additional_fields["memberCount"], 2);
    assert!(
        store
            .add_team_member(&team.id, "user", Some(2))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .add_team_member(&team.id, "user", Some(3))
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        store
            .get_team(team.id.typed().unwrap())
            .await
            .unwrap()
            .unwrap()
            .additional_fields["memberCount"]
            .as_f64(),
        Some(3.0)
    );
    store
        .remove_team_member(team.id.typed().unwrap(), "user")
        .await
        .unwrap();
    assert_eq!(
        store
            .get_team(team.id.typed().unwrap())
            .await
            .unwrap()
            .unwrap()
            .additional_fields["memberCount"]
            .as_f64(),
        Some(2.0)
    );
}

impl EphemeralStore {
    fn field_config(&self, role: EntityRole) -> AuthResult<crate::user_fields::UserConfig> {
        let fields = self.organization_fields()?;
        match role {
            EntityRole::Organization => Ok(fields.organization),
            EntityRole::Member => Ok(fields.member),
            EntityRole::Invitation => Ok(fields.invitation),
            EntityRole::Team => Ok(fields.team),
            EntityRole::OrganizationRole => Ok(fields.organization_role),
            _ => Err(AuthError::config("Expected an organization entity role")),
        }
    }

    pub(super) fn store_record<T: MemoryOrganizationRecord>(
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
                let _ = core.entry("teamId".to_owned()).or_insert(Value::Null);
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
                } else if create {
                    let _ = record.insert(name.clone(), Value::Null);
                }
            } else if create {
                let _ = stored.entry(storage_name.clone()).or_insert(Value::Null);
            }
        }
        record.extend(stored);
        decode_record(&schema, record)
    }

    pub(super) fn output_record<T: MemoryOrganizationRecord>(
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
            let _ = core.entry("teamId".to_owned()).or_insert(Value::Null);
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
        decode_record(&schema, schema.organization_output_fields(core, &storage)?)
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
    let store = EphemeralStore::new(test_config());
    store.configure_organization_fields(config).unwrap();
    let mut create = CreateOrganization::new("original", "original");
    create.id = Some("chosen-id".into());
    create.metadata = Some(Value::Null).into();
    let organization = store.create_organization(create).await.unwrap();
    assert_eq!(organization.id, "chosen-id");
    assert_eq!(organization.name, "original:in:out");
    assert_eq!(
        organization.logo.typed().unwrap().as_deref(),
        Some("default-logo")
    );
    assert_eq!(organization.metadata, Some(Value::Null));
    assert!(organization.additional_fields.is_empty());
    assert_eq!(
        store
            .lock()
            .unwrap()
            .organizations
            .get(&organization.id)
            .unwrap()
            .unwrap()
            .name,
        "original:in"
    );
    let updated = store
        .update_organization(
            organization.id.typed().unwrap(),
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
            organization.id.typed().unwrap(),
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
            .get_organization_by_id(organization.id.typed().unwrap())
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
            .typed()
            .unwrap()
            .is_none()
    );
    let member = store
        .create_member(CreateMember::new(
            organization.id.typed().unwrap(),
            "recipient",
            "member",
        ))
        .await
        .unwrap();
    assert_eq!(member.role, "member:in:out");
    assert!(member.additional_fields.is_empty());
    let invitation = store
        .create_invitation(CreateInvitation::new(
            organization.id.typed().unwrap(),
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
            team.id.typed().unwrap(),
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
            organization_id: organization.id.typed().unwrap().clone(),
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
    let store = EphemeralStore::new(test_config());
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
                        input_transform: Some(Arc::new(|_| {
                            Err(AuthError::bad_request("transform failed"))
                        })),
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
                organization.id.typed().unwrap(),
                UpdateOrganization {
                    name: Some("changed".into()),
                    slug: Some("changed".into()),
                    ..Default::default()
                }
            )
            .await
            .is_err()
    );
    let state = store.lock().unwrap();
    assert_eq!(
        state
            .organizations
            .get(&organization.id)
            .unwrap()
            .unwrap()
            .name,
        "original"
    );
    assert_eq!(
        state
            .organizations
            .get(&organization.id)
            .unwrap()
            .unwrap()
            .slug,
        "original"
    );
}

#[tokio::test]
async fn memory_core_fields_keep_dynamic_values_and_output_omission() {
    use crate::{
        SchemaValue, organization_fields::OrganizationFields, user_fields::UserFieldConfig,
    };
    use serde_json::json;
    let store = EphemeralStore::new(test_config());
    let mut fields = OrganizationFields::default();
    fields.organization.additional_fields.insert(
        "name".into(),
        UserFieldConfig {
            input_transform: Some(Arc::new(|_| Ok(Some(json!(12))))),
            ..Default::default()
        },
    );
    store.configure_organization_fields(fields.clone()).unwrap();
    let mut input = CreateOrganization::new("original", "original");
    input.slug = SchemaValue::Dynamic(json!(42));
    let organization = store.create_organization(input).await.unwrap();
    assert_eq!(organization.name.json().unwrap(), Some(json!(12)));
    assert_eq!(
        store
            .get_organization_by_slug_value(&json!(42))
            .await
            .unwrap()
            .unwrap()
            .id,
        organization.id
    );
    assert!(
        store
            .get_organization_by_slug_value(&json!("42"))
            .await
            .unwrap()
            .is_none()
    );
    fields
        .organization
        .additional_fields
        .get_mut("name")
        .unwrap()
        .output_transform = Some(Arc::new(|_| Ok(None)));
    store.configure_organization_fields(fields).unwrap();
    let omitted = store
        .get_organization_by_id(organization.id.typed().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(omitted.name.is_undefined());
    assert!(serde_json::to_value(omitted).unwrap().get("name").is_none());
    assert_eq!(
        store
            .lock()
            .unwrap()
            .organizations
            .get(&organization.id)
            .unwrap()
            .unwrap()
            .name
            .json()
            .unwrap(),
        Some(json!(12))
    );
}

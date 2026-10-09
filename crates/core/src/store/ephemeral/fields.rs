use super::*;
use crate::store::schema::resolve_field_name;
#[cfg(test)]
use crate::user_fields::{FieldTransforms, UserFieldTransform};
use better_auth_schema_registry::{EntityRole, core_fields};

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

fn object(value: &impl AuthRecordFields) -> AuthResult<FieldMap> {
    value.field_values()
}

pub(super) trait MemoryOrganizationRecord: AuthRecordFields + FromFieldMap + Send {}

impl MemoryOrganizationRecord for Organization {}
impl MemoryOrganizationRecord for Member {}
impl MemoryOrganizationRecord for Invitation {}
impl MemoryOrganizationRecord for crate::Team {}
impl MemoryOrganizationRecord for crate::OrganizationRole {}

fn decode_record<T: MemoryOrganizationRecord>(fields: FieldMap) -> AuthResult<T> {
    T::from_field_values(fields)
}

fn decode_output_record<T: MemoryOrganizationRecord>(mut fields: FieldMap) -> AuthResult<T> {
    if let Some(id) = fields.get_mut("id") {
        *id = EphemeralStore::project_id(&crate::SchemaValue::from_field(id.clone()))?
            .into_field_value();
    }
    decode_record(fields)
}

#[tokio::test]
async fn native_organization_defaults_and_replacements_survive_crud() {
    use crate::{
        CreateOrganizationRole, UpdateOrganizationRole, organization_fields::OrganizationFields,
        store::OrganizationRoleStore, user_fields::UserFieldConfig,
    };

    let store = EphemeralStore::new(test_config());
    let created = store
        .create_organization_role(CreateOrganizationRole {
            organization_id: "organization".into(),
            role: "reader".into(),
            permission: FieldMap::new().into(),
            additional_fields: [("createdAt".into(), Value::Undefined)].into(),
        })
        .await
        .unwrap();
    assert!(created.created_at.field_value().as_date().is_some());
    assert!(created.updated_at.is_undefined());
    let changed = store
        .update_organization_role_value(
            &created.id.field_value(),
            UpdateOrganizationRole {
                role: Some("writer".into()),
                additional_fields: [
                    ("createdAt".into(), "2000-01-02T03:04:05.000Z".into()),
                    ("updatedAt".into(), Value::Undefined),
                ]
                .into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        changed
            .created_at
            .field_value()
            .as_date()
            .unwrap()
            .milliseconds(),
        946_782_245_000.0
    );
    assert!(changed.updated_at.field_value().as_date().is_some());
    assert_eq!(
        store
            .get_organization_role(created.id.typed().unwrap())
            .await
            .unwrap()
            .unwrap(),
        changed
    );
    assert_eq!(
        store.list_organization_roles("organization").await.unwrap(),
        vec![changed]
    );
    store
        .delete_organization_role(created.id.typed().unwrap())
        .await
        .unwrap();
    assert_eq!(
        store
            .count_organization_roles("organization")
            .await
            .unwrap(),
        0
    );

    let mut fields = OrganizationFields::default();
    for name in ["createdAt", "updatedAt"] {
        let _ = fields
            .organization_role
            .fields_mut()
            .insert(name.into(), UserFieldConfig::default());
    }
    let _ = fields.organization_role.fields_mut().insert(
        "role".into(),
        UserFieldConfig {
            field_name: Some("permission".into()),
            ..Default::default()
        },
    );
    store.configure_organization_fields(fields).unwrap();
    let created = store
        .create_organization_role(CreateOrganizationRole {
            organization_id: "organization".into(),
            role: "reader".into(),
            permission: FieldMap::new().into(),
            additional_fields: [("createdAt".into(), Value::Undefined)].into(),
        })
        .await
        .unwrap();
    assert!(created.created_at.is_undefined());
    assert!(created.updated_at.is_undefined());
    assert_eq!(created.role.field_value(), Value::from("{}"));
    assert_eq!(created.permission.field_value(), Value::from("{}"));
    let changed = store
        .update_organization_role_value(
            &created.id.field_value(),
            UpdateOrganizationRole {
                role: Some("writer".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(changed.created_at.is_undefined());
    assert!(changed.updated_at.is_undefined());
    assert_eq!(changed.role.field_value(), Value::from("writer"));
    assert_eq!(changed.permission.field_value(), Value::from("writer"));
    assert_eq!(
        store
            .get_organization_role(created.id.typed().unwrap())
            .await
            .unwrap()
            .unwrap(),
        changed
    );
    store
        .delete_organization_role_by_fields(&[("role".into(), "writer".into())].into())
        .await
        .unwrap();
    assert_eq!(
        store
            .count_organization_roles("organization")
            .await
            .unwrap(),
        0
    );
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
    let _ = fields.team.fields_mut().insert(
        "createdAt".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(|_| {
                    Ok(Value::from("2000-01-02T03:04:05+02:00"))
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let _ = fields.team.fields_mut().insert(
        "memberCount".into(),
        UserFieldConfig {
            field_type: UserFieldType::Number,
            default_value: Some(Value::from(17.0)),
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(|value| {
                    assert_eq!(value, Value::from(0.0));
                    Ok(Value::from(2.0))
                })),
                ..Default::default()
            }),
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
    assert_eq!(team.additional_fields["memberCount"], Value::from(2.0));
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

#[derive(Clone)]
pub(super) struct PreparedOrganizationFields {
    schema: crate::user_fields::UserConfig,
    role: EntityRole,
    fields: FieldMap,
    create: bool,
}

impl PreparedOrganizationFields {
    pub(super) fn apply<T: MemoryOrganizationRecord>(self, value: T) -> AuthResult<T> {
        let mut record = object(&value)?;
        let core_names: Vec<_> = core_fields(self.role)
            .iter()
            .map(|field| public_name(field.name))
            .collect();
        if self.create {
            record.retain(|name, _| core_names.contains(name));
            for name in self.schema.fields().keys().filter(|name| *name != "id") {
                let _ = record.remove(name);
            }
        }
        let mut fields = self.fields;
        if let Some(id) = fields.get("id") {
            let _ = record.insert("id".into(), id.clone());
        }
        let mut native_storage = Vec::new();
        for (name, field) in self.schema.fields() {
            if name == "id" {
                continue;
            }
            let storage_name = resolve_field_name(field.field_name.as_deref(), name);
            if core_names.contains(name) {
                if let Some(value) = fields.get(storage_name) {
                    let _ = record.insert(name.clone(), value.clone());
                }
                native_storage.push(storage_name.to_owned());
            }
        }
        fields.retain(|name, _| !native_storage.contains(name));
        record.extend(fields);
        decode_record(record)
    }
}

fn record_input<T: MemoryOrganizationRecord>(role: EntityRole, value: &T) -> AuthResult<FieldMap> {
    let record = object(value)?;
    let core_names: Vec<_> = core_fields(role)
        .iter()
        .map(|field| public_name(field.name))
        .collect();
    let mut core: FieldMap = record
        .into_iter()
        .filter(|(name, value)| core_names.contains(name) && !value.is_undefined())
        .collect();
    if role == EntityRole::Invitation {
        let _ = core.entry("teamId".to_owned()).or_insert(Value::Null);
    }
    Ok(core)
}

pub(super) fn record_fields<T: MemoryOrganizationRecord>(
    role: EntityRole,
    value: &T,
    schema: &crate::user_fields::UserConfig,
) -> AuthResult<(FieldMap, FieldMap)> {
    let raw = object(value)?;
    let mut core: FieldMap = core_fields(role)
        .iter()
        .map(|field| public_name(field.name))
        .filter_map(|name| raw.get(&name).cloned().map(|value| (name, value)))
        .collect();
    if role == EntityRole::Invitation {
        let _ = core.entry("teamId".to_owned()).or_insert(Value::Null);
    }
    let mut storage = raw;
    for (name, field) in schema.fields() {
        if let Some(value) = core.get(name) {
            let _ = storage.insert(
                resolve_field_name(field.field_name.as_deref(), name).to_owned(),
                value.clone(),
            );
        }
    }
    Ok((core, storage))
}

fn record_output<T: MemoryOrganizationRecord>(
    role: EntityRole,
    value: &T,
    schema: &crate::user_fields::UserConfig,
) -> AuthResult<crate::user_fields::AdapterRecord> {
    let (core, storage) = record_fields(role, value, schema)?;
    Ok(crate::user_fields::AdapterRecord::new(core, storage))
}

impl EphemeralStore {
    pub(super) fn field_config(
        &self,
        role: EntityRole,
    ) -> AuthResult<crate::user_fields::UserConfig> {
        self.organization_fields()?.schema_for(role)
    }

    fn bind_record_id(&self, fields: &mut FieldMap) -> AuthResult<()> {
        if matches!(
            self.config.advanced.database.generate_id(),
            crate::id::IdGeneration::Serial
        ) && let Some(id) = fields.remove("id")
        {
            let number = crate::query::field_number(&id)?;
            if id.is_truthy() && !number.is_nan() {
                let _ = fields.insert("id".into(), Value::Number(number));
            }
        }
        Ok(())
    }

    pub(super) async fn prepare_record_patch(
        &self,
        role: EntityRole,
        mut core: FieldMap,
        extras: FieldMap,
    ) -> AuthResult<PreparedOrganizationFields> {
        let schema = self.field_config(role)?;
        self.bind_record_id(&mut core)?;
        let fields = schema
            .organization_storage_fields_with_binding(core, extras, false, |_, field, value| {
                self.memory_plugin_field_input(field, value)
            })
            .await?;
        Ok(PreparedOrganizationFields {
            schema,
            role,
            fields,
            create: false,
        })
    }

    pub(super) async fn store_record<T: MemoryOrganizationRecord>(
        &self,
        role: EntityRole,
        value: T,
        patch: Option<FieldMap>,
        extras: FieldMap,
    ) -> AuthResult<T> {
        let schema = self.field_config(role)?;
        let create = patch.is_none();
        let mut core = match patch {
            Some(patch) => patch,
            None => record_input(role, &value)?,
        };
        self.bind_record_id(&mut core)?;
        let fields = schema
            .organization_storage_fields_with_binding(core, extras, create, |_, field, value| {
                self.memory_plugin_field_input(field, value)
            })
            .await?;
        PreparedOrganizationFields {
            schema,
            role,
            fields,
            create,
        }
        .apply(value)
    }

    pub(super) async fn output_record_refs<T: MemoryOrganizationRecord + Clone>(
        &self,
        role: EntityRole,
        values: Vec<super::rows::RowRef<T>>,
    ) -> AuthResult<Vec<T>> {
        self.output_record_refs_batches_then(role, values, |rows| std::future::ready(Ok(rows)))
            .await
    }

    pub(super) async fn output_record_refs_batches_then<
        T: MemoryOrganizationRecord + Clone,
        R: Send,
        F,
    >(
        &self,
        role: EntityRole,
        values: Vec<super::rows::RowRef<T>>,
        complete: impl Fn(Vec<(usize, T)>) -> F + Sync,
    ) -> AuthResult<Vec<R>>
    where
        F: std::future::Future<Output = AuthResult<Vec<(usize, R)>>> + Send,
    {
        let schema = self.field_config(role)?;
        let fields: IndexMap<_, _> = self
            .model_fields
            .organization_output_field_names(&schema)
            .into_iter()
            .map(|name| {
                let field = schema.fields().get(&name).cloned().unwrap_or_default();
                (name, field)
            })
            .collect();
        let mut rows = values
            .into_iter()
            .map(|row| (row, FieldMap::new()))
            .collect::<Vec<_>>();
        crate::user_fields::project_source_fields_batches_then(
            &mut rows,
            &fields,
            |(source, _), name, field| {
                source.read(|row| {
                    let (_, storage) = record_fields(role, row, &schema)?;
                    let key = if name != "id" {
                        resolve_field_name(field.field_name.as_deref(), name)
                    } else {
                        name
                    };
                    Ok(storage.get(key).cloned())
                })
            },
            |(_, output), name, field, value| {
                Box::pin(async move {
                    if name != "id" {
                        let value = crate::user_fields::project_adapter_value(
                            value.unwrap_or_default(),
                            field,
                            field.references_id(),
                            true,
                        )
                        .await?;
                        let _ = output.insert(name.to_owned(), value);
                    } else if let Some(mut value) = value {
                        if name == "id" {
                            value = Self::project_id(&crate::SchemaValue::from_field(value))?
                                .into_field_value();
                        }
                        let _ = output.insert(name.to_owned(), value);
                    }
                    Ok(())
                })
            },
            |_, (_, output)| decode_record(std::mem::take(output)),
            complete,
        )
        .await
    }

    pub(super) async fn output_records<T: MemoryOrganizationRecord + Send>(
        &self,
        role: EntityRole,
        values: Vec<T>,
    ) -> AuthResult<Vec<T>> {
        let schema = self.field_config(role)?;
        let records = values
            .iter()
            .map(|value| record_output(role, value, &schema))
            .collect::<AuthResult<Vec<_>>>()?;
        schema
            .organization_output_memory_records(records)
            .await?
            .into_iter()
            .map(decode_output_record)
            .collect()
    }

    pub(super) async fn output_records_batches_then<T: MemoryOrganizationRecord, R: Send, F>(
        &self,
        role: EntityRole,
        values: Vec<T>,
        complete: impl Fn(Vec<(usize, T)>) -> F + Sync,
    ) -> AuthResult<Vec<R>>
    where
        F: std::future::Future<Output = AuthResult<Vec<(usize, R)>>> + Send,
    {
        let schema = self.field_config(role)?;
        let records = values
            .iter()
            .map(|value| record_output(role, value, &schema))
            .collect::<AuthResult<Vec<_>>>()?;
        schema
            .organization_output_memory_records_batches_then(
                records,
                |_, fields| decode_output_record(fields),
                complete,
            )
            .await
    }

    pub(super) async fn output_record<T: MemoryOrganizationRecord + Send>(
        &self,
        role: EntityRole,
        value: T,
    ) -> AuthResult<T> {
        Ok(self.output_records(role, vec![value]).await?.remove(0))
    }

    pub(super) fn output_team_member(mut row: crate::TeamMember) -> AuthResult<crate::TeamMember> {
        row.id = Self::project_id(&row.id)?;
        row.team_id = Self::project_id(&row.team_id)?;
        row.user_id = Self::project_id(&row.user_id)?;
        Ok(row)
    }
}

#[tokio::test]
async fn organization_id_slot_preserves_bound_zero_alias() {
    use crate::organization_fields::OrganizationFields;
    use crate::user_fields::{UserConfig, UserFieldConfig, UserFieldReference};

    let mut config = AuthConfig::default();
    config.advanced.database.generate_id = Some(crate::id::IdGeneration::Serial);
    let store = EphemeralStore::new(Arc::new(config));
    store
        .configure_organization_fields(OrganizationFields {
            organization: UserConfig {
                additional_fields: Some(
                    [(
                        "aliasId".into(),
                        UserFieldConfig {
                            field_name: Some("id".into()),
                            references: Some(UserFieldReference {
                                model: "organization".into(),
                                field: "id".into(),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    )]
                    .into(),
                ),
            },
            ..Default::default()
        })
        .unwrap();
    let patch = store
        .prepare_record_patch(
            EntityRole::Organization,
            [("id".into(), Value::from("7"))].into(),
            [("aliasId".into(), Value::from("0"))].into(),
        )
        .await
        .unwrap();
    assert_eq!(patch.fields, [("id".into(), Value::Number(0.0))].into());
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
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(|value| {
                Ok(if value.is_undefined() {
                    value
                } else {
                    Value::from(format!("{}:in", value.as_str().unwrap()))
                })
            })),
            output: Some(UserFieldTransform::new(|value| {
                Ok(if value.is_undefined() {
                    value
                } else {
                    Value::from(format!("{}:out", value.as_str().unwrap()))
                })
            })),
        }),
        ..Default::default()
    };
    let fields = |name: &str| UserConfig {
        additional_fields: Some([(name.into(), policy.clone())].into()),
    };
    let mut config = OrganizationFields {
        organization: fields("name"),
        member: fields("role"),
        invitation: fields("email"),
        team: fields("name"),
        organization_role: fields("role"),
    };
    let _ = config.organization.fields_mut().insert(
        "id".into(),
        UserFieldConfig {
            required: Some(false),
            field_name: Some("ignored_id".into()),
            default_value: Some(Value::from("ignored")),
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(|_| {
                    Err(AuthError::bad_request("id input must not run"))
                })),
                output: Some(UserFieldTransform::new(|_| {
                    Err(AuthError::bad_request("id output must not run"))
                })),
            }),
            ..Default::default()
        },
    );
    let _ = config.organization.fields_mut().insert(
        "logo".into(),
        UserFieldConfig {
            required: Some(false),
            default_value: Some(Value::from("default-logo")),
            ..Default::default()
        },
    );
    let _ = config.invitation.fields_mut().insert(
        "teamId".into(),
        UserFieldConfig {
            required: Some(false),
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(|value| {
                    assert_eq!(value, Value::Null);
                    Ok(value)
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    for schema in [&mut config.team, &mut config.organization_role] {
        let _ = schema.fields_mut().insert(
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
    // Upstream adapter.mjs:146 omits falsy create metadata before adapter input.
    assert!(organization.metadata.is_undefined());
    assert_eq!(
        serde_json::to_value(&organization).unwrap(),
        json!({
            "id":"chosen-id", "name":"original:in:out", "slug":"original",
            "logo":"default-logo", "createdAt":organization.created_at
        })
    );
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
    assert!(updated.metadata.is_undefined());
    let updated = store
        .update_organization(
            organization.id.typed().unwrap(),
            UpdateOrganization {
                metadata: Some(Value::from_json(json!({"literal":"value"})).unwrap()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    // Upstream adapter.mjs:361 stringifies object update metadata before the adapter write.
    assert_eq!(
        updated.metadata,
        Some(Value::from(r#"{"literal":"value"}"#))
    );
    assert_eq!(
        serde_json::to_value(&updated).unwrap(),
        json!({
            "id":"chosen-id", "name":"changed:in:out", "slug":"original",
            "logo":"default-logo", "createdAt":organization.created_at,
            "metadata":r#"{"literal":"value"}"#
        })
    );
    assert_eq!(
        store
            .get_organization_by_id(organization.id.typed().unwrap())
            .await
            .unwrap()
            .unwrap()
            .metadata,
        Some(Value::from(r#"{"literal":"value"}"#))
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
            (Utc::now() + chrono::Duration::days(1)).into(),
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
    assert!(team.updated_at.is_undefined());
    let role = store
        .create_organization_role(CreateOrganizationRole {
            additional_fields: Default::default(),
            organization_id: organization.id.clone(),
            role: "editor".into(),
            permission: Value::from_json(json!({"member":["read"]})).unwrap(),
        })
        .await
        .unwrap();
    assert_eq!(role.role, "editor:in:out");
    assert!(role.updated_at.is_undefined());
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
                additional_fields: Some(
                    [(
                        "name".into(),
                        UserFieldConfig {
                            transform: Some(FieldTransforms {
                                input: Some(UserFieldTransform::new(|_| {
                                    Err(AuthError::bad_request("transform failed"))
                                })),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    )]
                    .into(),
                ),
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
    fields.organization.fields_mut().insert(
        "name".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(|_| Ok(Value::from(12.0)))),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    store.configure_organization_fields(fields.clone()).unwrap();
    let mut input = CreateOrganization::new("original", "original");
    input.slug = SchemaValue::Dynamic(Value::from(42.0));
    let organization = store.create_organization(input).await.unwrap();
    assert_eq!(organization.name.json().unwrap(), Some(json!(12)));
    assert_eq!(
        store
            .get_organization_by_slug_value(&Value::from(42.0))
            .await
            .unwrap()
            .unwrap()
            .id,
        organization.id
    );
    assert!(
        store
            .get_organization_by_slug_value(&Value::from("42"))
            .await
            .unwrap()
            .is_none()
    );
    fields
        .organization
        .fields_mut()
        .get_mut("name")
        .unwrap()
        .transform
        .get_or_insert_default()
        .output = Some(UserFieldTransform::new(|_| Ok(Value::Undefined)));
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

use super::rows::RecordSource;
use super::*;
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

#[tokio::test]
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract."
)]
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
#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract. Fixture indexing must fail when an expected record or property is missing."
)]
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
    fields: FieldMap,
}

impl PreparedOrganizationFields {
    pub(super) fn apply(self, mut fields: FieldMap) -> FieldMap {
        self.apply_to(&mut fields);
        fields
    }

    pub(super) fn apply_to(self, fields: &mut FieldMap) {
        fields.extend(self.fields);
    }
}

fn record_input(role: EntityRole, value: &impl AuthRecordFields) -> AuthResult<FieldMap> {
    let record = value.field_values()?;
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

impl EphemeralStore {
    pub(super) fn field_config(
        &self,
        role: EntityRole,
    ) -> AuthResult<crate::user_fields::UserConfig> {
        if role == EntityRole::TeamMember {
            return Ok(self.model_fields.plugin_fields(role));
        }
        self.organization_fields()?.fields_for(role).cloned()
    }

    pub(super) async fn prepare_record_patch(
        &self,
        role: EntityRole,
        core: FieldMap,
        extras: FieldMap,
    ) -> AuthResult<PreparedOrganizationFields> {
        let fields = self
            .organization_storage_fields(role, core, extras, false)
            .await?;
        Ok(PreparedOrganizationFields { fields })
    }

    pub(super) async fn prepare_increment_one_patch(
        &self,
        role: EntityRole,
        core: FieldMap,
        extras: FieldMap,
    ) -> AuthResult<PreparedOrganizationFields> {
        let patch = self.prepare_record_patch(role, core, extras).await?;
        crate::store::validate_increment_one_update(false, !patch.fields.is_empty())?;
        Ok(patch)
    }

    pub(super) async fn create_record<T: AuthRecordFields + Send>(
        &self,
        role: EntityRole,
        value: T,
        extras: FieldMap,
    ) -> AuthResult<FieldMap> {
        self.organization_storage_fields(role, record_input(role, &value)?, extras, true)
            .await
    }

    pub(super) async fn organization_storage_fields(
        &self,
        role: EntityRole,
        core: FieldMap,
        extras: FieldMap,
        create: bool,
    ) -> AuthResult<FieldMap> {
        let mut input = extras;
        input.extend(core);
        let force_allow_id = create && input.contains_key("id");
        super::raw_records::MemoryRecordModel::new(self, role, self.field_config(role)?)
            .prepare(input.into(), create, force_allow_id)
            .await
    }

    pub(super) async fn output_record_refs<T: FromFieldMap + Send + 'static>(
        &self,
        role: EntityRole,
        values: Vec<super::rows::RowRef<FieldMap>>,
    ) -> AuthResult<Vec<T>> {
        self.project_record_sources_owned_batches_then(
            role,
            &self.field_config(role)?,
            values.into_iter().map(RecordSource::Live).collect(),
            |_, fields| T::from_field_values(fields),
            |ready| std::future::ready(Ok(ready)),
        )
        .await
    }

    pub(super) fn output_record_pages<'a>(
        &'a self,
        role: EntityRole,
        pages: Vec<&'a [super::rows::RowRef<FieldMap>]>,
    ) -> futures_util::future::BoxFuture<'a, AuthResult<Vec<Vec<FieldMap>>>> {
        let store = self.clone();
        let pages = pages.into_iter().map(|page| (Arc::from(page), 0)).collect();
        store.output_owned_record_pages(role, pages)
    }

    fn output_owned_record_pages(
        &self,
        role: EntityRole,
        pages: Vec<(Arc<[super::rows::RowRef<FieldMap>]>, usize)>,
    ) -> futures_util::future::BoxFuture<'static, AuthResult<Vec<Vec<FieldMap>>>> {
        let store = self.clone();
        Box::pin(async move {
            let mut output = vec![Vec::new(); pages.len()];
            let mut active = Vec::new();
            let mut sources = Vec::new();
            for (index, (page, position)) in pages.into_iter().enumerate() {
                if let Some(first) = page.get(position) {
                    sources.push(RecordSource::Live(first.clone()));
                    active.push((index, (page, position + 1)));
                }
            }
            if sources.is_empty() {
                return Ok(output);
            }
            let active = std::sync::Arc::new(active);
            let continuation = store.clone();
            let active_pages = active.clone();
            let projected = store
                .project_record_sources_owned_batches_then(
                    role,
                    &store.field_config(role)?,
                    sources,
                    |_, fields| Ok(fields),
                    move |ready: Vec<(usize, FieldMap)>| {
                        let active = active_pages.clone();
                        let store = continuation.clone();
                        async move {
                            let tails = ready
                                .iter()
                                .map(|(index, _)| {
                                    active.get(*index).map(|(_, tail)| tail.clone()).ok_or_else(
                                        || {
                                            AuthError::internal(
                                                "Child projection lost its parent page",
                                            )
                                        },
                                    )
                                })
                                .collect::<AuthResult<Vec<_>>>()?;
                            let remaining = store.output_owned_record_pages(role, tails).await?;
                            Ok(ready
                                .into_iter()
                                .zip(remaining)
                                .map(|((index, first), mut rest)| {
                                    rest.insert(0, first);
                                    (index, rest)
                                })
                                .collect())
                        }
                    },
                )
                .await?;
            for ((index, _), page) in active.iter().zip(projected) {
                *output.get_mut(*index).ok_or_else(|| {
                    AuthError::internal("Child projection lost its result page")
                })? = page;
            }
            Ok(output)
        })
    }

    pub(super) async fn output_records<T: FromFieldMap + Send>(
        &self,
        role: EntityRole,
        values: Vec<FieldMap>,
    ) -> AuthResult<Vec<T>> {
        let schema = self.field_config(role)?;
        let sources = values
            .into_iter()
            .map(|value| RecordSource::Snapshot(Box::new(value)))
            .collect();
        self.project_record_sources(role, &schema, sources)
            .await?
            .into_iter()
            .map(T::from_field_values)
            .collect()
    }

    pub(super) async fn output_record<T: FromFieldMap + Send>(
        &self,
        role: EntityRole,
        value: FieldMap,
    ) -> AuthResult<T> {
        Ok(self.output_records(role, vec![value]).await?.remove(0))
    }
}

#[tokio::test]
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract."
)]
async fn organization_id_slot_preserves_declaration_order_for_bound_alias() {
    use crate::organization_fields::OrganizationFields;
    use crate::user_fields::{UserConfig, UserFieldConfig, UserFieldReference};

    for id_first in [false, true] {
        let mut config = AuthConfig::default();
        config.advanced.database.generate_id = Some(crate::id::IdGeneration::Serial);
        let store = EphemeralStore::new(Arc::new(config));
        let mut fields = UserConfig::default();
        if id_first {
            let _ = fields
                .fields_mut()
                .insert("id".into(), UserFieldConfig::default());
        }
        let _ = fields.fields_mut().insert(
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
        );
        store
            .configure_organization_fields(OrganizationFields {
                organization: fields,
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
        assert_eq!(
            patch.fields,
            [("id".into(), Value::Number(if id_first { 0.0 } else { 7.0 }))].into()
        );
    }
}

#[tokio::test]
#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract. Fixture indexing must fail when an expected record or property is missing."
)]
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
            .operation(|op| op.capture_state())
            .unwrap()
            .fixture_table("organization")
            .get(&organization.id)
            .unwrap()
            .unwrap()["name"],
        Value::from("original:in")
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
#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract. Fixture indexing must fail when an expected record or property is missing."
)]
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
    let state = store.operation(|op| op.capture_state()).unwrap();
    assert_eq!(
        state
            .fixture_table("organization")
            .get(&organization.id)
            .unwrap()
            .unwrap()["name"],
        Value::from("original")
    );
    assert_eq!(
        state
            .fixture_table("organization")
            .get(&organization.id)
            .unwrap()
            .unwrap()["slug"],
        Value::from("original")
    );
}

#[tokio::test]
#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract. Fixture indexing must fail when an expected record or property is missing."
)]
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
            .operation(|op| op.capture_state())
            .unwrap()
            .fixture_table("organization")
            .get(&organization.id)
            .unwrap()
            .unwrap()["name"]
            .json()
            .unwrap(),
        Some(json!(12))
    );
}

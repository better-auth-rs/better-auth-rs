#![expect(
    clippy::panic_in_result_fn,
    reason = "The paired Memory contract asserts native query values, complete records, callback order, and unchanged storage"
)]

use better_auth_core::{
    AuthConfig, AuthError, AuthRecordFields, AuthResult, CreateMember, CreateOrganizationRole,
    FieldDate, FieldMap, FieldValue, SchemaValue,
    id::{IdGeneration, IdGenerator},
    organization_fields::OrganizationFields,
    store::{
        EphemeralStore, ListOrganizationMembersParams, MemberStore, OrganizationRoleStore,
        OrganizationStore, RuntimeStore, schema::EntityRole,
    },
    user_fields::{
        FieldTransforms, UserFieldConfig, UserFieldReference, UserFieldTransform, UserFieldType,
    },
};
use std::{
    fmt::Debug,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

type Events = Arc<Mutex<Vec<FieldValue>>>;

fn date() -> FieldValue {
    FieldDate::from_milliseconds(1_893_456_000_000.0).into()
}

fn trace(kind: &str, value: FieldValue) -> FieldValue {
    FieldMap::from([("kind".into(), kind.into()), ("value".into(), value)]).into()
}

fn record(events: &Events, kind: &str, value: FieldValue) -> AuthResult<()> {
    events
        .lock()
        .map_err(|_| AuthError::internal("Organization query trace lock poisoned"))?
        .push(trace(kind, value));
    Ok(())
}

fn take(events: &Events) -> AuthResult<Vec<FieldValue>> {
    Ok(std::mem::take(&mut *events.lock().map_err(|_| {
        AuthError::internal("Organization query trace lock poisoned")
    })?))
}

fn callbacks(events: &Events) -> FieldTransforms {
    let input = events.clone();
    let output = events.clone();
    FieldTransforms {
        input: Some(UserFieldTransform::new(move |value| {
            record(&input, "input", value)?;
            Err(AuthError::internal("query-input-must-not-run"))
        })),
        output: Some(UserFieldTransform::new(move |value| {
            record(&output, "output", value.clone())?;
            Ok(value)
        })),
    }
}

fn writer(prefix: &'static str) -> EphemeralStore {
    let counter = AtomicUsize::new(0);
    let mut config = AuthConfig::default();
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(move |_| {
            Ok(Some(format!(
                "{prefix}{}",
                counter.fetch_add(1, Ordering::SeqCst)
            )))
        })));
    EphemeralStore::new(Arc::new(config))
}

fn member(id: usize, organization: FieldValue, role: FieldValue) -> FieldMap {
    [
        ("id".into(), format!("m{id}").into()),
        ("organizationId".into(), organization),
        ("userId".into(), "owner".into()),
        ("role".into(), role),
        ("createdAt".into(), date()),
    ]
    .into()
}

fn member_rows(alias: bool) -> Vec<FieldMap> {
    if alias {
        [
            FieldValue::Number(1.0),
            FieldValue::Number(1.0),
            "01".into(),
        ]
        .into_iter()
        .enumerate()
        .map(|(id, role)| member(id, "untouched".into(), role))
        .collect()
    } else {
        [
            FieldValue::Number(1.0),
            FieldValue::Number(1.0),
            "01".into(),
            " ".into(),
            FieldValue::Number(0.0),
            "literal".into(),
            FieldValue::Bool(true),
            FieldValue::Bool(true),
            FieldValue::Bool(false),
            FieldValue::Bool(false),
            "true".into(),
            "false".into(),
            "anything".into(),
        ]
        .into_iter()
        .enumerate()
        .map(|(id, organization)| member(id, organization, "member".into()))
        .collect()
    }
}

fn field<'a>(row: &'a FieldMap, name: &str) -> AuthResult<&'a FieldValue> {
    row.get(name)
        .ok_or_else(|| AuthError::internal(format!("Fixture field {name} is missing")))
}

async fn seed_members(rows: &[FieldMap]) -> AuthResult<EphemeralStore> {
    let store = writer("m");
    let mut fields = OrganizationFields::default();
    let _ = fields.member.fields_mut().insert(
        "createdAt".into(),
        UserFieldConfig {
            field_type: UserFieldType::Date,
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(|_| Ok(date()))),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    store.configure_organization_fields(fields)?;
    for row in rows {
        let _ = store
            .create_member(CreateMember {
                organization_id: SchemaValue::from_field(field(row, "organizationId")?.clone()),
                user_id: "owner".into(),
                role: SchemaValue::from_field(field(row, "role")?.clone()),
                additional_fields: FieldMap::new(),
            })
            .await?;
    }
    assert_eq!(store.storage_rows(EntityRole::Member)?, rows);
    Ok(store)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Policy {
    Number,
    Boolean,
    Alias,
    Reference,
}

struct MemberCase {
    name: &'static str,
    policy: Policy,
    query: FieldValue,
    indices: &'static [usize],
    fails: bool,
}

fn member_cases() -> Vec<MemberCase> {
    [
        (
            "number-numeric",
            Policy::Number,
            "01".into(),
            &[0, 1][..],
            false,
        ),
        ("number-blank", Policy::Number, " ".into(), &[3][..], false),
        (
            "number-literal",
            Policy::Number,
            "literal".into(),
            &[5][..],
            false,
        ),
        (
            "boolean-true",
            Policy::Boolean,
            "true".into(),
            &[6, 7][..],
            false,
        ),
        (
            "boolean-false",
            Policy::Boolean,
            "false".into(),
            &[8, 9][..],
            false,
        ),
        (
            "boolean-other",
            Policy::Boolean,
            "anything".into(),
            &[8, 9][..],
            false,
        ),
        (
            "number-alias",
            Policy::Alias,
            "01".into(),
            &[0, 1][..],
            false,
        ),
        (
            "reference-numeric",
            Policy::Reference,
            "01".into(),
            &[0, 1][..],
            false,
        ),
        (
            "reference-boolean-text",
            Policy::Reference,
            "true".into(),
            &[][..],
            false,
        ),
        (
            "reference-object-error",
            Policy::Reference,
            FieldMap::from([("toString".into(), FieldValue::Null)]).into(),
            &[][..],
            true,
        ),
    ]
    .into_iter()
    .map(|(name, policy, query, indices, fails)| MemberCase {
        name,
        policy,
        query,
        indices,
        fails,
    })
    .collect()
}

fn check_result<T: Debug + PartialEq>(
    result: AuthResult<T>,
    expected: T,
    case: &MemberCase,
) -> AuthResult<()> {
    if case.fails {
        assert!(
            matches!(&result, Err(AuthError::TypeError(message)) if message == "No default value"),
            "{}: {result:?}",
            case.name
        );
    } else {
        assert_eq!(result?, expected, "{}", case.name);
    }
    Ok(())
}

async fn check_member(case: MemberCase) -> AuthResult<()> {
    let rows = member_rows(case.policy == Policy::Alias);
    let store = seed_members(&rows).await?;
    let events = Events::default();
    let mut config = AuthConfig::default();
    if case.policy == Policy::Reference {
        config.advanced.database.generate_id = Some(IdGeneration::Serial);
    }
    let reader = store.with_runtime(Arc::new(config), Vec::new(), Default::default())?;
    let mut fields = OrganizationFields::default();
    let _ = fields.member.fields_mut().insert(
        "organizationId".into(),
        UserFieldConfig {
            field_type: if matches!(case.policy, Policy::Number | Policy::Alias) {
                UserFieldType::Number
            } else {
                UserFieldType::Boolean
            },
            field_name: (case.policy == Policy::Alias).then(|| "role".into()),
            references: (case.policy == Policy::Reference).then(|| UserFieldReference {
                model: "organization".into(),
                field: "id".into(),
                ..Default::default()
            }),
            transform: Some(callbacks(&events)),
            ..Default::default()
        },
    );
    reader.configure_organization_fields(fields)?;
    let mut expected = Vec::new();
    let mut outputs = Vec::new();
    for index in case.indices {
        let mut row = rows.get(*index).cloned().ok_or_else(|| {
            AuthError::internal(format!("Fixture member index {index} is missing"))
        })?;
        let value = field(
            &row,
            if case.policy == Policy::Alias {
                "role"
            } else {
                "organizationId"
            },
        )?
        .clone();
        outputs.push(trace("output", value.clone()));
        let _ = row.insert(
            "organizationId".into(),
            if case.policy == Policy::Reference {
                "1".into()
            } else {
                value
            },
        );
        expected.push(row);
    }
    let result = reader
        .list_organization_members_value(&case.query)
        .await
        .and_then(|rows| rows.iter().map(AuthRecordFields::field_values).collect());
    check_result(result, expected.clone(), &case)?;
    assert_eq!(take(&events)?, outputs, "{}: list callbacks", case.name);
    assert_eq!(
        store.storage_rows(EntityRole::Member)?,
        rows,
        "{}: list storage",
        case.name
    );

    let count =
        i64::try_from(expected.len()).map_err(|error| AuthError::internal(error.to_string()))?;
    check_result(
        reader.count_organization_members_value(&case.query).await,
        count,
        &case,
    )?;
    assert!(take(&events)?.is_empty(), "{}: count callbacks", case.name);
    assert_eq!(
        store.storage_rows(EntityRole::Member)?,
        rows,
        "{}: count storage",
        case.name
    );

    let result = reader
        .query_organization_members(&ListOrganizationMembersParams {
            organization_id: SchemaValue::from_field(case.query.clone()),
            limit: Some(1.0),
            offset: Some(0.0),
            sort_by: Some("createdAt".into()),
            sort_direction: Some("asc".into()),
            ..Default::default()
        })
        .await
        .and_then(|(rows, total)| {
            rows.iter()
                .map(AuthRecordFields::field_values)
                .collect::<AuthResult<Vec<_>>>()
                .map(|rows| (rows, total))
        });
    check_result(
        result,
        (
            expected.iter().take(1).cloned().collect::<Vec<_>>(),
            expected.len(),
        ),
        &case,
    )?;
    assert_eq!(
        take(&events)?,
        outputs.into_iter().take(1).collect::<Vec<_>>(),
        "{}: page callbacks",
        case.name
    );
    assert_eq!(
        store.storage_rows(EntityRole::Member)?,
        rows,
        "{}: page storage",
        case.name
    );
    Ok(())
}

#[tokio::test]
async fn memory_organization_member_queries_bind_native_types_before_matching_and_pagination()
-> AuthResult<()> {
    for case in member_cases() {
        check_member(case).await?;
    }
    Ok(())
}

fn role(id: usize, organization: &str, name: FieldValue) -> FieldMap {
    [
        ("id".into(), format!("r{id}").into()),
        ("organizationId".into(), organization.into()),
        ("role".into(), name),
        ("permission".into(), "{}".into()),
        ("createdAt".into(), date()),
        ("updatedAt".into(), FieldValue::Null),
    ]
    .into()
}

fn role_rows() -> Vec<FieldMap> {
    [
        ("target-org", "01".into()),
        ("target-org", "literal".into()),
        ("target-org", FieldValue::Number(1.0)),
        ("target-org", FieldValue::Number(2.0)),
        ("target-org", "02".into()),
        ("other-org", "01".into()),
        ("other-org", FieldValue::Number(1.0)),
    ]
    .into_iter()
    .enumerate()
    .map(|(id, (organization, name))| role(id, organization, name))
    .collect()
}

async fn seed_roles(rows: &[FieldMap]) -> AuthResult<EphemeralStore> {
    let store = writer("r");
    for (index, row) in rows.iter().enumerate() {
        let _ = store
            .create_organization_role(CreateOrganizationRole {
                organization_id: SchemaValue::from_field(field(row, "organizationId")?.clone()),
                role: format!("seed-{index}"),
                permission: FieldMap::new().into(),
                additional_fields: [
                    ("role".into(), field(row, "role")?.clone()),
                    ("createdAt".into(), date()),
                    ("updatedAt".into(), FieldValue::Null),
                ]
                .into(),
            })
            .await?;
    }
    assert_eq!(store.storage_rows(EntityRole::OrganizationRole)?, rows);
    Ok(store)
}

#[tokio::test]
async fn memory_organization_role_names_bind_the_complete_array_and_retain_the_organization()
-> AuthResult<()> {
    for (names, indices) in [(["01", "literal"], [0, 1]), (["01", "02"], [2, 3])] {
        let rows = role_rows();
        let store = seed_roles(&rows).await?;
        let events = Events::default();
        let mut fields = OrganizationFields::default();
        let _ = fields.organization_role.fields_mut().insert(
            "role".into(),
            UserFieldConfig {
                field_type: UserFieldType::Number,
                transform: Some(callbacks(&events)),
                ..Default::default()
            },
        );
        store.configure_organization_fields(fields)?;
        let result = store
            .query_organization_roles("target-org", &names.map(String::from))
            .await?;
        let actual = result
            .iter()
            .map(AuthRecordFields::field_values)
            .collect::<AuthResult<Vec<_>>>()?;
        let expected = indices
            .into_iter()
            .map(|index| {
                rows.get(index).cloned().ok_or_else(|| {
                    AuthError::internal(format!("Fixture role index {index} is missing"))
                })
            })
            .collect::<AuthResult<Vec<_>>>()?;
        assert_eq!(actual, expected, "{names:?}");
        let expected_events = expected
            .iter()
            .map(|row| field(row, "role").map(|value| trace("output", value.clone())))
            .collect::<AuthResult<Vec<_>>>()?;
        assert_eq!(take(&events)?, expected_events, "{names:?}");
        assert_eq!(
            store.storage_rows(EntityRole::OrganizationRole)?,
            rows,
            "{names:?}"
        );
        assert_eq!(store.count_organization_roles("target-org").await?, 5);
        assert!(take(&events)?.is_empty());
        assert_eq!(store.storage_rows(EntityRole::OrganizationRole)?, rows);
    }
    Ok(())
}

#[tokio::test]
async fn memory_organization_role_json_in_checks_the_converted_operand_only_when_rows_exist()
-> AuthResult<()> {
    for populated in [false, true] {
        let rows = if populated {
            vec![role(0, "other-org", "reader".into())]
        } else {
            Vec::new()
        };
        let store = seed_roles(&rows).await?;
        let events = Events::default();
        let mut fields = OrganizationFields::default();
        let _ = fields.organization_role.fields_mut().insert(
            "role".into(),
            UserFieldConfig {
                field_type: UserFieldType::Json,
                transform: Some(callbacks(&events)),
                ..Default::default()
            },
        );
        store.configure_organization_fields(fields)?;
        let result = store
            .query_organization_roles("target-org", &["reader".into()])
            .await;
        if populated {
            assert!(
                matches!(&result, Err(AuthError::Internal(message)) if message == "Value must be an array"),
                "{result:?}"
            );
        } else {
            assert_eq!(result?, Vec::new());
        }
        assert!(take(&events)?.is_empty());
        assert_eq!(store.storage_rows(EntityRole::OrganizationRole)?, rows);
        assert_eq!(store.count_organization_roles("target-org").await?, 0);
        assert!(take(&events)?.is_empty());
        assert_eq!(store.storage_rows(EntityRole::OrganizationRole)?, rows);
    }
    Ok(())
}

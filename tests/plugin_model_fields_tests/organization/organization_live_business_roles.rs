#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
use super::*;
use better_auth_core::{CreateOrganizationRole, UpdateOrganizationRole};

async fn check<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    malformed: bool,
    native: bool,
) -> AuthResult<()> {
    let token = seed(raw.clone(), false, "user-a").await?;
    let _ = raw.update_member_role("owner-member", "custom").await?;
    let writer = BetterAuth::new(settings()?)
        .store_arc(raw.clone())
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            dynamic_access_control: true,
            ..Default::default()
        }))
        .plugin(Fields(vec![(
            EntityRole::OrganizationRole,
            declaration([(
                "updatedAt",
                UserFieldConfig {
                    field_type: UserFieldType::Date,
                    on_update: Some(better_auth_core::user_fields::UserFieldFactory::new(|| {
                        Ok(date().into())
                    })),
                    ..Default::default()
                },
            )]),
        )]))
        .build()
        .await?;
    let _ = writer
        .store()
        .create_organization_role(CreateOrganizationRole {
            organization_id: "organization".into(),
            role: "custom".into(),
            permission: FieldMap::new().into(),
            additional_fields: [
                ("createdAt".into(), date().into()),
                ("updatedAt".into(), date().into()),
            ]
            .into(),
        })
        .await?;
    let mut before = storage.snapshot_with_roles(true).await?;
    let events = Events::default();
    let permission = FieldValue::from_json(if malformed {
        json!({"team":true})
    } else {
        json!({"team":["create"]})
    })?;
    let permission_json = serde_json::to_string(&permission.json()?)?;
    let mut plugin = OrganizationConfig {
        dynamic_access_control: true,
        ac: Some(std::collections::HashMap::from([(
            "team".into(),
            vec!["create".into()],
        )])),
        ..Default::default()
    };
    plugin.teams.enabled = true;
    let policies = declaration([
        (
            "organizationId",
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new_async({
                        let writer = writer.store().clone();
                        let events = events.clone();
                        move |value| {
                            let writer = writer.clone();
                            let events = events.clone();
                            let permission = permission.clone();
                            async move {
                                event(
                                    &events,
                                    ["organizationId".into(), "output".into(), value.clone()],
                                )?;
                                let _ = writer
                                    .update_organization_role(
                                        "organizationRole-a",
                                        UpdateOrganizationRole {
                                            permission: Some(permission),
                                            ..Default::default()
                                        },
                                    )
                                    .await?;
                                Ok(value)
                            }
                        }
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ),
        (
            "permission",
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new({
                        let events = events.clone();
                        move |value| {
                            event(
                                &events,
                                ["permission".into(), "output".into(), value.clone()],
                            )?;
                            Ok(value)
                        }
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ),
    ]);
    let auth = BetterAuth::new(settings()?)
        .store_arc(raw)
        .plugin(OrganizationPlugin::with_config(plugin))
        .plugin(Fields(vec![(EntityRole::OrganizationRole, policies)]))
        .build()
        .await?;
    let actual = call(
        &auth,
        &token,
        native,
        "has-permission",
        json!({"organizationId":"organization","permissions":{"team":["create"]}}),
    )
    .await;
    let fails = storage.memory() && malformed;
    let expected = if fails {
        FieldMap::from_iter([(
            "message".into(),
            "Invalid permissions for role custom".into(),
        )])
    } else {
        FieldMap::from_iter([
            ("error".into(), FieldValue::Null),
            ("success".into(), storage.memory().into()),
        ])
    };
    let actual = if fails && native {
        match actual {
            Err(error) => {
                assert!(error.is_api_error_instance(better_auth_core::ApiErrorClass::BetterAuth));
                assert_eq!(
                    error.status_value()?,
                    FieldValue::from("INTERNAL_SERVER_ERROR")
                );
                error.to_auth_response().expect("fixture response succeeds")
            }
            other => {
                return Err(AuthError::internal(format!(
                    "Expected native invalid-permission APIError, got {other:?}"
                )));
            }
        }
    } else {
        actual?
    };
    response(
        actual,
        native,
        if fails { 500 } else { 200 },
        &expected.into(),
    )?;
    let expected_events: Vec<FieldValue> = vec![
        vec![
            "organizationId".into(),
            "output".into(),
            "organization".into(),
        ]
        .into(),
        vec![
            "permission".into(),
            "output".into(),
            if storage.memory() {
                permission_json.clone()
            } else {
                "{}".into()
            }
            .into(),
        ]
        .into(),
    ];
    ordered(
        &trace_lock(&events)?.clone().into(),
        &expected_events.into(),
    )?;
    let rows = before
        .get_mut("organizationRole")
        .ok_or_else(|| AuthError::internal("Expected dynamic role table"))?;
    assert_eq!(rows.len(), 1);
    let _ = required(rows.first_mut(), "Expected stored dynamic role")?
        .insert("permission".into(), permission_json.into());
    assert_eq!(storage.snapshot_with_roles(true).await?, before);
    Ok(())
}

#[tokio::test]
async fn memory_organization_role_business_consumes_live_permission_and_retains_failed_write()
-> AuthResult<()> {
    for malformed in [false, true] {
        for native in [false, true] {
            let (raw, storage) = memory_fixture();
            check(raw, storage, malformed, native).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_organization_role_business_consumes_snapshot_permission_and_retains_write()
-> AuthResult<()> {
    for malformed in [false, true] {
        for native in [false, true] {
            let (raw, storage) = sqlite_fixture().await?;
            check(raw, storage, malformed, native).await?;
        }
    }
    Ok(())
}

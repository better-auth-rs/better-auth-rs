#![expect(
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    reason = "Tests intentionally panic when fixture setup or adapter contract assertions fail."
)]

use super::*;
use better_auth_core::{
    Organization, UpdateOrganization, organization_fields::OrganizationFields,
    store::OrganizationStore,
};

fn record(name: &str, field: &str, value: &str) -> AuthResult<FieldMap> {
    Ok(FieldMap::from([
        ("name".into(), name.into()),
        ("slug".into(), "organization".into()),
        ("logo".into(), FieldValue::Null),
        (
            "createdAt".into(),
            better_auth_core::query::field_date(&INITIAL.into())?.into(),
        ),
        ("metadata".into(), FieldValue::Null),
        (field.into(), value.into()),
        ("id".into(), "legacy-organization".into()),
    ]))
}

async fn assert_record(
    store: &SeaOrmStore<BundledSchema>,
    actual: Organization,
    name: &str,
    field: &str,
    value: &str,
) -> AuthResult<()> {
    assert_eq!(
        actual.field_values()?,
        record(name, field, &format!("visible:{value}"))?
    );
    assert_eq!(
        stored(
            store.connection(),
            "organization",
            &[
                "id",
                "name",
                "slug",
                "logo",
                "created_at",
                "metadata",
                "updated_at"
            ],
        )
        .await?,
        FieldMap::from([
            ("id".into(), "legacy-organization".into()),
            ("name".into(), name.into()),
            ("slug".into(), "organization".into()),
            ("logo".into(), FieldValue::Null),
            ("created_at".into(), INITIAL.into()),
            ("metadata".into(), FieldValue::Null),
            ("updated_at".into(), value.into()),
        ])
    );
    Ok(())
}

#[tokio::test]
async fn organization_declarations_own_private_columns_before_defaults_and_callbacks()
-> AuthResult<()> {
    for name in ["stamp", "authUpdatedAt"] {
        for discard in [false, true] {
            let trace = Trace::default();
            trace.discard.store(discard, Ordering::SeqCst);
            let store = store(
                EntityRole::Organization,
                "CREATE TABLE organization (id TEXT PRIMARY KEY, name TEXT NOT NULL, slug TEXT NOT NULL, logo TEXT, created_at TEXT NOT NULL, metadata TEXT, updated_at TEXT NOT NULL DEFAULT '2000-01-01T00:00:00.000Z')",
                vec![(name, trace.alias(name, "updated_at"))],
            ).await?;
            let mut declaration = trace.alias(name, "updated_at");
            declaration.default_value = Some(FIRST.into());
            store.configure_organization_fields(OrganizationFields {
                organization: UserConfig {
                    additional_fields: Some([(name.into(), declaration)].into()),
                },
                ..Default::default()
            })?;
            let mut input = record("First", name, FIRST)?;
            if name == "authUpdatedAt" {
                let _ = input.remove(name);
            }
            let created = store
                .insert_organization(Organization::from_field_values(input)?)
                .await?;
            let mut value = if discard { INITIAL } else { FIRST };
            assert_record(&store, created, "First", name, value).await?;
            assert_eq!(
                trace.take()?,
                vec![
                    ("input", name, FIRST.into()),
                    ("output", name, value.into())
                ]
            );

            let updated = store
                .update_organization(
                    "legacy-organization",
                    UpdateOrganization {
                        name: Some("Next".into()),
                        additional_fields: [(name.into(), NEXT.into())].into(),
                        ..Default::default()
                    },
                )
                .await?;
            if !discard {
                value = NEXT;
            }
            assert_record(&store, updated, "Next", name, value).await?;
            assert_eq!(
                trace.take()?,
                vec![("input", name, NEXT.into()), ("output", name, value.into())]
            );

            trace.reject.store(true, Ordering::SeqCst);
            assert_declared_stop(
                store
                    .update_organization(
                        "legacy-organization",
                        UpdateOrganization {
                            name: Some("Committed".into()),
                            additional_fields: [(name.into(), LAST.into())].into(),
                            ..Default::default()
                        },
                    )
                    .await
                    .unwrap_err(),
            );
            if !discard {
                value = LAST;
            }
            assert_eq!(
                trace.take()?,
                vec![("input", name, LAST.into()), ("output", name, value.into())]
            );
            trace.reject.store(false, Ordering::SeqCst);
            let persisted = store
                .get_organization_by_id("legacy-organization")
                .await?
                .ok_or_else(|| {
                    AuthError::internal("Expected the Organization after rejected output")
                })?;
            assert_record(&store, persisted, "Committed", name, value).await?;
            assert_eq!(trace.take()?, vec![("output", name, value.into())]);
        }
    }
    Ok(())
}

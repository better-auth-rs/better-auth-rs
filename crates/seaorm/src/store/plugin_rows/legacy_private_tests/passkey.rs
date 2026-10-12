#![expect(
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    reason = "Tests intentionally panic when fixture setup or adapter contract assertions fail."
)]

use super::*;
use better_auth_core::{
    CreatePasskey, Passkey, PasskeyCredentialState, PasskeyView, UpdatePasskey,
    UpdatePasskeyAuthentication,
};

fn expected(name: &str, timestamp: &str, counter: u64) -> FieldMap {
    FieldMap::from([
        ("name".into(), format!("visible:{name}").into()),
        ("aaguid".into(), format!("visible:{timestamp}").into()),
        ("counter".into(), (counter as f64).into()),
        ("id".into(), "legacy-passkey".into()),
    ])
}

async fn assert_passkey(
    store: &SeaOrmStore<BundledSchema>,
    actual: Passkey,
    name: &str,
    timestamp: &str,
    counter: u64,
) -> AuthResult<()> {
    let public = expected(name, timestamp, counter);
    let mut complete = public.clone();
    let _ = complete.insert("credential".into(), name.into());
    let _ = complete.insert(
        "updatedAt".into(),
        better_auth_core::query::field_date(&timestamp.into())?.into(),
    );
    assert_eq!(actual, Passkey::from_field_values(complete)?);
    assert_eq!(actual.field_order, ["name", "aaguid", "counter", "id"]);
    let view = PasskeyView::from(&actual).field_values()?;
    assert_eq!(view, public);
    assert_eq!(
        view.keys().map(String::as_str).collect::<Vec<_>>(),
        ["name", "aaguid", "counter", "id"]
    );
    assert_eq!(
        stored(
            store.connection(),
            "passkeys",
            &["id", "credential", "updated_at", "counter"]
        )
        .await?,
        FieldMap::from([
            ("id".into(), "legacy-passkey".into()),
            ("credential".into(), name.into()),
            ("updated_at".into(), timestamp.into()),
            ("counter".into(), (counter as f64).into()),
        ])
    );
    Ok(())
}

#[tokio::test]
async fn aliases_own_legacy_passkey_columns_even_when_transforms_discard_values() -> AuthResult<()>
{
    for discard in [false, true] {
        let trace = Trace::default();
        trace.discard.store(discard, Ordering::SeqCst);
        let store = store(EntityRole::Passkey,
            "CREATE TABLE passkeys (id TEXT PRIMARY KEY, credential TEXT NOT NULL DEFAULT 'database-credential', updated_at TEXT NOT NULL DEFAULT '2000-01-01T00:00:00.000Z', counter INTEGER NOT NULL DEFAULT 0)",
            vec![
                ("name", trace.alias("name", "credential")),
                ("aaguid", trace.alias("aaguid", "updated_at")),
                ("counter", UserFieldConfig { field_type: UserFieldType::Number, ..Default::default() }),
            ],
        ).await?;
        let created = store
            .create_passkey(CreatePasskey {
                additional_fields: FieldMap::from([("id".into(), "legacy-passkey".into())]),
                user_id: "owner".into(),
                name: Some("source".into()).into(),
                credential_id: "credential-id".into(),
                public_key: "public-key".into(),
                counter: 7,
                device_type: "singleDevice".into(),
                backed_up: false,
                transports: None,
                credential: PasskeyCredentialState::Legacy("private-must-not-win".into()),
                aaguid: Some(FIRST.into()).into(),
            })
            .await?;
        let mut name = if discard {
            "database-credential"
        } else {
            "stored:source"
        };
        let mut timestamp = if discard { INITIAL } else { FIRST };
        assert_passkey(&store, created, name, timestamp, 7).await?;
        assert_eq!(
            trace.take()?,
            vec![
                ("input", "name", "source".into()),
                ("input", "aaguid", FIRST.into()),
                ("output", "name", name.into()),
                ("output", "aaguid", timestamp.into()),
            ]
        );

        let id = "legacy-passkey".to_owned().into();
        assert_eq!(
            store.get_passkey_record(&id).await?,
            Some(expected(name, timestamp, 7))
        );
        assert_eq!(
            trace.take()?,
            vec![
                ("output", "name", name.into()),
                ("output", "aaguid", timestamp.into())
            ]
        );
        let read = store
            .get_passkey_by_id("legacy-passkey")
            .await?
            .ok_or_else(|| AuthError::internal("Expected the typed Legacy Passkey"))?;
        assert_passkey(&store, read, name, timestamp, 7).await?;
        assert_eq!(
            trace.take()?,
            vec![
                ("output", "name", name.into()),
                ("output", "aaguid", timestamp.into())
            ]
        );

        let updated = store
            .update_passkey(
                &id,
                UpdatePasskey {
                    name: Some("next".into()).into(),
                    aaguid: Some(NEXT.into()).into(),
                    counter: Some(8),
                    ..Default::default()
                },
            )
            .await?;
        if !discard {
            name = "stored:next";
            timestamp = NEXT;
        }
        assert_passkey(&store, updated, name, timestamp, 8).await?;
        assert_eq!(
            trace.take()?,
            vec![
                ("input", "name", "next".into()),
                ("input", "aaguid", NEXT.into()),
                ("output", "name", name.into()),
                ("output", "aaguid", timestamp.into()),
            ]
        );

        let authenticated = store
            .update_passkey_authentication(
                &id,
                UpdatePasskeyAuthentication::Legacy {
                    credential: "private-auth-must-not-win".into(),
                    counter: 9,
                    backed_up: true,
                    device_type: "multiDevice".into(),
                },
            )
            .await?;
        assert_passkey(&store, authenticated, name, timestamp, 9).await?;
        assert_eq!(
            trace.take()?,
            vec![
                ("output", "name", name.into()),
                ("output", "aaguid", timestamp.into())
            ]
        );

        trace.discard_output.store(true, Ordering::SeqCst);
        let before = stored(
            store.connection(),
            "passkeys",
            &["id", "credential", "updated_at", "counter"],
        )
        .await?;
        let projected = store
            .get_passkey_by_id("legacy-passkey")
            .await?
            .ok_or_else(|| {
                AuthError::internal("Expected the Passkey with omitted output values")
            })?;
        let mut public = expected(name, timestamp, 9);
        let _ = public.insert("name".into(), FieldValue::Undefined);
        let _ = public.insert("aaguid".into(), FieldValue::Undefined);
        assert_eq!(PasskeyView::from(&projected).field_values()?, public);
        assert_eq!(projected.field_order, ["name", "aaguid", "counter", "id"]);
        let mut complete = public;
        let _ = complete.insert("credential".into(), name.into());
        let _ = complete.insert(
            "updatedAt".into(),
            better_auth_core::query::field_date(&timestamp.into())?.into(),
        );
        assert_eq!(projected, Passkey::from_field_values(complete)?);
        assert_eq!(
            stored(
                store.connection(),
                "passkeys",
                &["id", "credential", "updated_at", "counter"]
            )
            .await?,
            before
        );
        assert_eq!(
            trace.take()?,
            vec![
                ("output", "name", name.into()),
                ("output", "aaguid", timestamp.into())
            ]
        );
        trace.discard_output.store(false, Ordering::SeqCst);

        trace.reject.store(true, Ordering::SeqCst);
        assert_declared_stop(
            store
                .update_passkey(
                    &id,
                    UpdatePasskey {
                        name: Some("rejected".into()).into(),
                        aaguid: Some(LAST.into()).into(),
                        counter: Some(10),
                        ..Default::default()
                    },
                )
                .await
                .unwrap_err(),
        );
        if !discard {
            name = "stored:rejected";
            timestamp = LAST;
        }
        assert_eq!(
            trace.take()?,
            vec![
                ("input", "name", "rejected".into()),
                ("input", "aaguid", LAST.into()),
                ("output", "name", name.into()),
            ]
        );
        trace.reject.store(false, Ordering::SeqCst);
        let persisted = store
            .get_passkey_by_id("legacy-passkey")
            .await?
            .ok_or_else(|| AuthError::internal("Expected the Passkey after rejected output"))?;
        assert_passkey(&store, persisted, name, timestamp, 10).await?;
        assert_eq!(
            trace.take()?,
            vec![
                ("output", "name", name.into()),
                ("output", "aaguid", timestamp.into())
            ]
        );
    }
    Ok(())
}

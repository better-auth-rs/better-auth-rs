#![expect(
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    reason = "Tests intentionally panic when fixture setup or adapter contract assertions fail."
)]

use super::*;
use better_auth_core::{CreateTwoFactor, TwoFactor, UpdateTwoFactor};

fn expected(secret: &str, codes: &str, verified: bool) -> FieldMap {
    FieldMap::from([
        ("secret".into(), format!("visible:{secret}").into()),
        ("backupCodes".into(), format!("visible:{codes}").into()),
        ("userId".into(), "owner".into()),
        ("verified".into(), verified.into()),
        ("id".into(), "legacy-factor".into()),
    ])
}

async fn assert_factor(
    store: &SeaOrmStore<BundledSchema>,
    actual: TwoFactor,
    secret: &str,
    codes: &str,
    verified: bool,
) -> AuthResult<()> {
    let mut complete = expected(secret, codes, verified);
    let _ = complete.insert(
        "createdAt".into(),
        better_auth_core::query::field_date(&secret.into())?.into(),
    );
    let _ = complete.insert(
        "updatedAt".into(),
        better_auth_core::query::field_date(&codes.into())?.into(),
    );
    assert_eq!(actual, TwoFactor::from_field_values(complete)?);
    assert_eq!(
        stored(
            store.connection(),
            "two_factor",
            &["id", "user_id", "created_at", "updated_at", "verified"]
        )
        .await?,
        FieldMap::from([
            ("id".into(), "legacy-factor".into()),
            ("user_id".into(), "owner".into()),
            ("created_at".into(), secret.into()),
            ("updated_at".into(), codes.into()),
            ("verified".into(), f64::from(u8::from(verified)).into()),
        ])
    );
    Ok(())
}

#[tokio::test]
async fn aliases_own_legacy_two_factor_timestamps_and_preserve_atomic_guards() -> AuthResult<()> {
    for discard in [false, true] {
        let trace = Trace::default();
        trace.discard.store(discard, Ordering::SeqCst);
        let store = store(EntityRole::TwoFactor,
            "CREATE TABLE two_factor (id TEXT PRIMARY KEY, user_id TEXT, created_at TEXT NOT NULL DEFAULT '2000-01-01T00:00:00.000Z', updated_at TEXT NOT NULL DEFAULT '2000-01-01T00:00:00.000Z', verified BOOLEAN DEFAULT 0)",
            vec![
                ("secret", trace.alias("secret", "created_at")),
                ("backupCodes", trace.alias("backupCodes", "updated_at")),
                ("userId", UserFieldConfig::default()),
                ("verified", UserFieldConfig { field_type: UserFieldType::Boolean, ..Default::default() }),
            ],
        ).await?;
        let created = store
            .create_two_factor(CreateTwoFactor {
                additional_fields: FieldMap::from([("id".into(), "legacy-factor".into())]),
                user_id: "owner".into(),
                secret: FIRST.into(),
                backup_codes: NEXT.into(),
                verified: true,
            })
            .await?;
        let mut secret = if discard { INITIAL } else { FIRST };
        let mut codes = if discard { INITIAL } else { NEXT };
        assert_factor(&store, created, secret, codes, true).await?;
        assert_eq!(
            trace.take()?,
            vec![
                ("input", "secret", FIRST.into()),
                ("input", "backupCodes", NEXT.into()),
                ("output", "secret", secret.into()),
                ("output", "backupCodes", codes.into()),
            ]
        );
        let id = "legacy-factor".to_owned().into();
        let raw = store
            .get_two_factor_record(&id)
            .await?
            .ok_or_else(|| AuthError::internal("Expected the raw Legacy TwoFactor"))?;
        assert_eq!(raw, expected(secret, codes, true));
        assert_eq!(
            raw.keys().map(String::as_str).collect::<Vec<_>>(),
            ["secret", "backupCodes", "userId", "verified", "id"]
        );
        assert_eq!(
            trace.take()?,
            vec![
                ("output", "secret", secret.into()),
                ("output", "backupCodes", codes.into())
            ]
        );

        let updated = store
            .update_two_factor(
                &id,
                UpdateTwoFactor {
                    secret: Some(NEXT.into()),
                    backup_codes: Some(LAST.into()),
                    verified: Some(false),
                    ..Default::default()
                },
            )
            .await?;
        if !discard {
            secret = NEXT;
            codes = LAST;
        }
        assert_factor(&store, updated, secret, codes, false).await?;
        assert_eq!(
            trace.take()?,
            vec![
                ("input", "secret", NEXT.into()),
                ("input", "backupCodes", LAST.into()),
                ("output", "secret", secret.into()),
                ("output", "backupCodes", codes.into()),
            ]
        );

        if discard {
            let error = store
                .compare_exchange_two_factor_backup_codes(&id, &codes.into(), FIRST.into())
                .await
                .unwrap_err();
            assert!(
                matches!(error, AuthError::Internal(message) if message == "incrementOne resolved to an empty update: every increment/set field was unknown to the schema or transformed away.")
            );
            assert_eq!(trace.take()?, vec![("input", "backupCodes", FIRST.into())]);
        } else {
            assert!(
                store
                    .compare_exchange_two_factor_backup_codes(&id, &codes.into(), FIRST.into())
                    .await?
            );
            codes = FIRST;
            assert_eq!(
                trace.take()?,
                vec![
                    ("input", "backupCodes", FIRST.into()),
                    ("output", "secret", secret.into()),
                    ("output", "backupCodes", codes.into()),
                ]
            );
            assert!(
                !store
                    .compare_exchange_two_factor_backup_codes(&id, &LAST.into(), NEXT.into())
                    .await?
            );
            assert_eq!(trace.take()?, vec![("input", "backupCodes", NEXT.into())]);
        }
        let persisted = store
            .get_two_factor_by_user_id("owner")
            .await?
            .ok_or_else(|| {
                AuthError::internal("Expected the TwoFactor after conditional update")
            })?;
        assert_factor(&store, persisted, secret, codes, false).await?;
        assert_eq!(
            trace.take()?,
            vec![
                ("output", "secret", secret.into()),
                ("output", "backupCodes", codes.into())
            ]
        );

        trace.discard_output.store(true, Ordering::SeqCst);
        let before = stored(
            store.connection(),
            "two_factor",
            &["id", "user_id", "created_at", "updated_at", "verified"],
        )
        .await?;
        let projected = store
            .get_two_factor_by_user_id("owner")
            .await?
            .ok_or_else(|| {
                AuthError::internal("Expected the TwoFactor with omitted output values")
            })?;
        let mut complete = expected(secret, codes, false);
        let _ = complete.insert("secret".into(), FieldValue::Undefined);
        let _ = complete.insert("backupCodes".into(), FieldValue::Undefined);
        let _ = complete.insert(
            "createdAt".into(),
            better_auth_core::query::field_date(&secret.into())?.into(),
        );
        let _ = complete.insert(
            "updatedAt".into(),
            better_auth_core::query::field_date(&codes.into())?.into(),
        );
        assert_eq!(projected, TwoFactor::from_field_values(complete)?);
        assert_eq!(
            stored(
                store.connection(),
                "two_factor",
                &["id", "user_id", "created_at", "updated_at", "verified"]
            )
            .await?,
            before
        );
        assert_eq!(
            trace.take()?,
            vec![
                ("output", "secret", secret.into()),
                ("output", "backupCodes", codes.into())
            ]
        );
        trace.discard_output.store(false, Ordering::SeqCst);

        trace.reject.store(true, Ordering::SeqCst);
        assert_declared_stop(
            store
                .update_two_factor(
                    &id,
                    UpdateTwoFactor {
                        secret: Some(LAST.into()),
                        backup_codes: Some(NEXT.into()),
                        verified: Some(true),
                        ..Default::default()
                    },
                )
                .await
                .unwrap_err(),
        );
        if !discard {
            secret = LAST;
            codes = NEXT;
        }
        assert_eq!(
            trace.take()?,
            vec![
                ("input", "secret", LAST.into()),
                ("input", "backupCodes", NEXT.into()),
                ("output", "secret", secret.into()),
            ]
        );
        trace.reject.store(false, Ordering::SeqCst);
        let persisted = store
            .get_two_factor_by_user_id("owner")
            .await?
            .ok_or_else(|| AuthError::internal("Expected the TwoFactor after rejected output"))?;
        assert_factor(&store, persisted, secret, codes, true).await?;
        assert_eq!(
            trace.take()?,
            vec![
                ("output", "secret", secret.into()),
                ("output", "backupCodes", codes.into())
            ]
        );
    }
    Ok(())
}

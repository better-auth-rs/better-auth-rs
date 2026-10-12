#![expect(
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    reason = "Tests intentionally panic when fixture setup or adapter contract assertions fail."
)]

use super::*;

#[tokio::test]
async fn declared_output_errors_precede_missing_legacy_columns() -> AuthResult<()> {
    for role in [EntityRole::Passkey, EntityRole::TwoFactor] {
        let trace = Trace::default();
        trace.reject.store(true, Ordering::SeqCst);
        let (sql, name, field, seed, private) = match role {
            EntityRole::Passkey => (
                "CREATE TABLE passkeys (id TEXT PRIMARY KEY, name TEXT)",
                "name",
                trace.alias("name", "name"),
                "INSERT INTO passkeys VALUES ('row', 'source')",
                "credential",
            ),
            _ => (
                "CREATE TABLE two_factor (id TEXT PRIMARY KEY, user_id TEXT)",
                "userId",
                trace.alias("userId", "user_id"),
                "INSERT INTO two_factor VALUES ('row', 'source')",
                "created_at",
            ),
        };
        let store = store(role, sql, vec![(name, field)]).await?;
        let _ = store
            .connection()
            .execute_unprepared(seed)
            .await
            .map_err(map_db_err)?;
        for reject in [true, false] {
            trace.reject.store(reject, Ordering::SeqCst);
            let error = match role {
                EntityRole::Passkey => store.get_passkey_by_id("row").await.unwrap_err(),
                _ => store.get_two_factor_by_user_id("source").await.unwrap_err(),
            };
            if reject {
                assert_declared_stop(error);
            } else {
                assert!(
                    matches!(error, AuthError::Internal(message) if message.starts_with(&format!("Cannot read raw plugin column {private}:")))
                );
            }
            assert_eq!(trace.take()?, vec![("output", name, "source".into())]);
        }
    }
    Ok(())
}

#[tokio::test]
async fn private_values_use_the_snapshot_captured_before_output_callbacks() -> AuthResult<()> {
    for role in [EntityRole::Passkey, EntityRole::TwoFactor] {
        let database = Arc::new(Mutex::new(None::<DatabaseConnection>));
        let callback_database = database.clone();
        let output = UserFieldTransform::new_async(move |value| {
            let callback_database = callback_database.clone();
            async move {
                let database = callback_database
                    .lock()
                    .map_err(|_| {
                        AuthError::internal("Legacy snapshot connection lock is poisoned")
                    })?
                    .clone()
                    .ok_or_else(|| {
                        AuthError::internal("Expected the Legacy snapshot connection")
                    })?;
                let sql = if role == EntityRole::Passkey {
                    "UPDATE passkeys SET credential = 'mutated', updated_at = '2003-04-05T06:07:08.000Z'"
                } else {
                    "UPDATE two_factor SET created_at = '2003-04-05T06:07:08.000Z', updated_at = '2003-04-05T06:07:08.000Z'"
                };
                let _ = database.execute_unprepared(sql).await.map_err(map_db_err)?;
                Ok(value)
            }
        });
        let (table, sql, seed, name, column) = if role == EntityRole::Passkey {
            (
                "passkeys",
                "CREATE TABLE passkeys (id TEXT PRIMARY KEY, name TEXT, credential TEXT, updated_at TEXT)",
                "INSERT INTO passkeys VALUES ('row', 'source', 'original', '2000-01-01T00:00:00.000Z')",
                "name",
                "name",
            )
        } else {
            (
                "two_factor",
                "CREATE TABLE two_factor (id TEXT PRIMARY KEY, user_id TEXT, created_at TEXT, updated_at TEXT)",
                "INSERT INTO two_factor VALUES ('row', 'source', '2000-01-01T00:00:00.000Z', '2000-01-01T00:00:00.000Z')",
                "userId",
                "user_id",
            )
        };
        let store = store(
            role,
            sql,
            vec![(
                name,
                UserFieldConfig {
                    field_name: Some(column.into()),
                    transform: Some(FieldTransforms {
                        output: Some(output),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )],
        )
        .await?;
        *database
            .lock()
            .map_err(|_| AuthError::internal("Legacy snapshot connection lock is poisoned"))? =
            Some(store.connection().clone());
        let _ = store
            .connection()
            .execute_unprepared(seed)
            .await
            .map_err(map_db_err)?;
        let initial = better_auth_core::query::field_date(&INITIAL.into())?;
        if role == EntityRole::Passkey {
            let passkey = store
                .get_passkey_by_id("row")
                .await?
                .ok_or_else(|| AuthError::internal("Expected the Passkey snapshot"))?;
            assert_eq!(passkey.name, Some("source".into()));
            assert_eq!(passkey.credential, "original");
            assert_eq!(passkey.updated_at, initial);
            assert_eq!(
                stored(
                    store.connection(),
                    table,
                    &["id", "name", "credential", "updated_at"]
                )
                .await?,
                FieldMap::from([
                    ("id".into(), "row".into()),
                    ("name".into(), "source".into()),
                    ("credential".into(), "mutated".into()),
                    ("updated_at".into(), LAST.into()),
                ])
            );
        } else {
            let factor = store
                .get_two_factor_by_user_id("source")
                .await?
                .ok_or_else(|| AuthError::internal("Expected the TwoFactor snapshot"))?;
            assert_eq!(factor.user_id, "source");
            assert_eq!(factor.created_at, initial);
            assert_eq!(factor.updated_at, initial);
            assert_eq!(
                stored(
                    store.connection(),
                    table,
                    &["id", "user_id", "created_at", "updated_at"]
                )
                .await?,
                FieldMap::from([
                    ("id".into(), "row".into()),
                    ("user_id".into(), "source".into()),
                    ("created_at".into(), LAST.into()),
                    ("updated_at".into(), LAST.into()),
                ])
            );
        }
    }
    Ok(())
}

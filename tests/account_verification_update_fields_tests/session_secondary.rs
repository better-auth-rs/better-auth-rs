use super::*;
use better_auth_core::{
    AuthError,
    store::{SecondaryStorage, SessionStore, SessionUpdateWriter, secondary::SecondaryStore},
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Default)]
struct Cache {
    values: Mutex<BTreeMap<String, String>>,
    writes: Mutex<Vec<(String, String, Option<f64>)>>,
}

#[async_trait::async_trait]
impl SecondaryStorage for Cache {
    async fn get(&self, key: &str) -> AuthResult<Option<Value>> {
        Ok(self
            .values
            .lock()
            .unwrap()
            .get(key)
            .cloned()
            .map(Value::String))
    }
    async fn set_native(&self, key: &FieldValue, value: &str, ttl: Option<f64>) -> AuthResult<()> {
        let key = key
            .as_str()
            .ok_or_else(|| AuthError::internal("Contract cache keys must remain strings"))?;
        self.writes
            .lock()
            .unwrap()
            .push((key.into(), value.into(), ttl));
        let _ = self.values.lock().unwrap().insert(key.into(), value.into());
        Ok(())
    }
    async fn delete(&self, key: &str) -> AuthResult<()> {
        let _ = self.values.lock().unwrap().remove(key);
        Ok(())
    }
    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<Value>> {
        Ok(self.values.lock().unwrap().remove(key).map(Value::String))
    }
}

struct CacheHooks {
    shared: Hooks,
    nullish: FieldValue,
    write_database: bool,
}

#[better_auth::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for CacheHooks {
    async fn before_update_session(
        &self,
        data: &mut FieldMap,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        let outcome = self.shared.before(data)?;
        Ok(match outcome {
            DatabaseHookUpdate::Patch(mut fields) if self.shared.patch == Patch::Values => {
                let _ = fields.insert("expiresAt".into(), self.nullish.clone());
                if !self.write_database {
                    let _ = fields.insert("updatedAt".into(), self.nullish.clone());
                }
                let _ = fields.insert("createdAt".into(), date(4).into());
                DatabaseHookUpdate::Patch(fields)
            }
            outcome => outcome,
        })
    }
    async fn after_update_session(
        &self,
        data: Option<&SessionView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.shared
            .after
            .lock()
            .unwrap()
            .push(FieldMap::from(data.unwrap().clone()).into());
        Ok(())
    }
}

async fn seed<S: AuthSchema>(
    store: &dyn AuthStore<S>,
) -> AuthResult<(better_auth_core::UserView, SessionView)> {
    let user = store
        .create_user(
            CreateUser::new()
                .with_email("owner@secondary-update.test")
                .with_name("Owner"),
        )
        .await?;
    let session = store
        .create_session(CreateSession {
            user_id: user.id.clone(),
            expires_at: date(100),
            ip_address: Some("stored".into()),
            user_agent: Some("stored".into()),
            inherited_fields: Default::default(),
            additional_fields: Default::default(),
            impersonated_by: None,
            active_organization_id: None,
        })
        .await?;
    Ok((user, session))
}

async fn check<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    sqlite: bool,
    write_database: bool,
    patch: Patch,
    nullish: FieldValue,
) -> AuthResult<()> {
    let (user, session) = seed(raw.as_ref()).await?;
    let token = session.token.typed()?.clone();
    let reference_key = format!("active-sessions-{}", user.id.typed()?);
    let before = FieldMap::from(session.clone());
    let original_date = FieldValue::Date(date(1));
    let observed = Arc::new(Mutex::new(Vec::new()));
    let after = Arc::new(Mutex::new(Vec::new()));
    let hooks = [true, false]
        .into_iter()
        .map(|first| {
            Arc::new(CacheHooks {
                shared: Hooks {
                    first,
                    model: Model::Session,
                    patch,
                    original_date: original_date.clone(),
                    observed: observed.clone(),
                    after: after.clone(),
                },
                nullish: nullish.clone(),
                write_database,
            }) as Arc<dyn DatabaseHooks<S>>
        })
        .collect();
    let mut config = AuthConfig::default();
    config.session.store_session_in_database = Some(write_database);
    let config = Arc::new(config);
    let cache = Arc::new(Cache::default());
    let _ = cache.values.lock().unwrap().insert(
        token.clone(),
        serde_json::to_string(&json!({"session": session, "user": user}))?,
    );
    let inner = raw.with_runtime(config.clone(), hooks, Default::default())?;
    let runtime = SecondaryStore::new(inner, cache.clone(), config, Default::default())?
        .with_clock(|| chrono::DateTime::from_timestamp_millis(1_893_456_000_000).unwrap());
    let result = runtime
        .update_session_fields(
            &token,
            [
                ("ipAddress".into(), "requested".into()),
                ("userAgent".into(), "requested".into()),
                ("updatedAt".into(), original_date.clone()),
                ("expiresAt".into(), date(50).into()),
            ]
            .into(),
        )
        .await?
        .unwrap();
    let mut cached = before.clone();
    let _ = cached.insert(
        "token".into(),
        Model::Session.mutation(patch == Patch::Continue),
    );
    let expiration = if patch == Patch::Values { 100 } else { 50 };
    if patch == Patch::Values {
        let _ = cached.insert("ipAddress".into(), FieldValue::Undefined);
        let _ = cached.insert("userAgent".into(), 7.into());
        if write_database {
            let _ = cached.insert("updatedAt".into(), date(1).into());
        }
    } else {
        let value = if patch == Patch::Empty {
            "requested"
        } else {
            "late"
        };
        let _ = cached.insert("ipAddress".into(), value.into());
        let _ = cached.insert("userAgent".into(), value.into());
        let _ = cached.insert(
            "updatedAt".into(),
            date(if patch == Patch::Empty { 1 } else { 3 }).into(),
        );
        let _ = cached.insert("expiresAt".into(), date(50).into());
    }
    let mut stored = if write_database {
        cached.clone()
    } else {
        before.clone()
    };
    if write_database && patch == Patch::Values {
        let _ = stored.insert("ipAddress".into(), "stored".into());
        let _ = stored.insert(
            "userAgent".into(),
            if sqlite { "7".into() } else { 7.into() },
        );
        let _ = stored.insert("createdAt".into(), date(4).into());
    }
    let expected = if write_database {
        stored.clone()
    } else {
        cached.clone()
    };
    assert_eq!(FieldMap::from(result), expected);
    assert_eq!(
        *after.lock().unwrap(),
        vec![FieldValue::from(expected.clone()), expected.into()]
    );
    let lookup = stored.get("token").unwrap().as_str().unwrap();
    assert_eq!(
        FieldMap::from(raw.get_session(lookup).await?.unwrap()),
        stored
    );
    let values = cache.values.lock().unwrap().clone();
    assert_eq!(values.len(), 2);
    assert_eq!(
        serde_json::from_str::<Value>(&values[&token])?,
        json!({"session": cached.json()?, "user": user})
    );
    let references = json!([{"token":token,"expiresAt":date(expiration).milliseconds()}]);
    assert_eq!(
        FieldValue::from_json(serde_json::from_str::<Value>(&values[&reference_key])?)?,
        FieldValue::from_json(references)?
    );
    let writes = cache.writes.lock().unwrap();
    assert_eq!(writes.len(), 2);
    assert_eq!(
        (&writes[0].0, writes[0].2),
        (&token, Some(f64::from(expiration)))
    );
    assert_eq!(
        (&writes[1].0, writes[1].2),
        (&reference_key, Some(f64::from(expiration)))
    );
    let first: FieldMap = [
        ("ipAddress".into(), "requested".into()),
        ("userAgent".into(), "requested".into()),
        ("updatedAt".into(), original_date),
        ("expiresAt".into(), date(50).into()),
    ]
    .into();
    let mut second = first.clone();
    let _ = second.insert("token".into(), "in-place".into());
    assert_eq!(*observed.lock().unwrap(), vec![first, second]);
    Ok(())
}

#[tokio::test]
async fn secondary_session_updates_preserve_actual_data_nullish_dates_original_keys_and_ttl()
-> AuthResult<()> {
    for write_database in [false, true] {
        for patch in [Patch::Values, Patch::Empty, Patch::Continue] {
            for nullish in if !write_database && patch == Patch::Values {
                vec![FieldValue::Undefined, FieldValue::Null]
            } else {
                vec![FieldValue::Undefined]
            } {
                check(
                    Arc::new(EphemeralStore::new(Arc::new(AuthConfig::default()))),
                    false,
                    write_database,
                    patch,
                    nullish.clone(),
                )
                .await?;
                let db = Database::connect("sqlite::memory:").await.unwrap();
                migrator::run_migrations(&db).await.unwrap();
                check(
                    Arc::new(SeaOrmStore::<BundledSchema>::new(AuthConfig::default(), db)),
                    true,
                    write_database,
                    patch,
                    nullish,
                )
                .await?;
            }
        }
    }
    Ok(())
}

struct Aliases(FieldValue);

#[better_auth::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for Aliases {
    async fn before_update_session(
        &self,
        data: &mut FieldMap,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        assert_eq!(data["ipAddress"], FieldValue::from("requested"));
        assert_eq!(data["userAgent"], FieldValue::from("requested"));
        Ok(DatabaseHookUpdate::Patch(
            [
                ("first".into(), self.0.clone()),
                ("second".into(), self.0.clone()),
                ("ipAddress".into(), FieldValue::Undefined),
                ("userAgent".into(), 7.into()),
            ]
            .into(),
        ))
    }
}

async fn check_writer<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>) -> AuthResult<()> {
    let (_, session) = seed(raw.as_ref()).await?;
    let marker: FieldValue = FieldMap::from([("native".into(), FieldValue::Undefined)]).into();
    let expected = marker.clone();
    let token = session.token.typed()?.clone();
    let captured = session.clone();
    let store = raw.with_runtime(
        Arc::new(AuthConfig::default()),
        vec![Arc::new(Aliases(marker))],
        Default::default(),
    )?;
    let result = store
        .update_session_with_writer(
            &token,
            SessionUpdate {
                ip_address: Some(Some("requested".into())),
                user_agent: Some(Some("requested".into())),
                ..Default::default()
            },
            Some(SessionUpdateWriter {
                write_database: false,
                write: Box::new(move |fields| {
                    Box::pin(async move {
                        assert!(fields["first"].strict_equals(&expected));
                        assert!(fields["second"].strict_equals(&expected));
                        assert!(fields.contains_key("ipAddress"));
                        assert!(fields["ipAddress"].is_undefined());
                        assert_eq!(fields["userAgent"], FieldValue::Number(7.0));
                        assert_eq!(fields.len(), 4);
                        Ok(Some(captured))
                    })
                }),
            }),
        )
        .await?;
    assert_eq!(result, Some(session.clone()));
    assert_eq!(raw.get_session(&token).await?, Some(session));
    Ok(())
}

#[tokio::test]
async fn session_update_writer_keeps_native_patch_identity_until_the_custom_write_boundary()
-> AuthResult<()> {
    check_writer(Arc::new(EphemeralStore::new(Arc::new(
        AuthConfig::default(),
    ))))
    .await?;
    let db = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&db).await.unwrap();
    check_writer(Arc::new(SeaOrmStore::<BundledSchema>::new(
        AuthConfig::default(),
        db,
    )))
    .await?;
    Ok(())
}

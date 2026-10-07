use super::*;
use better_auth_core::Passkey;
use std::collections::BTreeMap;

const ROWS: [(&str, &str, &str); 2] = [
    (
        "Desk",
        "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4",
        "adce0002-35bc-c60a-648b-0b25f1f05503",
    ),
    (
        "Travel",
        "dd4ec289-e01d-41c9-bb89-70fa845d4bf2",
        "08987058-cadc-4b81-b6e1-30de50dcbe96",
    ),
];
const OUTPUT_ERROR: &str = "ordinary live Passkey output error";
type Trace = Arc<Mutex<BTreeMap<&'static str, Vec<Value>>>>;

#[expect(
    clippy::expect_used,
    reason = "Each selected row must retain every callback event"
)]
fn push(events: &Trace, key: &'static str, event: Value) {
    events
        .lock()
        .expect("Passkey trace lock")
        .get_mut(key)
        .expect("selected Passkey trace")
        .push(event);
}

fn passkey_input(owner: &str, key: &str, before: &str) -> CreatePasskey {
    let mut value = input(owner, key);
    value.aaguid = Some(before.to_owned()).into();
    value
}

fn visible(row: &Passkey, stored: &[Passkey], owner: &str, path: &str) -> AuthResult<Value> {
    let (key, _, _) = ROWS
        .iter()
        .find(|(key, _, _)| row.credential_id == format!("credential:{key}"))
        .ok_or_else(|| AuthError::internal("Unexpected selected Passkey credential"))?;
    let source = stored
        .iter()
        .find(|source| source.credential_id == row.credential_id)
        .ok_or_else(|| AuthError::internal("Selected Passkey is no longer stored"))?;
    assert!(!row.id.typed()?.is_empty());
    assert_eq!(row.id, source.id);
    assert_eq!(row.user_id, owner);
    assert_eq!(row.public_key, "ordinary-public-key");
    assert_eq!(row.counter, u64::from(path == "update-auth"));
    assert_eq!(row.device_type, "singleDevice");
    assert!(!row.backed_up);
    assert_eq!(row.transports, None);
    assert_eq!(row.credential.typed()?, "ordinary-private-record");
    assert!(row.created_at.typed()?.is_some());
    assert_eq!(row.created_at, source.created_at);
    Ok(json!({
        "id": format!("<{key}-id>"), "name": row.name,
        "publicKey": row.public_key, "userId": "<owner-id>",
        "credentialID": row.credential_id, "counter": row.counter,
        "deviceType": row.device_type, "backedUp": row.backed_up,
        "transports": row.transports, "createdAt": "<created-at>", "aaguid": row.aaguid,
    }))
}

#[expect(
    clippy::expect_used,
    reason = "The paired contract requires complete scenarios, selected rows, declared string fields, and callback traces"
)]
async fn observe<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>, case: &Value) -> AuthResult<Value> {
    let path = case["path"].as_str().expect("captured path");
    let configured = case["configuredAaguid"]
        .as_bool()
        .expect("captured field policy");
    let failure = case["failOutput"].as_bool().expect("captured error policy");
    let owner = owner(raw.as_ref(), "live-passkey").await?;
    let mut writers = BTreeMap::new();
    for (key, _, after) in ROWS {
        let writer = BetterAuth::new(config())
            .store_arc(raw.clone())
            .plugin(Fields(vec![(
                EntityRole::Passkey,
                fields(
                    "aaguid",
                    UserFieldConfig {
                        required: Some(false),
                        on_update: Some(Arc::new(move || after.into())),
                        ..Default::default()
                    },
                ),
            )]))
            .build()
            .await?;
        let _ = writers.insert(key, writer.store().clone());
    }
    let writers = Arc::new(writers);
    let selected = if path == "list" {
        &ROWS[..]
    } else {
        &ROWS[..1]
    };
    let events: Trace = Arc::new(Mutex::new(
        selected
            .iter()
            .map(|(key, _, _)| (*key, Vec::new()))
            .collect(),
    ));
    let name_events = events.clone();
    let name_policy = UserFieldConfig {
        required: Some(false),
        transform: Some(FieldTransforms {
            output: Some(UserFieldTransform::new_async(move |value| {
                let writers = writers.clone();
                let events = name_events.clone();
                async move {
                    let name = value.as_str().expect("stored Passkey name");
                    let (key, _, after) = ROWS
                        .iter()
                        .find(|(key, _, _)| name == *key || name == format!("{key}-renamed"))
                        .expect("selected Passkey name");
                    push(&events, key, json!(["name", name]));
                    let writer = writers.get(key).expect("callback writer");
                    let stored = writer
                        .get_passkey_by_credential_id(&format!("credential:{key}"))
                        .await?
                        .expect("selected Passkey exists");
                    let updated = writer.update_passkey_name(stored.id.typed()?, name).await?;
                    assert_eq!(updated.name.typed()?.as_deref(), Some(name));
                    assert_eq!(updated.aaguid.typed()?.as_deref(), Some(*after));
                    push(
                        &events,
                        key,
                        json!(["write", {"name": updated.name, "aaguid": updated.aaguid}]),
                    );
                    Ok(format!("{name}:out").into())
                }
            })),
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut policies = fields("name", name_policy);
    if configured {
        let aaguid_events = events.clone();
        let _ = policies.fields_mut().insert(
            "aaguid".into(),
            UserFieldConfig {
                required: Some(false),
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new(move |value| {
                        let aaguid = value.as_str().expect("stored Passkey AAGUID");
                        let (key, _, _) = ROWS
                            .iter()
                            .find(|(_, before, after)| aaguid == *before || aaguid == *after)
                            .expect("declared Passkey AAGUID");
                        push(&aaguid_events, key, json!(["aaguid", aaguid]));
                        if failure {
                            return Err(AuthError::internal(OUTPUT_ERROR));
                        }
                        Ok(aaguid.to_ascii_uppercase().into())
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
    }
    let reader = BetterAuth::new(config())
        .store_arc(raw.clone())
        .plugin(Fields(vec![(EntityRole::Passkey, policies)]))
        .build()
        .await?;
    let mut seeded = Vec::new();
    if path != "create" {
        for (key, before, _) in selected {
            seeded.push(
                raw.create_passkey(passkey_input(&owner, key, before))
                    .await?,
            );
        }
    }
    let result = match path {
        "create" => reader
            .store()
            .create_passkey(passkey_input(&owner, ROWS[0].0, ROWS[0].1))
            .await
            .map(|row| vec![row]),
        "get-id" => reader
            .store()
            .get_passkey_by_id(seeded[0].id.typed()?)
            .await
            .map(|row| vec![row.expect("selected Passkey exists")]),
        "get-credential" => reader
            .store()
            .get_passkey_by_credential_id(&seeded[0].credential_id)
            .await
            .map(|row| vec![row.expect("selected Passkey exists")]),
        "list" => reader.store().list_passkeys_by_user(&owner).await,
        "update-name" => reader
            .store()
            .update_passkey_name(seeded[0].id.typed()?, "Desk-renamed")
            .await
            .map(|row| vec![row]),
        "update-auth" => reader
            .store()
            .update_passkey_authentication(
                &seeded[0].id,
                UpdatePasskeyAuthentication::Legacy {
                    credential: seeded[0].credential.typed()?.clone(),
                    counter: 1,
                    backed_up: seeded[0].backed_up,
                    device_type: seeded[0].device_type.clone(),
                },
            )
            .await
            .map(|row| vec![row]),
        _ => return Err(AuthError::internal("Unknown Passkey live-field path")),
    };
    let (result, error) = match result {
        Ok(rows) => (Some(rows), Value::Null),
        Err(AuthError::Internal(message)) if message == OUTPUT_ERROR => {
            (None, json!({"sameError": true, "message": message}))
        }
        Err(error) => return Err(error),
    };
    assert_eq!(!error.is_null(), failure);
    let stored = raw.list_passkeys_by_user(&owner).await?;
    assert_eq!(
        stored
            .iter()
            .map(|row| row.credential_id.clone())
            .collect::<Vec<_>>(),
        selected
            .iter()
            .map(|(key, _, _)| format!("credential:{key}"))
            .collect::<Vec<_>>()
    );
    let normalize = |rows: &[Passkey]| {
        rows.iter()
            .map(|row| visible(row, &stored, &owner, path))
            .collect::<AuthResult<Vec<_>>>()
    };
    Ok(json!({
        "path": path, "configuredAaguid": configured, "failOutput": failure,
        "events": *events.lock().expect("Passkey trace lock"),
        "result": result.as_deref().map(normalize).transpose()?, "error": error,
        "stored": normalize(&stored)?,
    }))
}

#[expect(
    clippy::expect_used,
    reason = "The paired contract requires all nine captured cases per backend"
)]
async fn contract(backend: &str) -> AuthResult<()> {
    let fixture: Value =
        serde_json::from_str(include_str!("../fixtures/passkey-live-fields-1.7.6.json"))?;
    assert_eq!(fixture["version"], "1.7.6");
    let backends = fixture["backends"].as_array().expect("captured backends");
    assert_eq!(
        backends
            .iter()
            .map(|case| case["backend"].as_str())
            .collect::<Vec<_>>(),
        [Some("memory"), Some("sqlite")]
    );
    let cases = backends
        .iter()
        .find(|case| case["backend"] == backend)
        .expect("captured backend")["cases"]
        .as_array()
        .expect("captured cases");
    assert_eq!(cases.len(), 9);
    for case in cases {
        let observed = if backend == "memory" {
            observe(memory(), case).await?
        } else {
            observe(sqlite().await?, case).await?
        };
        assert_eq!(observed, *case, "{backend} Passkey live-field observation");
    }
    Ok(())
}

#[tokio::test]
async fn memory_passkey_outputs_observe_callback_writes_to_later_fields() -> AuthResult<()> {
    contract("memory").await
}

#[tokio::test]
async fn sqlite_passkey_outputs_retain_the_selected_field_snapshot() -> AuthResult<()> {
    contract("sqlite").await
}

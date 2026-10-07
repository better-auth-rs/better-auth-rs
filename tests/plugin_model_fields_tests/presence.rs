use super::*;
use better_auth::plugins::passkey::PasskeyPlugin;
use better_auth::server_api::EndpointInput;
use better_auth_core::{HttpMethod, SchemaValue, entity::AuthSession, wire::PasskeyView};

const AAGUID: &str = "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4";

pub(super) fn describe(value: &Option<Value>) -> String {
    value
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_else(|| "undefined".into())
}

pub(super) fn assert_display(row: &Value, field: &str, expected: Option<Value>) {
    assert_eq!(row.get(field), expected.as_ref());
}

pub(super) async fn token<S: AuthSchema>(auth: &BetterAuth<S>, owner: &str) -> AuthResult<String> {
    let session = auth
        .store()
        .create_session(CreateSession {
            user_id: owner.into(),
            expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).into(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            additional_fields: Default::default(),
        })
        .await?;
    Ok(session.token().to_owned())
}

pub(super) async fn read<S: AuthSchema>(
    auth: &BetterAuth<S>,
    token: &str,
    path: &str,
    query: Option<Value>,
) -> AuthResult<Value> {
    let response = auth
        .call_endpoint(
            HttpMethod::Get,
            path,
            EndpointInput {
                headers: Some([("authorization".into(), format!("Bearer {token}"))].into()),
                query,
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(response.status, 200);
    Ok(serde_json::from_slice(&response.body.bytes()?)?)
}

async fn passkey_contract<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>, sql: bool) -> AuthResult<()> {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let output = Arc::new(Mutex::new(None::<FieldValue>));
    let policy = |field: &'static str| {
        let input_trace = trace.clone();
        let output_trace = trace.clone();
        let output = output.clone();
        UserFieldConfig {
            required: Some(false),
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    input_trace
                        .lock()
                        .unwrap()
                        .push(format!("input:{field}:{}", describe(&value.json()?)));
                    Ok(value)
                })),
                output: Some(UserFieldTransform::new(move |value| {
                    output_trace
                        .lock()
                        .unwrap()
                        .push(format!("output:{field}:{}", describe(&value.json()?)));
                    Ok(output.lock().unwrap().clone().unwrap_or(value))
                })),
            }),
            ..Default::default()
        }
    };
    let mut cfg = config();
    cfg.session.bearer = Some(Default::default());
    let auth = BetterAuth::new(cfg)
        .store_arc(raw.clone())
        .plugin(PasskeyPlugin::new())
        .plugin(Fields(vec![(
            EntityRole::Passkey,
            UserConfig {
                additional_fields: Some(
                    [
                        ("name".into(), policy("name")),
                        ("aaguid".into(), policy("aaguid")),
                    ]
                    .into(),
                ),
            },
        )]))
        .build()
        .await?;
    let owner = owner(raw.as_ref(), "display-passkey").await?;
    let token = token(&auth, &owner).await?;
    let mut data = input(&owner, "Desk");
    data.aaguid = Some(AAGUID.into()).into();
    let created = auth.store().create_passkey(data).await?;
    assert_eq!(
        *trace.lock().unwrap(),
        [
            "input:name:\"Desk\"",
            &format!("input:aaguid:\"{AAGUID}\""),
            "output:name:\"Desk\"",
            &format!("output:aaguid:\"{AAGUID}\""),
        ]
    );
    trace.lock().unwrap().clear();
    for expected in [
        Some(json!("Display label")),
        Some(json!("")),
        Some(Value::Null),
        None,
    ] {
        *output.lock().unwrap() = Some(
            expected
                .clone()
                .map(FieldValue::from_json)
                .transpose()?
                .unwrap_or(FieldValue::Undefined),
        );
        let rows = auth.store().list_passkeys_by_user(&owner).await?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name.json()?, expected);
        assert_eq!(rows[0].aaguid.json()?, expected);
        let view = serde_json::to_value(PasskeyView::from(&rows[0]))?;
        for field in ["name", "aaguid"] {
            assert_display(&view, field, expected.clone());
        }
        assert_eq!(
            *trace.lock().unwrap(),
            [
                "output:name:\"Desk\"",
                &format!("output:aaguid:\"{AAGUID}\"")
            ]
        );
        trace.lock().unwrap().clear();
        let body = read(&auth, &token, "/passkey/list-user-passkeys", None).await?;
        assert_eq!(body.as_array().unwrap().len(), 1);
        for field in ["name", "aaguid"] {
            assert_display(&body[0], field, expected.clone());
        }
        assert_eq!(
            *trace.lock().unwrap(),
            [
                "output:name:\"Desk\"",
                &format!("output:aaguid:\"{AAGUID}\"")
            ]
        );
        trace.lock().unwrap().clear();
    }
    let stored = raw.get_passkey_by_id(created.id.typed()?).await?.unwrap();
    assert_eq!(stored.name, Some("Desk".into()));
    assert_eq!(stored.aaguid, Some(AAGUID.into()));
    *output.lock().unwrap() = None;
    for null in [false, true] {
        let mut data = input(&owner, if null { "null" } else { "omitted" });
        data.name = if null {
            None.into()
        } else {
            SchemaValue::Undefined
        };
        data.aaguid = data.name.clone();
        let row = auth.store().create_passkey(data).await?;
        let expected_input = if null { Some(Value::Null) } else { None };
        let expected_output = if sql || null { Some(Value::Null) } else { None };
        assert_eq!(
            *trace.lock().unwrap(),
            [
                format!("input:name:{}", describe(&expected_input)),
                format!("input:aaguid:{}", describe(&expected_input)),
                format!("output:name:{}", describe(&expected_output)),
                format!("output:aaguid:{}", describe(&expected_output)),
            ]
        );
        trace.lock().unwrap().clear();
        assert_eq!(row.name.json()?, expected_output);
        assert_eq!(row.aaguid.json()?, expected_output);
    }
    *output.lock().unwrap() = Some(42.0.into());
    assert!(
        auth.store()
            .update_passkey_name(created.id.typed()?, "Updated display")
            .await
            .is_err()
    );
    assert_eq!(
        raw.get_passkey_by_id(created.id.typed()?)
            .await?
            .unwrap()
            .name,
        Some("Updated display".into())
    );
    Ok(())
}

#[tokio::test]
async fn memory_display_presence_reaches_passkey_callbacks_and_public_json() -> AuthResult<()> {
    passkey_contract(memory(), false).await
}

#[tokio::test]
async fn sqlite_display_presence_reaches_passkey_callbacks_and_public_json() -> AuthResult<()> {
    passkey_contract(sqlite().await?, true).await
}

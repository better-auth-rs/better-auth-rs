use super::*;
use crate::user_fields::UserFieldConfig;
use serde_json::{Value as JsonValue, json};

const CREATED_AT: &str = "2030-01-02T03:04:05.000Z";
const EXPIRES_AT: &str = "2100-01-02T03:04:05.000Z";
const CHANGED_AT: &str = "2031-01-02T03:04:05.000Z";
const CHANGED_EXPIRY: &str = "2101-01-02T03:04:05.000Z";
const ROWS: [(&str, &str, &str); 2] = [
    ("Desk", "live-session-desk", "00101"),
    ("Travel", "live-session-travel", "00102"),
];

#[derive(Clone)]
struct GeneratedSession {
    token: String,
    created_at: crate::FieldDate,
    updated_at: crate::FieldDate,
}

#[derive(Default)]
struct Observations {
    events: Vec<JsonValue>,
    generated: Option<GeneratedSession>,
}

type Trace = Arc<Mutex<Observations>>;

fn required<T>(value: Option<T>, context: &str) -> AuthResult<T> {
    value.ok_or_else(|| AuthError::internal(context))
}

fn trace_lock(trace: &Trace) -> AuthResult<MutexGuard<'_, Observations>> {
    trace
        .lock()
        .map_err(|_| AuthError::internal("Session live-output trace lock poisoned"))
}

fn date(value: &str) -> AuthResult<crate::FieldDate> {
    value
        .parse::<DateTime<Utc>>()
        .map(Into::into)
        .map_err(|error| {
            AuthError::internal(format!("Invalid Session live-output fixture date: {error}"))
        })
}

fn observe_fields(fields: FieldMap) -> AuthResult<JsonValue> {
    let mut observed = serde_json::Map::new();
    for (name, value) in fields {
        let value = match &value {
            Value::Undefined => json!({"type":"undefined"}),
            Value::Date(_) => {
                json!({"type":"date", "value":required(value.json()?, "Fixture date must serialize")?})
            }
            value => required(value.json()?, "Fixture field must serialize")?,
        };
        let _ = observed.insert(name, value);
    }
    Ok(JsonValue::Object(observed))
}

fn observe_session(row: &SessionView, trace: &Trace) -> AuthResult<JsonValue> {
    let generated = trace_lock(trace)?.generated.clone();
    let mut row = row.clone();
    if let Some(generated) = generated {
        // Rust creates the token and dates internally. Normalize only the same generated values across every observation.
        assert_eq!(row.token, generated.token);
        assert_eq!(row.created_at, generated.created_at);
        if row.updated_at == generated.updated_at {
            row.updated_at = date(CREATED_AT)?;
        }
        row.token = "live-session-desk".into();
        row.created_at = date(CREATED_AT)?;
    }
    assert!(row.active);
    observe_fields(row.into())
}

fn observe_user(row: &UserView, raw: bool) -> AuthResult<JsonValue> {
    if !raw {
        return observe_fields(row.clone().into());
    }
    let mut fields = FieldMap::new();
    for name in [
        "name",
        "email",
        "emailVerified",
        "image",
        "createdAt",
        "updatedAt",
        "id",
    ] {
        let _ = fields.insert(
            name.into(),
            required(
                row.native_field_value(name),
                "Raw owner must contain every native user field",
            )?,
        );
    }
    observe_fields(fields)
}

fn observe_memory(store: &EphemeralStore, trace: &Trace) -> AuthResult<JsonValue> {
    let state = store.lock()?;
    let users = state
        .users
        .snapshot()?
        .iter()
        .map(|row| observe_user(row, true))
        .collect::<AuthResult<Vec<_>>>()?;
    let sessions = state
        .sessions
        .snapshot()?
        .iter()
        .map(|row| observe_session(row, trace))
        .collect::<AuthResult<Vec<_>>>()?;
    assert!(state.accounts.snapshot()?.is_empty());
    assert!(state.verifications.snapshot()?.is_empty());
    Ok(json!({"user":users, "account":[], "session":sessions, "verification":[]}))
}

fn session_input(label: &str) -> AuthResult<CreateSession> {
    Ok(CreateSession {
        user_id: "1".into(),
        expires_at: date(EXPIRES_AT)?,
        ip_address: Some(String::new()),
        user_agent: Some(String::new()),
        impersonated_by: None,
        active_organization_id: None,
        additional_fields: [
            ("label".into(), label.into()),
            ("tail".into(), format!("before:{label}").into()),
        ]
        .into(),
    })
}

fn reader(writer: &EphemeralStore, path: &str, trace: &Trace) -> EphemeralStore {
    let started = Utc::now().timestamp_millis() as f64;
    let mut reader = writer.clone();
    let mut config = writer.config.as_ref().clone();
    config.advanced.database.joins = Some(path == "get-native-join");
    reader.config = Arc::new(config);
    let output_writer = writer.clone();
    let output_trace = trace.clone();
    let create = path == "create";
    let tail_trace = trace.clone();
    reader.session_config.additional_fields = Some(
        [
            (
                "label".into(),
                UserFieldConfig {
                    transform: Some(FieldTransforms {
                        input: None,
                        output: Some(UserFieldTransform::new_async(move |value| {
                            let writer = output_writer.clone();
                            let trace = output_trace.clone();
                            async move {
                                let label = required(
                                    value.as_str(),
                                    "Session output must contain a label",
                                )?;
                                let (_, _, id) = required(
                                    ROWS.iter().find(|(candidate, _, _)| *candidate == label),
                                    "Session output must name a declared fixture row",
                                )?;
                                let stored = required(
                                    writer.lock()?.sessions.find(|row| {
                                        row.additional_fields.get("label").and_then(Value::as_str)
                                            == Some(label)
                                    })?,
                                    "Callback writer must find the selected Session",
                                )?;
                                if create {
                                    assert!(!stored.token.is_empty());
                                    let ended = Utc::now().timestamp_millis() as f64;
                                    assert!(
                                        (started..=ended)
                                            .contains(&stored.created_at.milliseconds())
                                    );
                                    assert!(
                                        (started..=ended)
                                            .contains(&stored.updated_at.milliseconds())
                                    );
                                    trace_lock(&trace)?.generated = Some(GeneratedSession {
                                        token: stored.token.clone(),
                                        created_at: stored.created_at.clone(),
                                        updated_at: stored.updated_at.clone(),
                                    });
                                }
                                trace_lock(&trace)?.events.push(json!(["label", label]));
                                let updated = required(
                                    writer
                                        .update_session_with_hooks(
                                            &stored.token,
                                            SessionUpdate {
                                                id: Some((*id).into()),
                                                expires_at: Some(date(CHANGED_EXPIRY)?),
                                                updated_at: Some(date(CHANGED_AT)?),
                                                additional_fields: [(
                                                    "tail".into(),
                                                    format!("after:{label}").into(),
                                                )]
                                                .into(),
                                                ..Default::default()
                                            },
                                        )
                                        .await?,
                                    "Callback writer must update the selected Session",
                                )?;
                                let observed = observe_session(&updated, &trace)?;
                                trace_lock(&trace)?
                                    .events
                                    .push(json!(["write", label, observed]));
                                Ok(format!("{label}:out").into())
                            }
                        })),
                    }),
                    ..Default::default()
                },
            ),
            (
                "tail".into(),
                UserFieldConfig {
                    transform: Some(FieldTransforms {
                        input: None,
                        output: Some(UserFieldTransform::new(move |value| {
                            let tail =
                                required(value.as_str(), "Session output must contain a tail")?;
                            trace_lock(&tail_trace)?.events.push(json!(["tail", tail]));
                            Ok(format!("{tail}:out").into())
                        })),
                    }),
                    ..Default::default()
                },
            ),
        ]
        .into(),
    );
    reader
}

async fn capture(path: &str) -> AuthResult<JsonValue> {
    let trace = Trace::default();
    let mut config = AuthConfig::default();
    config.advanced.database.generate_id = Some(crate::id::IdGeneration::Serial);
    config.session.additional_fields = Some(
        [
            ("label".into(), UserFieldConfig::default()),
            ("tail".into(), UserFieldConfig::default()),
        ]
        .into(),
    );
    let writer = EphemeralStore::new(Arc::new(config));
    let user = writer
        .create_user(CreateUser {
            name: Some("Session owner".into()).into(),
            email: Some("owner@session-live-output.test".into()),
            email_verified: Some(false),
            image: None::<String>.into(),
            created_at: Some(date(CREATED_AT)?),
            updated_at: Some(date(CREATED_AT)?),
            ..Default::default()
        })
        .await?;
    assert_eq!(user.id, "1");
    let reader = reader(&writer, path, &trace);
    let selected = if path == "list" {
        ROWS.as_slice()
    } else {
        &ROWS[..1]
    };
    let (first, token, _) = required(selected.first(), "Scenario must select a Session")?;
    if path != "create" {
        for (label, token, _) in selected {
            let seeded = writer.create_session(session_input(label)?).await?;
            let _ = required(
                writer
                    .update_session_with_hooks(
                        &seeded.token,
                        SessionUpdate {
                            token: Some((*token).into()),
                            created_at: Some(date(CREATED_AT)?),
                            updated_at: Some(date(CREATED_AT)?),
                            ..Default::default()
                        },
                    )
                    .await?,
                "Seeded Session must remain stored",
            )?;
        }
    }
    let before = observe_memory(&writer, &trace)?;
    let result = match path {
        "create" => observe_session(&reader.create_session(session_input(first)?).await?, &trace)?,
        "get-native-join" => {
            let (_, joined) = required(
                reader.get_session_snapshot(token).await?,
                "Native join must find the Session",
            )?;
            let joined = required(joined, "Native join must find the owner")?;
            let user = UserView::with_field_policies(
                &joined.user,
                &reader.config.user,
                &reader.config.user,
                &Default::default(),
                true,
            )
            .await?;
            json!({"session":observe_session(&joined.session, &trace)?, "user":observe_user(&user, false)?})
        }
        "list" => JsonValue::Array(
            reader
                .get_user_sessions("1")
                .await?
                .iter()
                .map(|row| observe_session(row, &trace))
                .collect::<AuthResult<Vec<_>>>()?,
        ),
        "update" => observe_session(
            &required(
                reader
                    .update_session_with_hooks(
                        token,
                        SessionUpdate {
                            updated_at: Some(date(CREATED_AT)?),
                            additional_fields: [("label".into(), (*first).into())].into(),
                            ..Default::default()
                        },
                    )
                    .await?,
                "Updated Session must remain stored",
            )?,
            &trace,
        )?,
        _ => {
            return Err(AuthError::internal(format!(
                "Unknown Session live-output path: {path}"
            )));
        }
    };
    let after = observe_memory(&writer, &trace)?;
    let events = trace_lock(&trace)?.events.clone();
    Ok(json!({"path":path, "before":before, "events":events, "result":result, "after":after}))
}

#[tokio::test]
async fn memory_session_live_output_matches_four_upstream_paths() -> AuthResult<()> {
    let fixture: JsonValue = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/session-live-output-1.7.6.json"
    )))?;
    assert_eq!(fixture.get("version"), Some(&json!("1.7.6")));
    assert_eq!(fixture.get("backend"), Some(&json!("memory")));
    assert_eq!(fixture.get("idSlot"), Some(&json!("implicit")));
    let cases = required(
        fixture.get("cases").and_then(JsonValue::as_array),
        "Session fixture must contain cases",
    )?;
    let paths = ["create", "get-native-join", "list", "update"];
    assert_eq!(cases.len(), paths.len());
    for (expected, path) in cases.iter().zip(paths) {
        assert_eq!(
            capture(path).await?,
            *expected,
            "Session live-output path {path}"
        );
    }
    Ok(())
}

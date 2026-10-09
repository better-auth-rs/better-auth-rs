use super::*;
use crate::id::{IdGeneration, IdGenerator};
use crate::organization_fields::OrganizationFields;
use crate::user_fields::{
    FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
};
use serde_json::{Value as JsonValue, json};
use std::sync::atomic::{AtomicUsize, Ordering};

mod organization;

const FIELDS: [(&str, &str, UserFieldType); 5] = [
    ("settings", "stored_settings", UserFieldType::Json),
    (
        "nullableSettings",
        "stored_nullable_settings",
        UserFieldType::Json,
    ),
    (
        "encodedSettings",
        "stored_encoded_settings",
        UserFieldType::Json,
    ),
    ("labels", "stored_labels", UserFieldType::StringArray),
    (
        "displayOrder",
        "stored_display_order",
        UserFieldType::NumberArray,
    ),
];

type Events = Arc<Mutex<Vec<JsonValue>>>;

fn transform(
    events: &Events,
    phase: &'static str,
    model: &'static str,
    field: &'static str,
) -> UserFieldTransform {
    let events = events.clone();
    UserFieldTransform::new(move |value| {
        if value.is_undefined() {
            return Err(AuthError::internal("Expected the supplied display field"));
        }
        events
            .lock()
            .map_err(|_| AuthError::internal("Display event lock poisoned"))?
            .push(json!([phase, model, field, value.json()?]));
        Ok(value)
    })
}

fn fields(model: &'static str, events: &Events) -> UserConfig {
    UserConfig {
        additional_fields: Some(
            FIELDS
                .into_iter()
                .map(|(name, alias, field_type)| {
                    (
                        name.into(),
                        UserFieldConfig {
                            field_type,
                            field_name: Some(alias.into()),
                            required: Some(false),
                            transform: Some(FieldTransforms {
                                input: Some(transform(events, "input", model, name)),
                                output: Some(transform(events, "output", model, name)),
                            }),
                            ..Default::default()
                        },
                    )
                })
                .collect(),
        ),
    }
}

fn input(label: &str, updated: bool) -> FieldMap {
    [
        (
            "settings".into(),
            FieldMap::from_iter([("label".into(), label.into())]).into(),
        ),
        ("nullableSettings".into(), Value::Null),
        (
            "encodedSettings".into(),
            Value::from(if updated {
                r#"{"kind":"updated"}"#
            } else {
                r#"{"kind":"text"}"#
            }),
        ),
        (
            "labels".into(),
            if updated {
                vec!["updated".into()].into()
            } else {
                vec!["alpha".into(), "beta".into()].into()
            },
        ),
        (
            "displayOrder".into(),
            if updated {
                vec![3.into()].into()
            } else {
                vec![1.into(), 2.into()].into()
            },
        ),
    ]
    .into_iter()
    .collect()
}

fn display(fields: &FieldMap) -> AuthResult<JsonValue> {
    let fields = FIELDS
        .iter()
        .map(|(name, _, _)| {
            fields
                .get(*name)
                .cloned()
                .map(|value| ((*name).to_owned(), value))
                .ok_or_else(|| {
                    AuthError::internal(format!("Missing returned display field {name}"))
                })
        })
        .collect::<AuthResult<FieldMap>>()?;
    Ok(JsonValue::Object(fields.json()?))
}

struct Fixture {
    store: EphemeralStore,
    events: Events,
}

impl Fixture {
    fn new() -> AuthResult<Self> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut config = AuthConfig::default();
        config.user = fields("user", &events);
        config.session.additional_fields = fields("session", &events).additional_fields;
        config.advanced.database.joins = Some(true);
        let next_id = AtomicUsize::new(1);
        config.advanced.database.generate_id =
            Some(IdGeneration::Custom(IdGenerator::new(move |_| {
                Ok(Some(next_id.fetch_add(1, Ordering::Relaxed).to_string()))
            })));
        let store = EphemeralStore::new(Arc::new(config));
        store.configure_organization_fields(OrganizationFields {
            organization: fields("organization", &events),
            member: fields("member", &events),
            invitation: fields("invitation", &events),
            team: fields("team", &events),
            organization_role: fields("organizationRole", &events),
        })?;
        Ok(Self { store, events })
    }

    fn stored_physical(
        &self,
        model: &str,
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<JsonValue> {
        let state = self.store.lock()?;
        let fields = match model {
            "user" => state.users.get(id)?.map(|row| row.additional_fields),
            "session" => state.sessions.get(id)?.map(|row| row.additional_fields),
            "organization" => state.organizations.get(id)?,
            "member" => state.members.get(id)?,
            "invitation" => state.invitations.get(id)?,
            "team" => state.teams.get(id)?,
            "organizationRole" => state.organization_roles.get(id)?,
            _ => return Err(AuthError::internal("Unknown display fixture model")),
        }
        .ok_or_else(|| AuthError::internal("Expected the stored display row"))?;
        let fields = FIELDS
            .iter()
            .map(|(_, alias, _)| {
                fields
                    .get(*alias)
                    .cloned()
                    .map(|value| ((*alias).to_owned(), value))
                    .ok_or_else(|| {
                        AuthError::internal(format!("Missing stored display field {alias}"))
                    })
            })
            .collect::<AuthResult<FieldMap>>()?;
        Ok(json!({"model": model, "fields": fields.json()?}))
    }

    fn observe(
        &self,
        operations: &mut Vec<JsonValue>,
        name: &str,
        result: JsonValue,
        rows: &[(&str, &crate::SchemaValue<String>)],
    ) -> AuthResult<()> {
        let stored = rows
            .iter()
            .map(|(model, id)| self.stored_physical(model, id))
            .collect::<AuthResult<Vec<_>>>()?;
        let events = std::mem::take(
            &mut *self
                .events
                .lock()
                .map_err(|_| AuthError::internal("Display event lock poisoned"))?,
        );
        operations.push(
            json!({"name": name, "events": events, "result": result, "storedPhysical": stored}),
        );
        Ok(())
    }

    fn point(
        &self,
        operations: &mut Vec<JsonValue>,
        name: &str,
        model: &str,
        id: &crate::SchemaValue<String>,
        fields: &FieldMap,
    ) -> AuthResult<()> {
        self.observe(operations, name, display(fields)?, &[(model, id)])
    }
}

async fn users(fixture: &Fixture) -> AuthResult<(JsonValue, UserView, UserView)> {
    let mut operations = Vec::new();
    let mut user = CreateUser::new()
        .with_name("Display User A")
        .with_email("user-a@memory-core-json.test");
    user.additional_fields = input("user-a", false);
    let user_a = fixture.store.create_user(user).await?;
    fixture.point(
        &mut operations,
        "create-a",
        "user",
        &user_a.id,
        &user_a.additional_fields,
    )?;
    let mut user = CreateUser::new()
        .with_name("Display User B")
        .with_email("user-b@memory-core-json.test");
    user.additional_fields = input("user-b", false);
    let user_b = fixture.store.create_user(user).await?;
    fixture.point(
        &mut operations,
        "create-b",
        "user",
        &user_b.id,
        &user_b.additional_fields,
    )?;
    let updated = fixture
        .store
        .update_user(
            user_a.id.typed()?,
            UpdateUser {
                additional_fields: input("user-a-updated", true),
                ..Default::default()
            },
        )
        .await?;
    fixture.point(
        &mut operations,
        "update-a",
        "user",
        &user_a.id,
        &updated.additional_fields,
    )?;
    let read = fixture
        .store
        .get_user_by_id(user_a.id.typed()?)
        .await?
        .ok_or_else(|| AuthError::internal("Expected the display user"))?;
    fixture.point(
        &mut operations,
        "read-a",
        "user",
        &user_a.id,
        &read.additional_fields,
    )?;
    Ok((
        json!({"name": "user", "operations": operations}),
        user_a,
        user_b,
    ))
}

async fn sessions(fixture: &Fixture, user: &UserView) -> AuthResult<JsonValue> {
    let mut operations = Vec::new();
    let create = |label| CreateSession {
        inherited_fields: Default::default(),
        additional_fields: input(label, false),
        user_id: user.id.clone(),
        expires_at: (Utc::now() + chrono::Duration::days(7)).into(),
        ip_address: None,
        user_agent: None,
        impersonated_by: None,
        active_organization_id: None,
    };
    let session_a = fixture.store.create_session(create("session-a")).await?;
    fixture.point(
        &mut operations,
        "create-a",
        "session",
        &session_a.id,
        &session_a.additional_fields,
    )?;
    let session_b = fixture.store.create_session(create("session-b")).await?;
    fixture.point(
        &mut operations,
        "create-b",
        "session",
        &session_b.id,
        &session_b.additional_fields,
    )?;
    let updated = fixture
        .store
        .update_session_fields(
            session_a.token.typed().unwrap(),
            input("session-a-updated", true),
        )
        .await?
        .ok_or_else(|| AuthError::internal("Expected the updated display session"))?;
    fixture.point(
        &mut operations,
        "update-a",
        "session",
        &session_a.id,
        &updated.additional_fields,
    )?;
    let sessions = fixture.store.get_user_sessions(user.id.typed()?).await?;
    let result = sessions
        .iter()
        .map(|row| display(&row.additional_fields))
        .collect::<AuthResult<Vec<_>>>()?;
    fixture.observe(
        &mut operations,
        "list",
        json!(result),
        &[("session", &session_a.id), ("session", &session_b.id)],
    )?;
    Ok(json!({"name": "session", "operations": operations}))
}

async fn contract() -> AuthResult<JsonValue> {
    let fixture = Fixture::new()?;
    let (user_group, user_a, user_b) = users(&fixture).await?;
    let session_group = sessions(&fixture, &user_a).await?;
    let (snapshot_group, joined_query_group) =
        organization::groups(&fixture, &user_a, &user_b).await?;
    Ok(
        json!({"version": "1.7.6", "groups": [user_group, session_group, snapshot_group, joined_query_group]}),
    )
}

#[tokio::test]
#[expect(
    clippy::expect_used,
    reason = "The fixture and ordinary adapter operations must succeed before complete contract comparison."
)]
async fn memory_core_json_matches_pinned_display_contract() {
    let expected: JsonValue = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/memory-core-json-1.7.6.json"
    ))
    .expect("Read the pinned Memory display contract");
    let actual = contract().await.expect("Run the Memory display contract");
    assert_eq!(actual, expected);
}

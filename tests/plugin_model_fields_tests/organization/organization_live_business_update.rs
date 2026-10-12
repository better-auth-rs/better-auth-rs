use super::*;
use better_auth::plugins::organization::hooks::{OrganizationActor, OrganizationHooks};
use better_auth_core::{Organization, Utf16String, user_fields::UserFieldFactory};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Metadata {
    Dynamic,
    Utf16,
}

fn values(mode: Metadata, events: &Events) -> (FieldValue, FieldValue) {
    if mode == Metadata::Utf16 {
        let source = Utf16String::from_units(
            r#"{"units":""#.encode_utf16().chain([0xd800])
                .chain(r#"","date":"2030-01-01T00:00:00.000Z"}"#.encode_utf16()).collect(),
        ).into();
        let expected = FieldMap::from_iter([
            ("units".into(), Utf16String::from_units(vec![0xd800]).into()),
            ("date".into(), date().into()),
        ])
        .into();
        return (source, expected);
    }
    let function: UserFieldFactory = UserFieldFactory::new({
        let events = events.clone();
        move || {
            event(&events, ["metadata.function".into(), "called".into()])?;
            Ok("called".into())
        }
    });
    let value: FieldValue = FieldMap::from_iter([
        ("undefined".into(), FieldValue::Undefined),
        ("infinity".into(), f64::INFINITY.into()),
        ("date".into(), date().into()),
        (
            "function".into(),
            better_auth_core::FieldFunction::from(function).into(),
        ),
        (
            "nested".into(),
            FieldMap::from_iter([("value".into(), "retained".into())]).into(),
        ),
    ])
    .into();
    (value.clone(), value)
}

struct Hooks {
    events: Events,
    source: FieldValue,
    mode: Metadata,
    metadata: Arc<Mutex<Option<FieldValue>>>,
}

#[async_trait]
impl OrganizationHooks for Hooks {
    async fn after_update_organization(
        &self,
        organization: &Organization,
        _actor: OrganizationActor<'_>,
    ) -> AuthResult<()> {
        let fields = organization.field_values()?;
        let metadata = required(fields.get("metadata"), "Expected updated metadata")?;
        if self.mode == Metadata::Dynamic {
            assert!(metadata.strict_equals(&self.source));
        }
        *trace_lock(&self.metadata)? = Some(metadata.clone());
        event(
            &self.events,
            ["afterUpdateOrganization".into(), fields.into()],
        )
    }
}

async fn check<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    mode: Metadata,
    native: bool,
) -> AuthResult<()> {
    let token = seed(raw.clone(), false, "user-a").await?;
    let mut before = storage.snapshot_with_roles(true).await?;
    let events = Events::default();
    let (source, metadata) = values(mode, &events);
    let observed = Arc::new(Mutex::new(None));
    let mut plugin = OrganizationConfig {
        dynamic_access_control: true,
        hooks: Some(Arc::new(Hooks {
            events: events.clone(),
            source: source.clone(),
            mode,
            metadata: observed.clone(),
        })),
        ..Default::default()
    };
    plugin.teams.enabled = true;
    let fields = declaration([(
        "metadata",
        UserFieldConfig {
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new({
                    let events = events.clone();
                    move |value| {
                        event(&events, ["metadata".into(), "output".into(), value])?;
                        Ok(source.clone())
                    }
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    )]);
    let auth = BetterAuth::new(settings()?)
        .store_arc(raw)
        .plugin(OrganizationPlugin::with_config(plugin))
        .plugin(Fields(vec![(EntityRole::Organization, fields)]))
        .build()
        .await?;
    let started = chrono::Utc::now().timestamp_millis();
    let actual = call(&auth, &token, native, "update", json!({"organizationId":"organization","data":{"name":"Updated","metadata":{"source":"written"}}})).await?;
    let finished = chrono::Utc::now().timestamp_millis();
    let expected: FieldValue = FieldMap::from_iter([
        ("name".into(), "Updated".into()),
        ("slug".into(), "organization".into()),
        ("logo".into(), FieldValue::Null),
        ("createdAt".into(), date().into()),
        ("metadata".into(), metadata),
        ("id".into(), "organization".into()),
    ])
    .into();
    if native {
        let fields = actual.body.field_value()?.enumerable_fields()?;
        assert!(
            required(fields.get("metadata"), "Expected native response metadata")?.strict_equals(
                required(trace_lock(&observed)?.as_ref(), "Expected hook metadata")?
            )
        );
    }
    response(actual, native, 200, &expected)?;
    let expected_events: Vec<FieldValue> = vec![
        vec![
            "metadata".into(),
            "output".into(),
            r#"{"source":"written"}"#.into(),
        ]
        .into(),
        vec!["afterUpdateOrganization".into(), expected].into(),
    ];
    ordered(
        &trace_lock(&events)?.clone().into(),
        &expected_events.into(),
    )?;
    let row = before
        .get_mut("organization")
        .and_then(|rows| {
            rows.iter_mut()
                .find(|row| row.get("id").and_then(FieldValue::as_str) == Some("organization"))
        })
        .ok_or_else(|| AuthError::internal("Expected stored Organization"))?;
    let _ = row.insert("name".into(), "Updated".into());
    let _ = row.insert("metadata".into(), r#"{"source":"written"}"#.into());
    super::create::check_storage(&storage, before, started, finished, "organization").await
}

#[tokio::test]
async fn organization_update_preserves_native_metadata_and_utf16_before_http_serialization()
-> AuthResult<()> {
    for mode in [Metadata::Dynamic, Metadata::Utf16] {
        for native in [false, true] {
            let (raw, storage) = memory_fixture();
            check(raw, storage, mode, native).await?;
            let (raw, storage) = sqlite_fixture().await?;
            check(raw, storage, mode, native).await?;
        }
    }
    Ok(())
}

use super::*;
use crate::plugins::api_key::{ApiKeyConfig, ApiKeyPlugin, ApiKeyStorage};
use async_trait::async_trait;
use better_auth_core::{
    AuthConfig, AuthContext, AuthPlugin, StatelessSchema,
    plugin_runtime::ModelFields,
    store::{
        ConsumeApiKeyResult, EphemeralStore, RuntimeStore, SecondaryStorage, schema::EntityRole,
    },
    user_fields::{
        FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
    },
};

fn database_snapshot(raw: &EphemeralStore) -> AuthResult<FieldValue> {
    [
        ("user", EntityRole::User),
        ("session", EntityRole::Session),
        ("account", EntityRole::Account),
        ("verification", EntityRole::Verification),
        ("apikey", EntityRole::ApiKey),
    ]
    .into_iter()
    .map(|(name, role)| {
        Ok((
            name.into(),
            raw.storage_rows(role)?
                .into_iter()
                .map(FieldValue::from)
                .collect::<Vec<_>>()
                .into(),
        ))
    })
    .collect::<AuthResult<FieldMap>>()
    .map(Into::into)
}

pub(super) async fn database(case: &Json, graph: &mut PropertyGraph, path: &str) -> AuthResult<()> {
    assert_eq!(case["name"], "second-window-failure");
    assert_eq!(case["boundary"], "database");
    let scenario = Scenario::new("second-window-failure")?;
    let config = Arc::new(AuthConfig::default());
    let raw = EphemeralStore::from_storage(
        config.clone(),
        [
            ("user".into(), Vec::new()),
            ("session".into(), Vec::new()),
            ("account".into(), Vec::new()),
            ("verification".into(), Vec::new()),
            ("apikey".into(), vec![seed()]),
        ],
    )?;
    let mut model_fields = ModelFields::default();
    <ApiKeyPlugin as AuthPlugin<StatelessSchema>>::schema(
        &ApiKeyPlugin::with_config(ApiKeyConfig::default()),
        &mut model_fields,
    )?;
    model_fields.register_model_fields(
        EntityRole::ApiKey,
        UserConfig {
            additional_fields: Some(
                [
                    (
                        "rateLimitTimeWindow",
                        scenario.key.rate_limit_time_window.field_value(),
                    ),
                    ("rateLimitMax", scenario.key.rate_limit_max.field_value()),
                    ("requestCount", scenario.key.request_count.field_value()),
                ]
                .into_iter()
                .map(|(name, value)| {
                    let state = scenario.state.clone();
                    (
                        name.into(),
                        UserFieldConfig {
                            field_type: UserFieldType::Number,
                            transform: Some(FieldTransforms {
                                output: Some(UserFieldTransform::new(move |input| {
                                    if name == "rateLimitTimeWindow" {
                                        lock(&state.events)?.push(FieldMap::from([
                                            ("phase".into(), "output-window".into()),
                                            ("value".into(), input.clone()),
                                        ]));
                                    }
                                    Ok(value.clone())
                                })),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    )
                })
                .collect(),
            ),
        },
    )?;
    let database = raw.with_runtime(config, Vec::new(), model_fields)?;
    graph.assert_snapshot(
        &database_snapshot(&raw)?,
        &case["before"],
        &format!("{path}/before"),
    )?;
    let row = database
        .get_api_key_by_id_value(&scenario.key.id)
        .await?
        .ok_or_else(|| AuthError::internal("Seeded rate-limit record missing"))?;
    let result = database.consume_api_key_usage(&row, true).await;
    outcome(
        graph,
        usage_result(result),
        &scenario.state.original,
        &case["outcome"],
        &format!("{path}/outcome"),
    )?;
    graph.assert_snapshot(
        &database_snapshot(&raw)?,
        &case["after"],
        &format!("{path}/after"),
    )?;
    events(
        graph,
        &scenario.state,
        &case["events"],
        &format!("{path}/events"),
    )
}

struct Cache {
    values: Mutex<Vec<(String, String)>>,
    events: Mutex<Vec<FieldValue>>,
}

impl Cache {
    fn new() -> AuthResult<Self> {
        Self::with_seed(seed())
    }

    fn with_seed(fields: FieldMap) -> AuthResult<Self> {
        let value = FieldValue::from(fields)
            .stringify()?
            .ok_or_else(|| AuthError::internal("Seeded rate-limit record cannot be serialized"))?;
        Ok(Self {
            values: Mutex::new(vec![
                ("api-key:usage-secret".into(), value.clone()),
                ("api-key:by-id:usage-key".into(), value),
                ("api-key:by-ref:owner".into(), "[\"usage-key\"]".into()),
            ]),
            events: Mutex::new(Vec::new()),
        })
    }

    fn snapshot(&self) -> AuthResult<FieldValue> {
        Ok(lock(&self.values)?
            .iter()
            .map(|(key, value)| FieldValue::from(vec![key.clone().into(), value.clone().into()]))
            .collect::<Vec<_>>()
            .into())
    }
}

#[async_trait]
impl SecondaryStorage for Cache {
    async fn get(&self, key: &str) -> AuthResult<Option<Json>> {
        lock(&self.events)?.push(vec!["get".into(), key.into()].into());
        Ok(lock(&self.values)?
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| Json::String(value.clone())))
    }

    async fn set_native(
        &self,
        key: &FieldValue,
        value: &FieldValue,
        ttl: Option<f64>,
    ) -> AuthResult<()> {
        lock(&self.events)?.push(
            vec![
                "set".into(),
                key.clone(),
                value.clone(),
                ttl.map_or(FieldValue::Undefined, Into::into),
            ]
            .into(),
        );
        let key: String = key.decode()?;
        let value: String = value.decode()?;
        let mut values = lock(&self.values)?;
        if let Some((_, existing)) = values.iter_mut().find(|(name, _)| name == &key) {
            *existing = value;
        } else {
            values.push((key, value));
        }
        Ok(())
    }

    async fn delete(&self, _: &str) -> AuthResult<()> {
        Err(AuthError::internal(
            "Rate-limit replay must not delete cache entries",
        ))
    }

    async fn get_and_delete(&self, _: &str) -> AuthResult<Option<Json>> {
        Err(AuthError::internal(
            "Rate-limit replay must not consume verification entries",
        ))
    }
}

fn usage_result(result: AuthResult<ConsumeApiKeyResult>) -> AuthResult<FieldValue> {
    match result? {
        ConsumeApiKeyResult::Allowed(key) => Ok(key.field_values()?.into()),
        _ => Err(AuthError::internal("Unexpected typed rate-limit rejection")),
    }
}

pub(super) async fn secondary(
    case: &Json,
    graph: &mut PropertyGraph,
    path: &str,
) -> AuthResult<()> {
    assert_eq!(case["boundary"], "secondary");
    let name = case["name"]
        .as_str()
        .ok_or_else(|| AuthError::internal("Missing secondary rate-limit scenario"))?;
    assert!(matches!(name, "start-null" | "second-window-failure"));
    let scenario = Scenario::new(name)?;
    let cache = Arc::new(Cache::new()?);
    let config = Arc::new(AuthConfig::default());
    let database = Arc::new(EphemeralStore::new(config.clone()));
    let now = clock()?;
    let context = AuthContext::new(config, database)?.with_clock(move || now);
    let options = ApiKeyConfig {
        storage: ApiKeyStorage::SecondaryStorage,
        custom_storage: Some(cache.clone()),
        disable_key_hashing: true,
        ..Default::default()
    };
    graph.assert_snapshot(
        &cache.snapshot()?,
        &case["before"],
        &format!("{path}/before"),
    )?;
    let result =
        super::super::super::consume(&options, &context, &scenario.key, "usage-secret").await;
    outcome(
        graph,
        usage_result(result),
        &scenario.state.original,
        &case["outcome"],
        &format!("{path}/outcome"),
    )?;
    graph.assert_snapshot(&cache.snapshot()?, &case["after"], &format!("{path}/after"))?;
    events(
        graph,
        &scenario.state,
        &case["events"],
        &format!("{path}/events"),
    )?;
    graph.assert_snapshot(
        &lock(&cache.events)?.clone().into(),
        &case["storageEvents"],
        &format!("{path}/storageEvents"),
    )
}

#[path = "rate_limit_public_contract.rs"]
mod public;

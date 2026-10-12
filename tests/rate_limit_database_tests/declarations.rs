use super::{TestResult, adapter_storage_snapshot::Storage};
use async_trait::async_trait;
use better_auth::BetterAuth;
use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse,
    AuthResult, AuthRoute, AuthSchema, AuthStore, FieldMap, FieldValue,
    id::{IdGeneration, IdGenerator},
    middleware::{EndpointRateLimit, RateLimitConfig, RateLimitStorageKind},
    plugin_runtime::ModelFields,
    store::{
        EphemeralStore,
        schema::{EntityRole, SchemaConfiguration},
    },
    user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform},
};
use better_auth_seaorm::{
    PluginModels, SeaOrmStore,
    sea_orm::{ConnectionTrait, Database},
    store::{
        __private_test_support::{bundled_schema::BundledSchema, migrator},
        entities,
    },
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

#[expect(
    unreachable_pub,
    reason = "SeaORM derives require public fixture entity types"
)]
mod mapped {
    use better_auth_seaorm::sea_orm::{self, entity::prelude::*};

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, better_auth_seaorm::AuthEntity)]
    #[auth(role = "rate_limit", model_name = "runtime_counter")]
    #[sea_orm(table_name = "runtime_counter")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "bucket", unique)]
        pub key: String,
        #[sea_orm(column_name = "hits", column_type = "Integer")]
        pub count: better_auth_seaorm::SqlNumber,
        #[sea_orm(column_name = "touched")]
        pub last_request: i64,
        #[sea_orm(unique)]
        pub runtime_bucket: Option<String>,
        #[sea_orm(column_type = "Integer")]
        pub runtime_hits: Option<better_auth_seaorm::SqlNumber>,
        pub runtime_touched: Option<i64>,
        pub unused_details: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

type MappedPlugins = PluginModels<
    entities::api_key::Model,
    entities::device_code::Model,
    entities::passkey::Model,
    entities::two_factor::Model,
    entities::jwk::Model,
    entities::wallet_address::Model,
    mapped::Model,
>;

#[derive(Default)]
struct Calls {
    init: Mutex<Vec<&'static str>>,
    callbacks: AtomicUsize,
    ids: AtomicUsize,
}

impl Calls {
    fn transform(self: &Arc<Self>, phase: &'static str) -> UserFieldTransform {
        let calls = self.clone();
        UserFieldTransform::new(move |_| {
            let _ = calls.callbacks.fetch_add(1, Ordering::Relaxed);
            Err(AuthError::internal(format!(
                "Discarded RateLimit {phase} ran"
            )))
        })
    }

    fn declaration(self: &Arc<Self>, name: &str) -> UserFieldConfig {
        let default = self.clone();
        let update = self.clone();
        UserFieldConfig {
            field_name: Some(format!("plugin_{name}")),
            required: Some(false),
            returned: Some(false),
            unique: Some(false),
            default_value_fn: Some(better_auth_core::user_fields::UserFieldFactory::new(
                move || {
                    let _ = default.callbacks.fetch_add(1, Ordering::Relaxed);
                    Err(AuthError::internal("Discarded RateLimit default ran"))
                },
            )),
            on_update: Some(better_auth_core::user_fields::UserFieldFactory::new(
                move || {
                    let _ = update.callbacks.fetch_add(1, Ordering::Relaxed);
                    Err(AuthError::internal("Discarded RateLimit update ran"))
                },
            )),
            transform: Some(FieldTransforms {
                input: Some(self.transform("input")),
                output: Some(self.transform("output")),
            }),
            ..Default::default()
        }
    }
}

struct Declaration {
    last: bool,
    calls: Arc<Calls>,
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Declaration {
    fn name(&self) -> &'static str {
        if self.last {
            "rate-limit-last"
        } else {
            "rate-limit-first"
        }
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    fn schema(
        &self,
        context: &mut better_auth_core::plugin_runtime::ModelFields,
    ) -> AuthResult<()> {
        context.register_custom_model(
            if self.last { "after" } else { "before" },
            None,
            UserConfig::default(),
        )?;
        let fields = if self.last {
            UserConfig::default()
        } else {
            UserConfig {
                additional_fields: Some(
                    ["id", "count", "key", "label"]
                        .into_iter()
                        .map(|name| (name.into(), self.calls.declaration(name)))
                        .collect(),
                ),
            }
        };
        context.register_model_schema(
            EntityRole::RateLimit,
            Some(if self.last {
                "plugin_counter"
            } else {
                "first_counter"
            }),
            fields,
        )
    }
    async fn on_init(&self, _context: &mut AuthInitContext<S>) -> AuthResult<()> {
        self.calls
            .init
            .lock()
            .map_err(|_| AuthError::internal("RateLimit init lock poisoned"))?
            .push(if self.last { "last" } else { "first" });
        Ok(())
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

fn config(calls: &Arc<Calls>) -> AuthConfig {
    let mut config =
        AuthConfig::new("rate-limit-declaration-secret-at-least-thirty-two-characters")
            .base_url("http://rate-limit-declaration.test");
    config.telemetry.enabled = false;
    config.logger = better_auth_core::LoggerConfig {
        disabled: Some(true),
        ..Default::default()
    }
    .into();
    let calls = calls.clone();
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(move |request| {
            if request.model != "rateLimit" {
                return Err(AuthError::internal(
                    "RateLimit must generate IDs with its logical model name",
                ));
            }
            let _ = calls.ids.fetch_add(1, Ordering::Relaxed);
            Ok(Some("counter".into()))
        })));
    config
}

#[derive(Clone, Copy, Debug)]
enum Mapping {
    Native,
    Mapped,
    Empty,
}

impl Mapping {
    const ALL: [Self; 3] = [Self::Native, Self::Mapped, Self::Empty];

    fn config(self) -> RateLimitConfig {
        let mut config = RateLimitConfig::new()
            .enabled(true)
            .storage(RateLimitStorageKind::Database);
        match self {
            Self::Native => {}
            Self::Mapped => {
                config.model_name = Some("runtime_counter".into());
                config.fields = Some(
                    [
                        ("lastRequest".into(), "runtime_touched".into()),
                        ("count".into(), "runtime_hits".into()),
                        ("key".into(), "runtime_bucket".into()),
                    ]
                    .into(),
                );
            }
            Self::Empty => {
                config.model_name = Some(String::new());
                config.fields = Some(
                    ["lastRequest", "count", "key"]
                        .map(|name| (name.into(), String::new()))
                        .into(),
                );
            }
        }
        config
    }

    fn memory(self) -> (&'static str, [&'static str; 3]) {
        match self {
            Self::Mapped => (
                "runtime_counter",
                ["runtime_bucket", "runtime_hits", "runtime_touched"],
            ),
            Self::Native | Self::Empty => ("rateLimit", ["key", "count", "lastRequest"]),
        }
    }

    fn sqlite(self) -> (&'static str, [&'static str; 3]) {
        match self {
            Self::Mapped => self.memory(),
            Self::Native | Self::Empty => ("rate_limit", ["key", "count", "last_request"]),
        }
    }
}

fn assert_rows(actual: &[FieldMap], expected: &[FieldMap]) {
    assert_eq!(actual, expected, "Complete physical counter rows");
    assert_eq!(
        actual
            .iter()
            .map(|row| row.keys().collect::<Vec<_>>())
            .collect::<Vec<_>>(),
        expected
            .iter()
            .map(|row| row.keys().collect::<Vec<_>>())
            .collect::<Vec<_>>(),
        "Physical counter field presence and order"
    );
}

async fn exercise<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    storage: Storage,
    table: &str,
    names: [&str; 3],
    calls: &Calls,
) -> TestResult {
    let key = "192.0.2.17|/ordinary-counter";
    let tables = [("counter", table, EntityRole::RateLimit)];
    let rule = EndpointRateLimit {
        window: 600.0,
        max_requests: 2.0,
    };
    let expected = |count: i32, last: FieldValue| -> FieldMap {
        let mut row = FieldMap::new();
        if matches!(&storage, Storage::Sqlite(_)) {
            let _ = row.insert("id".into(), "counter".into());
        }
        row.extend([
            (names[0].into(), key.into()),
            (names[1].into(), count.into()),
            (names[2].into(), last),
        ]);
        if matches!(&storage, Storage::Memory(_)) {
            let _ = row.insert("id".into(), "counter".into());
        }
        row
    };
    assert_eq!(
        *calls
            .init
            .lock()
            .map_err(|_| AuthError::internal("RateLimit init lock poisoned"))?,
        ["first", "last"]
    );
    for count in [1, 2] {
        let start = chrono::Utc::now().timestamp_millis() as f64;
        let decision = store.consume_rate_limit(key, rule, 600.0).await?;
        let finish = chrono::Utc::now().timestamp_millis() as f64;
        assert!(decision.allowed);
        assert_eq!(decision.retry_after, None);
        let snapshot = storage.snapshot(&tables).await?;
        let rows = snapshot
            .get("counter")
            .ok_or_else(|| AuthError::internal("Missing counter snapshot"))?;
        assert_eq!(rows.len(), 1);
        let last = rows
            .first()
            .and_then(|row| row.get(names[2]))
            .cloned()
            .ok_or_else(|| AuthError::internal("Missing counter timestamp"))?;
        let time = last
            .as_f64()
            .ok_or_else(|| AuthError::internal("Counter timestamp must be numeric"))?;
        assert!((start..=finish).contains(&time));
        assert_rows(rows, &[expected(count, last)]);
    }
    let before = storage.snapshot(&tables).await?;
    let denied = store.consume_rate_limit(key, rule, 600.0).await?;
    assert!(!denied.allowed);
    assert!(
        denied
            .retry_after
            .is_some_and(|value| value > 0.0 && value <= 600.0)
    );
    let after = storage.snapshot(&tables).await?;
    assert_eq!(after, before);
    assert_rows(
        after
            .get("counter")
            .ok_or("Missing denied counter snapshot")?,
        before
            .get("counter")
            .ok_or("Missing previous counter snapshot")?,
    );
    let start = chrono::Utc::now().timestamp_millis() as f64;
    let reset = store
        .consume_rate_limit(
            key,
            EndpointRateLimit {
                window: 0.0,
                ..rule
            },
            600.0,
        )
        .await?;
    let finish = chrono::Utc::now().timestamp_millis() as f64;
    assert!(reset.allowed);
    assert_eq!(reset.retry_after, None);
    let snapshot = storage.snapshot(&tables).await?;
    let rows = snapshot
        .get("counter")
        .ok_or_else(|| AuthError::internal("Missing reset snapshot"))?;
    assert_eq!(rows.len(), 1);
    let last = rows
        .first()
        .and_then(|row| row.get(names[2]))
        .cloned()
        .ok_or_else(|| AuthError::internal("Missing reset timestamp"))?;
    let time = last
        .as_f64()
        .ok_or_else(|| AuthError::internal("Reset timestamp must be numeric"))?;
    assert!((start..=finish).contains(&time));
    assert_rows(rows, &[expected(1, last)]);
    assert_eq!(calls.callbacks.load(Ordering::Relaxed), 0);
    assert_eq!(calls.ids.load(Ordering::Relaxed), 1);
    Ok(())
}

#[tokio::test]
async fn memory_counter_consumption_ignores_replaced_plugin_declarations() -> TestResult {
    for mapping in Mapping::ALL {
        let calls = Arc::new(Calls::default());
        let config = config(&calls);
        let (table, names) = mapping.memory();
        let mut fields = ModelFields::default();
        // The upstream fixture preinitializes the physical counter table. Root key inventory is outside this contract.
        if matches!(mapping, Mapping::Mapped) {
            fields.register_custom_model(table, None, UserConfig::default())?;
        }
        let shared_config = Arc::new(config.clone());
        fields.set_schema_configuration(&SchemaConfiguration {
            config: shared_config.clone(),
            plugins: Vec::new(),
            metadata: Default::default(),
            secondary_storage: false,
            rate_limit: mapping.config(),
        });
        let raw = EphemeralStore::from_schema(shared_config, &fields);
        let auth = BetterAuth::new(config)
            .store(raw.clone())
            .plugin(Declaration {
                last: false,
                calls: calls.clone(),
            })
            .plugin(Declaration {
                last: true,
                calls: calls.clone(),
            })
            .rate_limit(mapping.config())
            .build()
            .await?;
        exercise(
            auth.context().database.as_ref(),
            Storage::Memory(Box::new(raw)),
            table,
            names,
            &calls,
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_counter_consumption_preserves_native_and_mapped_columns_after_replacement()
-> TestResult {
    for mapping in Mapping::ALL {
        let calls = Arc::new(Calls::default());
        let config = config(&calls);
        let database = Database::connect("sqlite::memory:").await?;
        migrator::run_migrations(&database).await?;
        let auth = if matches!(mapping, Mapping::Mapped) {
            let _ = database
                .execute_unprepared("CREATE TABLE runtime_counter (id TEXT PRIMARY KEY, runtime_bucket TEXT UNIQUE NOT NULL, runtime_hits INTEGER NOT NULL, runtime_touched BIGINT NOT NULL)")
                .await?;
            BetterAuth::<BundledSchema>::new(config.clone())
                .store(
                    SeaOrmStore::<BundledSchema>::new(config, database.clone())
                        .with_plugin_schema::<MappedPlugins>(),
                )
                .plugin(Declaration {
                    last: false,
                    calls: calls.clone(),
                })
                .plugin(Declaration {
                    last: true,
                    calls: calls.clone(),
                })
                .rate_limit(mapping.config())
                .build()
                .await?
        } else {
            BetterAuth::<BundledSchema>::new(config.clone())
                .store(SeaOrmStore::<BundledSchema>::new(config, database.clone()))
                .plugin(Declaration {
                    last: false,
                    calls: calls.clone(),
                })
                .plugin(Declaration {
                    last: true,
                    calls: calls.clone(),
                })
                .rate_limit(mapping.config())
                .build()
                .await?
        };
        let (table, names) = mapping.sqlite();
        exercise(
            auth.context().database.as_ref(),
            Storage::Sqlite(database.clone()),
            table,
            names,
            &calls,
        )
        .await?;
        drop(auth);
        database.close().await?;
    }
    Ok(())
}

use super::*;
use better_auth_core::{SchemaValue, UpdatePasskey, id::IdGeneration};
use better_auth_seaorm::{
    sea_orm::{ActiveModelTrait, ConnectionTrait, IntoActiveModel, Schema},
    store::entities::passkey,
};

fn serial_config() -> AuthConfig {
    let mut config = config();
    config.advanced.database.generate_id = Some(IdGeneration::Serial);
    config
}

fn policy(field: &'static str, trace: Arc<Mutex<Vec<&'static str>>>) -> UserFieldConfig {
    UserFieldConfig {
        field_type: UserFieldType::Json,
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(move |value| {
                trace_lock(&trace)?.push(field);
                if value == FieldValue::from("reject") {
                    return Err(AuthError::internal("Passkey display input rejected"));
                }
                Ok(value)
            })),
            ..Default::default()
        }),
        ..Default::default()
    }
}

async fn contract<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>) -> AuthResult<()> {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let auth = BetterAuth::new(serial_config())
        .store_arc(raw.clone())
        .plugin(Fields(vec![(
            EntityRole::Passkey,
            UserConfig {
                additional_fields: Some(
                    [
                        ("name".into(), policy("name", trace.clone())),
                        ("aaguid".into(), policy("aaguid", trace.clone())),
                    ]
                    .into(),
                ),
            },
        )]))
        .build()
        .await?;
    let mut stored = required(raw.get_passkey_by_id("1").await?, "Expected serial Passkey")?;
    for (counter, id) in (1_u64..).zip([
        FieldValue::Number(1.0),
        FieldValue::from("001"),
        FieldValue::from("1e0"),
        FieldValue::from("0x1"),
    ]) {
        let name = json!({"label": ["desk", counter], "active": true});
        let aaguid = json!([{"vendor": "authenticator"}, counter]);
        trace_lock(&trace)?.clear();
        let updated = auth
            .store()
            .update_passkey(
                &SchemaValue::from_field(id.clone()),
                UpdatePasskey {
                    name: SchemaValue::from_field(FieldValue::from_json(name.clone())?),
                    aaguid: SchemaValue::from_field(FieldValue::from_json(aaguid.clone())?),
                    counter: Some(counter),
                    ..Default::default()
                },
            )
            .await?;
        assert_eq!(
            updated.name.field_value(),
            FieldValue::from_json(name.clone())?
        );
        assert_eq!(
            updated.aaguid.field_value(),
            FieldValue::from_json(aaguid.clone())?
        );
        assert_eq!(updated.counter, counter);
        assert_eq!(*trace_lock(&trace)?, ["name", "aaguid"]);
        let persisted = required(
            raw.get_passkey_by_id("1").await?,
            "Expected updated Passkey",
        )?;
        stored.name = Some(name.to_string()).into();
        stored.aaguid = Some(aaguid.to_string()).into();
        stored.counter = counter;
        stored.updated_at = persisted.updated_at.clone();
        assert_eq!(persisted, stored);

        trace_lock(&trace)?.clear();
        let error = auth
            .store()
            .update_passkey(
                &SchemaValue::from_field(id),
                UpdatePasskey {
                    name: SchemaValue::from_field(FieldValue::from_json(
                        json!({"uncommitted": true}),
                    )?),
                    aaguid: Some("reject".into()).into(),
                    counter: Some(99),
                    ..Default::default()
                },
            )
            .await
            .err()
            .ok_or_else(|| AuthError::internal("Expected the display input callback to fail"))?;
        original_error(error, "Passkey display input rejected");
        assert_eq!(*trace_lock(&trace)?, ["name", "aaguid"]);
        assert_eq!(raw.get_passkey_by_id("1").await?, Some(stored.clone()));
    }
    Ok(())
}

#[tokio::test]
async fn memory_serial_passkey_update_preserves_atomic_dynamic_fields() -> AuthResult<()> {
    let raw: Arc<dyn AuthStore<StatelessSchema>> =
        Arc::new(EphemeralStore::new(Arc::new(serial_config())));
    let _ = raw.create_passkey(input("1", "before")).await?;
    contract(raw).await
}

#[tokio::test]
async fn sqlite_serial_passkey_update_preserves_atomic_dynamic_fields() -> AuthResult<()> {
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(|error| {
            AuthError::internal(format!("SQLite fixture connection failed: {error}"))
        })?;
    let _ = database
        .execute(
            &Schema::new(database.get_database_backend()).create_table_from_entity(passkey::Entity),
        )
        .await
        .map_err(|error| {
            AuthError::internal(format!("Passkey fixture table creation failed: {error}"))
        })?;
    let now = chrono::Utc::now();
    let _ = passkey::Model {
        id: "1".into(),
        name: Some("before".into()),
        public_key: "ordinary-public-key".into(),
        user_id: "1".into(),
        credential_id: "credential:before".into(),
        counter: 0,
        device_type: "singleDevice".into(),
        backed_up: false,
        transports: None,
        credential: "ordinary-private-record".into(),
        aaguid: None,
        created_at: now,
        updated_at: now,
    }
    .into_active_model()
    .insert(&database)
    .await
    .map_err(|error| AuthError::internal(format!("Passkey fixture insertion failed: {error}")))?;
    contract(Arc::new(SeaOrmStore::<BundledSchema>::new(
        serial_config(),
        database,
    )))
    .await
}

use std::sync::Arc;

use better_auth::{
    AuthConfig, BetterAuth, SchemaValue,
    config::{UserFieldConfig, UserFieldType},
    prelude::{CreateAccount, CreateUser, CreateVerification, UpdateAccount},
    seaorm::{
        Database, SeaOrmStore,
        sea_orm::{ConnectionTrait, DbBackend, Statement},
    },
};
use serde_json::{Value, json};

mod generated {
    include!(env!("BETTER_AUTH_ACCOUNT_VERIFICATION_SCHEMA"));
}

fn label(column: &str) -> UserFieldConfig {
    UserFieldConfig {
        required: Some(false),
        field_name: Some(column.into()),
        default_value: Some(json!("default")),
        on_update: Some(Arc::new(|| json!("updated"))),
        input_transform: Some(Arc::new(|value| {
            Ok(value.map(|value| json!(format!("{}:in", value.as_str().unwrap()))))
        })),
        output_transform: Some(Arc::new(|value| {
            Ok(value.map(|value| json!({"stored": value})))
        })),
        ..Default::default()
    }
}

fn number(column: &str, required: bool) -> UserFieldConfig {
    UserFieldConfig {
        field_type: UserFieldType::Number,
        field_name: Some(column.into()),
        required: Some(required),
        input_transform: Some(Arc::new(|value| {
            Ok(value.map(|value| json!(value.as_f64().unwrap() + 0.5)))
        })),
        output_transform: Some(Arc::new(|value| {
            Ok(value.map(|value| json!({"number": value})))
        })),
        ..Default::default()
    }
}

#[tokio::test]
async fn generated_account_verification_fields_keep_storage_and_output_types_separate() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    generated::create_auth_tables(&db).await.unwrap();
    let mut config = AuthConfig::new("generated-account-verification-consumer-secret")
        .base_url("http://localhost:3000");
    config.account.additional_fields = [
        ("label".into(), label("account_label")),
        ("scope".into(), number("scope_number", false)),
    ]
    .into_iter()
    .collect();
    config.verification.additional_fields = [
        ("label".into(), label("verification_label")),
        ("value".into(), number("numeric_value", true)),
    ]
    .into_iter()
    .collect();
    let auth = BetterAuth::<generated::AppAuthSchema>::new(config.clone())
        .store(SeaOrmStore::<generated::AppAuthSchema>::new(
            config,
            db.clone(),
        ))
        .build()
        .await
        .unwrap();
    let user = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_email("mapped@example.com")
                .with_name("Mapped"),
        )
        .await
        .unwrap();
    let account = auth
        .store()
        .create_account(CreateAccount {
            user_id: user.id.into(),
            account_id: "subject".into(),
            provider_id: "fixture".into(),
            scope: SchemaValue::Dynamic(json!(1.25)),
            password: Some("private-credential".to_owned()).into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(account.scope.json().unwrap(), Some(json!({"number": 1.75})));
    assert_eq!(
        account.additional_fields["label"],
        json!({"stored": "default:in"})
    );
    assert!(
        serde_json::to_value(&account)
            .unwrap()
            .get("password")
            .is_none()
    );
    assert_eq!(
        account.internal_fields().unwrap()["password"],
        "private-credential"
    );
    let updated = auth
        .store()
        .update_account(
            account.id.typed().unwrap(),
            UpdateAccount {
                scope: SchemaValue::Dynamic(json!(2.25)),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.scope.json().unwrap(), Some(json!({"number": 2.75})));
    assert_eq!(
        updated.additional_fields["label"],
        json!({"stored": "updated:in"})
    );
    let verification = auth
        .store()
        .create_verification(CreateVerification {
            identifier: "numeric-code".into(),
            value: SchemaValue::Dynamic(json!(3.25)),
            expires_at: SchemaValue::Typed("2030-01-01T00:00:00Z".parse().unwrap()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        verification.value.json().unwrap(),
        Some(json!({"number": 3.75}))
    );
    assert_eq!(
        verification.additional_fields["label"],
        json!({"stored": "default:in"})
    );
    let stored = db
        .query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT provider_name, provider_subject, account_label, scope_number FROM app_accounts",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.try_get::<String>("", "provider_name").unwrap(),
        "fixture"
    );
    assert_eq!(
        stored.try_get::<String>("", "provider_subject").unwrap(),
        "subject"
    );
    assert_eq!(
        stored.try_get::<String>("", "account_label").unwrap(),
        "updated:in"
    );
    assert_eq!(stored.try_get::<f64>("", "scope_number").unwrap(), 2.75);
    let stored = db
        .query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT lookup_key, verification_label, numeric_value FROM app_verifications",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.try_get::<String>("", "lookup_key").unwrap(),
        "numeric-code"
    );
    assert_eq!(
        stored.try_get::<String>("", "verification_label").unwrap(),
        "default:in"
    );
    assert_eq!(stored.try_get::<f64>("", "numeric_value").unwrap(), 3.75);
    let found = auth
        .store()
        .get_verification_by_identifier("numeric-code")
        .await
        .unwrap()
        .unwrap();
    let result: Value = serde_json::to_value(found).unwrap();
    assert_eq!(result["value"], json!({"number": 3.75}));
    assert_eq!(result["label"], json!({"stored": "default:in"}));
}

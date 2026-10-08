use better_auth_core::{
    AuthConfig, CreateAccount, CreateSession, CreateUser, CreateVerification, FieldDate, FieldMap,
    UpdateAccount, UpdateUser,
    id::IdGeneration,
    store::{
        AccountStore, EphemeralStore, JoinValue, SessionStore, UserStore, VerificationStore,
        database_hooks::VerificationUpdate,
    },
    user_fields::{
        FieldTransforms, UserFieldConfig, UserFieldReference, UserFieldTransform, UserFieldType,
    },
};
use serde_json::{Map, Value, json};
use std::sync::{Arc, Mutex};

fn reference() -> UserFieldConfig {
    UserFieldConfig {
        references: Some(UserFieldReference {
            model: "user".into(),
            field: "id".into(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn selected(row: impl serde::Serialize) -> Value {
    let row = serde_json::to_value(row).unwrap();
    Value::Object(
        [
            "reference",
            "references",
            "nullable",
            "boolean",
            "defaulted",
        ]
        .into_iter()
        .map(|name| (name.to_owned(), row[name].clone()))
        .collect(),
    )
}

#[tokio::test]
async fn memory_reference_fields_match_pinned_conversion_and_callback_values() {
    let expected: Value =
        serde_json::from_str(include_str!("fixtures/memory-serial-references-1.7.6.json")).unwrap();
    let mut families = Map::new();
    for model in ["user", "session", "account", "verification"] {
        let trace = Arc::new(Mutex::new(Vec::new()));
        let input_trace = trace.clone();
        let output_trace = trace.clone();
        let fields = [
            (
                "reference".into(),
                UserFieldConfig {
                    field_name: Some("storedReference".into()),
                    transform: Some(FieldTransforms {
                        input: Some(UserFieldTransform::new(move |value| {
                            input_trace
                                .lock()
                                .unwrap()
                                .push(json!(["input", value.json()?]));
                            if value.is_undefined() {
                                return Ok(value);
                            }
                            Ok(value.as_str().unwrap().trim().into())
                        })),
                        output: Some(UserFieldTransform::new(move |value| {
                            output_trace
                                .lock()
                                .unwrap()
                                .push(json!(["output", value.json()?]));
                            Ok(value)
                        })),
                    }),
                    ..reference()
                },
            ),
            (
                "references".into(),
                UserFieldConfig {
                    field_type: UserFieldType::StringArray,
                    ..reference()
                },
            ),
            (
                "nullable".into(),
                UserFieldConfig {
                    required: Some(false),
                    ..reference()
                },
            ),
            (
                "boolean".into(),
                UserFieldConfig {
                    field_type: UserFieldType::Boolean,
                    ..reference()
                },
            ),
            (
                "defaulted".into(),
                UserFieldConfig {
                    default_value: Some("003".into()),
                    on_update: Some(Arc::new(|| Ok("004".into()))),
                    ..reference()
                },
            ),
        ]
        .into_iter()
        .collect();
        let mut config = AuthConfig::default();
        config.advanced.database.generate_id = Some(IdGeneration::Serial);
        match model {
            "user" => config.user.additional_fields = Some(fields),
            "session" => config.session.additional_fields = Some(fields),
            "account" => config.account.additional_fields = fields,
            "verification" => config.verification.additional_fields = fields,
            _ => unreachable!(),
        }
        let store = EphemeralStore::new(Arc::new(config));
        let extras = FieldMap::from_json(json!({"reference": " 002 ", "references": ["002", null, true], "nullable": null, "boolean": true}).as_object().unwrap().clone()).unwrap();
        let patch = FieldMap::from([("reference".into(), " 005 ".into())]);
        let expires_at = FieldDate::from(
            "2100-01-01T00:00:00Z"
                .parse::<chrono::DateTime<chrono::Utc>>()
                .unwrap(),
        );
        let (created, updated) = match model {
            "user" => {
                let mut input = CreateUser::new()
                    .with_email("example@serial-reference.test")
                    .with_name("Example");
                input.additional_fields = extras;
                let row = store.create_user(input).await.unwrap();
                let updated = store
                    .update_user(
                        row.id.typed().unwrap(),
                        UpdateUser {
                            additional_fields: patch,
                            ..Default::default()
                        },
                    )
                    .await
                    .unwrap();
                (selected(row), selected(updated))
            }
            "session" => {
                let row = store
                    .create_session(CreateSession {
                        inherited_fields: Default::default(),
                        user_id: "1".into(),
                        expires_at,
                        additional_fields: extras,
                        ip_address: None,
                        user_agent: None,
                        impersonated_by: None,
                        active_organization_id: None,
                    })
                    .await
                    .unwrap();
                let updated = store
                    .update_session_fields(&row.token, patch)
                    .await
                    .unwrap()
                    .unwrap();
                (selected(row), selected(updated))
            }
            "account" => {
                let row = store
                    .create_account(CreateAccount {
                        user_id: "1".into(),
                        provider_id: "example".into(),
                        account_id: "external".into(),
                        additional_fields: extras,
                        ..Default::default()
                    })
                    .await
                    .unwrap();
                let updated = store
                    .update_account(
                        row.id.typed().unwrap(),
                        UpdateAccount {
                            additional_fields: patch,
                            ..Default::default()
                        },
                    )
                    .await
                    .unwrap();
                (selected(row), selected(updated))
            }
            "verification" => {
                let row = store
                    .create_verification(CreateVerification {
                        identifier: "ordinary".into(),
                        value: "value".into(),
                        expires_at: expires_at.into(),
                        additional_fields: extras,
                        ..Default::default()
                    })
                    .await
                    .unwrap();
                let updated = store
                    .update_verification(
                        "ordinary",
                        VerificationUpdate {
                            additional_fields: patch,
                            ..Default::default()
                        },
                    )
                    .await
                    .unwrap()
                    .unwrap();
                (selected(row), selected(updated))
            }
            _ => unreachable!(),
        };
        let _ = families.insert(
            model.into(),
            json!({"created": created, "updated": updated, "trace": *trace.lock().unwrap()}),
        );
    }
    let mut config = AuthConfig::default();
    config.user.additional_fields = Some([("reference".into(), reference())].into_iter().collect());
    let store = EphemeralStore::new(Arc::new(config));
    let mut input = CreateUser::new().with_email("random@serial-reference.test");
    input.additional_fields = [("reference".into(), "002".into())].into_iter().collect();
    let row = store.create_user(input).await.unwrap();
    assert_eq!(
        json!({"families": families, "random": row.additional_fields["reference"].json().unwrap()}),
        expected
    );
}

#[tokio::test]
async fn serial_account_queries_retain_raw_bindings_for_both_join_modes() {
    for joins in [false, true] {
        let mut config = AuthConfig::default();
        config.advanced.database.generate_id = Some(IdGeneration::Serial);
        config.advanced.database.joins = Some(joins);
        let _ = config.account.additional_fields.insert(
            "userId".into(),
            UserFieldConfig {
                field_name: Some("storedOwner".into()),
                ..reference()
            },
        );
        let store = EphemeralStore::new(Arc::new(config));
        let user = store
            .create_user(CreateUser::new().with_email("account@serial-reference.test"))
            .await
            .unwrap();
        let account = store
            .create_account(CreateAccount {
                user_id: "001".into(),
                account_id: "1".into(),
                provider_id: "credential".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(account.user_id, user.id);
        assert_eq!(store.get_user_accounts("001").await.unwrap().len(), 1);
        assert_eq!(
            store.get_credential_account("1").await.unwrap().unwrap().id,
            account.id
        );
        let owner = store
            .get_account_owner("credential", "1")
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(owner.user, JoinValue::One(Some(owner)) if owner.id == user.id));
        let joined = store
            .get_user_with_accounts("account@serial-reference.test")
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(joined.accounts, JoinValue::Many(accounts) if accounts[0].user_id == user.id)
        );
        store.delete_user(user.id.typed().unwrap()).await.unwrap();
        assert!(store.get_user_accounts("1").await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn serial_verification_queries_follow_declared_identifier_and_value_references() {
    let mut config = AuthConfig::default();
    config.advanced.database.generate_id = Some(IdGeneration::Serial);
    config.verification.additional_fields = [
        (
            "identifier".into(),
            UserFieldConfig {
                field_name: Some("storedIdentifier".into()),
                ..reference()
            },
        ),
        ("value".into(), reference()),
    ]
    .into_iter()
    .collect();
    let store = EphemeralStore::new(Arc::new(config));
    let record = store
        .create_verification(CreateVerification {
            identifier: "002".into(),
            value: "003".into(),
            expires_at: "2100-01-01T00:00:00Z"
                .parse::<chrono::DateTime<chrono::Utc>>()
                .unwrap()
                .into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(record.identifier, "2");
    assert_eq!(
        store
            .get_verification("002", "003")
            .await
            .unwrap()
            .unwrap()
            .id,
        record.id
    );
    assert_eq!(
        store
            .get_verification_by_value("003")
            .await
            .unwrap()
            .unwrap()
            .id,
        record.id
    );
    let updated = store
        .update_verification(
            "002",
            VerificationUpdate {
                value: "004".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.value, "4");
    assert_eq!(
        store
            .get_verification_by_identifier("002")
            .await
            .unwrap()
            .unwrap()
            .value,
        "4"
    );
    store
        .delete_verification_by_identifier("002")
        .await
        .unwrap();
    assert!(
        store
            .get_verification_by_identifier("2")
            .await
            .unwrap()
            .is_none()
    );
}

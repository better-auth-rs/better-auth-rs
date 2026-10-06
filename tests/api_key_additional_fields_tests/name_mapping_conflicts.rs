use super::{contract, fixture};
use better_auth::{
    __private_core::{
        AuthError, AuthSchema, AuthStore,
        store::EphemeralStore,
        user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform},
    },
    BetterAuth,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn field(column: Option<&str>, calls: &Arc<AtomicUsize>) -> UserFieldConfig {
    let input = calls.clone();
    let output = calls.clone();
    UserFieldConfig {
        field_name: column.map(str::to_owned),
        required: Some(false),
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(move |value| {
                let _ = input.fetch_add(1, Ordering::SeqCst);
                Ok(value)
            })),
            output: Some(UserFieldTransform::new(move |value| {
                let _ = output.fetch_add(1, Ordering::SeqCst);
                Ok(value)
            })),
        }),
        ..Default::default()
    }
}

async fn reject<S: AuthSchema>(store: Arc<dyn AuthStore<S>>, physical_columns: &[&str]) {
    for (name, storage) in [
        ("label", Some("stored_name")),
        ("stored_name", None),
        ("stored_name", Some("stored_label")),
    ] {
        for reversed in [false, true] {
            for split in [false, true] {
                let calls = Arc::new(AtomicUsize::new(0));
                let mut declarations = [
                    ("name".to_owned(), field(Some("stored_name"), &calls)),
                    (name.to_owned(), field(storage, &calls)),
                ];
                if reversed {
                    declarations.reverse();
                }
                let mut auth = BetterAuth::new(contract::config()).store_arc(store.clone());
                if split {
                    for declaration in declarations {
                        auth = auth.plugin(contract::Fields(UserConfig {
                            additional_fields: Some([declaration].into()),
                        }));
                    }
                } else {
                    auth = auth.plugin(contract::Fields(UserConfig {
                        additional_fields: Some(declarations.into()),
                    }));
                }
                let result = auth.build().await;
                assert!(
                    matches!(result, Err(AuthError::Config(ref message)) if message.contains(" storage column ")),
                    "{name}/{storage:?}, reversed={reversed}, split={split}"
                );
                assert_eq!(calls.load(Ordering::SeqCst), 0);
            }
        }
    }
    for column in [
        "key",
        "key_hash",
        "referenceId",
        "requestCount",
        "remaining",
    ]
    .into_iter()
    .chain(physical_columns.iter().copied())
    {
        let calls = Arc::new(AtomicUsize::new(0));
        let result = BetterAuth::new(contract::config())
            .store_arc(store.clone())
            .plugin(contract::Fields(UserConfig {
                additional_fields: Some([("name".into(), field(Some(column), &calls))].into()),
            }))
            .build()
            .await;
        assert!(
            matches!(result, Err(AuthError::Config(_))),
            "name cannot alias {column}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn memory_rejects_api_key_name_mapping_collisions_before_callbacks() {
    let store = Arc::new(EphemeralStore::new(Arc::new(contract::config())));
    reject(store, &[]).await;
}

#[tokio::test]
async fn sqlite_rejects_api_key_name_mapping_collisions_before_callbacks()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (store, database) =
        fixture::sqlite_for::<fixture::renamed::Model>(contract::config()).await;
    reject(
        Arc::new(store),
        &["stored_key", "stored_owner", "stored_count"],
    )
    .await;
    database.close().await?;
    Ok(())
}

use super::{contract, display_fixture};
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
    let input_calls = calls.clone();
    let output_calls = calls.clone();
    UserFieldConfig {
        field_name: column.map(str::to_owned),
        required: Some(false),
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(move |value| {
                let _ = input_calls.fetch_add(1, Ordering::SeqCst);
                Ok(value)
            })),
            output: Some(UserFieldTransform::new(move |value| {
                let _ = output_calls.fetch_add(1, Ordering::SeqCst);
                Ok(value)
            })),
        }),
        ..Default::default()
    }
}

async fn reject_conflicts<S: AuthSchema>(store: Arc<dyn AuthStore<S>>) {
    for (native, other) in [("name", "aaguid"), ("aaguid", "name")] {
        let column = format!("stored_{native}");
        for (name, storage) in [
            ("label", Some(column.as_str())),
            (column.as_str(), None),
            (column.as_str(), Some("independent_label")),
            (other, Some(column.as_str())),
        ] {
            for reversed in [false, true] {
                for split in [false, true] {
                    let calls = Arc::new(AtomicUsize::new(0));
                    let mut declarations = [
                        (native.to_owned(), field(Some(&column), &calls)),
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
                    if name == other {
                        assert!(
                            result.is_ok(),
                            "shared displays {native}/{name}/{storage:?}, reversed={reversed}, split={split}: {:?}",
                            result.err()
                        );
                    } else {
                        assert!(
                            matches!(result, Err(AuthError::Config(ref message)) if message.contains(" storage column ")),
                            "{native}/{name}/{storage:?}, reversed={reversed}, split={split}"
                        );
                    }
                    assert_eq!(calls.load(Ordering::SeqCst), 0);
                }
            }
        }
    }
}

#[tokio::test]
async fn memory_rejects_display_mapping_collisions_before_callbacks() {
    reject_conflicts(Arc::new(EphemeralStore::new(Arc::new(contract::config())))).await;
}

#[tokio::test]
async fn sqlite_rejects_display_mapping_collisions_before_callbacks()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (store, database) =
        display_fixture::sqlite::<display_fixture::renamed::Model>(contract::config()).await;
    reject_conflicts(Arc::new(store)).await;
    database.close().await?;
    Ok(())
}

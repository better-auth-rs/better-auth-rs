use super::*;
use crate::{FieldMap, SchemaValue};

fn unconvertible_name() -> FieldValue {
    FieldMap::from_iter([("toString".into(), FieldValue::Number(0.0))]).into()
}

async fn create_names(names: &[FieldValue]) -> AuthResult<EphemeralStore> {
    let store = EphemeralStore::default();
    for (index, name) in names.iter().enumerate() {
        let _ = store
            .create_api_key(CreateApiKey {
                name: SchemaValue::from_field(name.clone()),
                key_hash: format!("stored-{index}"),
                ..input()
            })
            .await?;
    }
    Ok(store)
}

#[tokio::test]
async fn name_sort_skips_conversion_when_only_nullish_names_can_be_compared() -> AuthResult<()> {
    let object = unconvertible_name();
    for nullish in [FieldValue::Null, FieldValue::Undefined] {
        for names in [
            vec![nullish.clone(), object.clone()],
            vec![object.clone(), nullish.clone()],
        ] {
            let store = create_names(&names).await?;
            for (direction, expected) in [
                ("asc", vec![nullish.clone(), object.clone()]),
                ("desc", vec![object.clone(), nullish.clone()]),
            ] {
                let rows = store
                    .find_api_keys_by_reference("owner", Some(("name", direction)))
                    .await?;
                assert_eq!(
                    rows.iter()
                        .map(|row| row.name.field_value())
                        .collect::<Vec<_>>(),
                    expected
                );
                assert_eq!(
                    store
                        .lock()?
                        .api_keys
                        .snapshot()?
                        .iter()
                        .map(|row| row.name.field_value())
                        .collect::<Vec<_>>(),
                    names
                );
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn name_sort_preserves_conversion_errors_when_both_names_are_non_nullish() -> AuthResult<()> {
    let object = unconvertible_name();
    for names in [
        vec![FieldValue::from("desk"), object.clone()],
        vec![object, FieldValue::from("desk")],
    ] {
        let store = create_names(&names).await?;
        for direction in ["asc", "desc"] {
            assert!(matches!(
                store
                    .find_api_keys_by_reference("owner", Some(("name", direction)))
                    .await,
                Err(AuthError::Internal(message))
                    if message == "Cannot convert object to primitive value"
            ));
            assert_eq!(
                store
                    .find_api_keys_by_reference("owner", None)
                    .await?
                    .iter()
                    .map(|row| row.name.field_value())
                    .collect::<Vec<_>>(),
                names
            );
        }
    }
    Ok(())
}

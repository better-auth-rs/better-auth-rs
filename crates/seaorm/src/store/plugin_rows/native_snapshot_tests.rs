use super::*;
use crate::{
    SeaOrmOrganizationModel,
    store::{entities::team, joins, map_db_err},
};
use better_auth_core::user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform};
use sea_orm::{Database, QueryTrait};
use std::sync::MutexGuard;

fn locked<T>(value: &Mutex<T>) -> AuthResult<MutexGuard<'_, T>> {
    value
        .lock()
        .map_err(|_| AuthError::internal("Snapshot test lock is poisoned"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    None,
    Parent,
    Child,
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The regression asserts snapshot identity, callback order, errors, and unchanged database rows."
)]
async fn native_relation_mutations_share_projection_source_without_writing_database()
-> AuthResult<()> {
    let db = Database::connect("sqlite::memory:")
        .await
        .map_err(map_db_err)?;
    let _ = db
        .execute_unprepared(
            "CREATE TABLE team (id TEXT PRIMARY KEY, name TEXT, organization_id TEXT)",
        )
        .await
        .map_err(map_db_err)?;
    let _ = db
        .execute_unprepared(
            "INSERT INTO team VALUES ('stored-id', 'stored-name', 'stored-organization')",
        )
        .await
        .map_err(map_db_err)?;
    let query = select_all::<team::Entity>().into_query();
    for failure in [Failure::None, Failure::Parent, Failure::Child] {
        let row = SqlRow::from(
            db.query_one(&query)
                .await
                .map_err(map_db_err)?
                .ok_or_else(|| AuthError::internal("Stored snapshot is missing"))?,
        );
        let observed = Arc::new(Mutex::new(None::<FieldObject>));
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut fields = UserConfig::default();
        let callback_object = observed.clone();
        let callback_events = events.clone();
        let _ = fields.fields_mut().insert(
            "name".into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new(move |value| {
                        assert_eq!(value, FieldValue::from("parent-name"));
                        locked(&callback_events)?.push("child:name");
                        let object = locked(&callback_object)?.clone().ok_or_else(|| {
                            AuthError::internal("Parent did not capture its child")
                        })?;
                        assert_eq!(
                            object.set("organizationId", 9.0.into())?,
                            Some("stored-organization".into())
                        );
                        assert_eq!(object.set("id", 42.0.into())?, None);
                        if failure == Failure::Child {
                            return Err(AuthError::internal("child failure"));
                        }
                        Ok(value)
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let callback_events = events.clone();
        let _ = fields.fields_mut().insert(
            "organizationId".into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new(move |value| {
                        locked(&callback_events)?.push("child:organizationId");
                        assert_eq!(value, FieldValue::Number(9.0));
                        Ok(value)
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let fields = fields.adapter_fields(&[]);
        let relation = joins::raw_relation_value(
            std::slice::from_ref(&row),
            &fields,
            false,
            team::Model::column,
        )?;
        let object = relation
            .as_object()
            .ok_or_else(|| AuthError::internal("Native relation is not an object"))?
            .clone();
        let _ = locked(&observed)?.replace(object.clone());
        assert!(object.same_object(&row.clone().native_object(&fields, team::Model::column)?));
        let mut parent_fields = UserConfig::default();
        let callback_events = events.clone();
        let _ = parent_fields.fields_mut().insert(
            "relation".into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new(move |value| {
                        locked(&callback_events)?.push("parent");
                        let object = value.as_object().ok_or_else(|| {
                            AuthError::internal("Parent relation is not an object")
                        })?;
                        assert_eq!(
                            object.set("name", "parent-name".into())?,
                            Some("stored-name".into())
                        );
                        assert_eq!(object.delete("id")?, Some("stored-id".into()));
                        if failure == Failure::Parent {
                            return Err(AuthError::internal("parent failure"));
                        }
                        Ok(value)
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let result = async {
            let _ = parent_fields
                .project_adapter_records(
                    vec![AdapterRecord::new(
                        FieldMap::new(),
                        [("relation".into(), relation)].into(),
                    )],
                    false,
                    false,
                )
                .await?;
            fields
                .project_adapter_records(
                    vec![row.native_record(&fields, DbBackend::Sqlite, team::Model::column)?],
                    false,
                    false,
                )
                .await
        }
        .await;
        match failure {
            Failure::None => {
                let output = result?;
                assert_eq!(
                    output,
                    vec![
                        [
                            ("name".into(), "parent-name".into()),
                            ("organizationId".into(), 9.0.into()),
                            ("id".into(), "42".into()),
                        ]
                        .into()
                    ]
                );
                assert_eq!(
                    *locked(&events)?,
                    ["parent", "child:name", "child:organizationId"]
                );
            }
            Failure::Parent => {
                assert!(
                    matches!(result, Err(AuthError::Internal(message)) if message == "parent failure")
                );
                assert_eq!(*locked(&events)?, ["parent"]);
                assert_eq!(object.get("id")?, None);
            }
            Failure::Child => {
                assert!(
                    matches!(result, Err(AuthError::Internal(message)) if message == "child failure")
                );
                assert_eq!(*locked(&events)?, ["parent", "child:name"]);
                assert_eq!(object.get("organizationId")?, Some(9.0.into()));
                assert_eq!(object.get("id")?, Some(42.0.into()));
            }
        }
        let stored = SqlRow::from(
            db.query_one(&query)
                .await
                .map_err(map_db_err)?
                .ok_or_else(|| {
                    AuthError::internal("Stored snapshot is missing after projection")
                })?,
        );
        assert_eq!(stored.value("id")?, "stored-id".into());
        assert_eq!(stored.value("name")?, "stored-name".into());
        assert_eq!(
            stored.value("organization_id")?,
            "stored-organization".into()
        );
        assert!(!object.same_object(&stored.native_object(&fields, team::Model::column)?));
    }
    Ok(())
}

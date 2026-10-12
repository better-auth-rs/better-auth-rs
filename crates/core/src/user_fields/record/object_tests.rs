#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify callback order and shared properties; source errors propagate."
)]

use super::*;
use crate::user_fields::{FieldTransforms, UserFieldTransform};

#[tokio::test]
async fn shared_storage_reads_mapped_fields_and_id_after_earlier_callbacks() -> AuthResult<()> {
    let source = FieldObject::from(FieldMap::from([
        ("first".into(), "start".into()),
        ("physicalPayload".into(), "[]".into()),
        ("id".into(), "before".into()),
    ]));
    let payload = Value::from(FieldMap::from([("answer".into(), 7.into())]));
    let mutate = {
        let source = source.clone();
        let payload = payload.clone();
        UserFieldTransform::new(move |value| {
            assert_eq!(source.get("attached")?, Some(true.into()));
            assert_eq!(source.get("physicalPayload")?, Some("[]".into()));
            source.set("physicalPayload", payload.clone())?;
            assert_eq!(source.get("id")?, Some("before".into()));
            source.set("id", 9.into())?;
            Ok(value)
        })
    };
    let output = {
        let payload = payload.clone();
        UserFieldTransform::new(move |value| {
            assert!(value.strict_equals(&payload));
            Ok("[3,4]".into())
        })
    };
    let fields = UserConfig {
        additional_fields: Some(
            [
                (
                    "first".into(),
                    UserFieldConfig {
                        transform: Some(FieldTransforms {
                            output: Some(mutate),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                ),
                (
                    "payload".into(),
                    UserFieldConfig {
                        field_name: Some("physicalPayload".into()),
                        field_type: UserFieldType::Json,
                        transform: Some(FieldTransforms {
                            output: Some(output),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                ),
                ("id".into(), UserFieldConfig::default()),
            ]
            .into(),
        ),
    };
    let record = AdapterRecord::from_storage_object(
        source.clone(),
        FieldOutputCapabilities::json_only(false),
    )
    .with_storage_property("attached", true.into());
    let projected = fields
        .project_adapter_records_with_capabilities(
            vec![record],
            FieldOutputCapabilities::json_only(true),
        )
        .await?;
    assert_eq!(
        projected,
        vec![FieldMap::from([
            ("first".into(), "start".into()),
            (
                "payload".into(),
                Value::from(vec![Value::from(3), Value::from(4)])
            ),
            ("id".into(), "9".into()),
        ])]
    );
    assert_eq!(
        source.snapshot_fields()?,
        FieldMap::from([
            ("first".into(), "start".into()),
            ("physicalPayload".into(), payload),
            ("id".into(), 9.into()),
            ("attached".into(), true.into()),
        ])
    );
    Ok(())
}

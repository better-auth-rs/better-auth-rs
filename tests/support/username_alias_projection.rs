use super::*;
use better_auth_core::{
    plugin::MetadataMap,
    user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform},
    wire::UserView,
};
use serde_json::Value;
use std::sync::Mutex;

#[tokio::test]
async fn raw_username_projection_resolves_empty_aliases_and_preserves_serialized_values() {
    let user = user::Model {
        id: 1,
        name: Some("Ordinary User".into()),
        email: Some("ordinary@example.test".into()),
        email_verified: false,
        image: None,
        username: Some("ordinary_user".into()),
        display_username: Some("Ordinary Display".into()),
        two_factor_enabled: false,
        role: None,
        banned: false,
        ban_reason: None,
        ban_expires: None,
        metadata: json!({}),
        created_at: DateTime::<Utc>::UNIX_EPOCH,
        updated_at: DateTime::<Utc>::UNIX_EPOCH,
        tenant_id: 1,
        locale: "serialized-locale".into(),
    };
    let metadata = MetadataMap::from([
        ("username.enabled".into(), json!(true)),
        ("username.display.enabled".into(), json!(true)),
    ]);
    for (name, native) in [
        ("username", "ordinary_user"),
        ("displayUsername", "Ordinary Display"),
    ] {
        for (alias, observed) in [
            (None, Some(json!(native))),
            (Some(""), Some(json!(native))),
            (Some(name), Some(json!(native))),
            (Some("locale"), Some(json!("serialized-locale"))),
            (Some("image"), Some(Value::Null)),
            (Some("missing_display"), None),
            (Some(" "), None),
        ] {
            for returned in [true, false] {
                let events = Arc::new(Mutex::new(Vec::new()));
                let callback_events = events.clone();
                let mut fields = UserConfig::default();
                let _ = fields.fields_mut().insert(
                    name.into(),
                    UserFieldConfig {
                        field_name: alias.map(str::to_owned),
                        returned: Some(returned),
                        transform: Some(FieldTransforms {
                            output: Some(UserFieldTransform::new(move |value| {
                                callback_events
                                    .lock()
                                    .expect("projection trace lock")
                                    .push(value.json()?);
                                Ok(value)
                            })),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                );
                for public in [false, true] {
                    events.lock().expect("projection trace lock").clear();
                    let projected = if public {
                        UserView::with_fields(&user, &fields, &metadata).await
                    } else {
                        UserView::with_internal_fields(&user, &fields, &metadata).await
                    }
                    .expect("ordinary model projection succeeds");
                    assert_eq!(
                        events.lock().expect("projection trace lock").as_slice(),
                        std::slice::from_ref(&observed),
                        "callback: {name}, alias={alias:?}, public={public}, returned={returned}",
                    );
                    let expected = if public && !returned {
                        None
                    } else {
                        observed.clone()
                    };
                    let expected_field = if public && !returned {
                        None
                    } else {
                        Some(
                            observed
                                .clone()
                                .map(FieldValue::from_json)
                                .transpose()
                                .expect("expected projection field imports")
                                .unwrap_or(FieldValue::Undefined),
                        )
                    };
                    assert_eq!(
                        FieldMap::from(projected.clone()).get(name).cloned(),
                        expected_field,
                        "stored projection: {name}, alias={alias:?}, public={public}, returned={returned}",
                    );
                    let serialized = serde_json::to_value(projected)
                        .expect("projected display fields serialize");
                    assert_eq!(
                        serialized.get(name).cloned(),
                        expected,
                        "visible projection: {name}, alias={alias:?}, public={public}, returned={returned}",
                    );
                }
            }
        }
    }
}

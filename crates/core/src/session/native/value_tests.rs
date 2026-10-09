use super::*;
use crate::{FieldDate, FromFieldMap, Utf16String};

#[test]
fn public_user_projection_preserves_falsy_values_and_enumerates_native_values() -> AuthResult<()> {
    let config = UserConfig::default();
    for user in [
        FieldValue::Undefined,
        FieldValue::Null,
        false.into(),
        0.0.into(),
        (-0.0).into(),
        f64::NAN.into(),
        "".into(),
    ] {
        let data = NativeSessionData {
            session: SessionView::default(),
            user: user.clone(),
        };
        assert!(data.public_user(&config)?.same_value_zero(&user));
    }
    for user in [
        true.into(),
        7.0.into(),
        f64::INFINITY.into(),
        FieldDate::from_milliseconds(123.0).into(),
        FieldDate::invalid().into(),
    ] {
        let data = NativeSessionData {
            session: SessionView::default(),
            user,
        };
        assert_eq!(data.public_user(&config)?, FieldMap::new().into());
    }

    let mut config = config;
    let _ = config.fields_mut().insert(
        "1".into(),
        crate::user_fields::UserFieldConfig {
            returned: Some(false),
            ..Default::default()
        },
    );
    for user in [
        FieldValue::from("A😀B"),
        Utf16String::from_units(vec![0x41, 0xd83d, 0xde00, 0x42]).into(),
    ] {
        let data = NativeSessionData {
            session: SessionView::default(),
            user,
        };
        assert_eq!(
            data.public_user(&config)?,
            FieldMap::from([
                ("0".into(), "A".into()),
                ("2".into(), Utf16String::from_units(vec![0xde00]).into()),
                ("3".into(), "B".into()),
            ])
            .into()
        );
    }
    Ok(())
}

#[test]
fn native_session_input_preserves_user_shape_and_shared_values_before_explicit_views()
-> AuthResult<()> {
    let shared: FieldValue =
        FieldMap::from([("ownUndefined".into(), FieldValue::Undefined)]).into();
    let date: FieldValue = FieldDate::from_milliseconds(123.0).into();
    let object: FieldValue = FieldMap::from([
        ("0".into(), shared.clone()),
        ("1".into(), shared.clone()),
        ("name".into(), FieldValue::Null),
        ("email".into(), 7.0.into()),
        ("when".into(), date.clone()),
    ])
    .into();
    for user in [
        FieldValue::Undefined,
        FieldValue::Null,
        7.0.into(),
        vec![shared.clone(), shared.clone()].into(),
        object.clone(),
    ] {
        let data = NativeSessionData::from_field_values(FieldMap::from([
            ("session".into(), FieldMap::new().into()),
            ("user".into(), user.clone()),
        ]))?;
        assert!(data.user.strict_equals(&user));
        if user.is_object() {
            let view = data.user_view()?;
            assert!(view.id.is_undefined());
            assert!(view.name.field_value().is_null());
            assert_eq!(view.email.field_value(), FieldValue::from(7.0));
            let fields = FieldMap::from(view);
            assert_eq!(FieldValue::from(fields.clone()), object);
            assert!(fields.get("0").unwrap().strict_equals(&shared));
            assert!(fields.get("1").unwrap().strict_equals(&shared));
            assert!(fields.get("when").unwrap().strict_equals(&date));
            let (view, _) = data.into_views()?;
            assert_eq!(FieldValue::from(FieldMap::from(view)), object);
        } else {
            assert!(data.user_view().is_err());
        }
    }
    let missing = NativeSessionData::from_field_values(FieldMap::from([(
        "session".into(),
        FieldMap::new().into(),
    )]))?;
    assert!(missing.user.is_undefined());
    Ok(())
}

#[test]
fn native_session_json_decode_keeps_user_absence_null_arrays_and_numeric_keys() -> AuthResult<()> {
    for source in [
        serde_json::json!({"session": {}}),
        serde_json::json!({"session": {}, "user": null}),
        serde_json::json!({"session": {}, "user": 7}),
        serde_json::json!({"session": {}, "user": [{"name": null}]}),
        serde_json::json!({"session": {}, "user": {"0": {"id": 7}, "id": null}}),
    ] {
        let data: NativeSessionData = serde_json::from_value(source.clone())?;
        assert_eq!(data.user.is_undefined(), source.get("user").is_none());
        assert_eq!(serde_json::to_value(data)?, source);
    }
    Ok(())
}

#[tokio::test]
async fn native_snapshot_tokens_keep_mapping_identity_and_many_relationships() -> AuthResult<()> {
    use crate::store::{EphemeralStore, SessionStore, UserStore};
    use crate::user_fields::{
        FieldTransforms, UserFieldConfig, UserFieldReference, UserFieldTransform,
    };
    use crate::{AuthConfig, CreateSession, CreateUser};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    let object: FieldValue = FieldMap::from([("token".into(), 7.into())]).into();
    for joins in [false, true] {
        for token in [7.into(), FieldValue::Null, object.clone()] {
            let writes = Arc::new(AtomicUsize::new(0));
            let observed = writes.clone();
            let stored_token = token.clone();
            let mut config = AuthConfig::default();
            config.advanced.database.joins = Some(joins);
            let _ = config.session.fields_mut().insert(
                "token".into(),
                UserFieldConfig {
                    field_name: Some("stored_token".into()),
                    transform: Some(FieldTransforms {
                        input: Some(UserFieldTransform::new(move |_| {
                            let _ = observed.fetch_add(1, Ordering::SeqCst);
                            Ok(stored_token.clone())
                        })),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            );
            let _ = config.user.fields_mut().insert(
                "image".into(),
                UserFieldConfig {
                    references: Some(UserFieldReference {
                        model: "session".into(),
                        field: "id".into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            );
            let store = EphemeralStore::new(Arc::new(config));
            let created = store
                .create_session(CreateSession {
                    inherited_fields: Default::default(),
                    user_id: "canonical-owner".into(),
                    expires_at: FieldDate::from_milliseconds(4_102_444_800_000.0),
                    additional_fields: [("token".into(), "original-token".into())].into(),
                    ip_address: None,
                    user_agent: None,
                    impersonated_by: None,
                    active_organization_id: None,
                })
                .await?;
            assert!(created.token.field_value().strict_equals(&token));
            let mut expected = Vec::new();
            for email in ["first@example.test", "second@example.test"] {
                let mut user = CreateUser::new().with_email(email);
                user.image = Some(created.id.typed()?.clone()).into();
                expected.push(FieldValue::from(FieldMap::from(
                    store.create_user(user).await?,
                )));
            }
            let (selected, relation) =
                store
                    .get_session_snapshot_value(&token)
                    .await?
                    .ok_or_else(|| {
                        AuthError::internal("Native token must select the stored Session")
                    })?;
            assert_eq!(FieldMap::from(selected), FieldMap::from(created));
            let relation = NativeSessionData::from(relation.ok_or_else(|| {
                AuthError::internal("Native token lookup must retain the loaded User relationship")
            })?);
            assert_eq!(relation.user, FieldValue::from(expected));
            for unmatched in [
                FieldValue::from("7"),
                FieldMap::from([("token".into(), 7.into())]).into(),
            ] {
                assert!(
                    store
                        .get_session_snapshot_value(&unmatched)
                        .await?
                        .is_none()
                );
            }
            assert_eq!(writes.load(Ordering::SeqCst), 1);
        }
    }
    Ok(())
}

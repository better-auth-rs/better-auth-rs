use super::*;
use crate::{
    AuthConfig, AuthRequest, FieldObject, HttpMethod,
    field_value::{FieldObjectSource, FieldPropertyDescriptor},
};
use std::sync::{Arc, Mutex};

struct RootSource {
    fields: FieldObject,
    reads: Arc<Mutex<Vec<String>>>,
}

impl FieldObjectSource for RootSource {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        Err(AuthError::internal(
            "Native Session root must not be enumerated",
        ))
    }

    fn own_property_descriptor(&self, name: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        self.fields.own_property_descriptor(name)
    }

    fn get_with_receiver(
        &self,
        name: &str,
        receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        self.reads
            .lock()
            .map_err(|_| AuthError::internal("Read trace poisoned"))?
            .push(name.into());
        self.fields.get_with_receiver(name, receiver)
    }

    fn set_with_receiver(
        &self,
        name: String,
        value: FieldValue,
        receiver: &FieldValue,
    ) -> AuthResult<bool> {
        self.fields.set_with_receiver(&name, value, receiver)
    }

    fn delete(&self, name: &str) -> AuthResult<bool> {
        self.fields.delete(name)
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Err(AuthError::internal(
            "Native Session root must not be snapshotted",
        ))
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }

    fn define_own_property(
        &self,
        name: String,
        definition: crate::FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        self.fields.define_own_property(name, definition)
    }
}

#[test]
fn request_and_issuance_share_the_native_root_without_eager_property_reads() -> AuthResult<()> {
    let reads = Arc::new(Mutex::new(Vec::new()));
    let user: FieldValue = FieldMap::from([("id".into(), 7.into())]).into();
    let session: FieldValue = FieldMap::from([
        ("token".into(), FieldValue::Null),
        ("active".into(), "public-extension".into()),
        ("ownUndefined".into(), FieldValue::Undefined),
    ])
    .into();
    let root = FieldValue::Object(FieldObject::from_source(Arc::new(RootSource {
        fields: FieldMap::from([
            ("session".into(), session.clone()),
            ("user".into(), user.clone()),
        ])
        .into(),
        reads: reads.clone(),
    })));
    let data = NativeSessionData::from_native(root.clone(), false);
    let request = AuthRequest::new(HttpMethod::Get, "/session-probe");
    request.set_session_snapshot(Some(data.clone().into()))?;
    request.set_new_session(data.clone())?;
    let current = request
        .native_session_snapshot()?
        .ok_or(AuthError::SessionNotFound)?;
    let issued = request.new_session()?.ok_or(AuthError::SessionNotFound)?;
    assert!(current.field_value().strict_equals(&root));
    assert!(issued.field_value().strict_equals(&root));
    assert!(
        reads
            .lock()
            .map_err(|_| AuthError::internal("Read trace poisoned"))?
            .is_empty()
    );
    assert!(current.user_value()?.strict_equals(&user));
    assert!(issued.session_value()?.strict_equals(&session));
    let view = data.session_view()?;
    assert!(!view.active);
    assert!(view.token.field_value().is_null());
    assert_eq!(
        view.additional_fields.get("active"),
        Some(&"public-extension".into())
    );
    session.set_model_property("token", 17.into())?;
    assert_eq!(current.session_property("token")?, 17.into());
    assert!(view.token.field_value().is_null());
    root.set_model_property("user", FieldValue::Undefined)?;
    assert!(issued.user_value()?.is_undefined());
    assert!(issued.user_property("id").is_err());
    assert_eq!(
        *reads
            .lock()
            .map_err(|_| AuthError::internal("Read trace poisoned"))?,
        ["user", "session", "session", "session", "user", "user"]
    );
    Ok(())
}

#[test]
fn public_projection_retains_private_liveness_and_original_relationship_cardinality()
-> AuthResult<()> {
    let mut session = SessionView::default();
    session.active = false;
    session.additional_fields = FieldMap::from([
        ("active".into(), true.into()),
        ("hidden".into(), "private".into()),
    ]);
    let data = NativeSessionData::new(
        session,
        vec![FieldMap::from([("id".into(), "owner".into())]).into()].into(),
    );
    let mut config = AuthConfig::default();
    let _ = config.session.fields_mut().insert(
        "hidden".into(),
        crate::user_fields::UserFieldConfig {
            returned: Some(false),
            ..Default::default()
        },
    );
    let public = data.public_data(&config)?;
    assert!(!public.field_value().strict_equals(&data.field_value()));
    assert!(
        !public
            .session_value()?
            .strict_equals(&data.session_value()?)
    );
    assert_eq!(data.session_property("hidden")?, "private".into());
    assert!(public.session_property("hidden")?.is_undefined());
    assert_eq!(public.session_property("active")?, true.into());
    assert!(!public.session_view()?.active);
    assert!(public.user_value()?.is_object());
    assert!(
        matches!(SessionSnapshot::from(public).into_typed(), Err(AuthError::Internal(message)) if message == "A User relationship array cannot authenticate a typed User")
    );
    Ok(())
}

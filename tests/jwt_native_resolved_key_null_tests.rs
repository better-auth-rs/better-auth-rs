#![expect(
    clippy::panic_in_result_fn,
    reason = "The native JWT contract asserts truthiness, callback order, error class, and zero persistence."
)]

use better_auth::{AuthConfig, AuthError, AuthResult, BetterAuth, plugins::JwtPlugin};
use better_auth_core::{
    FieldFunction, FieldMap, FieldObject, FieldValue,
    field_value::{
        FieldObjectSource, FieldProperty, FieldPropertyDefinition, FieldPropertyDescriptor,
    },
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

struct ChangingSigner {
    reads: Arc<AtomicUsize>,
    getter: FieldFunction,
}

impl ChangingSigner {
    fn new(events: Arc<Mutex<Vec<&'static str>>>, next: FieldValue) -> Self {
        let reads = Arc::new(AtomicUsize::new(0));
        let observed = reads.clone();
        let getter = FieldFunction::contextual(move |_, _| {
            let first = observed.fetch_add(1, Ordering::SeqCst) == 0;
            events
                .lock()
                .map_err(|_| AuthError::internal("Signer trace lock poisoned"))?
                .push(if first { "sign.get:1" } else { "sign.get:2" });
            Ok(if first { false.into() } else { next.clone() })
        });
        Self { reads, getter }
    }
}

impl FieldObjectSource for ChangingSigner {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        Ok(vec!["sign".into()])
    }

    fn own_property_descriptor(&self, name: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        Ok((name == "sign").then(|| FieldPropertyDescriptor {
            enumerable: true,
            configurable: true,
            property: FieldProperty::Accessor {
                get: Some(self.getter.clone()),
                set: None,
            },
        }))
    }

    fn get_with_receiver(
        &self,
        name: &str,
        receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        if name == "sign" {
            self.getter.call_with(receiver, &[]).map(Some)
        } else {
            Ok(None)
        }
    }

    fn set_with_receiver(&self, _: String, _: FieldValue, _: &FieldValue) -> AuthResult<bool> {
        Err(AuthError::internal("Signing must not mutate JWT options"))
    }
    fn define_own_property(&self, _: String, _: FieldPropertyDefinition) -> AuthResult<bool> {
        Err(AuthError::internal("Signing must not mutate JWT options"))
    }

    fn delete(&self, _: &str) -> AuthResult<bool> {
        Err(AuthError::internal("Signing must not remove JWT options"))
    }
    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Err(AuthError::internal(
            "Signing must not snapshot nested JWT options",
        ))
    }
    fn identity(&self) -> usize {
        std::ptr::from_ref(self).addr()
    }
}

#[tokio::test]
async fn changing_sign_truthiness_rejects_the_null_resolved_key_before_storage() -> AuthResult<()> {
    for callable in [true, false] {
        let mut config = AuthConfig::new("native-jwt-null-key-secret-at-least-32-characters");
        config.base_url = "http://jwt-native-null-key.test".into();
        config.telemetry.enabled = false;
        let auth = BetterAuth::stateless(config)
            .plugin(JwtPlugin::new())
            .build()
            .await?;
        let events = Arc::new(Mutex::new(Vec::new()));
        let observed = events.clone();
        let next = if callable {
            FieldFunction::contextual(move |_, _| {
                observed
                    .lock()
                    .map_err(|_| AuthError::internal("Signer trace lock poisoned"))?
                    .push("sign.call");
                Err(AuthError::internal(
                    "Resolving a delegated signing key must not call the signer",
                ))
            })
            .into()
        } else {
            FieldMap::from([("delegated".into(), true.into())]).into()
        };
        let signer = Arc::new(ChangingSigner::new(events.clone(), next));
        let result = auth
            .jwt()?
            .sign_value_with_overrides(
                FieldMap::from([("iat".into(), 10.0.into()), ("exp".into(), 70.0.into())]).into(),
                FieldMap::from([(
                    "jwt".into(),
                    FieldObject::from_source(signer.clone()).into(),
                )])
                .into(),
            )
            .await;
        let error = match result {
            Err(error) => error,
            Ok(_) => {
                return Err(AuthError::internal(
                    "Null resolved keys must reject signing",
                ));
            }
        };
        assert!(!error.is_api_error()?);
        let native = error.into_thrown_value()?;
        assert_eq!(native.model_property("name")?, "TypeError".into());
        assert_eq!(
            native.model_property("message")?,
            "Cannot destructure property 'alg' from null or undefined value".into(),
        );
        assert_eq!(signer.reads.load(Ordering::SeqCst), 2);
        assert_eq!(
            *events
                .lock()
                .map_err(|_| AuthError::internal("Signer trace lock poisoned"))?,
            ["sign.get:1", "sign.get:2"]
        );
        assert!(auth.store().list_jwk_records().await?.is_empty());
    }
    Ok(())
}

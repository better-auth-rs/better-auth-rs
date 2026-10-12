#![expect(
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract. Fixture indexing must fail when an expected record or property is missing. Assertions report exact contract mismatches while Result propagates fixture errors."
)]

use super::*;
use crate::config::CookieCacheVersion;
use crate::field_value::{FieldObject, FieldObjectSource};
use crate::{FromFieldMap, HttpMethod, SessionView};
use std::sync::{Arc, Mutex};

type Events = Arc<Mutex<Vec<String>>>;

fn record(events: &Events, event: impl Into<String>) -> AuthResult<()> {
    events
        .lock()
        .map_err(|_| AuthError::internal("Cache trace poisoned"))?
        .push(event.into());
    Ok(())
}

struct Probe {
    model: &'static str,
    events: Events,
    error: Arc<Mutex<Option<AuthError>>>,
    properties: FieldObject,
}

impl Probe {
    fn new(model: &'static str, events: Events, failure: Option<AuthError>) -> Self {
        let error = Arc::new(Mutex::new(failure));
        let properties = ["value", "later"]
            .into_iter()
            .map(|name| {
                let events = events.clone();
                let error = error.clone();
                (
                    name.into(),
                    crate::FieldPropertyDescriptor {
                        enumerable: true,
                        configurable: true,
                        property: crate::FieldProperty::Accessor {
                            get: Some(crate::FieldFunction::contextual(move |_, _| {
                                Self::read(model, &events, &error, name)
                            })),
                            set: None,
                        },
                    },
                )
            })
            .collect::<indexmap::IndexMap<_, _>>()
            .into();
        Self {
            model,
            events,
            error,
            properties,
        }
    }

    fn read(
        model: &str,
        events: &Events,
        error: &Mutex<Option<AuthError>>,
        name: &str,
    ) -> AuthResult<FieldValue> {
        record(events, format!("{model}.{name}"))?;
        if let Some(error) = error
            .lock()
            .map_err(|_| AuthError::internal("Cache error poisoned"))?
            .take()
        {
            return Err(error);
        }
        Ok(name.into())
    }
}

impl FieldObjectSource for Probe {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        Ok(vec!["value".into(), "later".into()])
    }

    fn own_property_descriptor(
        &self,
        name: &str,
    ) -> AuthResult<Option<crate::field_value::FieldPropertyDescriptor>> {
        self.properties.own_property_descriptor(name)
    }

    fn get_with_receiver(
        &self,
        name: &str,
        _receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        Self::read(self.model, &self.events, &self.error, name).map(Some)
    }

    fn set_with_receiver(
        &self,
        _: String,
        _: FieldValue,
        _receiver: &FieldValue,
    ) -> AuthResult<bool> {
        Err(AuthError::internal("Cache probes are immutable"))
    }

    fn delete(&self, _: &str) -> AuthResult<bool> {
        Err(AuthError::internal("Cache probes are immutable"))
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Err(AuthError::internal(
            "Cache probes require one property read at a time",
        ))
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }

    fn define_own_property(
        &self,
        _name: String,
        _definition: crate::FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        Err(AuthError::internal(
            "This contract source does not define properties",
        ))
    }
}

fn data(session_payload: FieldValue, user_name: FieldValue) -> AuthResult<NativeSessionData> {
    Ok(NativeSessionData::new(
        SessionView::from_field_values(FieldMap::from([
            ("id".into(), "session".into()),
            ("token".into(), "token".into()),
            ("userId".into(), "owner".into()),
            ("payload".into(), session_payload),
        ]))?,
        FieldMap::from([("id".into(), "owner".into()), ("name".into(), user_name)]).into(),
    ))
}

#[tokio::test]
async fn cache_failures_preserve_filter_version_json_order_and_original_errors() -> AuthResult<()> {
    for strategy in [
        CookieCacheStrategy::Compact,
        CookieCacheStrategy::Jwt,
        CookieCacheStrategy::Jwe,
    ] {
        for stage in [
            "session-getter",
            "user-getter",
            "version",
            "session-cycle",
            "user-cycle",
        ] {
            let events = Events::default();
            let message = "cookie cache original error".to_owned();
            let allocation = message.as_ptr() as usize;
            let error = Arc::new(Mutex::new(Some(AuthError::internal(message))));
            let mut cycles = Vec::new();
            let mut probe = |model: &'static str| -> AuthResult<FieldValue> {
                if stage.strip_suffix("-cycle") == Some(model) {
                    let object = FieldObject::from(FieldMap::new());
                    object.set("self", FieldValue::Object(object.clone()))?;
                    cycles.push(object.clone());
                    return Ok(FieldValue::Object(object));
                }
                let failure = if stage.strip_suffix("-getter") == Some(model) {
                    error
                        .lock()
                        .map_err(|_| AuthError::internal("Cache error poisoned"))?
                        .take()
                } else {
                    None
                };
                Ok(FieldValue::Object(FieldObject::from_source(Arc::new(
                    Probe::new(model, events.clone(), failure),
                ))))
            };
            let data = data(probe("session")?, probe("user")?)?;
            let mut config =
                AuthConfig::new("cookie-json-contract-secret-at-least-thirty-two-characters");
            config.session.additional_fields = Some(Default::default());
            config.session.cookie_cache = Some(CookieCacheConfig {
                enabled: Some(true),
                strategy: Some(strategy),
                version: CookieCacheVersion::dynamic({
                    let events = events.clone();
                    let error = error.clone();
                    move |_| {
                        let events = events.clone();
                        let error = error.clone();
                        async move {
                            record(&events, "version")?;
                            if stage == "version" {
                                return Err(error
                                    .lock()
                                    .map_err(|_| AuthError::internal("Cache error poisoned"))?
                                    .take()
                                    .ok_or_else(|| {
                                        AuthError::internal("Missing version failure")
                                    })?);
                            }
                            Ok("v2".into())
                        }
                    }
                }),
                ..Default::default()
            });
            let request = AuthRequest::new(HttpMethod::Get, "/get-session");
            let result = write(&request, &data, &config, false, None, false, None).await;
            for cycle in cycles {
                let _ = cycle.delete("self")?;
            }
            if stage.ends_with("cycle") {
                assert!(
                    matches!(result, Err(AuthError::TypeError(message)) if message == "Converting circular structure to JSON"),
                    "{stage}/{strategy:?}"
                );
            } else {
                assert!(
                    matches!(result, Err(AuthError::Internal(message)) if message == "cookie cache original error" && message.as_ptr() as usize == allocation),
                    "{stage}/{strategy:?}"
                );
            }
            let expected: &[&str] = match stage {
                "session-getter" => &["session.value"],
                "user-getter" => &["session.value", "session.later", "user.value"],
                "version" => &[
                    "session.value",
                    "session.later",
                    "user.value",
                    "user.later",
                    "version",
                ],
                "session-cycle" => &["user.value", "user.later", "version"],
                _ => &["session.value", "session.later", "version"],
            };
            assert_eq!(
                *events
                    .lock()
                    .map_err(|_| AuthError::internal("Cache trace poisoned"))?,
                expected,
                "{stage}/{strategy:?}"
            );
            assert!(request.take_response_headers()?.is_empty());
        }
    }
    Ok(())
}

#[tokio::test]
async fn payload_preserves_public_active_extension_and_omits_private_active() -> AuthResult<()> {
    for visible in [None, Some(FieldValue::from("public-active"))] {
        let original = data(FieldValue::Null, "Owner".into())?;
        let data = NativeSessionData::from_native(original.field_value(), true);
        if let Some(value) = &visible {
            data.session_value()?
                .set_model_property("active", value.clone())?;
        }
        let (payload, _) = payload(
            &data,
            &AuthConfig::default(),
            &CookieCacheConfig::default(),
            false,
        )
        .await?;
        let session = payload
            .get("session")
            .ok_or_else(|| AuthError::internal("Missing cache Session"))?;
        let mut expected = FieldMap::from([
            ("id".into(), FieldValue::from("session")),
            ("token".into(), "token".into()),
            ("userId".into(), "owner".into()),
            ("payload".into(), FieldValue::Null),
        ]);
        if visible.is_some() {
            let _ = expected.insert("active".into(), "public-active".into());
        }
        assert_eq!(
            session
                .as_object()
                .ok_or_else(|| AuthError::internal("Cache Session is not an object"))?
                .snapshot_fields()?,
            expected
        );
        assert!(data.active());
        assert_eq!(
            data.session_value()?.as_object().unwrap().get("active")?,
            visible
        );
    }
    Ok(())
}

#[tokio::test]
async fn compact_serializes_live_session_children_twice_after_version() -> AuthResult<()> {
    let events = Events::default();
    let child = FieldObject::from(FieldMap::from([("serial".into(), 0.0.into())]));
    child.set(
        "toJSON",
        crate::FieldFunction::contextual({
            let events = events.clone();
            move |receiver, arguments| {
                assert_eq!(arguments, &[FieldValue::from("payload")]);
                let serial = receiver
                    .model_property("serial")?
                    .as_f64()
                    .ok_or_else(|| AuthError::internal("Missing live serial"))?
                    + 1.0;
                receiver
                    .as_object()
                    .ok_or_else(|| AuthError::internal("Missing toJSON receiver"))?
                    .set("serial", serial.into())?;
                record(&events, format!("payload:{serial}"))?;
                Ok(FieldMap::from([("serial".into(), serial.into())]).into())
            }
        })
        .into(),
    )?;
    let data = data(FieldValue::Object(child.clone()), "Owner".into())?;
    let config = AuthConfig::new("cookie-live-contract-secret-at-least-thirty-two-characters");
    let cache = CookieCacheConfig {
        strategy: Some(CookieCacheStrategy::Compact),
        version: CookieCacheVersion::dynamic({
            let events = events.clone();
            move |_| {
                let events = events.clone();
                async move {
                    record(&events, "version")?;
                    Ok("live".into())
                }
            }
        }),
        ..Default::default()
    };
    let encoded = encode(&data, &config, &cache, false).await?;
    assert_eq!(child.get("serial")?, Some(2.0.into()));
    assert_eq!(
        *events
            .lock()
            .map_err(|_| AuthError::internal("Cache trace poisoned"))?,
        ["version", "payload:1", "payload:2"]
    );
    let envelope: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|error| AuthError::internal(error.to_string()))?,
    )?;
    assert_eq!(envelope["session"]["session"]["payload"]["serial"], 2);
    let mut signed = envelope["session"]
        .as_object()
        .ok_or_else(|| AuthError::internal("Missing signed payload"))?
        .clone();
    signed["session"]["payload"]["serial"] = 1.into();
    let _ = signed.insert("expiresAt".into(), envelope["expiresAt"].clone());
    let mut mac = Hmac::<Sha256>::new_from_slice(config.signing_secret().as_bytes())
        .map_err(|error| AuthError::internal(error.to_string()))?;
    mac.update(&serde_json::to_vec(&signed)?);
    assert_eq!(
        envelope["signature"],
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    );
    Ok(())
}

#[tokio::test]
async fn clone_boundaries_reject_functions_before_to_json_and_preserve_absent_session_config()
-> AuthResult<()> {
    for strategy in [
        CookieCacheStrategy::Compact,
        CookieCacheStrategy::Jwt,
        CookieCacheStrategy::Jwe,
    ] {
        for declared in [false, true] {
            let events = Events::default();
            let value = FieldMap::from([(
                "toJSON".into(),
                crate::FieldFunction::contextual({
                    let events = events.clone();
                    move |_, _| {
                        record(&events, "toJSON")?;
                        Ok("encoded".into())
                    }
                })
                .into(),
            )]);
            let data = data(value.into(), "Owner".into())?;
            let mut config =
                AuthConfig::new("cookie-clone-contract-secret-at-least-thirty-two-characters");
            if declared {
                config.session.additional_fields = Some(Default::default());
            }
            let cache = CookieCacheConfig {
                strategy: Some(strategy),
                version: CookieCacheVersion::dynamic({
                    let events = events.clone();
                    move |_| {
                        let events = events.clone();
                        async move {
                            record(&events, "version")?;
                            Ok("native".into())
                        }
                    }
                }),
                ..Default::default()
            };
            let result = encode(&data, &config, &cache, false).await;
            let expected: &[&str] = if declared {
                assert!(matches!(result, Err(AuthError::DataClone)));
                &[]
            } else if matches!(strategy, CookieCacheStrategy::Compact) {
                assert!(result.is_ok());
                &["version", "toJSON", "toJSON"]
            } else {
                assert!(matches!(result, Err(AuthError::DataClone)));
                &["version"]
            };
            assert_eq!(
                *events
                    .lock()
                    .map_err(|_| AuthError::internal("Cache trace poisoned"))?,
                expected,
                "{strategy:?}/{declared}"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn version_callback_mutations_follow_cache_projection_identity() -> AuthResult<()> {
    for filter_session in [false, true] {
        let data = data("before".into(), "Before".into())?;
        let root = data.field_value();
        let cache = CookieCacheConfig {
            version: CookieCacheVersion::dynamic(move |observed| {
                let root = root.clone();
                async move {
                    assert!(observed.field_value().strict_equals(&root));
                    observed
                        .session_value()?
                        .set_model_property("payload", "after".into())?;
                    observed
                        .user_value()?
                        .set_model_property("name", "After".into())?;
                    Ok("mutated".into())
                }
            }),
            ..Default::default()
        };
        let mut config = AuthConfig::default();
        if filter_session {
            config.session.additional_fields = Some(Default::default());
        }
        let (payload, _) = payload(&data, &config, &cache, false).await?;
        let session = payload.get("session").ok_or(AuthError::SessionNotFound)?;
        let user = payload.get("user").ok_or(AuthError::UserNotFound)?;
        assert_eq!(
            session.model_property("payload")?,
            if filter_session { "before" } else { "after" }.into()
        );
        assert_eq!(user.model_property("name")?, "Before".into());
        assert_eq!(data.session_property("payload")?, "after".into());
        assert_eq!(data.user_property("name")?, "After".into());
        assert_eq!(payload.get("version"), Some(&"mutated".into()));
    }
    Ok(())
}

//! Paired with social-native-defaults.test.mjs at the production HTTP profile boundary.

use super::*;
use better_auth_core::{
    FieldFunction, FieldMap, FieldObject, FieldValue,
    field_value::{
        FieldObjectSource, FieldProperty, FieldPropertyDefinition, FieldPropertyDescriptor,
    },
};
use std::sync::atomic::{AtomicUsize, Ordering};

fn object<const N: usize>(fields: [(&str, FieldValue); N]) -> FieldValue {
    fields
        .into_iter()
        .map(|(name, value)| (name.into(), value))
        .collect::<FieldMap>()
        .into()
}

fn keys(value: &FieldValue) -> Vec<String> {
    value.as_object().unwrap().enumerable_keys().unwrap()
}

struct NativeMapper {
    id: &'static str,
    shared: FieldValue,
    raw: Mutex<Option<FieldValue>>,
    events: Arc<Mutex<Vec<&'static str>>>,
}

impl NativeMapper {
    fn new(id: &'static str, shared: FieldValue) -> Arc<Self> {
        Arc::new(Self {
            id,
            shared,
            raw: Mutex::new(None),
            events: Arc::default(),
        })
    }

    fn raw(&self) -> FieldValue {
        self.raw.lock().unwrap().clone().unwrap()
    }
}

#[async_trait]
impl OAuthProfileMapper for NativeMapper {
    async fn map_profile_native(&self, profile: &FieldValue) -> AuthResult<FieldValue> {
        *self.raw.lock().unwrap() = Some(profile.clone());
        self.events.lock().unwrap().push("mapper");
        let raw = profile.as_object().unwrap();
        match self.id {
            "cloudflare" => {
                raw.set("first_name", "Mutated".into())?;
                raw.set("last_name", "Name".into())?;
                raw.set("email", self.shared.clone())?;
                Ok(object([
                    ("emailVerified", "verified".into()),
                    ("nativeExtra", FieldValue::Undefined),
                ]))
            }
            "roblox" | "zoom" => {
                let (name, image) = if self.id == "roblox" {
                    ("nickname", "picture")
                } else {
                    ("display_name", "pic_url")
                };
                raw.set(name, self.shared.clone())?;
                raw.set(image, FieldValue::Undefined)?;
                if self.id == "zoom" {
                    raw.set("email", self.shared.clone())?;
                    raw.set("verified", Vec::<FieldValue>::new().into())?;
                }
                raw.set("child", self.shared.clone())?;
                raw.set("ownUndefined", FieldValue::Undefined)?;
                Ok(object([
                    ("mappedExtra", self.shared.clone()),
                    ("mappedUndefined", FieldValue::Undefined),
                ]))
            }
            "reddit" => {
                raw.set("id", "mutated-reddit".into())?;
                raw.set("name", self.shared.clone())?;
                raw.set("icon_img", FieldValue::Undefined)?;
                Ok(FieldObject::from_source(Arc::new(RedditMapped::new(
                    self.shared.clone(),
                    self.events.clone(),
                )))
                .into())
            }
            _ => Err(AuthError::internal(
                "Unknown native profile contract provider",
            )),
        }
    }
}

struct RedditMapped {
    fields: FieldObject,
}

impl RedditMapped {
    fn new(shared: FieldValue, events: Arc<Mutex<Vec<&'static str>>>) -> Self {
        let email_reads = AtomicUsize::new(0);
        let email_events = events.clone();
        let email = FieldFunction::contextual(move |_, _| {
            let read = email_reads.fetch_add(1, Ordering::SeqCst);
            email_events.lock().unwrap().push(match read {
                0 => "email:1",
                1 => "email:2",
                _ => "email:extra",
            });
            Ok(if read == 0 { "" } else { "spread@reddit.test" }.into())
        });
        let verified_reads = AtomicUsize::new(0);
        let verified = shared.clone();
        let email_verified = FieldFunction::contextual(move |_, _| {
            let read = verified_reads.fetch_add(1, Ordering::SeqCst);
            events.lock().unwrap().push(match read {
                0 => "verified:1",
                1 => "verified:2",
                _ => "verified:extra",
            });
            Ok(if read == 0 {
                verified.clone()
            } else {
                FieldValue::Null
            })
        });
        let mut fields = [("email", email), ("emailVerified", email_verified)]
            .into_iter()
            .map(|(name, get)| {
                (
                    name.into(),
                    FieldPropertyDescriptor {
                        enumerable: true,
                        configurable: true,
                        property: FieldProperty::Accessor {
                            get: Some(get),
                            set: None,
                        },
                    },
                )
            })
            .collect::<indexmap::IndexMap<_, _>>();
        let _ = fields.insert("nativeExtra".into(), FieldPropertyDescriptor::data(shared));
        Self {
            fields: fields.into(),
        }
    }
}

impl FieldObjectSource for RedditMapped {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        self.fields.own_keys()
    }

    fn own_property_descriptor(&self, name: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        self.fields.own_property_descriptor(name)
    }

    fn get_with_receiver(
        &self,
        name: &str,
        receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        self.fields.get_with_receiver(name, receiver)
    }

    fn set_with_receiver(&self, _: String, _: FieldValue, _: &FieldValue) -> AuthResult<bool> {
        Err(AuthError::internal("Mapper result must not be mutated"))
    }

    fn define_own_property(&self, _: String, _: FieldPropertyDefinition) -> AuthResult<bool> {
        Err(AuthError::internal("Mapper result must not be mutated"))
    }

    fn delete(&self, _: &str) -> AuthResult<bool> {
        Err(AuthError::internal("Mapper result must not be mutated"))
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        self.own_keys()?
            .into_iter()
            .map(|key| {
                self.get_with_receiver(&key, &FieldValue::Undefined)
                    .map(|value| (key, value.unwrap()))
            })
            .collect()
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }
}

async fn fetch(
    mapper: &Arc<NativeMapper>,
) -> (
    social_profile::ProviderProfile,
    resolved::ResolvedOAuthConfig,
    OAuthTokenSet,
) {
    let id = mapper.id;
    let profile = profile_response(id, &fixture()["providers"][id]["profile"]);
    let server = ProfileServer::start(profile, mapper.events.clone(), "GET", None).await;
    let mut config = provider(id);
    config.user_info_url = Some(format!("{}/profile", server.url));
    config.map_profile_to_user = Some(mapper.clone());
    let resolved = resolve(id, config).await;
    let request = OAuthUserInfoRequest {
        access_token: Some("ordinary-access".into()).into(),
        ..Default::default()
    };
    let tokens = OAuthTokenSet::from_fields(request.fields());
    let response = social_profile::fetch_user_info_for_code(&resolved.providers[id], request, None)
        .await
        .unwrap();
    assert_eq!(keys(&response.value), ["user", "data"]);
    (response, resolved, tokens)
}

#[tokio::test]
async fn cloudflare_keeps_pre_mapper_name_and_reads_mutated_native_email() {
    let email = object([("address", "dynamic@cloudflare.test".into())]);
    let mapper = NativeMapper::new("cloudflare", email.clone());
    let (response, resolved, tokens) = fetch(&mapper).await;
    assert_eq!(*mapper.events.lock().unwrap(), ["http", "mapper"]);
    let user = profile_test_support::property(&response, "user");
    assert_eq!(
        user,
        object([
            ("name", "Cloudflare Owner".into()),
            ("email", email.clone()),
            ("emailVerified", "verified".into()),
            ("nativeExtra", FieldValue::Undefined),
        ])
    );
    assert_eq!(
        keys(&user),
        ["name", "email", "emailVerified", "nativeExtra"]
    );
    assert!(user.model_property("email").unwrap().strict_equals(&email));
    let data = profile_test_support::property(&response, "data");
    assert!(data.strict_equals(&mapper.raw()));
    let expected: FieldValue = fixture()["providers"]["cloudflare"]["profile"]
        .clone()
        .into();
    let raw = expected.as_object().unwrap();
    raw.set("first_name", "Mutated".into()).unwrap();
    raw.set("last_name", "Name".into()).unwrap();
    raw.set("email", email).unwrap();
    assert_eq!(data, expected);
    assert_eq!(
        profile_test_support::subject(&resolved.providers["cloudflare"], &tokens, &response).await,
        FieldValue::from("cloudflare-owner")
    );
}

async fn assert_shallow_profile(id: &'static str) {
    let shared = object([("marker", id.into()), ("missing", FieldValue::Undefined)]);
    let mapper = NativeMapper::new(id, shared.clone());
    let (response, resolved, tokens) = fetch(&mapper).await;
    assert_eq!(*mapper.events.lock().unwrap(), ["http", "mapper"]);
    let user = profile_test_support::property(&response, "user");
    assert_eq!(
        user,
        object([
            ("name", shared.clone()),
            ("image", FieldValue::Undefined),
            (
                "email",
                if id == "roblox" {
                    "1234567890@roblox.placeholder.invalid".into()
                } else {
                    shared.clone()
                },
            ),
            ("emailVerified", (id == "zoom").into()),
            ("mappedExtra", shared.clone()),
            ("mappedUndefined", FieldValue::Undefined),
        ])
    );
    assert_eq!(
        keys(&user),
        [
            "name",
            "image",
            "email",
            "emailVerified",
            "mappedExtra",
            "mappedUndefined"
        ]
    );
    assert!(user.model_property("name").unwrap().strict_equals(&shared));
    assert!(
        user.model_property("mappedExtra")
            .unwrap()
            .strict_equals(&shared)
    );
    let data = profile_test_support::property(&response, "data");
    let raw = mapper.raw();
    assert!(!data.strict_equals(&raw));
    assert_eq!(data, raw);
    let original: FieldValue = fixture()["providers"][id]["profile"].clone().into();
    let mut expected_keys = keys(&original);
    expected_keys.extend(["child".into(), "ownUndefined".into()]);
    assert_eq!(keys(&data), expected_keys);
    assert!(data.model_property("child").unwrap().strict_equals(&shared));
    assert!(
        data.as_object()
            .unwrap()
            .has_property("ownUndefined")
            .unwrap()
    );
    assert!(data.model_property("ownUndefined").unwrap().is_undefined());
    assert_eq!(
        profile_test_support::subject(&resolved.providers[id], &tokens, &response).await,
        FieldValue::from(if id == "roblox" {
            "1234567890"
        } else {
            "zoom-owner"
        })
    );
    raw.model_property("child")
        .unwrap()
        .as_object()
        .unwrap()
        .set("marker", "changed-after-copy".into())
        .unwrap();
    assert_eq!(
        data.model_property("child")
            .unwrap()
            .model_property("marker")
            .unwrap(),
        FieldValue::from("changed-after-copy")
    );
}

#[tokio::test]
async fn roblox_consumes_native_mutations_and_shallow_copies_complete_profile() {
    assert_shallow_profile("roblox").await;
}

#[tokio::test]
async fn zoom_consumes_native_mutations_and_shallow_copies_complete_profile() {
    assert_shallow_profile("zoom").await;
}

#[tokio::test]
async fn reddit_reads_mapped_getters_around_spread_and_retains_earlier_email_fallback() {
    let shared = object([
        ("marker", "reddit".into()),
        ("missing", FieldValue::Undefined),
    ]);
    let mapper = NativeMapper::new("reddit", shared.clone());
    let (response, resolved, tokens) = fetch(&mapper).await;
    assert_eq!(
        *mapper.events.lock().unwrap(),
        [
            "http",
            "mapper",
            "email:1",
            "email:2",
            "verified:1",
            "verified:2"
        ]
    );
    let user = profile_test_support::property(&response, "user");
    assert_eq!(
        user,
        object([
            ("name", shared.clone()),
            ("image", FieldValue::Undefined),
            ("email", "mutated-reddit@reddit.placeholder.invalid".into()),
            ("emailVerified", false.into()),
            ("nativeExtra", shared.clone()),
        ])
    );
    assert_eq!(
        keys(&user),
        ["name", "image", "email", "emailVerified", "nativeExtra"]
    );
    assert!(user.model_property("name").unwrap().strict_equals(&shared));
    assert!(
        user.model_property("nativeExtra")
            .unwrap()
            .strict_equals(&shared)
    );
    let data = profile_test_support::property(&response, "data");
    assert!(data.strict_equals(&mapper.raw()));
    let expected: FieldValue = fixture()["providers"]["reddit"]["profile"].clone().into();
    let raw = expected.as_object().unwrap();
    raw.set("id", "mutated-reddit".into()).unwrap();
    raw.set("name", shared).unwrap();
    raw.set("icon_img", FieldValue::Undefined).unwrap();
    assert_eq!(data, expected);
    assert_eq!(
        profile_test_support::subject(&resolved.providers["reddit"], &tokens, &response).await,
        FieldValue::from("mutated-reddit")
    );
}

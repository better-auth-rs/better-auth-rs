use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::{
    FieldFunction, FieldObject,
    field_value::{
        FieldObjectSource, FieldProperty, FieldPropertyDefinition, FieldPropertyDescriptor,
    },
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone, Copy)]
pub(super) enum Action {
    Observe,
    Mutate,
    Overlay,
    Throw,
    SpreadThrow,
}

pub(super) struct Probe {
    pub id: &'static str,
    action: Action,
    pub shared: FieldValue,
    pub failure: FieldValue,
    pub events: Arc<Mutex<Vec<&'static str>>>,
    pub inputs: Mutex<Vec<FieldValue>>,
    pub before: Mutex<Vec<FieldValue>>,
}

impl Probe {
    pub fn new(id: &'static str, action: Action) -> Arc<Self> {
        Arc::new(Self {
            id,
            action,
            shared: object([("marker", id.into()), ("missing", FieldValue::Undefined)]),
            failure: object([
                ("code", "NATIVE_MAPPER_FAILURE".into()),
                ("detail", json!({"retry": false}).into()),
                ("missing", FieldValue::Undefined),
            ]),
            events: Arc::default(),
            inputs: Mutex::default(),
            before: Mutex::default(),
        })
    }

    pub fn raw(&self) -> FieldValue {
        self.inputs.lock().unwrap().first().unwrap().clone()
    }
}

#[async_trait]
impl OAuthProfileMapper for Probe {
    async fn map_profile_native(&self, profile: &FieldValue) -> AuthResult<FieldValue> {
        self.events.lock().unwrap().push("mapper");
        self.inputs.lock().unwrap().push(profile.clone());
        self.before
            .lock()
            .unwrap()
            .push(profile.enumerable_fields()?.into());
        match self.action {
            Action::Throw => Err(AuthError::from_thrown(self.failure.clone())),
            Action::SpreadThrow => Ok(FieldObject::from_source(Arc::new(FailingSpread::new(
                self.shared.clone(),
                self.failure.clone(),
                self.events.clone(),
            )))
            .into()),
            Action::Mutate => {
                let raw = profile.as_object().unwrap();
                raw.set(
                    "name",
                    if self.id == "google" {
                        self.shared.clone()
                    } else {
                        0.0.into()
                    },
                )?;
                if self.id == "github" {
                    raw.set("login", self.shared.clone())?;
                }
                raw.set("email", self.shared.clone())?;
                raw.set(
                    if self.id == "google" {
                        "picture"
                    } else {
                        "avatar_url"
                    },
                    FieldValue::Undefined,
                )?;
                if self.id == "google" {
                    raw.set("email_verified", 0.0.into())?;
                }
                raw.set("ownUndefined", FieldValue::Undefined)?;
                Ok(object([
                    ("mappedExtra", self.shared.clone()),
                    ("mappedUndefined", FieldValue::Undefined),
                ]))
            }
            Action::Overlay => Ok(object([
                ("name", FieldValue::Undefined),
                ("email", FieldValue::Null),
                ("image", self.shared.clone()),
                ("emailVerified", "mapped".into()),
                ("extra", self.shared.clone()),
            ])),
            Action::Observe => Ok(FieldMap::new().into()),
        }
    }
}

struct FailingSpread {
    fields: FieldObject,
}

impl FailingSpread {
    fn new(shared: FieldValue, failure: FieldValue, events: Arc<Mutex<Vec<&'static str>>>) -> Self {
        let extra_events = events.clone();
        let extra = FieldFunction::contextual(move |_, _| {
            extra_events.lock().unwrap().push("spread:extra");
            Ok(shared.clone())
        });
        let email = FieldFunction::contextual(move |_, _| {
            events.lock().unwrap().push("spread:email");
            Err(AuthError::from_thrown(failure.clone()))
        });
        let fields = [("extra", extra), ("email", email)]
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
            .collect::<indexmap::IndexMap<_, _>>()
            .into();
        Self { fields }
    }
}

impl FieldObjectSource for FailingSpread {
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

pub(super) struct Run {
    pub result: AuthResult<ProviderProfile>,
    pub probe: Arc<Probe>,
}

pub(super) async fn invoke(
    mut config: OAuthProvider,
    request: OAuthUserInfoRequest,
    probe: Arc<Probe>,
) -> Run {
    config.map_profile_to_user = Some(probe.clone());
    let provider = ResolvedProvider {
        config,
        generic: None,
    };
    let result = fetch_user_info_from_provider(&provider, request, None).await;
    Run { result, probe }
}

pub(super) async fn run(id: &'static str, profile: Value, emails: Value, action: Action) -> Run {
    let probe = Probe::new(id, action);
    let mut request = OAuthUserInfoRequest {
        access_token: Some("native-profile-token".into()).into(),
        ..Default::default()
    };
    if id == "google" {
        let token = format!(
            "{}.{}.signature",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#),
            URL_SAFE_NO_PAD.encode(profile.to_string()),
        );
        request.id_token = Some(token).into();
        return invoke(OAuthProvider::google("client", "secret"), request, probe).await;
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let events = probe.events.clone();
    let server = tokio::spawn(async move {
        for (path, event, value) in [
            ("/user", "profile", profile),
            ("/user/emails", "emails", emails),
        ] {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            while !bytes.windows(4).any(|part| part == b"\r\n\r\n") {
                let mut buffer = [0; 2048];
                let count = stream.read(&mut buffer).await.unwrap();
                assert_ne!(count, 0, "The request must contain complete HTTP headers");
                bytes.extend(buffer.into_iter().take(count));
            }
            let request = String::from_utf8(bytes).unwrap();
            assert!(request.starts_with(&format!("GET {path} HTTP/1.1\r\n")));
            let headers = request.to_ascii_lowercase();
            assert!(headers.contains("authorization: bearer native-profile-token\r\n"));
            assert!(headers.contains("user-agent: better-auth\r\n"));
            events.lock().unwrap().push(event);
            let body = value.to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len(),
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    });
    let config = OAuthProvider::github_with_endpoints(
        "client",
        "secret",
        "https://github.com/login/oauth/authorize",
        "https://github.com/login/oauth/access_token",
        &format!("{endpoint}/user"),
        &format!("{endpoint}/user/emails"),
    );
    let result = invoke(config, request, probe).await;
    server.await.unwrap();
    result
}

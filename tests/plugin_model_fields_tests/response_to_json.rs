#![expect(
    clippy::panic_in_result_fn,
    reason = "Response contracts assert callback identity, ordering, original errors, and complete HTTP results."
)]

use super::*;
use better_auth::plugins::api_key::ApiKeyPlugin;
use better_auth::server_api::EndpointInput;
use better_auth_core::{
    FieldFunction, HttpMethod,
    observability::{AfterEndpointHook, EndpointHooks},
};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone, Copy)]
enum Model {
    ApiKey,
    Passkey,
}

#[derive(Clone, Copy)]
enum Mode {
    Nested,
    Omit,
    Error,
}

struct Call {
    label: &'static str,
    key: String,
    receiver: FieldValue,
}

type Calls = Arc<Mutex<Vec<Call>>>;

fn callable(
    label: &'static str,
    calls: &Calls,
    body: impl Fn(&str) -> AuthResult<FieldValue> + Send + Sync + 'static,
) -> FieldValue {
    let calls = calls.clone();
    FieldMap::from([(
        "toJSON".into(),
        FieldFunction::contextual(move |receiver, arguments| {
            assert_eq!(arguments.len(), 1);
            let key = required(
                arguments.first().and_then(FieldValue::as_str),
                "toJSON must receive its containing property key",
            )?;
            trace_lock(&calls)?.push(Call {
                label,
                key: key.into(),
                receiver: receiver.clone(),
            });
            body(key)
        })
        .into(),
    )])
    .into()
}

struct Probe {
    value: FieldValue,
    bundle: FieldValue,
    alias: FieldValue,
    omitted: FieldValue,
    date: FieldValue,
    calls: Calls,
    error_allocation: Arc<AtomicUsize>,
}

impl Probe {
    fn new(mode: Mode) -> AuthResult<Self> {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let error_allocation = Arc::new(AtomicUsize::new(0));
        let bundle: FieldValue = FieldMap::new().into();
        let mutated = bundle.clone();
        let allocation = error_allocation.clone();
        let alias = callable("alias", &calls, move |key| {
            let fields = required(mutated.as_object(), "Expected the returned JSON object")?;
            fields.set("tail", "after".into())?;
            let _ = fields.delete("drop")?;
            fields.set("added", true.into())?;
            if matches!(mode, Mode::Error) {
                let message = "original response toJSON error".to_owned();
                allocation.store(message.as_ptr() as usize, Ordering::SeqCst);
                return Err(AuthError::Internal(message));
            }
            Ok(key.into())
        });
        let omitted = callable("omit", &calls, |_| Ok(FieldValue::Undefined));
        let date = callable("date", &calls, |_| {
            Ok(FieldDate::from_milliseconds(0.0).into())
        });
        let fields = required(bundle.as_object(), "Expected the JSON result object")?;
        for (name, value) in [
            ("first", alias.clone()),
            ("omit", omitted.clone()),
            ("last", alias.clone()),
            ("date", date.clone()),
            ("tail", "before".into()),
            ("drop", true.into()),
        ] {
            fields.set(name, value)?;
        }
        let returned = bundle.clone();
        let value = callable("name", &calls, move |_| {
            Ok(if matches!(mode, Mode::Omit) {
                FieldValue::Undefined
            } else {
                returned.clone()
            })
        });
        Ok(Self {
            value,
            bundle,
            alias,
            omitted,
            date,
            calls,
            error_allocation,
        })
    }

    fn assert_calls(&self, mode: Mode) -> AuthResult<()> {
        let calls = trace_lock(&self.calls)?;
        let signatures = calls
            .iter()
            .map(|call| (call.label, call.key.as_str()))
            .collect::<Vec<_>>();
        let expected = match mode {
            Mode::Nested => vec![
                ("name", "name"),
                ("alias", "first"),
                ("omit", "omit"),
                ("alias", "last"),
                ("date", "date"),
            ],
            Mode::Omit => vec![("name", "name")],
            Mode::Error => vec![("name", "name"), ("alias", "first")],
        };
        assert_eq!(signatures, expected);
        for call in calls.iter() {
            let receiver = match call.label {
                "name" => &self.value,
                "alias" => &self.alias,
                "omit" => &self.omitted,
                "date" => &self.date,
                _ => return Err(AuthError::internal("Unexpected toJSON callback")),
            };
            assert!(call.receiver.strict_equals(receiver));
        }
        drop(calls);
        let fields = required(self.bundle.as_object(), "Expected the JSON result object")?;
        assert_eq!(
            fields.get("tail")?,
            Some(
                if matches!(mode, Mode::Omit) {
                    "before"
                } else {
                    "after"
                }
                .into()
            )
        );
        assert_eq!(fields.get("drop")?.is_some(), matches!(mode, Mode::Omit));
        assert_eq!(fields.get("added")?.is_some(), !matches!(mode, Mode::Omit));
        trace_lock(&self.calls)?.clear();
        // The mutation callback retains its result object. Remove the back-references after observation.
        let _ = fields.delete("first")?;
        let _ = fields.delete("last")?;
        Ok(())
    }
}

#[derive(Default)]
struct Observe(Mutex<Vec<FieldValue>>);

#[async_trait]
impl<S: AuthSchema> AfterEndpointHook<S> for Observe {
    async fn after(
        &self,
        _: &AuthRequest,
        response: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<()> {
        trace_lock(&self.0)?.push(response.body.field_value()?);
        Ok(())
    }
}

fn row(model: Model, result: &FieldValue) -> AuthResult<FieldValue> {
    match model {
        Model::ApiKey => Ok(result.clone()),
        Model::Passkey => required(
            required(result.as_array(), "Expected a Passkey array")?.first()?,
            "Expected the stored Passkey in the response",
        ),
    }
}

async fn read<S: AuthSchema>(
    auth: &BetterAuth<S>,
    model: Model,
    token: &str,
    id: &str,
) -> AuthResult<AuthResponse> {
    let (path, query) = match model {
        Model::ApiKey => ("/api-key/get", Some(json!({"id": id}))),
        Model::Passkey => ("/passkey/list-user-passkeys", None),
    };
    auth.call_endpoint(
        HttpMethod::Get,
        path,
        EndpointInput {
            headers: Some([("authorization".into(), format!("Bearer {token}"))].into()),
            query,
            ..Default::default()
        },
    )
    .await
}

async fn stored<S: AuthSchema>(
    raw: &dyn AuthStore<S>,
    model: Model,
    id: &str,
) -> AuthResult<Value> {
    match model {
        Model::ApiKey => Ok(serde_json::to_value(required(
            raw.get_api_key_by_id(id).await?,
            "Expected the complete stored API Key",
        )?)?),
        Model::Passkey => Ok(serde_json::to_value(required(
            raw.get_passkey_by_id(id).await?,
            "Expected the complete stored Passkey",
        )?)?),
    }
}

async fn contract<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    model: Model,
    mode: Mode,
) -> AuthResult<()> {
    let probe = Probe::new(mode)?;
    let observer = Arc::new(Observe::default());
    let replacement = Arc::new(Mutex::new(None::<FieldValue>));
    let output = replacement.clone();
    let mut config = config();
    config.session.bearer = Some(Default::default());
    let auth = BetterAuth::new(config)
        .store_arc(raw.clone())
        .plugin(ApiKeyPlugin::builder().build())
        .plugin(PasskeyPlugin::new())
        .plugin(Fields(vec![(
            match model {
                Model::ApiKey => EntityRole::ApiKey,
                Model::Passkey => EntityRole::Passkey,
            },
            fields(
                "name",
                UserFieldConfig {
                    required: Some(false),
                    transform: Some(FieldTransforms {
                        output: Some(UserFieldTransform::new(move |value| {
                            Ok(trace_lock(&output)?.clone().unwrap_or(value))
                        })),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ),
        )]))
        .hooks(EndpointHooks {
            before: None,
            after: Some(observer.clone()),
        })
        .build()
        .await?;
    let owner = owner(raw.as_ref(), "response-json").await?;
    let token = super::presence::token(&auth, &owner).await?;
    let id = match model {
        Model::ApiKey => {
            let mut data = super::api_key::input(Some("Stored"), "response-json-key");
            data.reference_id = owner.clone().into();
            raw.create_api_key(data).await?.id.typed()?.clone()
        }
        Model::Passkey => raw
            .create_passkey(input(&owner, "Stored"))
            .await?
            .id
            .typed()?
            .clone(),
    };
    let baseline = read(&auth, model, &token, &id).await?;
    let mut expected: Value =
        serde_json::from_slice(&baseline.into_http_response()?.body.bytes()?)?;
    let before = stored(raw.as_ref(), model, &id).await?;
    trace_lock(&observer.0)?.clear();
    *trace_lock(&replacement)? = Some(probe.value.clone());
    let native = read(&auth, model, &token, &id).await?;
    assert!(native.is_native());
    assert!(
        row(model, &native.body.field_value()?)?
            .model_property("name")?
            .strict_equals(&probe.value)
    );
    {
        let observed = trace_lock(&observer.0)?;
        assert_eq!(observed.len(), 1);
        let observed_name = row(
            model,
            required(observed.first(), "Expected the after-hook value")?,
        )?
        .model_property("name")?;
        assert!(observed_name.strict_equals(&probe.value));
        assert!(
            observed_name
                .model_property("toJSON")?
                .strict_equals(&probe.value.model_property("toJSON")?)
        );
    }
    assert!(trace_lock(&probe.calls)?.is_empty());
    match (mode, native.into_http_response()) {
        (Mode::Error, Err(AuthError::Internal(message))) => {
            assert_eq!(message, "original response toJSON error");
            assert_eq!(
                message.as_ptr() as usize,
                probe.error_allocation.load(Ordering::SeqCst)
            );
        }
        (Mode::Error, _) => {
            return Err(AuthError::internal("Expected the original HTTP JSON error"));
        }
        (_, Err(error)) => return Err(error),
        (_, Ok(response)) => {
            assert_eq!(response.status, 200);
            assert_eq!(
                response.headers.get("content-type").map(String::as_str),
                Some("application/json")
            );
            let expected_row = match model {
                Model::ApiKey => &mut expected,
                Model::Passkey => required(expected.get_mut(0), "Expected the baseline Passkey")?,
            };
            let expected_fields = required(
                expected_row.as_object_mut(),
                "Expected complete baseline fields",
            )?;
            if matches!(mode, Mode::Omit) {
                let _ = expected_fields.shift_remove("name");
            } else {
                let _ = expected_fields.insert(
                    "name".into(),
                    json!({"first":"first","last":"last","date":{},"tail":"after"}),
                );
            }
            assert_eq!(
                response.body.bytes()?.as_ref(),
                serde_json::to_vec(&expected)?
            );
        }
    }
    assert_eq!(stored(raw.as_ref(), model, &id).await?, before);
    probe.assert_calls(mode)
}

#[tokio::test]
async fn memory_api_key_response_keeps_to_json_identity_until_http() -> AuthResult<()> {
    for mode in [Mode::Nested, Mode::Omit, Mode::Error] {
        contract(memory(), Model::ApiKey, mode).await?;
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_api_key_response_keeps_to_json_identity_until_http() -> AuthResult<()> {
    for mode in [Mode::Nested, Mode::Omit, Mode::Error] {
        contract(sqlite().await?, Model::ApiKey, mode).await?;
    }
    Ok(())
}

#[tokio::test]
async fn memory_passkey_response_keeps_to_json_identity_until_http() -> AuthResult<()> {
    for mode in [Mode::Nested, Mode::Omit, Mode::Error] {
        contract(memory(), Model::Passkey, mode).await?;
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_passkey_response_keeps_to_json_identity_until_http() -> AuthResult<()> {
    for mode in [Mode::Nested, Mode::Omit, Mode::Error] {
        contract(sqlite().await?, Model::Passkey, mode).await?;
    }
    Ok(())
}

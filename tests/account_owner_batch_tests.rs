#![cfg(feature = "seaorm2")]
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "Contract fixtures fail immediately on invalid setup, unexpected channel events, or a changed two-row result shape."
)]

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, AuthStore, CreateAccount, CreateUser, FieldMap,
    FieldValue,
    store::{EphemeralStore, JoinValue},
    user_fields::{
        AdapterRecord, FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform,
    },
    wire::AccountView,
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::Database,
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use serde_json::{Value, json};
use std::{
    future::Future,
    sync::{Arc, Mutex},
};
use tokio::sync::{mpsc, oneshot};

type Events = Arc<Mutex<Vec<String>>>;

fn accounts() -> Vec<FieldMap> {
    ["A", "B"]
        .into_iter()
        .map(|name| {
            FieldMap::from_iter([
                ("id".into(), format!("account-{name}").into()),
                (
                    "accountId".into(),
                    format!("provider-account-{name}").into(),
                ),
                ("providerId".into(), "ordinary-provider".into()),
                ("userId".into(), format!("user-{name}").into()),
                ("accessToken".into(), format!("access-{name}").into()),
                ("refreshToken".into(), format!("refresh-{name}").into()),
            ])
        })
        .collect()
}

async fn project<R: Send, F: Future<Output = AuthResult<R>> + Send>(
    extracted: bool,
    fields: &UserConfig,
    complete: impl Fn(usize, AccountView) -> F + Sync,
) -> AuthResult<Vec<R>> {
    let rows = accounts();
    if extracted {
        let records = rows
            .into_iter()
            .map(|row| {
                let core = [("id".into(), row["id"].clone())].into_iter().collect();
                AdapterRecord::new(core, row)
            })
            .collect();
        fields
            .project_adapter_records_then(records, true, true, |index, output| {
                complete(index, AccountView::from_adapter_fields(output))
            })
            .await
    } else {
        fields
            .project_records_then(&rows, true, true, |index, output| {
                complete(index, AccountView::from_adapter_fields(output))
            })
            .await
    }
}

fn tokens(index: usize, account: &AccountView) -> Value {
    json!({
        "index": index,
        "accessToken": account.access_token.json().unwrap(),
        "refreshToken": account.refresh_token.json().unwrap(),
    })
}

fn expected_tokens() -> Vec<Value> {
    ["A", "B"]
        .into_iter()
        .enumerate()
        .map(|(index, name)| {
            json!({
                "index": index,
                "accessToken": format!("access-{name}:out"),
                "refreshToken": format!("refresh-{name}:out"),
            })
        })
        .collect()
}

fn sync_fields(events: &Events, reject: bool) -> UserConfig {
    let mut config = AuthConfig::default();
    for name in ["accessToken", "refreshToken"] {
        let events = events.clone();
        let _ = config.account.additional_fields.insert(
            name.into(),
            UserFieldConfig {
                returned: Some(false),
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new(move |value| {
                        let text = value.as_str().unwrap();
                        events.lock().unwrap().push(format!("{name}:{text}"));
                        if reject && name == "accessToken" && text == "access-A" {
                            return Err(AuthError::Config("projection-A".into()));
                        }
                        Ok(format!("{text}:out").into())
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
    }
    config.account.field_schema()
}

#[tokio::test]
async fn synchronous_account_batches_interleave_fields_before_continuations() {
    for extracted in [false, true] {
        let events = Events::default();
        let fields = sync_fields(&events, false);
        let rows = project(extracted, &fields, |index, account| {
            events.lock().unwrap().push(format!("complete:{index}"));
            std::future::ready(Ok(tokens(index, &account)))
        })
        .await
        .unwrap();
        assert_eq!(rows, expected_tokens());
        assert_eq!(
            *events.lock().unwrap(),
            [
                "accessToken:access-A",
                "accessToken:access-B",
                "refreshToken:refresh-A",
                "refreshToken:refresh-B",
                "complete:0",
                "complete:1",
            ]
        );
    }
}

#[tokio::test]
async fn synchronous_account_errors_preserve_successful_row_continuations() {
    for extracted in [false, true] {
        for reject_projection in [false, true] {
            let events = Events::default();
            let fields = sync_fields(&events, reject_projection);
            let result = project(extracted, &fields, |index, account| {
                events.lock().unwrap().push(format!("complete:{index}"));
                std::future::ready(if !reject_projection && index == 0 {
                    Err(AuthError::Config(format!("continuation-{index}")))
                } else {
                    Ok(tokens(index, &account))
                })
            })
            .await;
            let expected_error = if reject_projection {
                "projection-A"
            } else {
                "continuation-0"
            };
            assert!(matches!(result, Err(AuthError::Config(message)) if message == expected_error));
            let expected = if reject_projection {
                vec![
                    "accessToken:access-A",
                    "accessToken:access-B",
                    "refreshToken:refresh-B",
                    "complete:1",
                ]
            } else {
                vec![
                    "accessToken:access-A",
                    "accessToken:access-B",
                    "refreshToken:refresh-A",
                    "refreshToken:refresh-B",
                    "complete:0",
                    "complete:1",
                ]
            };
            assert_eq!(*events.lock().unwrap(), expected);
        }
    }
}

#[derive(Debug)]
struct Call {
    name: &'static str,
    value: FieldValue,
    reply: oneshot::Sender<AuthResult<FieldValue>>,
}

#[derive(Debug)]
enum Event {
    Field(Call),
    Complete(usize, Value),
}

fn async_fields(sender: &mpsc::UnboundedSender<Event>) -> UserConfig {
    let mut config = AuthConfig::default();
    for name in ["accessToken", "refreshToken"] {
        let sender = sender.clone();
        let _ = config.account.additional_fields.insert(
            name.into(),
            UserFieldConfig {
                returned: Some(false),
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new_async(move |value| {
                        let sender = sender.clone();
                        async move {
                            let (reply, result) = oneshot::channel();
                            sender
                                .send(Event::Field(Call { name, value, reply }))
                                .map_err(|_| AuthError::internal("Field controller closed"))?;
                            result
                                .await
                                .map_err(|_| AuthError::internal("Field answer missing"))?
                        }
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
    }
    config.account.field_schema()
}

async fn next_field(
    receiver: &mut mpsc::UnboundedReceiver<Event>,
    name: &str,
    value: &str,
) -> Call {
    let Some(Event::Field(call)) = receiver.recv().await else {
        panic!("Expected {name}:{value} before continuation");
    };
    assert_eq!((call.name, &call.value), (name, &FieldValue::from(value)));
    call
}

fn answer(call: Call) {
    call.reply
        .send(Ok(format!("{}:out", call.value.as_str().unwrap()).into()))
        .unwrap();
}

async fn completed(receiver: &mut mpsc::UnboundedReceiver<Event>, index: usize) {
    let Some(Event::Complete(actual, value)) = receiver.recv().await else {
        panic!("Expected continuation {index}");
    };
    assert_eq!(actual, index);
    assert_eq!(value, expected_tokens()[index]);
}

#[tokio::test]
async fn async_fast_account_continues_before_slow_projection_and_keeps_row_order() {
    for extracted in [false, true] {
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let fields = async_fields(&sender);
        let operation = project(extracted, &fields, |index, account| {
            let value = tokens(index, &account);
            sender.send(Event::Complete(index, value.clone())).unwrap();
            std::future::ready(Ok(value))
        });
        let controller = async {
            let slow = next_field(&mut receiver, "accessToken", "access-A").await;
            answer(next_field(&mut receiver, "accessToken", "access-B").await);
            answer(next_field(&mut receiver, "refreshToken", "refresh-B").await);
            completed(&mut receiver, 1).await;
            // The slow callback still owns an unanswered oneshot when row B completes.
            answer(slow);
            answer(next_field(&mut receiver, "refreshToken", "refresh-A").await);
            completed(&mut receiver, 0).await;
        };
        let (result, ()) = tokio::join!(operation, controller);
        assert_eq!(result.unwrap(), expected_tokens());
    }
}

#[tokio::test]
async fn async_account_error_keeps_other_rows_running_and_preserves_original_error() {
    for extracted in [false, true] {
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let fields = async_fields(&sender);
        let operation = project(extracted, &fields, |index, account| {
            let value = tokens(index, &account);
            sender.send(Event::Complete(index, value.clone())).unwrap();
            std::future::ready(Ok(value))
        });
        let controller = async {
            let rejected = next_field(&mut receiver, "accessToken", "access-A").await;
            let other = next_field(&mut receiver, "accessToken", "access-B").await;
            rejected
                .reply
                .send(Err(AuthError::Config("first projection error".into())))
                .unwrap();
            answer(other);
            answer(next_field(&mut receiver, "refreshToken", "refresh-B").await);
            completed(&mut receiver, 1).await;
        };
        let (result, ()) = tokio::join!(operation, controller);
        assert!(
            matches!(result, Err(AuthError::Config(message)) if message == "first projection error")
        );
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }
}

#[derive(Default)]
struct OwnerTrace {
    armed: bool,
    reject: Option<&'static str>,
    events: Vec<String>,
}

fn owner_config(trace: &Arc<Mutex<OwnerTrace>>) -> AuthConfig {
    let mut config = AuthConfig::default();
    for name in ["accessToken", "refreshToken", "name", "image"] {
        let trace = trace.clone();
        let field = UserFieldConfig {
            returned: Some(matches!(name, "name" | "image")),
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(move |value| {
                    let mut trace = trace.lock().unwrap();
                    if !trace.armed {
                        return Ok(value);
                    }
                    let text = value.as_str().unwrap();
                    trace.events.push(format!("{name}:{text}"));
                    if trace.reject == Some(name) {
                        return Err(AuthError::Config(format!("{name} rejected")));
                    }
                    Ok(format!("{text}:out").into())
                })),
                ..Default::default()
            }),
            ..Default::default()
        };
        let fields = if matches!(name, "name" | "image") {
            config.user.fields_mut()
        } else {
            &mut config.account.additional_fields
        };
        let _ = fields.insert(name.into(), field);
    }
    config
}

async fn check_owner<S: AuthSchema>(store: &impl AuthStore<S>, trace: &Arc<Mutex<OwnerTrace>>) {
    let user = store
        .create_user(CreateUser {
            image: Some("https://ordinary-owner.test/image.png".into()).into(),
            ..CreateUser::new()
                .with_name("Fixture User")
                .with_email("ordinary-owner@example.test")
        })
        .await
        .unwrap();
    let _ = store
        .create_account(CreateAccount {
            user_id: user.id.clone(),
            provider_id: "ordinary-provider".into(),
            account_id: "ordinary-account".into(),
            access_token: Some("access".into()).into(),
            refresh_token: Some("refresh".into()).into(),
            ..Default::default()
        })
        .await
        .unwrap();
    trace.lock().unwrap().armed = true;
    let owner = store
        .get_account_owner("ordinary-provider", "ordinary-account")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        owner.account.access_token.json().unwrap(),
        Some(json!("access:out"))
    );
    assert_eq!(
        owner.account.refresh_token.json().unwrap(),
        Some(json!("refresh:out"))
    );
    let JoinValue::One(owner_user) = owner.user else {
        panic!("Expected a single Account owner");
    };
    assert_eq!(
        owner_user.as_ref().unwrap().name.json().unwrap(),
        Some(json!("Fixture User:out"))
    );
    assert_eq!(
        owner_user.as_ref().unwrap().image.json().unwrap(),
        Some(json!("https://ordinary-owner.test/image.png:out"))
    );
    let expected = [
        "accessToken:access",
        "refreshToken:refresh",
        "name:Fixture User",
        "image:https://ordinary-owner.test/image.png",
    ];
    assert_eq!(trace.lock().unwrap().events, expected);
    for (index, name) in ["accessToken", "refreshToken", "name", "image"]
        .into_iter()
        .enumerate()
    {
        {
            let mut trace = trace.lock().unwrap();
            trace.reject = Some(name);
            trace.events.clear();
        }
        let result = store
            .get_account_owner("ordinary-provider", "ordinary-account")
            .await;
        assert!(
            matches!(result, Err(AuthError::Config(message)) if message == format!("{name} rejected"))
        );
        assert_eq!(trace.lock().unwrap().events, expected[..=index]);
    }
}

#[tokio::test]
async fn ephemeral_owner_projects_tokens_then_user_and_preserves_errors() {
    let trace = Arc::new(Mutex::new(OwnerTrace::default()));
    let store = EphemeralStore::new(owner_config(&trace).into());
    check_owner(&store, &trace).await;
}

#[tokio::test]
async fn sqlite_owner_projects_tokens_then_user_and_preserves_errors() {
    let trace = Arc::new(Mutex::new(OwnerTrace::default()));
    let db = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&db).await.unwrap();
    let store = SeaOrmStore::<BundledSchema>::new(owner_config(&trace), db);
    check_owner(&store, &trace).await;
}

#[tokio::test]
async fn ready_account_rows_batch_multifield_owner_projection() {
    let fixtures: Value = serde_json::from_str(include_str!(
        "fixtures/account-owner-multiple-fields-1.7.6.json"
    ))
    .unwrap();
    let fixture = fixtures
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["backend"] == "memory")
        .unwrap();
    let events = Arc::new(Mutex::new(Vec::<Value>::new()));
    let field = |name: &'static str| {
        let events = events.clone();
        UserFieldConfig {
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(move |value| {
                    let mut events = events.lock().unwrap();
                    events.push(json!([name, value.json()?]));
                    Ok(format!("{}:{}", value.as_str().unwrap(), events.len()).into())
                })),
                ..Default::default()
            }),
            ..Default::default()
        }
    };
    let mut config = AuthConfig::default();
    for name in ["accessToken", "refreshToken"] {
        config
            .account
            .additional_fields
            .insert(name.into(), field(name));
    }
    let user = UserConfig {
        additional_fields: Some(
            [
                ("name".into(), field("name")),
                ("image".into(), field("image")),
            ]
            .into(),
        ),
    };
    let fields = config.account.field_schema();
    let accounts = ["A", "B"]
        .into_iter()
        .map(|label| {
            FieldMap::from_iter([
                ("id".into(), format!("account-{label}").into()),
                ("accessToken".into(), format!("{label}-access").into()),
                ("refreshToken".into(), format!("{label}-refresh").into()),
            ])
        })
        .collect::<Vec<_>>();
    let owners = ["A", "B"]
        .into_iter()
        .map(|label| {
            FieldMap::from_iter([
                ("id".into(), format!("user-{label}").into()),
                ("name".into(), label.into()),
                ("image".into(), format!("{label}-image").into()),
            ])
        })
        .collect::<Vec<_>>();
    let rows = fields.project_records_batches_then(&accounts, true, true, |ready| {
        let user = &user;
        let owners = &owners;
        async move {
            let raw = ready.iter().map(|(index, _)| owners[*index].clone()).collect::<Vec<_>>();
            let projected = user.project_records(&raw, true, true).await?;
            ready.into_iter().zip(projected).map(|((index, account), owner)| Ok((index, json!({
                "accessToken":account["accessToken"].json()?, "refreshToken":account["refreshToken"].json()?, "name":owner["name"].json()?, "image":owner["image"].json()?
            })))).collect::<AuthResult<Vec<_>>>()
        }
    }).await.unwrap();
    assert_eq!(json!(rows), fixture["rows"]);
    assert_eq!(json!(*events.lock().unwrap()), fixture["events"]);
}

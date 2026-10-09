#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "The pinned ordinary-display fixture requires exact seeded rows and callback channels."
)]

use super::*;
use crate::AuthResponse;
use crate::organization_fields::OrganizationFields;
use crate::store::{MemberUser, OrganizationDetailsQuery, OrganizationKey};
use crate::user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform};
use serde_json::{Value as JsonValue, json};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::{mpsc, oneshot};

struct Control {
    path: String,
    mode: String,
    enabled: AtomicBool,
    changed: AtomicBool,
    events: Mutex<Vec<JsonValue>>,
    store: Mutex<Weak<EphemeralStore>>,
    gate: Mutex<Option<oneshot::Receiver<()>>>,
    started: mpsc::UnboundedSender<()>,
    finished: mpsc::UnboundedSender<()>,
}

impl Control {
    fn event(&self, event: JsonValue) {
        self.events.lock().unwrap().push(event);
    }

    fn parent(&self) -> (&str, &str) {
        match self.path.as_str() {
            "full" => ("organization.name", "O-A"),
            "invitations" => ("invitation.label", "I-A"),
            _ => ("member.label", "M-A"),
        }
    }

    fn inject_detail(&self) -> AuthResult<()> {
        self.changed.store(true, Ordering::Relaxed);
        let store = self.store.lock().unwrap().upgrade().unwrap();
        let state = store.lock()?;
        let (model, detail) = if self.path == "invitations" {
            let mut row = state.invitations.get_mut("invitation-a")?.unwrap();
            let _ = row.insert("detail".into(), Value::from("I-A-detail-after"));
            ("invitation", "I-A-detail-after")
        } else {
            let mut row = state.members.get_mut("member-a")?.unwrap();
            let _ = row.insert("detail".into(), Value::from("M-A-detail-after"));
            ("member", "M-A-detail-after")
        };
        drop(state);
        // This test changes backend display data; it does not simulate an adapter update API.
        self.event(json!(["display-write", model, {"detail": detail}]));
        Ok(())
    }

    async fn update_display(&self) -> AuthResult<()> {
        if self.path != "full" {
            return self.inject_detail();
        }
        self.changed.store(true, Ordering::Relaxed);
        let store = self.store.lock().unwrap().upgrade().unwrap();
        let _ = store
            .update_organization(
                "organization-a",
                UpdateOrganization {
                    logo: Some(Some("O-A-logo-after".into())),
                    ..Default::default()
                },
            )
            .await?;
        self.event(json!(["display-write", "organization", {"logo":"O-A-logo-after"}]));
        Ok(())
    }
}

fn failure() -> AuthError {
    AuthResponse::json(400, &json!({
        "code":"ORDINARY_PARENT_DISPLAY_FAILURE", "message":"Ordinary parent display callback failed"
    })).unwrap().with_header("x-ordinary-error", "original").into()
}

fn field(control: &Arc<Control>, name: &'static str) -> UserFieldConfig {
    let asynchronous =
        name == control.parent().0 && (control.mode != "read" || control.path == "full");
    let state = control.clone();
    let transform = if asynchronous {
        UserFieldTransform::new_async(move |value| {
            let state = state.clone();
            async move {
                if !state.enabled.load(Ordering::Relaxed) {
                    return Ok(value);
                }
                let text = value.as_str().unwrap();
                state.event(json!([name, text]));
                if text == state.parent().1 && !state.changed.load(Ordering::Relaxed) {
                    if state.mode == "read" {
                        state.update_display().await?;
                    } else {
                        let receiver = state.gate.lock().unwrap().take().unwrap();
                        state.started.send(()).unwrap();
                        receiver.await.map_err(|_| {
                            AuthError::internal("Ordinary parent display gate closed")
                        })?;
                        if state.mode == "error" {
                            return Err(failure());
                        }
                    }
                }
                Ok(Value::from(format!("{text}-visible")))
            }
        })
    } else {
        UserFieldTransform::new(move |value| {
            if !state.enabled.load(Ordering::Relaxed) {
                return Ok(value);
            }
            let text = value.as_str().unwrap();
            state.event(json!([name, text]));
            if name == "organization.logo" && text == "O-B-logo" {
                state.finished.send(()).unwrap();
            }
            if name == state.parent().0
                && text == state.parent().1
                && !state.changed.load(Ordering::Relaxed)
            {
                state.inject_detail()?;
            }
            Ok(Value::from(format!("{text}-visible")))
        })
    };
    UserFieldConfig {
        required: Some(false),
        transform: Some(FieldTransforms {
            output: Some(transform),
            ..Default::default()
        }),
        ..Default::default()
    }
}

async fn seed(store: &EphemeralStore) -> AuthResult<()> {
    let now = "2025-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
    let _ = store
        .create_user(CreateUser {
            id: Some("user-a".into()),
            image: Some("U-A-image".to_owned()).into(),
            created_at: Some(now.into()),
            updated_at: Some(now.into()),
            email_verified: Some(true),
            ..CreateUser::new()
                .with_name("U-A")
                .with_email("a@ordinary-parent.test")
        })
        .await?;
    for label in ["A", "B"] {
        let suffix = label.to_lowercase();
        let mut organization =
            CreateOrganization::new(format!("O-{label}"), format!("ordinary-{suffix}"));
        organization.id = Some(format!("organization-{suffix}"));
        organization.logo = Some(format!("O-{label}-logo")).into();
        let _ = store.create_organization(organization).await?;
        let _ = store
            .insert_member(Member {
                id: format!("member-{suffix}").into(),
                organization_id: format!("organization-{suffix}").into(),
                user_id: "user-a".into(),
                role: "member".into(),
                created_at: now.into(),
                additional_fields: [
                    ("label".into(), Value::from(format!("M-{label}"))),
                    ("detail".into(), Value::from(format!("M-{label}-detail"))),
                ]
                .into_iter()
                .collect(),
            })
            .await?;
        let mut invitation = CreateInvitation::new(
            format!("organization-{suffix}"),
            "recipient@ordinary-parent.test",
            "member",
            "user-a",
            "2099-01-01T00:00:00Z"
                .parse::<DateTime<Utc>>()
                .unwrap()
                .into(),
        );
        invitation.id = Some(format!("invitation-{suffix}"));
        invitation.created_at = Some(now.into());
        invitation.additional_fields = [
            ("label".into(), Value::from(format!("I-{label}"))),
            ("detail".into(), Value::from(format!("I-{label}-detail"))),
        ]
        .into_iter()
        .collect();
        let _ = store.create_invitation(invitation).await?;
    }
    Ok(())
}

fn member(row: MemberUser) -> AuthResult<JsonValue> {
    Ok(
        json!({"label":row.member.additional_fields["label"].json()?, "detail":row.member.additional_fields["detail"].json()?,
        "user":{"name":row.user.name, "image":row.user.image}}),
    )
}

async fn query(store: &EphemeralStore, path: &str) -> AuthResult<JsonValue> {
    Ok(match path {
        "member-org" => member(
            store
                .get_member_with_user("organization-a", "user-a")
                .await?
                .unwrap(),
        )?,
        "member-id" => member(store.get_member_by_id_with_user("member-a").await?.unwrap())?,
        "organizations" => json!(
            store
                .list_user_organizations("user-a")
                .await?
                .into_iter()
                .map(|row| json!({"name":row.name,"logo":row.logo}))
                .collect::<Vec<_>>()
        ),
        "invitations" => json!(
            store
                .list_user_invitations("RECIPIENT@ordinary-parent.test")
                .await?
                .into_iter()
                .map(|row| Ok(
                    json!({"label":row.invitation.additional_fields["label"].json()?,
                "detail":row.invitation.additional_fields["detail"].json()?,
                "organizationName":row.organization.unwrap().name})
                ))
                .collect::<AuthResult<Vec<_>>>()?
        ),
        "full" => {
            let row = store
                .get_organization_details(OrganizationDetailsQuery {
                    organization: OrganizationKey::Id("organization-a"),
                    members_limit: None,
                    users_limit: 100.0,
                    include_teams: false,
                })
                .await?
                .unwrap();
            json!({"name":row.organization.name,"logo":row.organization.logo,
                "members":row.members.into_iter().map(member).collect::<AuthResult<Vec<_>>>()?,
                "invitations":row.invitations.into_iter().map(|row| Ok(json!({
                    "label":row.additional_fields["label"].json()?,"detail":row.additional_fields["detail"].json()?
                }))).collect::<AuthResult<Vec<_>>>()?})
        }
        _ => return Err(AuthError::internal("Unknown ordinary parent fixture")),
    })
}

async fn check_case(fixture: &JsonValue) -> AuthResult<()> {
    let (started, mut started_rx) = mpsc::unbounded_channel();
    let (finished, mut finished_rx) = mpsc::unbounded_channel();
    let (release, receiver) = oneshot::channel();
    let control = Arc::new(Control {
        path: fixture["path"].as_str().unwrap().into(),
        mode: fixture["mode"].as_str().unwrap().into(),
        enabled: AtomicBool::new(false),
        changed: AtomicBool::new(false),
        events: Mutex::new(Vec::new()),
        store: Mutex::new(Weak::new()),
        gate: Mutex::new(Some(receiver)),
        started,
        finished,
    });
    let mut config = AuthConfig::default();
    config.advanced.database.joins = fixture["joins"].as_bool();
    config.advanced.database.default_find_many_limit = Some(2.0);
    for name in ["user.name", "user.image"] {
        let _ = config.user.fields_mut().insert(
            name.split('.').next_back().unwrap().into(),
            field(&control, name),
        );
    }
    let store = Arc::new(EphemeralStore::new(Arc::new(config)));
    *control.store.lock().unwrap() = Arc::downgrade(&store);
    let mut fields = OrganizationFields::default();
    for (schema, names) in [
        (
            &mut fields.organization,
            ["organization.name", "organization.logo"],
        ),
        (&mut fields.member, ["member.label", "member.detail"]),
        (
            &mut fields.invitation,
            ["invitation.label", "invitation.detail"],
        ),
    ] {
        for name in names {
            let _ = schema.fields_mut().insert(
                name.split('.').next_back().unwrap().into(),
                field(&control, name),
            );
        }
    }
    store.configure_organization_fields(fields)?;
    seed(&store).await?;
    control.enabled.store(true, Ordering::Relaxed);
    let controller = async {
        if control.mode != "read" {
            started_rx.recv().await.unwrap();
            let list = matches!(control.path.as_str(), "organizations" | "invitations");
            if list {
                finished_rx.recv().await.unwrap();
            }
            control.event(json!([
                "controller",
                if list {
                    "peer-finished"
                } else {
                    "parent-blocked"
                }
            ]));
            control.update_display().await.unwrap();
            release.send(()).unwrap();
        }
    };
    let (result, ()) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(query(&store, &control.path), controller)
    })
    .await
    .unwrap();
    match result {
        Ok(value) => {
            assert_eq!(value, fixture["result"], "{fixture}");
            assert_eq!(fixture["originalError"], false);
        }
        Err(error) => {
            assert!(matches!(error, AuthError::Response(_)), "{error:?}");
            let response = error.to_auth_response();
            assert_eq!(response.status, 400);
            assert_eq!(
                response.headers.get("x-ordinary-error").map(String::as_str),
                Some("original")
            );
            let body: JsonValue = serde_json::from_slice(&response.body.bytes().unwrap()).unwrap();
            assert_eq!(
                json!({"status":"BAD_REQUEST","code":body["code"],"message":body["message"]}),
                fixture["error"]
            );
            assert_eq!(fixture["originalError"], true);
        }
    }
    let events = control.events.lock().unwrap().clone();
    assert_eq!(json!(events), fixture["events"], "{fixture}");
    let state = store.lock()?;
    assert_eq!(
        json!({
            "memberDetail":state.members.get("member-a")?.unwrap()["detail"].json()?,
            "invitationDetail":state.invitations.get("invitation-a")?.unwrap()["detail"].json()?,
            "logo":state.organizations.get("organization-a")?.unwrap().get("logo").unwrap().json()?,
        }),
        fixture["stored"]
    );
    Ok(())
}

#[tokio::test]
async fn memory_organization_fallback_parent_reads_match_pinned_display_contracts() -> AuthResult<()>
{
    let fixture: JsonValue = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/organization-fallback-parent-1.7.6.json"
    ))
    .unwrap();
    for row in fixture["cases"].as_array().unwrap() {
        check_case(row).await?;
    }
    Ok(())
}

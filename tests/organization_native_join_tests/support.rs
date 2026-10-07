use super::*;
use std::sync::Weak;

pub struct State<T> {
    pub unconfigured_logo: bool,
    pub enabled: AtomicBool,
    pub changed: AtomicBool,
    pub events: Mutex<Vec<Value>>,
    pub gate: Mutex<Option<oneshot::Receiver<()>>>,
    pub started: mpsc::UnboundedSender<()>,
    pub finished: mpsc::UnboundedSender<()>,
    pub store: Mutex<Weak<T>>,
}
impl<T> State<T> {
    fn event(&self, value: Value) -> usize {
        let mut events = self.events.lock().unwrap();
        events.push(value);
        events.len()
    }
}
fn failure() -> AuthError {
    AuthResponse::json(400, &json!({
        "code":"ORDINARY_ORGANIZATION_DISPLAY_FAILURE", "message":"Ordinary display callback failed"
    })).unwrap().with_header("x-ordinary-error", "original").into()
}
fn phase(path: &str, child: bool) -> (&'static str, &'static str) {
    match (path, child) {
        ("full", false) => ("organization.name", "O-A"),
        ("invitations", false) => ("invitation.label", "I-A"),
        (_, false) => ("member.label", "M-A"),
        ("full", true) => ("invitation.label", "I-A"),
        ("teams", true) => ("team.name", "T-A"),
        (_, true) => ("user.name", "U-A"),
    }
}
async fn update_display<S: AuthSchema, T: AuthStore<S>>(
    store: &T,
    path: &str,
    child: bool,
) -> AuthResult<Value> {
    let update = match (path, child) {
        ("teams", true) => {
            let _ = store
                .update_team(
                    "team-b",
                    UpdateTeam {
                        additional_fields: [("label".into(), "T-B-label-after".into())]
                            .into_iter()
                            .collect(),
                        ..Default::default()
                    },
                )
                .await?;
            json!(["display-write", "team", {"label":"T-B-label-after"}])
        }
        ("full", child) => {
            // Use the typed invitation update; its configured onUpdate writes the ordinary detail field.
            let id = if child {
                "invitation-a-other"
            } else {
                "invitation-a"
            };
            let detail = if child {
                "I-A2-detail-after"
            } else {
                "I-A-detail-after"
            };
            let _ = store
                .update_invitation_expiry(
                    id,
                    "2099-01-01T00:00:00Z"
                        .parse::<chrono::DateTime<chrono::Utc>>()
                        .unwrap()
                        .into(),
                )
                .await?;
            json!(["display-write", "invitation", {"detail":detail}])
        }
        ("member-org", false) => {
            let _ = store
                .update_user(
                    "user-a",
                    UpdateUser {
                        image: Some("U-A-image-after".to_owned()).into(),
                        ..Default::default()
                    },
                )
                .await?;
            json!(["display-write", "user", {"image":"U-A-image-after"}])
        }
        _ => {
            let _ = store
                .update_organization(
                    "organization-a",
                    UpdateOrganization {
                        logo: Some(Some("O-A-logo-after".into())),
                        ..Default::default()
                    },
                )
                .await?;
            json!(["display-write", "organization", {"logo":"O-A-logo-after"}])
        }
    };
    Ok(update)
}
pub fn field<S: AuthSchema, T: AuthStore<S> + 'static>(
    state: &Arc<State<T>>,
    path: &str,
    mode: &str,
    name: &'static str,
) -> UserFieldConfig {
    let parent = if state.unconfigured_logo {
        ("organization.name", "O-A")
    } else {
        phase(path, false)
    };
    let child = phase(path, true);
    let asynchronous = (name == parent.0 && matches!(mode, "parent-read" | "parent-wait"))
        || (name == child.0 && matches!(mode, "child-read" | "child-wait"));
    let (state, path, mode) = (state.clone(), path.to_owned(), mode.to_owned());
    let output = if asynchronous {
        UserFieldTransform::new_async(move |value| {
            let (state, path, mode) = (state.clone(), path.clone(), mode.clone());
            async move {
                if !state.enabled.load(Ordering::Relaxed) {
                    return Ok(value);
                }
                let text = value.as_str().unwrap().to_owned();
                let _ = state.event(json!([name, text]));
                let selected = if mode.starts_with("parent-") {
                    parent
                } else {
                    child
                };
                if text == selected.1 {
                    if mode.ends_with("-wait") {
                        let gate = state.gate.lock().unwrap().take().unwrap();
                        state.started.send(()).unwrap();
                        gate.await
                            .map_err(|_| AuthError::internal("Ordinary display gate closed"))?;
                    } else if !state.changed.swap(true, Ordering::Relaxed) {
                        let store = state.store.lock().unwrap().upgrade().unwrap();
                        let _ = state.event(
                            update_display::<S, T>(&store, &path, mode == "child-read").await?,
                        );
                    }
                }
                Ok(format!("{text}-visible").into())
            }
        })
    } else {
        UserFieldTransform::new(move |value| {
            if !state.enabled.load(Ordering::Relaxed) {
                return Ok(value);
            }
            let text = value.as_str().unwrap();
            let sequence = state.event(json!([name, text]));
            if (name == "organization.logo" && text == "O-B-logo")
                || (name == "team.label" && text == "T-B-label")
            {
                state.finished.send(()).unwrap();
            }
            if (mode == "parent-error" && (name, text) == parent)
                || (mode == "child-error" && (name, text) == child)
            {
                return Err(failure());
            }
            Ok((if mode == "sync" {
                format!("{text}:{sequence}")
            } else {
                format!("{text}-visible")
            })
            .into())
        })
    };
    UserFieldConfig {
        required: Some(false),
        field_name: match name.split('.').next_back().unwrap() {
            "label" => Some("stored_label".into()),
            "detail" => Some("marker".into()),
            _ => None,
        },
        transform: Some(FieldTransforms {
            output: Some(output),
            ..Default::default()
        }),
        ..Default::default()
    }
}
pub fn organization_fields<S: AuthSchema, T: AuthStore<S> + 'static>(
    state: &Arc<State<T>>,
    path: &str,
    mode: &str,
) -> OrganizationFields {
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
        (&mut fields.team, ["team.name", "team.label"]),
    ] {
        for name in names {
            let _ = schema.fields_mut().insert(
                name.split('.').next_back().unwrap().into(),
                field::<S, T>(state, path, mode, name),
            );
        }
    }
    if state.unconfigured_logo {
        let _ = fields.organization.fields_mut().shift_remove("logo");
    }
    if path == "full" && matches!(mode, "parent-read" | "child-read") {
        let value = if mode == "child-read" {
            "I-A2-detail-after"
        } else {
            "I-A-detail-after"
        };
        fields
            .invitation
            .fields_mut()
            .get_mut("detail")
            .unwrap()
            .on_update = Some(Arc::new(move || Ok(value.into())));
    }
    fields
}
pub async fn seed<S: AuthSchema>(store: &impl AuthStore<S>) {
    let now: chrono::DateTime<chrono::Utc> = "2025-01-01T00:00:00Z".parse().unwrap();
    for label in ["A", "B"] {
        let suffix = label.to_lowercase();
        let _ = store
            .create_user(CreateUser {
                id: Some(format!("user-{suffix}")),
                image: Some(format!("U-{label}-image")).into(),
                created_at: Some(now.into()),
                updated_at: Some(now.into()),
                email_verified: Some(true),
                ..CreateUser::new()
                    .with_name(format!("U-{label}"))
                    .with_email(format!("{suffix}@ordinary-native-org.test"))
            })
            .await
            .unwrap();
        let mut input = CreateOrganization::new(format!("O-{label}"), format!("ordinary-{suffix}"));
        input.id = Some(format!("organization-{suffix}"));
        input.logo = Some(format!("O-{label}-logo")).into();
        let _ = store.create_organization(input).await.unwrap();
        let _ = store
            .insert_member(Member {
                id: format!("member-{suffix}").into(),
                organization_id: format!("organization-{suffix}").into(),
                user_id: "user-a".into(),
                role: "member".into(),
                created_at: now.into(),
                additional_fields: [
                    ("label".into(), format!("M-{label}").into()),
                    ("detail".into(), format!("M-{label}-detail").into()),
                ]
                .into_iter()
                .collect(),
            })
            .await
            .unwrap();
        let _ = store
            .create_team(CreateTeam {
                id: Some(format!("team-{suffix}")),
                name: format!("T-{label}").into(),
                organization_id: "organization-a".into(),
                created_at: Some(now.into()),
                updated_at: Some(now.into()),
                additional_fields: [("label".into(), format!("T-{label}-label").into())]
                    .into_iter()
                    .collect(),
            })
            .await
            .unwrap();
        let _ = store
            .add_team_member(&format!("team-{suffix}").into(), "user-a", None)
            .await
            .unwrap()
            .unwrap();
        let mut input = CreateInvitation::new(
            format!("organization-{suffix}"),
            "recipient@ordinary-native-org.test",
            "member",
            "user-a",
            "2099-01-01T00:00:00Z"
                .parse::<chrono::DateTime<chrono::Utc>>()
                .unwrap()
                .into(),
        );
        input.id = Some(format!("invitation-{suffix}"));
        input.created_at = Some(now.into());
        input.additional_fields = [
            ("label".into(), format!("I-{label}").into()),
            ("detail".into(), format!("I-{label}-detail").into()),
        ]
        .into_iter()
        .collect();
        let _ = store.create_invitation(input).await.unwrap();
    }
    let _ = store
        .insert_member(Member {
            id: "member-a-other".into(),
            organization_id: "organization-a".into(),
            user_id: "user-b".into(),
            role: "member".into(),
            created_at: now.into(),
            additional_fields: [
                ("label".into(), "M-A2".into()),
                ("detail".into(), "M-A2-detail".into()),
            ]
            .into_iter()
            .collect(),
        })
        .await
        .unwrap();
    let mut input = CreateInvitation::new(
        "organization-a",
        "other@ordinary-native-org.test",
        "member",
        "user-a",
        "2099-01-01T00:00:00Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap()
            .into(),
    );
    input.id = Some("invitation-a-other".into());
    input.created_at = Some(now.into());
    input.additional_fields = [
        ("label".into(), "I-A2".into()),
        ("detail".into(), "I-A2-detail".into()),
    ]
    .into_iter()
    .collect();
    let _ = store.create_invitation(input).await.unwrap();
    let _ = store
        .add_team_member(&"team-a".into(), "user-b", None)
        .await
        .unwrap()
        .unwrap();
}

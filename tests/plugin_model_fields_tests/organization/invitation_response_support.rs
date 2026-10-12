use super::*;
use better_auth::plugins::organization::hooks::{OrganizationHooks, OrganizationInvitationEvent};
use better_auth_core::user_fields::UserFieldFactory;

#[derive(Clone)]
pub(super) struct Values {
    pub invitation: FieldValue,
    pub member: FieldValue,
    pub organization: FieldValue,
}

impl Values {
    pub(super) fn new(events: &Events) -> Self {
        fn function(events: &Events, name: &'static str) -> FieldValue {
            let events = events.clone();
            let function: UserFieldFactory = UserFieldFactory::new(move || {
                events.push(name, "called", FieldValue::Undefined)?;
                Ok(name.into())
            });
            FieldValue::Function(function.into())
        }
        Self {
            invitation: function(events, "invitation.createdAt"),
            member: function(events, "member.probeFunction"),
            organization: function(events, "organization.name"),
        }
    }
}

fn output(
    events: &Events,
    name: String,
    value: FieldValue,
    config: UserFieldConfig,
) -> UserFieldConfig {
    let events = events.clone();
    UserFieldConfig {
        transform: Some(FieldTransforms {
            output: Some(UserFieldTransform::new(move |input| {
                events.push(&name, "output", input)?;
                Ok(value.clone())
            })),
            ..Default::default()
        }),
        ..config
    }
}

fn date_input(events: &Events, name: &'static str) -> UserFieldTransform {
    let events = events.clone();
    UserFieldTransform::new(move |value| {
        let _ = required(value.as_date(), "Expected a native timestamp input")?;
        events.push(name, "input", "native-date".into())?;
        Ok(date(0).into())
    })
}

fn record_fields(events: &Events, model: &str, values: &Values) -> AuthResult<UserConfig> {
    let invitation = model == "invitation";
    let mut timestamp = output(
        events,
        format!("{model}.createdAt"),
        if invitation {
            values.invitation.clone()
        } else {
            date(0).into()
        },
        UserFieldConfig {
            field_type: UserFieldType::Date,
            ..Default::default()
        },
    );
    if !invitation {
        required(
            timestamp.transform.as_mut(),
            "Output field must have transforms",
        )?
        .input = Some(date_input(events, "member.createdAt"));
    }
    let mut fields = declaration([("createdAt", timestamp)]);
    let mut extra = vec![
        ("probeUndefined", FieldValue::Undefined),
        ("probeNull", FieldValue::Null),
    ];
    if invitation {
        extra.extend([
            ("organizationName", "shadow-name".into()),
            ("organizationSlug", "shadow-slug".into()),
            ("inviterEmail", "shadow-email".into()),
        ]);
    } else {
        extra.push(("probeFunction", values.member.clone()));
    }
    for (name, value) in extra {
        let _ = fields.fields_mut().insert(
            name.into(),
            output(
                events,
                format!("{model}.{name}"),
                value,
                UserFieldConfig {
                    required: Some(false),
                    field_name: Some("role".into()),
                    ..Default::default()
                },
            ),
        );
    }
    Ok(fields)
}

struct Hooks<S: AuthSchema> {
    events: Events,
    raw: Arc<dyn AuthStore<S>>,
    case: Case,
    original_invitation: AtomicUsize,
}

impl<S: AuthSchema> Hooks<S> {
    fn event(
        &self,
        name: &str,
        event: OrganizationInvitationEvent<'_>,
        member: Option<&Member>,
        cancel: bool,
    ) -> AuthResult<()> {
        let organization = event.organization;
        let mut fields: FieldMap = [
            ("id".into(), organization.id.field_value()),
            ("name".into(), organization.name.field_value()),
            ("slug".into(), organization.slug.field_value()),
            ("logo".into(), organization.logo.field_value()),
            ("createdAt".into(), organization.created_at.field_value()),
            ("metadata".into(), organization.metadata.field_value()),
        ]
        .into();
        fields.retain(|_, value| !value.is_undefined());
        fields.extend(organization.additional_fields.clone());
        let mut value: FieldMap = [
            ("invitation".into(), event.invitation.field_values()?.into()),
            (
                if cancel { "cancelledBy" } else { "user" }.into(),
                event.user.clone(),
            ),
            ("organization".into(), fields.into()),
        ]
        .into();
        if let Some(member) = member {
            let _ = value.insert("member".into(), member.field_values()?.into());
        }
        self.events.push(name, "hook", value.into())
    }

    async fn before(
        &self,
        name: &str,
        event: OrganizationInvitationEvent<'_>,
        cancel: bool,
    ) -> AuthResult<()> {
        self.original_invitation.store(
            std::ptr::from_ref(event.invitation) as usize,
            Ordering::Relaxed,
        );
        self.event(name, event, None, cancel)?;
        if self.case.deletes() {
            self.raw.delete_organization_records("organization").await?;
        }
        Ok(())
    }

    #[expect(
        clippy::panic_in_result_fn,
        reason = "Contract assertions report mismatches while setup and callback errors propagate"
    )]
    fn after(
        &self,
        name: &str,
        event: OrganizationInvitationEvent<'_>,
        cancel: bool,
    ) -> AuthResult<()> {
        if self.case.deletes() {
            assert_eq!(
                self.original_invitation.load(Ordering::Relaxed),
                std::ptr::from_ref(event.invitation) as usize
            );
        }
        self.event(name, event, None, cancel)?;
        if self.case.after_error() {
            return Err(AuthError::internal("invitation-after-hook-failed"));
        }
        Ok(())
    }
}

#[async_trait]
impl<S: AuthSchema> OrganizationHooks for Hooks<S> {
    async fn before_accept_invitation(
        &self,
        event: OrganizationInvitationEvent<'_>,
    ) -> AuthResult<()> {
        self.event("beforeAcceptInvitation", event, None, false)
    }
    async fn after_accept_invitation(
        &self,
        member: &Member,
        event: OrganizationInvitationEvent<'_>,
    ) -> AuthResult<()> {
        self.event("afterAcceptInvitation", event, Some(member), false)
    }
    async fn before_reject_invitation(
        &self,
        event: OrganizationInvitationEvent<'_>,
    ) -> AuthResult<()> {
        self.before("beforeRejectInvitation", event, false).await
    }
    async fn after_reject_invitation(
        &self,
        event: OrganizationInvitationEvent<'_>,
    ) -> AuthResult<()> {
        self.after("afterRejectInvitation", event, false)
    }
    async fn before_cancel_invitation(
        &self,
        event: OrganizationInvitationEvent<'_>,
    ) -> AuthResult<()> {
        self.before("beforeCancelInvitation", event, true).await
    }
    async fn after_cancel_invitation(
        &self,
        event: OrganizationInvitationEvent<'_>,
    ) -> AuthResult<()> {
        self.after("afterCancelInvitation", event, true)
    }
}

pub(super) async fn auth<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    case: Case,
    events: &Events,
    values: &Values,
) -> AuthResult<BetterAuth<S>> {
    let mut config = config();
    {
        let better_auth_core::LoggerSource::Config(logger_options) = &mut config.logger else {
            return Err(AuthError::internal(
                "Fixture requires authored logger options",
            ));
        };
        logger_options.disabled = Some(true);
    }
    config.advanced.database.joins = Some(case == Case::UserFunctionJoin);
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(|request| {
            Ok(Some(format!("{}-a", request.model)))
        })));
    let mut options = OrganizationConfig::default();
    options.teams.enabled = true;
    options.schema.organization = declaration([(
        "name",
        UserFieldConfig {
            returned: Some(false),
            ..Default::default()
        },
    )]);
    let hidden_date = declaration([(
        "createdAt",
        UserFieldConfig {
            returned: Some(false),
            field_type: UserFieldType::Date,
            ..Default::default()
        },
    )]);
    options.schema.invitation = hidden_date.clone();
    options.schema.member = hidden_date;
    options.hooks = Some(Arc::new(Hooks {
        events: events.clone(),
        raw: raw.clone(),
        case,
        original_invitation: AtomicUsize::new(0),
    }));
    let name = if case == Case::UserUndefined {
        FieldValue::Undefined
    } else if case.user_list() || case == Case::GetClone {
        values.organization.clone()
    } else {
        "Organization".into()
    };
    let mut organization = declaration([(
        "name",
        output(
            events,
            "organization.name".into(),
            name,
            UserFieldConfig::default(),
        ),
    )]);
    if matches!(case, Case::Get | Case::GetClone) {
        let _ = organization.fields_mut().insert(
            "slug".into(),
            output(
                events,
                "organization.slug".into(),
                FieldValue::Null,
                UserFieldConfig::default(),
            ),
        );
    }
    let session = declaration([(
        "updatedAt",
        UserFieldConfig {
            field_type: UserFieldType::Date,
            on_update: Some(better_auth_core::user_fields::UserFieldFactory::new(|| {
                Ok(date(0).into())
            })),
            transform: Some(FieldTransforms {
                input: Some(date_input(events, "session.updatedAt")),
                ..Default::default()
            }),
            ..Default::default()
        },
    )]);
    let mut invitation = record_fields(events, "invitation", values)?;
    if case.deletes() || case.empty_status().is_some() {
        let events = events.clone();
        let _ = invitation.fields_mut().insert(
            "status".into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(move |value| {
                        events.push("invitation.status", "input", value.clone())?;
                        Ok(if case.empty_status() == value.as_str() {
                            FieldValue::Undefined
                        } else {
                            value
                        })
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
    }
    let mut member = record_fields(events, "member", values)?;
    if case.restores_empty() {
        let events = events.clone();
        let raw = raw.clone();
        let _ = member.fields_mut().insert(
            "role".into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new_async(move |value| {
                        let events = events.clone();
                        let raw = raw.clone();
                        async move {
                            events.push("member.role", "input", value)?;
                            if case == Case::AcceptRestoreDeletedEmpty {
                                raw.delete_organization_records("organization").await?;
                            }
                            Err(AuthError::internal("invitation-member-input-failed"))
                        }
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
    }
    BetterAuth::new(config)
        .store_arc(raw)
        .plugin(OrganizationPlugin::with_config(options))
        .plugin(Fields(vec![
            (EntityRole::Invitation, invitation),
            (EntityRole::Member, member),
            (EntityRole::Organization, organization),
            (EntityRole::Session, session),
        ]))
        .build()
        .await
}

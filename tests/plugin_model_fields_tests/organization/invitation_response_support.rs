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
    pub fn new(events: &Events) -> Self {
        fn function(events: &Events, name: &'static str) -> FieldValue {
            let events = events.clone();
            let function: UserFieldFactory = Arc::new(move || {
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

fn record_fields(events: &Events, model: &str, values: &Values) -> UserConfig {
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
        timestamp
            .transform
            .as_mut()
            .expect("Output field has transforms")
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
    fields
}

struct Hooks(Events);

impl Hooks {
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
        self.0.push(name, "hook", value.into())
    }
}

#[async_trait]
impl OrganizationHooks for Hooks {
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
        self.event("beforeRejectInvitation", event, None, false)
    }
    async fn after_reject_invitation(
        &self,
        event: OrganizationInvitationEvent<'_>,
    ) -> AuthResult<()> {
        self.event("afterRejectInvitation", event, None, false)
    }
    async fn before_cancel_invitation(
        &self,
        event: OrganizationInvitationEvent<'_>,
    ) -> AuthResult<()> {
        self.event("beforeCancelInvitation", event, None, true)
    }
    async fn after_cancel_invitation(
        &self,
        event: OrganizationInvitationEvent<'_>,
    ) -> AuthResult<()> {
        self.event("afterCancelInvitation", event, None, true)
    }
}

pub(super) async fn auth<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    case: Case,
    events: &Events,
    values: &Values,
) -> AuthResult<BetterAuth<S>> {
    let mut config = config();
    config.logger.disabled = Some(true);
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
    options.hooks = Some(Arc::new(Hooks(events.clone())));
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
            on_update: Some(Arc::new(|| Ok(date(0).into()))),
            transform: Some(FieldTransforms {
                input: Some(date_input(events, "session.updatedAt")),
                ..Default::default()
            }),
            ..Default::default()
        },
    )]);
    BetterAuth::new(config)
        .store_arc(raw)
        .plugin(OrganizationPlugin::with_config(options))
        .plugin(Fields(vec![
            (
                EntityRole::Invitation,
                record_fields(events, "invitation", values),
            ),
            (EntityRole::Member, record_fields(events, "member", values)),
            (EntityRole::Organization, organization),
            (EntityRole::Session, session),
        ]))
        .build()
        .await
}

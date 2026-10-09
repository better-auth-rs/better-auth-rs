use super::*;
use better_auth::plugins::organization::hooks::{
    OrganizationEndpoint, OrganizationHooks, OrganizationPolicy, OrganizationTeamDraft,
    OrganizationTeamEvent, OrganizationTeamLimit,
};
use better_auth::plugins::organization::types::OrganizationResponse;
use better_auth_core::user_fields::UserFieldFactory;

struct Callbacks(Events);

#[async_trait]
impl OrganizationPolicy for Callbacks {
    async fn maximum_teams(
        &self,
        data: OrganizationTeamLimit<'_>,
        _: OrganizationEndpoint<'_>,
    ) -> AuthResult<Option<usize>> {
        let actor = required(data.session, "Expected the current session")?;
        let user = required(actor.user.as_object(), "Expected the actor user")?;
        self.0.push(
            "maximumTeams",
            "callback",
            vec![
                data.organization_id.clone(),
                required(user.get("id")?, "Expected the actor ID")?,
            ]
            .into(),
        )?;
        Ok(Some(2))
    }
}

#[async_trait]
impl OrganizationHooks for Callbacks {
    async fn before_create_team(
        &self,
        draft: &mut OrganizationTeamDraft,
        _: &OrganizationResponse,
        _: Option<&FieldValue>,
    ) -> AuthResult<()> {
        let mut fields = draft.additional_fields.clone();
        fields.extend([
            ("name".into(), draft.name.field_value()),
            ("organizationId".into(), draft.organization_id.field_value()),
        ]);
        self.0.push("beforeCreateTeam", "hook", fields.into())
    }
    async fn after_create_team(&self, event: OrganizationTeamEvent<'_>) -> AuthResult<()> {
        self.0
            .push("afterCreateTeam", "hook", event.team.field_values()?.into())
    }
    async fn before_update_team(
        &self,
        _: &mut UpdateTeam,
        _: OrganizationTeamEvent<'_>,
    ) -> AuthResult<()> {
        self.0
            .push("beforeUpdateTeam", "hook", FieldValue::Undefined)
    }
    async fn after_update_team(&self, _: OrganizationTeamEvent<'_>) -> AuthResult<()> {
        self.0
            .push("afterUpdateTeam", "hook", FieldValue::Undefined)
    }
    async fn before_delete_team(&self, _: OrganizationTeamEvent<'_>) -> AuthResult<()> {
        self.0
            .push("beforeDeleteTeam", "hook", FieldValue::Undefined)
    }
    async fn after_delete_team(&self, _: OrganizationTeamEvent<'_>) -> AuthResult<()> {
        self.0
            .push("afterDeleteTeam", "hook", FieldValue::Undefined)
    }
}

fn read_sentinel(field: &'static str, events: &Events) -> UserFieldConfig {
    let events = events.clone();
    UserFieldConfig {
        transform: Some(FieldTransforms {
            output: Some(UserFieldTransform::new(move |value| {
                events.push(field, "output", value.clone())?;
                Ok(value)
            })),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn route_fields(case: Case, events: &Events) -> UserConfig {
    let calls = AtomicUsize::new(0);
    let called = events.clone();
    let function: UserFieldFactory = Arc::new(move || {
        called.push("team.name", "called", FieldValue::Undefined)?;
        Ok("Visible Team A".into())
    });
    let function = FieldValue::Function(function.into());
    let name_events = events.clone();
    let input_events = events.clone();
    let owner_events = events.clone();
    let mut fields = declaration([
        (
            "name",
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new(move |value| {
                        name_events.push("team.name", "output", value.clone())?;
                        let call = calls.fetch_add(1, Ordering::SeqCst);
                        Ok(
                            if case.mode == Mode::Page || (case.limited_page() && call == 0) {
                                value
                            } else {
                                function.clone()
                            },
                        )
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ),
        (
            "organizationId",
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(move |value| {
                        input_events.push("team.organizationId", "input", value.clone())?;
                        Ok(value)
                    })),
                    output: Some(UserFieldTransform::new(move |value| {
                        owner_events.push("team.organizationId", "output", value.clone())?;
                        Ok(match case.mode {
                            Mode::Scope => "wrong-organization".into(),
                            Mode::OwnerUnset | Mode::OwnerEmpty => "visible-organization".into(),
                            _ => value,
                        })
                    })),
                }),
                ..Default::default()
            },
        ),
    ]);
    for (name, label) in [
        ("createdAt", "team.createdAt"),
        ("updatedAt", "team.updatedAt"),
    ] {
        let events = events.clone();
        let _ = fields.fields_mut().insert(
            name.into(),
            UserFieldConfig {
                field_type: UserFieldType::Date,
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(move |value| {
                        let _ = required(value.as_date(), "Expected a native Team timestamp")?;
                        events.push(label, "input", "native-date".into())?;
                        Ok(date(0).into())
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
    }
    fields
}

pub(super) async fn endpoint<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    case: Case,
    events: &Events,
) -> AuthResult<BetterAuth<S>> {
    let mut config = config();
    config.logger.disabled = Some(true);
    config.advanced.database.joins = Some(case.joins);
    config.advanced.database.default_find_many_limit = case.limited_page().then_some(1.0);
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(|request| {
            Ok(Some(if request.model == "team" {
                "team-c".into()
            } else {
                format!("{}-a", request.model)
            }))
        })));
    let mut options = OrganizationConfig::default();
    options.teams.enabled = true;
    if case.mode != Mode::OwnerUnset {
        options.schema.team.additional_fields = Some(Default::default());
    }
    options.policy = Some(Arc::new(Callbacks(events.clone())));
    options.hooks = Some(Arc::new(Callbacks(events.clone())));
    BetterAuth::new(config)
        .store_arc(raw)
        .plugin(OrganizationPlugin::with_config(options))
        .plugin(Fields(vec![
            (EntityRole::Team, route_fields(case, events)),
            (
                EntityRole::TeamMember,
                details::member_fields(events, "id", false, false),
            ),
            (
                EntityRole::Member,
                declaration([("role", read_sentinel("member.role", events))]),
            ),
            (
                EntityRole::Organization,
                declaration([("name", read_sentinel("organization.name", events))]),
            ),
        ]))
        .build()
        .await
}

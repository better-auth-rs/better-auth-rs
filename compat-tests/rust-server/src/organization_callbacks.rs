use axum::{Json, Router, routing::get};
use better_auth::plugins::organization::{
    OrganizationPlugin, OrganizationTeamsConfig,
    hooks::{
        MembershipLimitPolicy, OrganizationActor, OrganizationEndpoint, OrganizationHooks,
        OrganizationInvitationDraft, OrganizationInvitationEvent, OrganizationMemberDraft,
        OrganizationMemberEvent, OrganizationPolicy, OrganizationTeamDraft, OrganizationTeamEvent,
        OrganizationTeamLimit, OrganizationTeamMemberLimit, OrganizationTeamMemberTarget,
        OrganizationUser, TeamMemberLimitPolicy,
    },
    types::OrganizationResponse as Organization,
};
use better_auth_core::{
    AuthError, AuthResult, CreateOrganization, CreateTeam, Member, Team, TeamMember,
    UpdateOrganization, UpdateTeam, wire::UserView,
};
use serde_json::{Map, Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Default)]
struct State {
    events: Vec<Value>,
    fail: Option<String>,
    organization_id_override: Option<String>,
    clear_logo: bool,
    metadata_override: Option<Value>,
    limits: Map<String, Value>,
}

#[derive(Clone)]
pub(super) struct OrganizationCallbacks {
    state: Arc<Mutex<State>>,
    enabled: bool,
    custom_team: bool,
}

fn project(value: &Value) -> Value {
    if value.is_null() {
        return Value::Null;
    }
    let mut projected: Map<_, _> = [
        "id",
        "name",
        "slug",
        "email",
        "organizationId",
        "userId",
        "role",
        "teamId",
        "status",
        "activeOrganizationId",
        "activeTeamId",
        "secretNote",
    ]
    .into_iter()
    .filter_map(|key| {
        value
            .get(key)
            .filter(|value| !value.is_null())
            .map(|value| (key.into(), value.clone()))
    })
    .collect();
    if let Some(metadata) = value.get("metadata") {
        let _ = projected.insert("metadata".into(), metadata.clone());
    }
    let dates: Map<_, _> = ["createdAt", "updatedAt", "expiresAt"]
        .into_iter()
        .map(|key| {
            (
                key.into(),
                json!(match value.get(key) {
                    None => "absent",
                    Some(Value::Null) => "null",
                    Some(_) => "value",
                }),
            )
        })
        .collect();
    let _ = projected.insert("dates".into(), dates.into());
    projected.into()
}

fn put_optional(value: &mut Value, name: &str, field: Option<impl serde::Serialize>) {
    if let Some(field) = field {
        value[name] = json!(field);
    }
}

fn member_event(event: OrganizationMemberEvent<'_>) -> Value {
    json!({"organization":event.organization,"member":event.member,"user":event.user})
}
fn invitation_event(event: OrganizationInvitationEvent<'_>) -> Value {
    json!({"organization":event.organization,"invitation":event.invitation,"user":event.user})
}
fn team_event(event: OrganizationTeamEvent<'_>) -> Value {
    json!({"organization":event.organization,"team":event.team,"user":event.user})
}
fn team_target(target: OrganizationTeamMemberTarget<'_>, member: Option<&TeamMember>) -> Value {
    json!({"organization":target.organization,"team":target.team,"user":target.user,"teamMember":member})
}

impl OrganizationCallbacks {
    pub(super) fn new(profile: &str) -> Self {
        Self {
            state: Default::default(),
            enabled: matches!(
                profile,
                "organization-callbacks" | "organization-custom-team"
            ),
            custom_team: profile == "organization-custom-team",
        }
    }
    pub(super) fn apply(&self, plugin: OrganizationPlugin) -> OrganizationPlugin {
        if !self.enabled {
            return plugin;
        }
        plugin
            .hooks(Arc::new(self.clone()))
            .policy(Arc::new(self.clone()))
            .membership_limit_callback(Arc::new(self.clone()))
            .teams(OrganizationTeamsConfig {
                enabled: true,
                allow_removing_all_teams: true,
                maximum_members_per_team_callback: Some(Arc::new(self.clone())),
                ..Default::default()
            })
            .dynamic_access_control(true)
    }
    pub(super) async fn reset(&self) {
        *self.state.lock().await = State::default();
    }
    pub(super) fn router(&self) -> Router {
        let read = self.clone();
        let control = self.clone();
        Router::new().route(
            "/__test/organization-callbacks",
            get(move || {
                let fixture = read.clone();
                async move { Json(fixture.state.lock().await.events.clone()) }
            })
            .post(move |Json(body): Json<Value>| {
                let fixture = control.clone();
                async move {
                    *fixture.state.lock().await = State {
                        events: Vec::new(),
                        organization_id_override: body["organizationIdOverride"]
                            .as_str()
                            .map(str::to_owned),
                        clear_logo: body["clearLogo"].as_bool() == Some(true),
                        metadata_override: body.get("metadataOverride").cloned(),
                        fail: body["fail"].as_str().map(str::to_owned),
                        limits: body["limits"].as_object().cloned().unwrap_or_default(),
                    };
                    Json(json!({"status":true}))
                }
            }),
        )
    }
    async fn record(&self, event: &str, data: Value, has_request: Option<bool>) -> AuthResult<()> {
        let mut state = self.state.lock().await;
        state.events.push(json!({
            "event":event, "organization":project(&data["organization"]), "user":project(&data["user"]),
            "member":project(&data["member"]), "team":project(&data["team"]),
            "invitation":project(&data["invitation"]), "teamMember":project(&data["teamMember"]),
            "newRole":data["newRole"], "previousRole":data["previousRole"],
            "organizationId":data["organizationId"], "teamId":data["teamId"],
            "session":data.get("session").filter(|value| !value.is_null()).map(|session| json!({"user":project(&session["user"]),"session":project(&session["session"])})),
            "hasRequest":has_request,
        }));
        if state.fail.as_deref() == Some(event) {
            return Err(AuthError::Upstream {
                status: 403,
                code: "FIXTURE_HOOK_REJECTED",
                message: "Hook rejected",
            });
        }
        Ok(())
    }
    async fn limit(&self, name: &str, data: Value, has_request: Option<bool>) -> AuthResult<usize> {
        self.record(name, data, has_request).await?;
        Ok(self
            .state
            .lock()
            .await
            .limits
            .get(name)
            .map(|value| value.as_u64().expect("numeric callback limit") as usize)
            .unwrap_or(100))
    }
}

#[async_trait::async_trait]
impl OrganizationPolicy for OrganizationCallbacks {
    async fn allow_user_to_create_organization(&self, user: &UserView) -> AuthResult<Option<bool>> {
        self.record("allowCreate", json!({"user":user}), None)
            .await?;
        Ok(Some(
            self.state.lock().await.limits.get("allowCreate") != Some(&Value::Bool(false)),
        ))
    }
    async fn organization_limit_reached(&self, user: &UserView) -> AuthResult<Option<bool>> {
        self.record("organizationLimit", json!({"user":user}), None)
            .await?;
        Ok(Some(
            self.state.lock().await.limits.get("organizationLimit") == Some(&Value::Bool(true)),
        ))
    }
    async fn invitation_limit(
        &self,
        event: OrganizationMemberEvent<'_>,
        _ctx: OrganizationEndpoint<'_>,
    ) -> AuthResult<Option<usize>> {
        self.limit("invitationLimit", member_event(event), None)
            .await
            .map(Some)
    }
    async fn maximum_teams(
        &self,
        data: OrganizationTeamLimit<'_>,
        ctx: OrganizationEndpoint<'_>,
    ) -> AuthResult<Option<usize>> {
        self.limit("maximumTeams", json!({"organizationId":data.organization_id,"session":data.session.map(|session| json!({"user":session.user,"session":session.session}))}), Some(ctx.request.is_some())).await.map(Some)
    }
    async fn maximum_roles_per_organization(
        &self,
        organization_id: &str,
    ) -> AuthResult<Option<usize>> {
        self.limit(
            "maximumRoles",
            json!({"organizationId":organization_id}),
            None,
        )
        .await
        .map(Some)
    }
    async fn create_default_team(
        &self,
        organization: &Organization,
        ctx: OrganizationEndpoint<'_>,
    ) -> AuthResult<Option<Team>> {
        if !self.custom_team {
            return Ok(None);
        }
        self.record(
            "createDefaultTeam",
            json!({"organization":organization}),
            Some(ctx.request.is_some()),
        )
        .await?;
        ctx.teams
            .create_team(CreateTeam {
                name: format!("custom:{}", organization.name),
                organization_id: organization.id.clone(),
                ..Default::default()
            })
            .await
            .map(Some)
    }
}

#[async_trait::async_trait]
impl OrganizationHooks for OrganizationCallbacks {
    async fn before_create_organization(
        &self,
        data: &mut CreateOrganization,
        user: &UserView,
    ) -> AuthResult<()> {
        let mut organization = json!({"id":data.id,"name":data.name,"slug":data.slug});
        put_optional(&mut organization, "metadata", data.metadata.as_ref());
        self.record(
            "beforeCreateOrganization",
            json!({"organization":organization,"user":user}),
            None,
        )
        .await?;
        data.name = format!("hook:{}", data.name);
        if let Some(metadata) = self.state.lock().await.metadata_override.clone() {
            data.metadata = Some(metadata);
        }
        Ok(())
    }
    async fn after_create_organization(
        &self,
        event: OrganizationMemberEvent<'_>,
    ) -> AuthResult<()> {
        self.record("afterCreateOrganization", member_event(event), None)
            .await
    }
    async fn before_update_organization(
        &self,
        data: &mut UpdateOrganization,
        actor: OrganizationActor<'_>,
    ) -> AuthResult<()> {
        let mut organization = json!({"id":data.id,"name":data.name,"slug":data.slug});
        put_optional(&mut organization, "createdAt", data.created_at);
        put_optional(&mut organization, "metadata", data.metadata.as_ref());
        self.record(
            "beforeUpdateOrganization",
            json!({"organization":organization,"member":actor.member,"user":actor.user}),
            None,
        )
        .await?;
        if let Some(name) = &mut data.name {
            if !name.is_empty() {
                *name = format!("updated:{name}");
            }
        }
        if let Some(id) = self.state.lock().await.organization_id_override.clone() {
            data.id = Some(id);
        }
        if self.state.lock().await.clear_logo {
            data.logo = Some(None);
        }
        if let Some(metadata) = self.state.lock().await.metadata_override.clone() {
            data.metadata = Some(metadata);
        }
        Ok(())
    }
    async fn after_update_organization(
        &self,
        organization: &Organization,
        actor: OrganizationActor<'_>,
    ) -> AuthResult<()> {
        self.record(
            "afterUpdateOrganization",
            json!({"organization":organization,"member":actor.member,"user":actor.user}),
            None,
        )
        .await
    }
    async fn before_delete_organization(
        &self,
        event: OrganizationUser<'_>,
        ctx: OrganizationEndpoint<'_>,
    ) -> AuthResult<()> {
        self.record(
            "beforeDeleteOrganization",
            json!({"organization":event.organization,"user":event.user}),
            Some(ctx.request.is_some()),
        )
        .await
    }
    async fn after_delete_organization(
        &self,
        event: OrganizationUser<'_>,
        ctx: OrganizationEndpoint<'_>,
    ) -> AuthResult<()> {
        self.record(
            "afterDeleteOrganization",
            json!({"organization":event.organization,"user":event.user}),
            Some(ctx.request.is_some()),
        )
        .await
    }
    async fn before_add_member(
        &self,
        data: &mut OrganizationMemberDraft,
        event: OrganizationUser<'_>,
    ) -> AuthResult<()> {
        let mut member = json!({"organizationId":data.organization_id,"userId":data.user_id,"role":data.role,"teamId":data.team_id});
        put_optional(&mut member, "createdAt", data.created_at);
        self.record(
            "beforeAddMember",
            json!({"member":member,"organization":event.organization,"user":event.user}),
            None,
        )
        .await?;
        if data.role == "member" {
            data.role = "admin".into();
        }
        Ok(())
    }
    async fn after_add_member(&self, event: OrganizationMemberEvent<'_>) -> AuthResult<()> {
        self.record("afterAddMember", member_event(event), None)
            .await
    }
    async fn before_remove_member(&self, event: OrganizationMemberEvent<'_>) -> AuthResult<()> {
        self.record("beforeRemoveMember", member_event(event), None)
            .await
    }
    async fn after_remove_member(&self, event: OrganizationMemberEvent<'_>) -> AuthResult<()> {
        self.record("afterRemoveMember", member_event(event), None)
            .await
    }
    async fn before_update_member_role(
        &self,
        role: &mut String,
        event: OrganizationMemberEvent<'_>,
    ) -> AuthResult<()> {
        let mut data = member_event(event);
        data["newRole"] = json!(role);
        self.record("beforeUpdateMemberRole", data, None).await?;
        *role = "member".into();
        Ok(())
    }
    async fn after_update_member_role(
        &self,
        previous_role: &str,
        event: OrganizationMemberEvent<'_>,
    ) -> AuthResult<()> {
        let mut data = member_event(event);
        data["previousRole"] = json!(previous_role);
        self.record("afterUpdateMemberRole", data, None).await
    }
    async fn before_create_invitation(
        &self,
        data: &mut OrganizationInvitationDraft,
        event: OrganizationUser<'_>,
    ) -> AuthResult<()> {
        let mut invitation = json!({"id":data.id,"organizationId":data.organization_id,"email":data.email,"role":data.role,"teamId":data.team_id,"status":data.status});
        put_optional(&mut invitation, "createdAt", data.created_at);
        put_optional(&mut invitation, "expiresAt", data.expires_at);
        self.record(
            "beforeCreateInvitation",
            json!({"invitation":invitation,"organization":event.organization,"user":event.user}),
            None,
        )
        .await?;
        data.role = "admin".into();
        Ok(())
    }
    async fn after_create_invitation(
        &self,
        event: OrganizationInvitationEvent<'_>,
    ) -> AuthResult<()> {
        self.record("afterCreateInvitation", invitation_event(event), None)
            .await
    }
    async fn before_accept_invitation(
        &self,
        event: OrganizationInvitationEvent<'_>,
    ) -> AuthResult<()> {
        self.record("beforeAcceptInvitation", invitation_event(event), None)
            .await
    }
    async fn after_accept_invitation(
        &self,
        member: &Member,
        event: OrganizationInvitationEvent<'_>,
    ) -> AuthResult<()> {
        let mut data = invitation_event(event);
        data["member"] = json!(member);
        self.record("afterAcceptInvitation", data, None).await
    }
    async fn before_reject_invitation(
        &self,
        event: OrganizationInvitationEvent<'_>,
    ) -> AuthResult<()> {
        self.record("beforeRejectInvitation", invitation_event(event), None)
            .await
    }
    async fn after_reject_invitation(
        &self,
        event: OrganizationInvitationEvent<'_>,
    ) -> AuthResult<()> {
        self.record("afterRejectInvitation", invitation_event(event), None)
            .await
    }
    async fn before_cancel_invitation(
        &self,
        event: OrganizationInvitationEvent<'_>,
    ) -> AuthResult<()> {
        self.record("beforeCancelInvitation", invitation_event(event), None)
            .await
    }
    async fn after_cancel_invitation(
        &self,
        event: OrganizationInvitationEvent<'_>,
    ) -> AuthResult<()> {
        self.record("afterCancelInvitation", invitation_event(event), None)
            .await
    }
    async fn before_create_team(
        &self,
        data: &mut OrganizationTeamDraft,
        organization: &Organization,
        user: Option<&UserView>,
    ) -> AuthResult<()> {
        let mut team = json!({"id":data.id,"organizationId":data.organization_id,"name":data.name});
        put_optional(&mut team, "createdAt", data.created_at);
        put_optional(&mut team, "updatedAt", data.updated_at);
        self.record(
            "beforeCreateTeam",
            json!({"team":team,"organization":organization,"user":user}),
            None,
        )
        .await?;
        data.name = format!("team:{}", data.name);
        Ok(())
    }
    async fn after_create_team(&self, event: OrganizationTeamEvent<'_>) -> AuthResult<()> {
        self.record("afterCreateTeam", team_event(event), None)
            .await
    }
    async fn before_update_team(
        &self,
        updates: &mut UpdateTeam,
        event: OrganizationTeamEvent<'_>,
    ) -> AuthResult<()> {
        self.record("beforeUpdateTeam", team_event(event), None)
            .await?;
        if let Some(name) = &mut updates.name {
            if !name.is_empty() {
                *name = format!("updated:{name}");
            }
        }
        Ok(())
    }
    async fn after_update_team(&self, event: OrganizationTeamEvent<'_>) -> AuthResult<()> {
        self.record("afterUpdateTeam", team_event(event), None)
            .await
    }
    async fn before_delete_team(&self, event: OrganizationTeamEvent<'_>) -> AuthResult<()> {
        self.record("beforeDeleteTeam", team_event(event), None)
            .await
    }
    async fn after_delete_team(&self, event: OrganizationTeamEvent<'_>) -> AuthResult<()> {
        self.record("afterDeleteTeam", team_event(event), None)
            .await
    }
    async fn before_add_team_member(
        &self,
        target: OrganizationTeamMemberTarget<'_>,
    ) -> AuthResult<()> {
        let mut data = team_target(target, None);
        data["teamMember"] = json!({"teamId":target.team.id,"userId":target.user.id});
        self.record("beforeAddTeamMember", data, None).await
    }
    async fn after_add_team_member(
        &self,
        member: &TeamMember,
        target: OrganizationTeamMemberTarget<'_>,
    ) -> AuthResult<()> {
        self.record(
            "afterAddTeamMember",
            team_target(target, Some(member)),
            None,
        )
        .await
    }
    async fn before_remove_team_member(
        &self,
        member: &TeamMember,
        target: OrganizationTeamMemberTarget<'_>,
    ) -> AuthResult<()> {
        self.record(
            "beforeRemoveTeamMember",
            team_target(target, Some(member)),
            None,
        )
        .await
    }
    async fn after_remove_team_member(
        &self,
        member: &TeamMember,
        target: OrganizationTeamMemberTarget<'_>,
    ) -> AuthResult<()> {
        self.record(
            "afterRemoveTeamMember",
            team_target(target, Some(member)),
            None,
        )
        .await
    }
}

#[async_trait::async_trait]
impl TeamMemberLimitPolicy for OrganizationCallbacks {
    async fn maximum_members_per_team(
        &self,
        data: OrganizationTeamMemberLimit<'_>,
    ) -> AuthResult<usize> {
        self.limit("maximumMembersPerTeam", json!({"organizationId":data.organization_id,"teamId":data.team_id,"session":{"user":data.session.user,"session":data.session.session}}), None).await
    }
}

#[async_trait::async_trait]
impl MembershipLimitPolicy for OrganizationCallbacks {
    async fn membership_limit(&self, event: OrganizationUser<'_>) -> AuthResult<usize> {
        self.limit(
            "membershipLimit",
            json!({"user":event.user,"organization":event.organization}),
            None,
        )
        .await
    }
}

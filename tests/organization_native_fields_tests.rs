#![expect(
    clippy::unwrap_used,
    reason = "Contract fixtures fail immediately when setup or native response decoding fails"
)]

use async_trait::async_trait;
use better_auth::plugins::organization::{
    AddMemberInput, OrganizationConfig, OrganizationPlugin,
    hooks::{OrganizationHooks, OrganizationMemberDraft, OrganizationUser},
    types::RoleInput,
};
use better_auth::{AuthConfig, AuthError, AuthResult, BetterAuth};
use better_auth_core::endpoint_input::EndpointInputPatch;
use better_auth_core::observability::{AfterEndpointHook, BeforeEndpointHook, EndpointHooks};
use better_auth_core::store::{EphemeralStore, StatelessSchema};
use better_auth_core::user_fields::{
    FieldTransforms, UserFieldConfig, UserFieldTransform, UserFieldType,
};
use better_auth_core::{
    AuthContext, AuthRecordFields, AuthRequest, AuthResponse, BeforeRequestAction,
    CreateOrganization, CreateUser, FieldDate, FieldMap, FieldValue, FromFieldMap, Member,
};
use serde_json::json;
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy)]
enum Mode {
    MergeRole,
    ReplaceBody,
    ReplaceResponse,
}

#[derive(Default)]
struct Trace {
    phases: Vec<&'static str>,
    before: Option<FieldMap>,
    draft: Option<(String, FieldMap)>,
    response: Option<Member>,
    before_scope: Option<FieldValue>,
    member_scope: Option<FieldValue>,
    after_scope: Option<FieldValue>,
}

struct Hooks {
    mode: Mode,
    replacement: FieldMap,
    trace: Mutex<Trace>,
}

impl Hooks {
    fn trace(&self) -> AuthResult<std::sync::MutexGuard<'_, Trace>> {
        self.trace
            .lock()
            .map_err(|_| AuthError::internal("Organization native trace lock poisoned"))
    }
}

#[async_trait]
impl BeforeEndpointHook<StatelessSchema> for Hooks {
    async fn before(
        &self,
        request: &AuthRequest,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        let body = request.input_field_value()?;
        let fields = body
            .as_object()
            .ok_or_else(|| AuthError::internal("Expected native member input"))?
            .snapshot_fields()?;
        {
            let mut trace = self.trace()?;
            trace.phases.push("before");
            trace.before = Some(fields.clone());
            trace.before_scope = Some(
                better_auth_core::hooks::current_request_hook_context()
                    .ok_or_else(|| AuthError::internal("Missing native before scope"))?
                    .body,
            );
        }
        Ok(match self.mode {
            Mode::MergeRole => Some(BeforeRequestAction::MergeContext(EndpointInputPatch {
                body: Some(json!({"role": "admin"})),
                query: None,
            })),
            Mode::ReplaceBody => {
                let id = |name| {
                    fields
                        .get(name)
                        .and_then(FieldValue::as_str)
                        .ok_or_else(|| {
                            AuthError::internal(format!("Expected {name} in native member input"))
                        })
                };
                Some(BeforeRequestAction::ReplaceBody(serde_json::to_vec(
                    &json!({
                        "userId": id("userId")?,
                        "organizationId": id("organizationId")?,
                        "role": "owner",
                        "nativeDate": null,
                        "left": {"marker": "replaced-left"},
                        "right": {"marker": "replaced-right"}
                    }),
                )?))
            }
            Mode::ReplaceResponse => None,
        })
    }
}

#[async_trait]
impl OrganizationHooks for Hooks {
    async fn before_add_member(
        &self,
        data: &mut OrganizationMemberDraft,
        _: OrganizationUser<'_>,
    ) -> AuthResult<()> {
        let mut trace = self.trace()?;
        trace.phases.push("member");
        trace.draft = Some((data.role.typed()?.clone(), data.additional_fields.clone()));
        trace.member_scope = Some(
            better_auth_core::hooks::current_request_hook_context()
                .ok_or_else(|| AuthError::internal("Missing native member scope"))?
                .body,
        );
        Ok(())
    }
}

#[async_trait]
impl AfterEndpointHook<StatelessSchema> for Hooks {
    async fn after(
        &self,
        _: &AuthRequest,
        response: &mut AuthResponse,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<()> {
        let body = response.body.field_value()?;
        let fields = body
            .as_object()
            .ok_or_else(|| AuthError::internal("Expected native member response"))?
            .snapshot_fields()?;
        let mut member = Member::from_field_values(fields)?;
        {
            let mut trace = self.trace()?;
            trace.phases.push("after");
            trace.response = Some(member.clone());
            trace.after_scope = Some(
                better_auth_core::hooks::current_request_hook_context()
                    .ok_or_else(|| AuthError::internal("Missing native after scope"))?
                    .body,
            );
        }
        if matches!(self.mode, Mode::ReplaceResponse) {
            member.id = "after-replacement".into();
            member.role = "owner".into();
            member.additional_fields = self.replacement.clone();
            response.replace_returned(AuthResponse::native(200, member.field_values()?.into()));
        }
        Ok(())
    }
}

fn native_fields(milliseconds: f64, marker: &str) -> FieldMap {
    let shared = FieldValue::from(FieldMap::from([("marker".into(), marker.into())]));
    FieldMap::from([
        (
            "nativeDate".into(),
            FieldDate::from_milliseconds(milliseconds).into(),
        ),
        ("ownUndefined".into(), FieldValue::Undefined),
        ("left".into(), shared.clone()),
        ("right".into(), shared),
        (
            "loneSurrogate".into(),
            better_auth_core::Utf16String::from_units(vec![0xd800]).into(),
        ),
    ])
}

struct Fixture {
    auth: BetterAuth<StatelessSchema>,
    plugin: OrganizationPlugin,
    input: AddMemberInput,
    output: FieldMap,
    hooks: Arc<Hooks>,
}

impl Fixture {
    async fn new(mode: Mode) -> AuthResult<Self> {
        let hooks = Arc::new(Hooks {
            mode,
            replacement: native_fields(1_767_225_600_123.0, "after-replacement"),
            trace: Mutex::new(Trace::default()),
        });
        let output = native_fields(1_735_689_600_123.0, "adapter-output");
        let mut options = OrganizationConfig {
            hooks: Some(hooks.clone()),
            ..Default::default()
        };
        for (name, value) in &output {
            let value = value.clone();
            let _ = options.schema.member.fields_mut().insert(
                name.clone(),
                UserFieldConfig {
                    field_type: if name == "nativeDate" {
                        UserFieldType::Date
                    } else {
                        UserFieldType::Enum(vec!["configured".into()])
                    },
                    required: Some(false),
                    transform: Some(FieldTransforms {
                        output: Some(UserFieldTransform::new(move |_| Ok(value.clone()))),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            );
        }
        let config = AuthConfig::new("organization-native-fields-secret-at-least-32-characters")
            .base_url("http://organization-native.test");
        let plugin = OrganizationPlugin::with_config(options);
        let auth = BetterAuth::<StatelessSchema>::new(config.clone())
            .store(EphemeralStore::new(Arc::new(config)))
            .plugin(plugin.clone())
            .hooks(EndpointHooks {
                before: Some(hooks.clone()),
                after: Some(hooks.clone()),
            })
            .build()
            .await?;
        let user = auth
            .store()
            .create_user(
                CreateUser::new()
                    .with_name("Native member")
                    .with_email("native-member@example.test"),
            )
            .await?;
        let organization = auth
            .store()
            .create_organization(CreateOrganization::new("Native", "native-fields"))
            .await?;
        let input = AddMemberInput {
            user_id: user.id.clone(),
            organization_id: organization.id.clone(),
            role: RoleInput::One("member".into()).into(),
            team_id: Default::default(),
            additional_fields: native_fields(1_704_067_200_123.0, "caller-input"),
        };
        Ok(Self {
            auth,
            plugin,
            input,
            output,
            hooks,
        })
    }

    async fn add_member(&self) -> (Member, Trace) {
        let member = self
            .plugin
            .add_member(self.input.clone(), None, self.auth.context())
            .await
            .unwrap();
        let trace = std::mem::take(&mut *self.hooks.trace().unwrap());
        assert_eq!(trace.phases, ["before", "member", "after"]);
        assert_native_fields(
            trace.before.as_ref().unwrap(),
            &self.input.additional_fields,
        );
        assert_native_fields(
            &trace
                .before_scope
                .as_ref()
                .unwrap()
                .as_object()
                .unwrap()
                .snapshot_fields()
                .unwrap(),
            &self.input.additional_fields,
        );
        if !matches!(self.hooks.mode, Mode::ReplaceBody) {
            assert_native_fields(
                &trace
                    .member_scope
                    .as_ref()
                    .unwrap()
                    .as_object()
                    .unwrap()
                    .snapshot_fields()
                    .unwrap(),
                &self.input.additional_fields,
            );
            assert_native_fields(
                &trace
                    .after_scope
                    .as_ref()
                    .unwrap()
                    .as_object()
                    .unwrap()
                    .snapshot_fields()
                    .unwrap(),
                &self.input.additional_fields,
            );
        }
        assert_native_fields(
            &trace.response.as_ref().unwrap().additional_fields,
            &self.output,
        );
        (member, trace)
    }
}

fn assert_native_fields(actual: &FieldMap, expected: &FieldMap) {
    assert!(matches!(
        actual.get("nativeDate"),
        Some(FieldValue::Date(_))
    ));
    assert!(actual.contains_key("ownUndefined"));
    assert!(matches!(
        actual.get("ownUndefined"),
        Some(FieldValue::Undefined)
    ));
    assert!(
        matches!(actual.get("loneSurrogate"), Some(FieldValue::Utf16String(value)) if value.as_utf16() == [0xd800])
    );
    for (name, value) in expected {
        assert!(
            actual
                .get(name)
                .is_some_and(|actual| actual.strict_equals(value)),
            "{name} must retain its native value and identity"
        );
    }
    assert!(
        actual
            .get("left")
            .unwrap()
            .strict_equals(actual.get("right").unwrap())
    );
}

#[tokio::test]
async fn merge_context_preserves_native_member_input_and_adapter_output() {
    let fixture = Fixture::new(Mode::MergeRole).await.unwrap();
    let (member, trace) = fixture.add_member().await;
    let (role, fields) = trace.draft.unwrap();
    assert_eq!(role, "admin");
    assert_native_fields(&fields, &fixture.input.additional_fields);
    assert_eq!(member.role, "admin");
    assert_native_fields(&member.additional_fields, &fixture.output);
}

#[tokio::test]
async fn replace_body_discards_original_native_member_input() {
    let fixture = Fixture::new(Mode::ReplaceBody).await.unwrap();
    let (member, trace) = fixture.add_member().await;
    let (role, fields) = trace.draft.unwrap();
    assert_eq!(role, "owner");
    assert_eq!(fields.get("nativeDate"), Some(&FieldValue::Null));
    assert!(!fields.contains_key("ownUndefined"));
    for (name, marker) in [("left", "replaced-left"), ("right", "replaced-right")] {
        let object = fields.get(name).unwrap();
        assert!(!object.strict_equals(fixture.input.additional_fields.get(name).unwrap()));
        assert_eq!(
            object
                .as_object()
                .unwrap()
                .get("marker")
                .unwrap()
                .as_ref()
                .and_then(FieldValue::as_str),
            Some(marker)
        );
    }
    assert_eq!(member.role, "owner");
    assert_native_fields(&member.additional_fields, &fixture.output);
}

#[tokio::test]
async fn native_after_hook_replacement_is_the_returned_member() {
    let fixture = Fixture::new(Mode::ReplaceResponse).await.unwrap();
    let (member, trace) = fixture.add_member().await;
    let (role, fields) = trace.draft.unwrap();
    assert_eq!(role, "member");
    assert_native_fields(&fields, &fixture.input.additional_fields);
    let original = trace.response.unwrap();
    assert_eq!(original.role, "member");
    assert_ne!(original.id, member.id);
    assert_eq!(member.id, "after-replacement");
    assert_eq!(member.role, "owner");
    assert_native_fields(&member.additional_fields, &fixture.hooks.replacement);
}

use super::member_contract_support::*;
use super::*;
use better_auth::plugins::organization::hooks::{OrganizationHooks, OrganizationMemberEvent};
use better_auth::server_api::EndpointInput;
use better_auth_core::{AuthRecordFields, HttpMethod};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone, Copy, Debug)]
enum Case {
    RemoveEmail,
    RemoveId,
    UpdateOther,
    UpdateSelf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    None,
    Before,
    After,
}

impl Failure {
    fn message(self) -> &'static str {
        match self {
            Self::None => "",
            Self::Before => "member-before-hook-failed",
            Self::After => "member-after-hook-failed",
        }
    }
}

impl Case {
    fn failures(self) -> &'static [Failure] {
        if matches!(self, Self::RemoveEmail | Self::UpdateOther) {
            &[Failure::None, Failure::Before, Failure::After]
        } else {
            &[Failure::None]
        }
    }

    fn removes(self) -> bool {
        matches!(self, Self::RemoveEmail | Self::RemoveId)
    }

    fn user(self) -> &'static str {
        if matches!(self, Self::UpdateSelf) {
            "user-a"
        } else {
            "user-b"
        }
    }

    fn id(self) -> &'static str {
        if matches!(self, Self::UpdateSelf) {
            "owner-member"
        } else {
            "member-b"
        }
    }

    fn role(self, updated: bool) -> &'static str {
        match (self, updated) {
            (Self::UpdateSelf, false) => "owner",
            (Self::UpdateSelf, true) => "owner,admin",
            (Self::UpdateOther, true) => "admin",
            _ => "member",
        }
    }

    fn endpoint(self) -> &'static str {
        if self.removes() {
            "remove-member"
        } else {
            "update-member-role"
        }
    }

    fn body(self) -> Value {
        if self.removes() {
            json!({"organizationId":"organization", "memberIdOrEmail":
                if matches!(self, Self::RemoveEmail) { "user-b@fields.test" } else { self.id() }})
        } else {
            json!({"organizationId":"organization", "memberId":self.id(), "role":self.role(true)})
        }
    }
}

fn name(user: &str, read: usize, mutated: bool) -> FieldValue {
    if user == "user-a" {
        return user.into();
    }
    let mut fields: FieldMap = [("read".into(), FieldValue::Number(read as f64))].into();
    if mutated {
        let _ = fields.insert("touched".into(), true.into());
    }
    fields.into()
}

fn summary(case: Case, mutated: bool) -> FieldValue {
    let mut fields: FieldMap = [
        ("id".into(), case.user().into()),
        ("name".into(), name(case.user(), 1, mutated)),
        (
            "email".into(),
            format!("{}@fields.test", case.user()).into(),
        ),
        ("image".into(), FieldValue::Null),
    ]
    .into();
    if mutated {
        let _ = fields.insert("hook".into(), "before".into());
    }
    fields.into()
}

fn visible_member(case: Case, after: bool, mutated: bool) -> FieldValue {
    let updated = after && !case.removes();
    let mut fields: FieldMap = [
        ("organizationId".into(), "organization".into()),
        ("userId".into(), case.user().into()),
        ("role".into(), case.role(updated).into()),
        ("createdAt".into(), date().into()),
    ]
    .into();
    if matches!(case, Case::RemoveEmail) {
        let _ = fields.insert("user".into(), summary(case, mutated));
    } else if updated {
        let _ = fields.insert("user".into(), "declared-user".into());
    }
    let _ = fields.insert("id".into(), case.id().into());
    if !case.removes() && !after {
        let _ = fields.insert("user".into(), summary(case, mutated));
    }
    fields.into()
}

fn independent_user(case: Case) -> FieldValue {
    FieldMap::from_iter([
        ("id".into(), case.user().into()),
        ("name".into(), name(case.user(), 2, false)),
        (
            "email".into(),
            format!("{}@fields.test", case.user()).into(),
        ),
        ("emailVerified".into(), true.into()),
        ("image".into(), FieldValue::Null),
        ("createdAt".into(), date().into()),
        ("updatedAt".into(), date().into()),
    ])
    .into()
}

#[derive(Default)]
struct Observations {
    calls: Vec<&'static str>,
    member_address: usize,
    summary: Option<FieldValue>,
    independent_user: Option<FieldValue>,
}

struct Hooks {
    case: Case,
    failure: Failure,
    observations: Arc<Mutex<Observations>>,
}

impl Hooks {
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Contract assertions report mismatches while setup and callback errors propagate"
    )]
    fn common(&self, event: OrganizationMemberEvent<'_>) -> AuthResult<()> {
        assert_eq!(event.user, &independent_user(self.case));
        assert_eq!(
            serde_json::to_value(event.organization)?,
            json!({
                "id":"organization", "name":"Organization", "slug":"organization",
                "logo":null, "metadata":"{}", "createdAt":"2030-01-01T00:00:00.000Z",
            })
        );
        Ok(())
    }

    fn before(&self, hook: &'static str, event: OrganizationMemberEvent<'_>) -> AuthResult<()> {
        self.common(event)?;
        let member = event.member.field_values()?;
        ordered(
            &member.clone().into(),
            &visible_member(self.case, false, false),
        )?;
        let mut observations = trace_lock(&self.observations)?;
        observations.calls.push(hook);
        observations.member_address = std::ptr::from_ref(event.member) as usize;
        observations.independent_user = Some(event.user.clone());
        if !matches!(self.case, Case::RemoveId) {
            let user = required(member.get("user"), "Expected lifecycle member user summary")?;
            let object = required(user.as_object(), "Expected native user summary object")?;
            object.set("hook", "before".into())?;
            if self.case.user() == "user-b" {
                let value = required(object.get("name")?, "Expected summary name")?;
                let name = required(value.as_object(), "Expected native summary name object")?;
                name.set("touched", true.into())?;
            }
            observations.summary = Some(user.clone());
            ordered(user, &summary(self.case, true))?;
            self.common(event)?;
        }
        if self.failure == Failure::Before {
            return Err(AuthError::internal(self.failure.message()));
        }
        Ok(())
    }

    #[expect(
        clippy::panic_in_result_fn,
        reason = "Contract assertions report mismatches while setup and callback errors propagate"
    )]
    fn after(&self, hook: &'static str, event: OrganizationMemberEvent<'_>) -> AuthResult<()> {
        self.common(event)?;
        let member = event.member.field_values()?;
        ordered(
            &member.clone().into(),
            &visible_member(self.case, true, true),
        )?;
        let mut observations = trace_lock(&self.observations)?;
        observations.calls.push(hook);
        assert!(event.user.strict_equals(required(
            observations.independent_user.as_ref(),
            "Expected original event user"
        )?));
        if self.case.removes() {
            assert_eq!(
                observations.member_address,
                std::ptr::from_ref(event.member) as usize
            );
        }
        if matches!(self.case, Case::RemoveEmail) {
            assert!(
                required(member.get("user"), "Expected retained email user")?.strict_equals(
                    required(
                        observations.summary.as_ref(),
                        "Expected original user summary"
                    )?
                )
            );
        }
        if self.failure == Failure::After {
            return Err(AuthError::internal(self.failure.message()));
        }
        Ok(())
    }
}

#[async_trait]
impl OrganizationHooks for Hooks {
    async fn before_remove_member(&self, event: OrganizationMemberEvent<'_>) -> AuthResult<()> {
        self.before("beforeRemoveMember", event)
    }

    async fn after_remove_member(&self, event: OrganizationMemberEvent<'_>) -> AuthResult<()> {
        self.after("afterRemoveMember", event)
    }

    async fn before_update_member_role(
        &self,
        role: &mut String,
        event: OrganizationMemberEvent<'_>,
    ) -> AuthResult<()> {
        assert_eq!(role.as_str(), self.case.role(true));
        self.before("beforeUpdateMemberRole", event)
    }

    async fn after_update_member_role(
        &self,
        previous_role: &str,
        event: OrganizationMemberEvent<'_>,
    ) -> AuthResult<()> {
        assert_eq!(previous_role, self.case.role(false));
        self.after("afterUpdateMemberRole", event)
    }
}

async fn check<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    case: Case,
    native: bool,
    joins: bool,
    failure: Failure,
) -> AuthResult<()> {
    let token = seed(raw.clone(), true, "user-a").await?;
    let mut expected_storage = storage.snapshot().await?;
    let observations = Arc::new(Mutex::new(Observations::default()));
    let reads = Arc::new(AtomicUsize::new(0));
    let mut options = config();
    {
        let better_auth_core::LoggerSource::Config(logger_options) = &mut options.logger else {
            return Err(AuthError::internal(
                "Fixture requires authored logger options",
            ));
        };
        logger_options.disabled = Some(true);
    }
    options.session.disable_session_refresh = Some(true);
    options.advanced.database.joins = Some(joins);
    let _ = options.user.fields_mut().insert(
        "name".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new({
                    let reads = reads.clone();
                    move |value| {
                        if value.as_str() == Some("user-b") {
                            Ok(name(
                                "user-b",
                                reads.fetch_add(1, Ordering::Relaxed) + 1,
                                false,
                            ))
                        } else {
                            Ok(value)
                        }
                    }
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let organization = OrganizationConfig {
        hooks: Some(Arc::new(Hooks {
            case,
            failure,
            observations: observations.clone(),
        })),
        ..Default::default()
    };
    let auth = BetterAuth::new(options)
        .store_arc(raw)
        .plugin(OrganizationPlugin::with_config(organization))
        .plugin(Fields(vec![(
            EntityRole::Member,
            fields(
                "user",
                UserFieldConfig {
                    field_name: Some("role".into()),
                    transform: Some(FieldTransforms {
                        output: Some(UserFieldTransform::new(|_| Ok("declared-user".into()))),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ),
        )]))
        .build()
        .await?;
    let headers = std::collections::HashMap::from([
        ("content-type".into(), "application/json".into()),
        ("origin".into(), "http://fields.test".into()),
        (
            "cookie".into(),
            format!(
                "better-auth.session_token={}",
                better_auth_core::utils::cookie_utils::sign_cookie_value(
                    &token,
                    auth.config().signing_secret()
                )
            ),
        ),
    ]);
    let path = format!("/organization/{}", case.endpoint());
    let body = case.body();
    let response = if native {
        auth.call_endpoint(
            HttpMethod::Post,
            &path,
            EndpointInput {
                headers: Some(headers),
                body: Some(body),
                ..Default::default()
            },
        )
        .await
    } else {
        auth.handle_request(
            AuthRequest::from_parts(
                HttpMethod::Post,
                format!("/api/auth{path}"),
                headers,
                Some(serde_json::to_vec(&body)?),
                None,
            )
            .with_url(
                format!("http://fields.test/api/auth{path}")
                    .parse()
                    .map_err(|error| {
                        AuthError::internal(format!("Invalid member hook URL: {error}"))
                    })?,
            ),
        )
        .await
    };
    if failure != Failure::None {
        if native {
            assert!(
                matches!(response, Err(AuthError::Internal(message)) if message == failure.message())
            );
        } else {
            let response = response?;
            assert_eq!(response.status, 500, "{case:?} {failure:?}");
            assert!(response.body.bytes()?.is_empty());
        }
    } else {
        let response = response?;
        assert_eq!(
            response.status, 200,
            "{case:?} native={native} joins={joins}"
        );
        let expected_member = visible_member(case, true, true);
        let expected = if case.removes() {
            FieldValue::from(FieldMap::from_iter([("member".into(), expected_member)]))
        } else {
            expected_member
        };
        if native {
            let actual = response.body.field_value()?;
            ordered(&actual, &expected)?;
            if matches!(case, Case::RemoveEmail) {
                let member = required(actual.as_object(), "Expected remove response object")?
                    .get("member")?
                    .ok_or_else(|| AuthError::internal("Expected removed member"))?;
                let user = required(member.as_object(), "Expected removed member object")?
                    .get("user")?
                    .ok_or_else(|| AuthError::internal("Expected removed user summary"))?;
                assert!(user.strict_equals(required(
                    trace_lock(&observations)?.summary.as_ref(),
                    "Expected hook user summary"
                )?));
            }
        } else {
            assert_eq!(
                response.body.bytes()?,
                serde_json::to_vec(&required(
                    expected.json()?,
                    "Expected JSON member response"
                )?)?
            );
        }
    }
    let mut expected_calls = if case.removes() {
        vec!["beforeRemoveMember", "afterRemoveMember"]
    } else {
        vec!["beforeUpdateMemberRole", "afterUpdateMemberRole"]
    };
    if failure == Failure::Before {
        expected_calls.truncate(1);
    }
    assert_eq!(trace_lock(&observations)?.calls, expected_calls);
    assert_eq!(
        reads.load(Ordering::Relaxed),
        if matches!(case, Case::UpdateSelf) {
            0
        } else {
            2
        }
    );
    if failure != Failure::Before {
        let members = expected_storage
            .get_mut("member")
            .ok_or_else(|| AuthError::internal("Expected Member storage table"))?;
        if case.removes() {
            members.retain(|row| row.get("id").and_then(FieldValue::as_str) != Some(case.id()));
        } else {
            let target = members
                .iter_mut()
                .find(|row| row.get("id").and_then(FieldValue::as_str) == Some(case.id()))
                .ok_or_else(|| AuthError::internal("Expected stored updated Member"))?;
            let _ = target.insert("role".into(), case.role(true).into());
        }
    }
    assert_eq!(
        storage.snapshot().await?,
        expected_storage,
        "{case:?} native={native} joins={joins} {failure:?}"
    );
    Ok(())
}

#[tokio::test]
async fn memory_member_hooks_preserve_subjects_identity_and_storage() -> AuthResult<()> {
    for case in [
        Case::RemoveEmail,
        Case::RemoveId,
        Case::UpdateOther,
        Case::UpdateSelf,
    ] {
        for native in [false, true] {
            for joins in [false, true] {
                for &failure in case.failures() {
                    let (raw, storage) = memory_fixture();
                    check(raw, storage, case, native, joins, failure).await?;
                }
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_member_hooks_preserve_subjects_identity_and_storage() -> AuthResult<()> {
    for case in [
        Case::RemoveEmail,
        Case::RemoveId,
        Case::UpdateOther,
        Case::UpdateSelf,
    ] {
        for native in [false, true] {
            for joins in [false, true] {
                for &failure in case.failures() {
                    let (raw, storage) = sqlite_fixture().await?;
                    check(raw, storage, case, native, joins, failure).await?;
                }
            }
        }
    }
    Ok(())
}

use super::member_contract_support::*;
use super::*;
use better_auth::server_api::EndpointInput;
use better_auth_core::{
    AuthRecordFields, HttpMethod,
    id::{IdGeneration, IdGenerator},
};

#[path = "organization_live_business_create.rs"]
mod create;
#[path = "organization_output_boundary.rs"]
mod output_boundary;
#[path = "organization_live_business_roles.rs"]
mod roles;
#[path = "organization_live_business_update.rs"]
mod update;

type Events = Arc<Mutex<Vec<FieldValue>>>;
type Snapshot = std::collections::BTreeMap<String, Vec<FieldMap>>;

fn event(events: &Events, values: impl IntoIterator<Item = FieldValue>) -> AuthResult<()> {
    trace_lock(events)?.push(values.into_iter().collect::<Vec<_>>().into());
    Ok(())
}

fn declaration(values: impl IntoIterator<Item = (&'static str, UserFieldConfig)>) -> UserConfig {
    UserConfig {
        additional_fields: Some(
            values
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value))
                .collect(),
        ),
    }
}

fn settings() -> AuthResult<AuthConfig> {
    let mut settings = config();
    {
        let better_auth_core::LoggerSource::Config(logger_options) = &mut settings.logger else {
            return Err(AuthError::internal(
                "Fixture requires authored logger options",
            ));
        };
        logger_options.disabled = Some(true);
    }
    settings.session.disable_session_refresh = Some(true);
    settings.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(|request| {
            Ok(Some(format!("{}-a", request.model)))
        })));
    Ok(settings)
}

fn fixed_creation(model: &'static str, events: &Events) -> UserFieldConfig {
    UserFieldConfig {
        field_type: UserFieldType::Date,
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new({
                let events = events.clone();
                move |value| {
                    assert!(value.as_date().is_some(), "Creation supplies a native Date");
                    event(
                        &events,
                        [
                            format!("{model}.createdAt").into(),
                            "input".into(),
                            "native-date".into(),
                        ],
                    )?;
                    Ok(date().into())
                }
            })),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn stored(storage: &Storage, fields: FieldMap) -> FieldMap {
    fields
        .into_iter()
        .map(|(name, value)| {
            let physical = if storage.memory() {
                name.as_str()
            } else {
                match name.as_str() {
                    "organizationId" => "organization_id",
                    "userId" => "user_id",
                    "createdAt" => "created_at",
                    "updatedAt" => "updated_at",
                    name => name,
                }
            }
            .to_owned();
            let value = if !storage.memory() && value.as_date().is_some() {
                "2030-01-01T00:00:00.000Z".into()
            } else {
                value
            };
            (physical, value)
        })
        .collect()
}

fn append(snapshot: &mut Snapshot, table: &str, row: FieldMap) -> AuthResult<()> {
    let rows = snapshot
        .get_mut(table)
        .ok_or_else(|| AuthError::internal("Expected business contract table"))?;
    rows.push(row);
    rows.sort_by(|left, right| {
        left.get("id")
            .and_then(FieldValue::as_str)
            .cmp(&right.get("id").and_then(FieldValue::as_str))
    });
    Ok(())
}

async fn call<S: AuthSchema>(
    auth: &BetterAuth<S>,
    token: &str,
    native: bool,
    endpoint: &str,
    body: Value,
) -> AuthResult<AuthResponse> {
    let headers = std::collections::HashMap::from([
        ("content-type".into(), "application/json".into()),
        ("origin".into(), "http://fields.test".into()),
        (
            "cookie".into(),
            format!(
                "better-auth.session_token={}",
                better_auth_core::utils::cookie_utils::sign_cookie_value(
                    token,
                    auth.config().signing_secret()
                )
            ),
        ),
    ]);
    let path = format!("/organization/{endpoint}");
    if native {
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
                        AuthError::internal(format!("Invalid business contract URL: {error}"))
                    })?,
            ),
        )
        .await
    }
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "Contract assertions report mismatches while setup and callback errors propagate"
)]
fn response(
    response: AuthResponse,
    native: bool,
    status: u16,
    expected: &FieldValue,
) -> AuthResult<()> {
    if native && response.is_api_error()? {
        assert_eq!(response.api_error_status()?, status);
        ordered(&response.api_error_body()?, expected)?;
    } else if native {
        assert_eq!(response.status, status);
        ordered(&response.body.field_value()?, expected)?;
    } else {
        assert_eq!(response.status, status);
        assert_eq!(
            response.body.bytes()?,
            required(expected.stringify()?, "Expected business JSON response")?.as_bytes()
        );
    }
    Ok(())
}

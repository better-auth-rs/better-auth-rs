use super::*;
use better_auth_core::{
    email::SendVerificationEmail,
    observability::{LogArgument, LogLevel, LogSink},
    wire::UserView,
};

const DIAGNOSTIC: &str = "Cannot create an OAuth verification token without a user email";

pub(super) struct Sender(pub(super) Events);

#[async_trait::async_trait]
impl SendVerificationEmail for Sender {
    async fn send(&self, user: &UserView, url: &str, token: &str) -> AuthResult<()> {
        self.0.push(json!({
            "kind": "email.sender",
            "data": {"user": values::observe(&FieldMap::from(user.clone()).into())?, "url": url, "token": token},
        }))
    }
}

struct Logger(Events);

fn argument(value: &LogArgument<'_>) -> Value {
    match value {
        LogArgument::Text(value) => json!(value),
        LogArgument::Value(value) => (*value).clone(),
        LogArgument::Error(value) => json!({
            "type": "rust-error", "debug": format!("{value:?}"), "display": value.to_string(),
        }),
    }
}

impl LogSink for Logger {
    #[expect(
        clippy::expect_used,
        reason = "The synchronous logger cannot return recorder errors; poisoning must fail the contract."
    )]
    fn log(&self, level: LogLevel, message: LogArgument<'_>, arguments: &[LogArgument<'_>]) {
        self.0
            .push(json!({
                "kind": "logger", "level": level.as_str(), "message": argument(&message),
                "args": arguments.iter().map(argument).collect::<Vec<_>>(),
            }))
            .expect("Record verification logger event");
    }
}

async fn contract<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    database: Option<&DatabaseConnection>,
    scenario: &Scenario,
    case: &Case,
) -> TestResult {
    assert!(case.setup.is_none());
    assert_eq!(case.request.method, "POST");
    assert_eq!(
        case.request.url,
        format!("{ORIGIN}/api/auth/sign-in/social")
    );
    assert_eq!(
        case.request.body,
        json!({"provider": "google", "idToken": {"token": ID_TOKEN, "nonce": NONCE}})
    );
    storage::seed(raw.as_ref(), scenario).await?;
    let before = storage::snapshot(raw.as_ref(), database, &[]).await?;
    storage::assert_snapshot(&before, &case.before, database.is_some(), case);
    let events = Events::default();
    let mut options = config::configured(scenario, case.joins, Some(&events))?;
    options.logger.disabled = Some(false);
    options.logger.level = Some(LogLevel::Error);
    options.logger.log = Some(Arc::new(Logger(events.clone())));
    let store = raw.with_runtime(
        Arc::new(options.clone()),
        vec![Arc::new(hooks::Hooks(events.clone()))],
        Default::default(),
    )?;
    let harness = http::auth(store, options, scenario, &events).await?;
    assert!(harness.flow.is_none());
    assert!(events.take()?.is_empty());
    let start = chrono::Utc::now().timestamp_millis();
    let response = http::request(harness.auth, &case.request)
        .with_subscriber(tracing_subscriber::registry().with(events.clone()))
        .await?;
    let end = chrono::Utc::now().timestamp_millis();
    let mut observed = events.take()?;
    let tokens = observe::issued_tokens(&observed)?;
    assert!(
        tokens.is_empty(),
        "Verification rejection must precede Session issuance"
    );
    let mut after = storage::snapshot(raw.as_ref(), database, &tokens).await?;
    assert_eq!(after["user"], before["user"]);
    assert_eq!(after["session"], json!([]));
    let anchors = observe::account_update_anchors(&observed, &after, case, start..=end)?;
    observe::normalize(&mut observed, &mut after, &anchors)?;
    assert_events(&observed, case, scenario)?;
    storage::assert_snapshot(&after, &case.after, database.is_some(), case);
    http::assert_response(response, &case.response, &anchors)?;
    assert_eq!(case.response.status, 403);
    assert_eq!(
        serde_json::from_str::<Value>(&case.response.body)?,
        json!({"message": "Email not verified", "code": "EMAIL_NOT_VERIFIED"})
    );
    assert_eq!(
        case.checked,
        json!({
            "noNetwork": true, "completeStorage": true, "admissionIdIsUndefined": true,
            "preservedCanonicalAccountOwner": true, "accountDatesWithinRequest": true,
            "verificationRejectedBeforeSession": true, "emailSenderCalls": 0,
            "missingEmailFailureLogged": scenario.email_sender,
        })
    );
    Ok(())
}

fn assert_events(actual: &[Value], case: &Case, scenario: &Scenario) -> TestResult {
    for kind in ["email.sender", "api-error", "console.error"] {
        assert!(
            !actual.iter().any(|event| event["kind"] == kind),
            "{case:?}: unexpected {kind}"
        );
    }
    let logs: Vec<_> = actual
        .iter()
        .filter(|event| event["kind"] == "logger")
        .collect();
    assert_eq!(
        logs.len(),
        usize::from(scenario.email_sender),
        "scenario={}, backend={}, joins={}",
        case.scenario,
        case.backend,
        case.joins
    );
    let admissions: Vec<_> = actual
        .iter()
        .filter(|event| event["kind"] == "admission")
        .collect();
    assert_eq!(admissions.len(), 1);
    assert_eq!(
        admissions[0]["data"]["user"].get("id"),
        Some(&json!({"type": "undefined"}))
    );
    if let Some(log) = logs.first() {
        assert_eq!(
            actual.last(),
            Some(*log),
            "Email rejection must precede sender execution and Session creation"
        );
        let completed = actual
            .iter()
            .position(|event| {
                event["kind"] == "hook" && event["model"] == "account" && event["phase"] == "after"
            })
            .ok_or("Missing completed Account hook")?;
        assert!(completed < actual.len() - 1);
    }
    let mut expected = case.events.clone();
    for event in &mut expected {
        if event["kind"] != "logger" {
            continue;
        }
        assert_eq!(event["level"], "error");
        assert_eq!(event["message"], "Failed to send OAuth verification email");
        let errors = event["args"]
            .as_array()
            .ok_or("Expected logger arguments")?;
        assert_eq!(errors.len(), 1);
        let error = &errors[0];
        assert_eq!(error.as_object().map(serde_json::Map::len), Some(4));
        assert_eq!(error["name"], "TypeError");
        assert!(
            error["message"]
                .as_str()
                .is_some_and(|value| value.contains("email.toLowerCase"))
        );
        assert_eq!(error["keys"], json!([]));
        assert_eq!(error["properties"], json!({}));
        // The fixture retains native JavaScript diagnostics; Rust logs its real typed error.
        let expected_error = AuthError::internal(DIAGNOSTIC);
        event["args"] = json!([argument(&LogArgument::Error(&expected_error))]);
    }
    assert_eq!(
        actual, expected,
        "{case:?}: complete Email callback and query sequence"
    );
    Ok(())
}

#[tokio::test]
async fn selected_user_email_verification_matches_upstream_http() -> TestResult {
    let fixture = Fixture::read_email()?;
    for case in &fixture.cases {
        let scenario = fixture.scenario(&case.scenario)?;
        if case.backend == "memory" {
            let raw = Arc::new(EphemeralStore::new(Arc::new(config::baseline())));
            contract(raw, None, scenario, case).await?;
        } else {
            assert_eq!(case.backend, "sqlite");
            let database = storage::sqlite(scenario).await?;
            let raw = Arc::new(SeaOrmStore::<models::Core>::new(
                config::baseline(),
                database.clone(),
            ));
            contract(raw, Some(&database), scenario, case).await?;
        }
    }
    Ok(())
}

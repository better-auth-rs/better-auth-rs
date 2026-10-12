#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "Claim contracts require complete storage snapshots and original failure identity. Fixture locks must remain available."
)]
use super::*;
use better_auth_core::{
    AuthConfig, FieldFunction,
    id::{IdGeneration, IdGenerator},
};

#[path = "email_claim_store.rs"]
mod store;

const EMAIL: &str = "owner@siwe-claims.test";
const CLAIM: &str = "siwe-email-claim-owner@siwe-claims.test";
const MODES: [&str; 12] = [
    "success",
    "reserve-before",
    "reserve-after",
    "cleanup-before",
    "cleanup-after",
    "create-error",
    "create-error-cleanup-before",
    "create-error-cleanup-after",
    "retry-query-error",
    "initial-query-error",
    "ens-error",
    "retry-success",
];

struct State {
    mode: &'static str,
    raw: Arc<EphemeralStore>,
    events: Mutex<Vec<&'static str>>,
    errors: FieldMap,
    lookups: AtomicUsize,
    creates: AtomicUsize,
    logs: AtomicUsize,
    claimed: Mutex<Vec<FieldMap>>,
    created_users: Mutex<Vec<FieldMap>>,
}

impl State {
    fn new(mode: &'static str, raw: Arc<EphemeralStore>) -> AuthResult<Self> {
        let errors = ["reserve", "cleanup", "create", "lookup", "ens", "logger"]
            .into_iter()
            .map(|phase| {
                Ok((
                    phase.into(),
                    AuthError::from_status(
                        "CONFLICT",
                        FieldMap::from([
                            ("code".into(), format!("CLAIM_{phase}").into()),
                            ("message".into(), format!("Original {phase} error").into()),
                        ])
                        .into(),
                    )
                    .into_thrown_value()?,
                ))
            })
            .collect::<AuthResult<FieldMap>>()?;
        Ok(Self {
            mode,
            raw,
            errors,
            events: Mutex::default(),
            lookups: AtomicUsize::new(0),
            creates: AtomicUsize::new(0),
            logs: AtomicUsize::new(0),
            claimed: Mutex::default(),
            created_users: Mutex::default(),
        })
    }

    fn record(&self, phase: &'static str) {
        self.events.lock().unwrap().push(phase);
    }

    fn error(&self, phase: &str) -> AuthError {
        AuthError::from_thrown(self.errors[phase].clone())
    }
}

async fn run_claim_case(mode: &'static str) -> AuthResult<()> {
    let mut config: AuthConfig = crate::plugins::test_helpers::create_test_config();
    let generated = AtomicUsize::new(0);
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(move |request| {
            Ok(Some(format!(
                "{}-{}",
                request.model,
                generated.fetch_add(1, Ordering::SeqCst) + 1
            )))
        })));
    let raw = Arc::new(EphemeralStore::new(Arc::new(config.clone())));
    let state = Arc::new(State::new(mode, raw.clone())?);
    let logger: better_auth_core::FieldObject = FieldMap::from([
        ("level".into(), "warn".into()),
        (
            "log".into(),
            FieldFunction::contextual({
                let state = state.clone();
                move |_, _| {
                    state.logs.fetch_add(1, Ordering::SeqCst);
                    Err(state.error("logger"))
                }
            })
            .into(),
        ),
    ])
    .into();
    config.logger = logger.into();
    let config = Arc::new(config);
    let store = Arc::new(store::ClaimStore {
        inner: raw.clone(),
        state: state.clone(),
    });
    let verified = state.clone();
    let ens = state.clone();
    let plugin = SiwePlugin::new(
        "example.com",
        || async { Ok(NONCE.into()) },
        move |_| {
            let state = verified.clone();
            async move {
                state.record("verify");
                Ok(true)
            }
        },
    )
    .anonymous(false)
    .ens_lookup(move |_| {
        let state = ens.clone();
        async move {
            state.record("ens");
            if state.mode == "ens-error" {
                Err(state.error("ens"))
            } else {
                Ok(EnsProfile::default())
            }
        }
    });
    let ctx =
        crate::plugins::test_helpers::initialize_test_context(config, store, &[&plugin]).await?;
    let mut req = request(&ctx, "1").await?;
    let mut body: Value = serde_json::from_slice(req.body.as_ref().unwrap())?;
    body["email"] = EMAIL.to_uppercase().into();
    req.body = Some(serde_json::to_vec(&body)?);
    let req = req.clone().with_original_request(req);
    let result = ctx
        .with_native_context(Default::default(), |context| async move {
            plugin.verify(&req, &context).await
        })
        .await;
    let expected_error = if mode == "retry-query-error" || mode == "initial-query-error" {
        Some("lookup")
    } else if mode.starts_with("create-error") {
        Some("create")
    } else if mode == "ens-error" {
        Some("ens")
    } else {
        None
    };
    let user_rows = raw.storage_rows(EntityRole::User)?;
    let sessions = raw.storage_rows(EntityRole::Session)?;
    let wallets = raw.storage_rows(EntityRole::WalletAddress)?;
    let accounts = raw.storage_rows(EntityRole::Account)?;
    if let Some(phase) = expected_error {
        let error = result
            .err()
            .ok_or_else(|| AuthError::internal("Expected original claim error"))?;
        assert!(
            error
                .raw_value()
                .is_some_and(|value| value.strict_equals(&state.errors[phase]))
        );
        assert_eq!(error.status_code()?, 409);
        assert!(sessions.is_empty());
        assert!(wallets.is_empty());
        assert!(accounts.is_empty());
        assert!(user_rows.is_empty());
    } else {
        let response = result?;
        assert_eq!(response.status, 200);
        assert_eq!(user_rows.len(), if mode == "retry-success" { 2 } else { 1 });
        assert_eq!(sessions.len(), 1);
        assert_eq!(wallets.len(), 1);
        assert_eq!(accounts.len(), 1);
        let user = user_rows.last().unwrap();
        let placeholder = format!("{ADDRESS}@siwe.placeholder.invalid");
        let expected_email = if matches!(mode, "reserve-before" | "reserve-after" | "retry-success")
        {
            placeholder.as_str()
        } else {
            EMAIL
        };
        assert_eq!(user["email"], FieldValue::from(expected_email));
        assert_eq!(user["name"], FieldValue::from(ADDRESS));
        assert_eq!(user["image"], FieldValue::from(""));
        assert_eq!(user["emailVerified"], FieldValue::Bool(false));
        assert_eq!(wallets[0]["userId"], user["id"]);
        assert_eq!(wallets[0]["address"], FieldValue::from(ADDRESS));
        assert_eq!(wallets[0]["chainId"], 1.into());
        assert_eq!(wallets[0]["isPrimary"], true.into());
        assert_eq!(accounts[0]["userId"], user["id"]);
        assert_eq!(accounts[0]["providerId"], FieldValue::from("siwe"));
        assert_eq!(accounts[0]["accountId"], format!("{ADDRESS}:1").into());
        assert_eq!(sessions[0]["userId"], user["id"]);
        assert_eq!(
            response.body.field_value()?.json()?,
            Some(json!({
                "token":sessions[0]["token"].json()?.unwrap(), "success":true,
                "user":{"id":user["id"].json()?.unwrap(), "walletAddress":ADDRESS, "chainId":1},
            }))
        );
        if mode == "retry-success" {
            assert_eq!(user_rows[0]["email"], FieldValue::from(EMAIL));
        }
    }
    assert_eq!(user_rows, *state.created_users.lock().unwrap());
    let expected_events = if mode == "initial-query-error" {
        vec!["nonce", "verify", "reserve", "lookup"]
    } else if mode == "ens-error" {
        vec!["nonce", "verify", "reserve", "lookup", "ens"]
    } else if matches!(mode, "reserve-before" | "reserve-after") {
        vec!["nonce", "verify", "reserve", "ens", "create"]
    } else if mode == "retry-success" {
        vec![
            "nonce", "verify", "reserve", "lookup", "ens", "create", "lookup", "create", "cleanup",
        ]
    } else if mode.starts_with("create-error") || mode == "retry-query-error" {
        vec![
            "nonce", "verify", "reserve", "lookup", "ens", "create", "lookup", "cleanup",
        ]
    } else {
        vec![
            "nonce", "verify", "reserve", "lookup", "ens", "create", "cleanup",
        ]
    };
    assert_eq!(*state.events.lock().unwrap(), expected_events, "{mode}");
    assert_eq!(state.logs.load(Ordering::SeqCst), 0, "{mode}");
    let claim_remains = matches!(mode, "reserve-after" | "initial-query-error" | "ens-error")
        || mode.ends_with("cleanup-before");
    let remaining = raw.storage_rows(EntityRole::Verification)?;
    assert_eq!(
        remaining,
        if claim_remains {
            state.claimed.lock().unwrap().clone()
        } else {
            Vec::new()
        }
    );
    if claim_remains {
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0]["identifier"], FieldValue::from(CLAIM));
        assert_eq!(remaining[0]["value"], FieldValue::from(ADDRESS));
    }
    Ok(())
}

#[tokio::test]
async fn email_claim_cleanup_preserves_source_catch_scope_and_original_failures() -> AuthResult<()>
{
    for mode in MODES {
        run_claim_case(mode).await?;
    }
    Ok(())
}

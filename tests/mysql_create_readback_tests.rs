#![cfg(feature = "seaorm2")]
#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::unreachable,
    reason = "The paired fixture must fail immediately on missing observations or poisoned capture state."
)]

#[path = "support/mysql_create_readback.rs"]
mod contract;
#[path = "support/mysql_create_lifecycle.rs"]
mod lifecycle;
#[path = "support/mysql_lifecycle_cache.rs"]
mod lifecycle_cache;
#[path = "support/mysql_lifecycle_hooks.rs"]
mod lifecycle_hooks;
#[path = "support/mysql_lifecycle_models.rs"]
mod lifecycle_models;
#[path = "support/mysql_readback_trace.rs"]
mod trace;
#[path = "support/device_where_values.rs"]
mod values;

macro_rules! jwk_case {
    ($test:ident, $case:literal) => {
        #[tokio::test]
        #[ignore = "Requires BETTER_AUTH_TEST_MYSQL_URL and permission to create isolated test databases"]
        async fn $test() -> contract::TestResult {
            contract::in_mysql_catalog(|database| contract::jwk(database, $case)).await
        }
    };
}

jwk_case!(live_mysql_jwk_explicit_id, "explicit-id");
jwk_case!(live_mysql_jwk_serial_id, "serial-id");
jwk_case!(
    live_mysql_jwk_database_default,
    "database-default-full-match"
);
jwk_case!(live_mysql_jwk_first_unique_hit, "mapped-unique-first-hit");
jwk_case!(
    live_mysql_jwk_second_unique_hit,
    "mapped-unique-first-miss-second-hit"
);
jwk_case!(
    live_mysql_jwk_null_unique_skipped,
    "mapped-unique-null-skipped"
);
jwk_case!(
    live_mysql_jwk_empty_unique_probed,
    "mapped-unique-empty-probed"
);
jwk_case!(
    live_mysql_jwk_duplicate_direct,
    "full-match-single-then-duplicate"
);
jwk_case!(
    live_mysql_jwk_duplicate_transaction,
    "full-match-transaction-single-then-duplicate"
);
jwk_case!(live_mysql_jwk_error_direct, "readback-error-direct");
jwk_case!(
    live_mysql_jwk_error_transaction,
    "readback-error-transaction"
);

macro_rules! lifecycle_case {
    ($test:ident, $case:literal) => {
        #[tokio::test]
        #[ignore = "Requires BETTER_AUTH_TEST_MYSQL_URL and permission to create isolated test databases"]
        async fn $test() -> contract::TestResult {
            contract::in_mysql_catalog(|database| lifecycle::check(database, $case)).await
        }
    };
}

lifecycle_case!(
    live_mysql_lifecycle_user_cancel,
    "user-before-cancel-transaction"
);
lifecycle_case!(
    live_mysql_lifecycle_user_null_direct,
    "user-written-null-direct"
);
lifecycle_case!(
    live_mysql_lifecycle_user_null_transaction,
    "user-written-null-transaction"
);
lifecycle_case!(
    live_mysql_lifecycle_user_after_error_direct,
    "user-after-null-error-direct"
);
lifecycle_case!(
    live_mysql_lifecycle_user_after_error_transaction,
    "user-after-null-error-transaction"
);
lifecycle_case!(
    live_mysql_lifecycle_user_rollback,
    "user-written-null-rollback"
);
lifecycle_case!(
    live_mysql_lifecycle_session_writer_immediate,
    "session-secondary-immediate"
);
lifecycle_case!(
    live_mysql_lifecycle_session_writer_deferred,
    "session-secondary-deferred"
);
lifecycle_case!(
    live_mysql_lifecycle_session_writer_cancel,
    "session-secondary-before-cancel"
);
lifecycle_case!(
    live_mysql_lifecycle_session_writer_after_error,
    "session-secondary-deferred-after-error"
);
lifecycle_case!(
    live_mysql_lifecycle_verification_writer_immediate,
    "verification-secondary-immediate"
);
lifecycle_case!(
    live_mysql_lifecycle_verification_writer_cancel,
    "verification-secondary-before-cancel"
);
lifecycle_case!(
    live_mysql_lifecycle_verification_writer_after_error,
    "verification-secondary-after-error"
);

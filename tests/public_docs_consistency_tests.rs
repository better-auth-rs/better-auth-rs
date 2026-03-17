#![allow(
    clippy::expect_used,
    reason = "doc consistency tests intentionally panic immediately when required repo files are missing"
)]

use std::fs;
use std::path::PathBuf;

fn repo_file(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn read_repo_file(path: &str) -> String {
    fs::read_to_string(repo_file(path)).expect("repo documentation file should be readable")
}

fn crate_minor_version() -> String {
    let version = env!("CARGO_PKG_VERSION");
    let mut parts = version.split('.');
    let major = parts.next().expect("major version should exist");
    let minor = parts.next().expect("minor version should exist");
    format!("{major}.{minor}")
}

// Rust-specific surface: public docs are part of the Rust crate interface and
// must stay aligned with the published crate version and canonical module paths.
#[test]
fn docs_use_current_minor_version_and_canonical_paths() {
    let expected_minor = crate_minor_version();

    let readme = read_repo_file("README.md");
    let installation = read_repo_file("docs/content/docs/installation.mdx");
    let quick_start = read_repo_file("docs/content/docs/quick-start.mdx");
    let axum = read_repo_file("docs/content/docs/integrations/axum.mdx");

    assert!(
        readme.contains(&format!("better-auth = \"{expected_minor}\"")),
        "README should use the current minor crate version",
    );
    assert!(
        installation.contains(&format!("better-auth = \"{expected_minor}\"")),
        "installation guide should use the current minor crate version",
    );
    assert!(
        axum.contains(&format!("better-auth = {{ version = \"{expected_minor}\"")),
        "axum guide should use the current minor crate version",
    );

    for text in [&readme, &quick_start, &axum] {
        assert!(!text.contains("better_auth::handlers"));
        assert!(!text.contains("better_auth::types"));
        assert!(text.contains("better_auth::store::Database"));
        assert!(!text.contains("better_auth::store::sea_orm::Database"));
    }
}

// Rust-specific surface: cookie names are user-visible and must stay aligned
// with the actual default session cookie emitted by the crate.
#[test]
fn docs_use_current_session_cookie_name() {
    let sessions = read_repo_file("docs/content/docs/authentication/sessions.mdx");
    let cookies = read_repo_file("docs/content/docs/concepts/cookies.mdx");
    let config = read_repo_file("docs/content/docs/reference/configuration-options.mdx");

    for text in [&sessions, &cookies, &config] {
        assert!(text.contains("better-auth.session_token"));
        assert!(!text.contains("better-auth.session-token"));
    }
}

// Rust-specific surface: the documented Axum integration should show the
// generic AppState + FromRef pattern that downstream apps are expected to use.
#[test]
fn axum_docs_show_generic_app_state_integration() {
    let axum = read_repo_file("docs/content/docs/integrations/axum.mdx");

    assert!(axum.contains("axum_router_with_state::<AppState>()"));
    assert!(axum.contains("impl FromRef<AppState> for Arc<BetterAuth>"));
    assert!(axum.contains("better_auth::integrations::axum"));
}

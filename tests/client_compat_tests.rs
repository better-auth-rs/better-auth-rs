#![expect(
    clippy::panic,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test harness code must fail on orchestration errors or invalid checked-in fixture fields"
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::Duration;

#[path = "support/compat_server.rs"]
mod compat_server;
use compat_server::ManagedChild;

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

async fn wait_for_health(child: &mut ManagedChild, timeout: Duration) -> u16 {
    compat_server::wait_for_health(child, timeout)
        .await
        .unwrap_or_else(|error| panic!("{error}"))
}

fn start_oidc_server() -> ManagedChild {
    let child = Command::new("bun")
        .args(["run", "oidc-server.ts"])
        .current_dir(project_root().join("compat-tests/reference-server"))
        .env("PORT", "0")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to start OIDC issuer: {error}"));
    ManagedChild::new("oidc-issuer", child)
}

fn start_reference_server(profile: &str, oidc_url: &str) -> ManagedChild {
    let child = proxy_environment(&mut Command::new("bun"), profile)
        .args(["run", "server.ts"])
        .current_dir(project_root().join("compat-tests/reference-server"))
        .env("PORT", "0")
        .env("COMPAT_PROFILE", profile)
        .env("COMPAT_OIDC_URL", oidc_url)
        .env("NO_PROXY", "localhost,127.0.0.1")
        .env("no_proxy", "localhost,127.0.0.1")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to start Bun reference server: {error}"));

    ManagedChild::new("ts-reference", child)
}

fn rust_compat_binary() -> &'static Path {
    static BINARY: OnceLock<PathBuf> = OnceLock::new();
    BINARY
        .get_or_init(|| {
            let manifest = "compat-tests/rust-server/Cargo.toml";
            let status = Command::new("cargo")
                .args(["build", "--locked", "--manifest-path", manifest])
                .current_dir(project_root())
                .status()
                .unwrap_or_else(|error| panic!("failed to build Rust compat server: {error}"));
            assert!(
                status.success(),
                "Rust compat server build failed: {status}"
            );
            let output = Command::new("cargo")
                .args([
                    "metadata",
                    "--locked",
                    "--no-deps",
                    "--format-version",
                    "1",
                    "--manifest-path",
                    manifest,
                ])
                .current_dir(project_root())
                .output()
                .unwrap_or_else(|error| panic!("failed to locate Rust compat binary: {error}"));
            assert!(
                output.status.success(),
                "cargo metadata failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let metadata: serde_json::Value = serde_json::from_slice(&output.stdout)
                .unwrap_or_else(|error| panic!("invalid cargo metadata: {error}"));
            let target = metadata
                .get("target_directory")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_else(|| panic!("cargo metadata omitted target_directory"));
            PathBuf::from(target).join("debug").join(format!(
                "compat-rust-server{}",
                std::env::consts::EXE_SUFFIX
            ))
        })
        .as_path()
}

fn start_rust_compat_server(binary: &Path, profile: &str, oidc_url: &str) -> ManagedChild {
    let child = proxy_environment(&mut Command::new(binary), profile)
        .current_dir(project_root())
        .env("PORT", "0")
        .env("COMPAT_PROFILE", profile)
        .env("COMPAT_OIDC_URL", oidc_url)
        .env("NO_PROXY", "localhost,127.0.0.1")
        .env("no_proxy", "localhost,127.0.0.1")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to start Rust compat server: {error}"));

    ManagedChild::new("rust-compat", child)
}

fn proxy_case(profile: &str) -> Option<serde_json::Value> {
    let index = profile.strip_prefix("oauth-proxy-env:")?;
    let cases: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../compat-tests/client-tests/tests/config/oauth-proxy-env/cases.json"
    ))
    .expect("proxy environment cases");
    Some(
        cases
            .get(index.parse::<usize>().expect("case index"))
            .expect("environment case")
            .clone(),
    )
}

fn dynamic_environment_case(profile: &str) -> Option<serde_json::Value> {
    let index = profile
        .strip_prefix("dynamic-environment:")?
        .parse::<usize>()
        .expect("dynamic environment index");
    let cases: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../compat-tests/client-tests/tests/config/dynamic-environment/cases.json"
    ))
    .expect("dynamic environment cases");
    Some(cases.get(index).expect("dynamic environment case").clone())
}

fn proxy_environment<'a>(command: &'a mut Command, profile: &str) -> &'a mut Command {
    if matches!(profile, "api-error" | "api-error-production") {
        let _ = command.env(
            "NODE_ENV",
            if profile == "api-error-production" {
                "production"
            } else {
                "development"
            },
        );
    }
    for key in [
        "VERCEL_URL",
        "NETLIFY_URL",
        "RENDER_URL",
        "AWS_LAMBDA_FUNCTION_NAME",
        "GOOGLE_CLOUD_FUNCTION_NAME",
        "AZURE_FUNCTION_NAME",
        "BETTER_AUTH_URL",
        "COMPAT_PROXY_OPTIONS",
    ] {
        let _ = command.env_remove(key);
    }
    if let Some(case) = proxy_case(profile) {
        let _ = command.env("COMPAT_PROXY_CASE", case.to_string());
        for (key, value) in case["env"].as_object().expect("case environment") {
            let _ = command.env(key, value.as_str().expect("environment string"));
        }
        let _ = command.env("COMPAT_PROXY_OPTIONS", case["options"].to_string());
    }
    if let Some(case) = dynamic_environment_case(profile) {
        for key in [
            "BETTER_AUTH_URL",
            "NEXT_PUBLIC_BETTER_AUTH_URL",
            "PUBLIC_BETTER_AUTH_URL",
            "NUXT_PUBLIC_BETTER_AUTH_URL",
            "NUXT_PUBLIC_AUTH_URL",
            "BASE_URL",
            "BETTER_AUTH_TRUSTED_ORIGINS",
            "NODE_ENV",
        ] {
            let _ = command.env_remove(key);
        }
        for (key, value) in case["env"].as_object().expect("dynamic environment") {
            let _ = command.env(key, value.as_str().expect("environment value"));
        }
    }
    command
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "Only completed suite failures are collected; Bun process I/O failures must abort the harness"
)]
fn run_bun_phase_suite(
    paths: &[&str],
    ts_port: u16,
    rust_port: u16,
    profile: &str,
    oidc_url: &str,
) -> Result<(), String> {
    let output = Command::new("bun")
        .arg("test")
        // A timed-out scenario can still write to the shared fixture database.
        .arg("--bail")
        .args(paths.iter().map(|path| Path::new(".").join(path)))
        .env("COMPAT_PROFILE", profile)
        .env(
            "COMPAT_DYNAMIC_CASE",
            dynamic_environment_case(profile)
                .map(|case| case.to_string())
                .unwrap_or_default(),
        )
        .current_dir(project_root().join("compat-tests/client-tests"))
        .env("AUTH_BASE_URL_TS", format!("http://localhost:{ts_port}"))
        .env("COMPAT_OIDC_URL", oidc_url)
        .env(
            "AUTH_BASE_URL_RUST",
            format!("http://localhost:{rust_port}"),
        )
        .env("NO_PROXY", "localhost,127.0.0.1")
        .env("no_proxy", "localhost,127.0.0.1")
        .env(
            "COMPAT_PROXY_CASE",
            proxy_case(profile)
                .map(|case| case.to_string())
                .unwrap_or_default(),
        )
        .output()
        .unwrap_or_else(|error| panic!("failed to run Bun phase suite: {error}"));

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "Bun phase suite failed ({status}).\nstdout:\n{stdout}\n\nstderr:\n{stderr}",
            status = output.status,
        ));
    }
    Ok(())
}

async fn run_client_compat(paths: &[&str]) {
    run_client_compat_profile(paths, "default")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
}

async fn run_client_compat_profile(paths: &[&str], profile: &str) -> Result<(), String> {
    println!("Client compatibility profile: {profile}");
    let binary = rust_compat_binary();
    let mut oidc_server = start_oidc_server();
    let oidc_port = wait_for_health(&mut oidc_server, Duration::from_secs(20)).await;
    let oidc_url = format!("http://127.0.0.1:{oidc_port}");
    let mut ts_server = start_reference_server(profile, &oidc_url);
    let ts_port = wait_for_health(&mut ts_server, Duration::from_secs(20)).await;
    let mut rust_server = start_rust_compat_server(binary, profile, &oidc_url);
    let rust_port = wait_for_health(&mut rust_server, Duration::from_secs(90)).await;

    run_bun_phase_suite(paths, ts_port, rust_port, profile, &oidc_url)
}

async fn collect_client_compat_profile(
    paths: &[&str],
    profile: &str,
    failures: &mut Vec<(String, String)>,
) {
    if let Err(error) = run_client_compat_profile(paths, profile).await {
        eprintln!("Client compatibility profile failed: {profile}\n{error}");
        failures.push((profile.to_owned(), error));
    }
}

fn selected_configuration_profiles<'a>(
    profiles: &[&'a str],
    selected: Option<&str>,
) -> Result<Vec<&'a str>, String> {
    let Some(selected) = selected else {
        return Ok(profiles.to_vec());
    };
    let requested: Vec<_> = selected.split(',').map(str::trim).collect();
    let unknown: Vec<_> = requested
        .iter()
        .copied()
        .filter(|profile| !profiles.contains(profile))
        .collect();
    if !unknown.is_empty() {
        return Err(format!("Unknown configuration profiles: {unknown:?}"));
    }
    Ok(profiles
        .iter()
        .copied()
        .filter(|profile| requested.contains(profile))
        .collect())
}

#[tokio::test]
#[ignore = "starts isolated profiles with intentional Bun failures to verify failure aggregation"]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The Result propagates fixture I/O errors; assertions verify failure aggregation"
)]
async fn configuration_failure_aggregation() -> Result<(), Box<dyn std::error::Error>> {
    let profiles = [
        "api-error",
        "api-error-production",
        "request-query-memory",
        "unselected",
    ];
    assert_eq!(selected_configuration_profiles(&profiles, None)?, profiles);
    for invalid in ["api-error,missing", "", "api-error,"] {
        assert!(selected_configuration_profiles(&profiles, Some(invalid)).is_err());
    }
    let selected = selected_configuration_profiles(
        &profiles,
        Some("request-query-memory, api-error, api-error-production,api-error"),
    )?;
    assert_eq!(
        selected,
        ["api-error", "api-error-production", "request-query-memory"]
    );
    let directory = std::env::temp_dir().join(format!(
        "better-auth-compat-aggregation-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos(),
    ));
    std::fs::create_dir(&directory)?;
    let failure = directory.join("failure.test.ts");
    let success = directory.join("success.test.ts");
    let marker = directory.join("completed-profile");
    std::fs::write(
        &failure,
        r#"import { test } from "bun:test";
test("intentional harness failure", () => {
  process.stdout.write(`harness stdout ${process.env.COMPAT_PROFILE}\n`);
  process.stderr.write(`harness stderr ${process.env.COMPAT_PROFILE}\n`);
  throw new Error(`intentional harness failure ${process.env.COMPAT_PROFILE}`);
});
"#,
    )?;
    std::fs::write(
        &success,
        format!(
            r#"import {{ expect, test }} from "bun:test";
import {{ writeFileSync }} from "node:fs";
test("profile after failure executes", async () => {{
  for (const key of ["AUTH_BASE_URL_TS", "AUTH_BASE_URL_RUST"]) {{
    expect((await fetch(`${{process.env[key]}}/__health`)).status).toBe(200);
  }}
  writeFileSync({}, process.env.COMPAT_PROFILE);
}});
"#,
            serde_json::to_string(&marker)?,
        ),
    )?;
    let failure = failure.to_str().expect("temporary fixture path is UTF-8");
    let success = success.to_str().expect("temporary fixture path is UTF-8");
    let mut failures = Vec::new();
    for profile in selected {
        let path = if profile == "api-error-production" {
            success
        } else {
            failure
        };
        collect_client_compat_profile(&[path], profile, &mut failures).await;
    }
    let completed = std::fs::read_to_string(marker)?;
    assert_eq!(completed, "api-error-production");
    assert_eq!(
        failures
            .iter()
            .map(|(profile, _)| profile.as_str())
            .collect::<Vec<_>>(),
        ["api-error", "request-query-memory"],
    );
    for (profile, output) in failures {
        assert!(output.contains(&format!("harness stdout {profile}")));
        assert!(output.contains(&format!("harness stderr {profile}")));
        assert!(output.contains(&format!("intentional harness failure {profile}")));
    }
    std::fs::remove_dir_all(directory)?;
    Ok(())
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn parallel_server_startup() {
    let binary = rust_compat_binary();
    let mut first_oidc = start_oidc_server();
    let mut second_oidc = start_oidc_server();
    let (first_port, second_port) = tokio::join!(
        wait_for_health(&mut first_oidc, Duration::from_secs(20)),
        wait_for_health(&mut second_oidc, Duration::from_secs(20)),
    );
    let first_url = format!("http://127.0.0.1:{first_port}");
    let second_url = format!("http://127.0.0.1:{second_port}");
    let mut first_ts = start_reference_server("default", &first_url);
    let mut second_ts = start_reference_server("default", &second_url);
    let mut first_rust = start_rust_compat_server(binary, "default", &first_url);
    let mut second_rust = start_rust_compat_server(binary, "default", &second_url);
    let (first_ts_port, second_ts_port, first_rust_port, second_rust_port) = tokio::join!(
        wait_for_health(&mut first_ts, Duration::from_secs(20)),
        wait_for_health(&mut second_ts, Duration::from_secs(20)),
        wait_for_health(&mut first_rust, Duration::from_secs(90)),
        wait_for_health(&mut second_rust, Duration::from_secs(90)),
    );
    let ports = [
        first_port,
        second_port,
        first_ts_port,
        second_ts_port,
        first_rust_port,
        second_rust_port,
    ];
    assert_eq!(
        ports
            .into_iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        ports.len()
    );
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("HTTP client");
    for base in [first_url, second_url] {
        let discovery: serde_json::Value = client
            .get(format!("{base}/discovery/standard"))
            .send()
            .await
            .expect("OIDC discovery")
            .error_for_status()
            .expect("discovery status")
            .json()
            .await
            .expect("discovery document");
        assert_eq!(discovery["issuer"], base);
        assert_eq!(discovery["token_endpoint"], format!("{base}/token"));
    }
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn phase0_client_compat() {
    run_client_compat(&["tests/phase0"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn phase1_client_compat() {
    run_client_compat(&["tests/phase1"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn phase2_client_compat() {
    run_client_compat(&["tests/phase2"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn phase3_client_compat() {
    run_client_compat(&["tests/phase3"]).await;
}

#[tokio::test]
#[ignore = "starts external OIDC, TS and Rust servers"]
async fn oidc_client_compat() {
    run_client_compat(&[
        "tests/phase3/oidc.test.ts",
        "tests/phase3/oidc-boundaries.test.ts",
    ])
    .await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn phase4_client_compat() {
    run_client_compat(&["tests/phase4"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn phase5_client_compat() {
    run_client_compat(&["tests/phase5"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn phase6_client_compat() {
    run_client_compat(&["tests/phase6"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn phase7_client_compat() {
    run_client_compat(&["tests/phase7"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn phase8_client_compat() {
    run_client_compat(&["tests/phase8"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn phase9_client_compat() {
    run_client_compat(&["tests/phase9"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn phase10_client_compat() {
    run_client_compat(&["tests/phase10"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn phase11_client_compat() {
    run_client_compat(&["tests/phase11"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn phase12_client_compat() {
    run_client_compat(&["tests/phase12"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn full_client_compat() {
    run_client_compat(&[
        "tests/phase0",
        "tests/phase1",
        "tests/phase2",
        "tests/phase3",
        "tests/phase4",
        "tests/phase5",
        "tests/phase6",
        "tests/phase7",
        "tests/phase8",
        "tests/phase9",
        "tests/phase10",
        "tests/phase11",
        "tests/phase12",
    ])
    .await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers for each configuration"]
async fn configuration_client_compat() {
    let selected = std::env::var("COMPAT_TEST_PROFILE").ok();
    let mut failures = Vec::new();
    let profiles = [
        "api-error",
        "api-error-production",
        "request-security-memory",
        "request-security-sqlite",
        "native-dispatch",
        "two-factor-after-memory",
        "two-factor-after-sqlite",
        "phone-native-memory",
        "phone-native-sqlite",
        "phone-native-custom",
        "request-otp-memory",
        "request-otp-sqlite",
        "request-oauth-memory",
        "request-oauth-sqlite",
        "request-two-factor-memory",
        "request-two-factor-sqlite",
        "request-two-factor-passwordless-memory",
        "request-two-factor-nested-sqlite",
        "request-admin-memory",
        "request-api-key-memory",
        "request-api-key-sqlite",
        "request-admin-sqlite",
        "request-organization-memory",
        "request-organization-sqlite",
        "request-query-memory",
        "request-query-sqlite",
        "request-record-memory",
        "request-record-sqlite",
        "request-plugin-memory",
        "request-plugin-sqlite",
        "request-change-email",
        "request-change-email-no-sender",
        "request-change-email-no-confirmation",
        "request-change-email-disabled",
        "trailing-slashes-default",
        "trailing-slashes-true",
        "trailing-slashes-false",
        "organization-callbacks",
        "organization-custom-team",
        "organization-extended",
        "organization-cache",
        "organization-jwt",
        "organization-limits",
        "organization-no-ac",
        "organization-fields",
        "organization-core-fields",
        "organization-dynamic-fields",
        "organization-member-fields",
        "organization-invitation-teams",
        "organization-native-json",
        "organization-native-json-object",
        "verification-identifiers",
        "organization-invitation-options",
        "organization-invitation-unverified",
        "api-key-zero",
        "api-key-storage",
        "secondary-session-only",
        "session-fields",
        "session-fields-cache",
        "session-fields-database",
        "cookie-version-compact",
        "cookie-version-jwt",
        "cookie-version-jwe",
        "cookie-version-plugin-jwt",
        "jwt-claims",
        "jwt-date",
        "jwt-relative",
        "password-policy",
        "password-scrypt",
        "password-security",
        "password-security-after",
        "password-security-disabled",
        "password-security-empty",
        "password-security-custom",
        "auth-lifecycle",
        "auth-lifecycle-confirmation",
        "auth-lifecycle-zero",
        "crypto-database",
        "crypto-cookie",
        "oauth-link-id-token",
        "oauth-link-id-token-disabled",
        "oauth-popup-database",
        "oauth-popup-cookie",
        "admin-default-options",
        "admin-empty-roles",
        "admin-options",
        "stateless-default",
        "stateless-explicit",
        "stateless-refresh",
        "stateless-no-refresh",
        "stateless-secondary",
        "dispatch-errors",
        "dynamic-context",
        "dynamic-native",
        "organization-metadata",
        "id-policy",
        "dynamic-oauth",
        "dynamic-environment",
        "identity-context",
        "rate-limit-options",
        "last-login-cookie",
        "last-login-database",
        "last-login-secondary",
        "last-login-ephemeral",
        "last-login-fields",
        "username-order-default",
        "username-order-pre",
        "username-order-post",
        "username-normalization-disabled",
        "username-no-display",
        "username-immutable-validation",
        "username-writes",
        "device-generators",
        "http-body",
        "http-body-csrf-explicit",
        "http-body-csrf-legacy",
        "user-admission",
        "user-admission-protected",
        "captcha-turnstile",
        "captcha-recaptcha",
        "captcha-hcaptcha",
        "captcha-captchafox",
        "captcha-botid",
        "captcha-botid-default",
        "captcha-paths",
        "captcha-empty-secret",
        "captcha-rate-limit",
        "signup-enumeration",
        "signup-verification",
        "signup-synthetic",
        "organization-empty-roles",
        "custom-session",
        "custom-session-list",
        "custom-session-deferred",
        "otp-callbacks",
        "otp-callbacks-override",
        "passkey-options",
        "passkey-first",
        "passkey-no-resolver",
        "passkey-stale",
        "native-passkey",
        "native-two-factor",
        "two-factor-options",
        "two-factor-context",
        "two-factor-plain",
        "two-factor-hashed",
        "two-factor-encrypted",
        "two-factor-custom",
        "two-factor-custom-encrypted",
        "two-factor-disabled",
        "two-factor-password-policy",
        "secondary-session-database",
        "secondary-session-preserved",
        "secondary-verification-only",
        "secondary-verification-database",
        "api-key-callbacks",
        "plugin-schema",
        "device-custom",
        "device-collision",
        "device-rate-limit",
        "device-rate-window",
        "device-bearer",
        "email-otp",
        "email-otp-native",
        "email-otp-native-hash",
        "email-otp-native-encrypted",
        "email-otp-native-custom-hash",
        "email-otp-native-custom-encrypted",
        "email-otp-transaction",
        "email-otp-options",
        "email-otp-reuse",
        "magic-link",
        "magic-link-disabled",
        "one-time-token",
        "one-time-token-options",
        "multi-session",
        "multi-session-limit",
        "anonymous",
        "anonymous-disabled",
        "phone-number",
        "phone-number-options",
        "siwe",
        "siwe-email",
        "one-tap",
        "one-tap-options",
        "oauth-proxy",
        "oauth-proxy-cookie",
        "oauth-proxy-anonymous",
        "oauth-proxy-env",
        "jwt",
        "jwt-rs256",
        "jwt-es256",
        "jwt-identity",
        "user-fields",
        "jwt-ps256",
        "jwt-es512",
        "jwt-advanced",
        "jwt-remote",
        "jwt-cache",
        "jwt-adapter",
        "openapi",
        "account-verification-fields",
        "database-lifecycle",
        "database-lifecycle-cache",
        "database-lifecycle-database",
        "database-lifecycle-preserved",
    ];
    let selected = selected_configuration_profiles(&profiles, selected.as_deref())
        .unwrap_or_else(|error| panic!("{error}"));
    for profile in selected {
        if profile.starts_with("two-factor-after-") {
            collect_client_compat_profile(
                &["./tests/config/two-factor-after/"],
                profile,
                &mut failures,
            )
            .await;
        } else if profile.starts_with("phone-native-") {
            collect_client_compat_profile(
                &["./tests/config/phone-native/"],
                profile,
                &mut failures,
            )
            .await;
        } else if profile == "dynamic-environment" {
            let cases: Vec<serde_json::Value> = serde_json::from_str(include_str!(
                "../compat-tests/client-tests/tests/config/dynamic-environment/cases.json"
            ))
            .expect("dynamic environment cases");
            for index in 0..cases.len() {
                collect_client_compat_profile(
                    &["./tests/config/dynamic-environment/"],
                    &format!("{profile}:{index}"),
                    &mut failures,
                )
                .await;
            }
        } else if profile == "oauth-proxy-env" {
            let cases: Vec<serde_json::Value> = serde_json::from_str(include_str!(
                "../compat-tests/client-tests/tests/config/oauth-proxy-env/cases.json"
            ))
            .expect("proxy environment cases");
            for (index, case) in cases.iter().enumerate() {
                println!("OAuth proxy environment: {}", case["name"]);
                collect_client_compat_profile(
                    &["./tests/config/oauth-proxy-env/"],
                    &format!("{profile}:{index}"),
                    &mut failures,
                )
                .await;
            }
        } else if profile.starts_with("password-security") {
            collect_client_compat_profile(
                &["./tests/config/password-security/"],
                profile,
                &mut failures,
            )
            .await;
        } else if profile.starts_with("http-body") {
            collect_client_compat_profile(&["./tests/config/http-body/"], profile, &mut failures)
                .await;
        } else if profile.starts_with("oauth-popup-") {
            collect_client_compat_profile(&["./tests/config/oauth-popup/"], profile, &mut failures)
                .await;
        } else if profile.starts_with("admin-") {
            collect_client_compat_profile(
                &["./tests/config/admin-options/"],
                profile,
                &mut failures,
            )
            .await;
        } else if profile.starts_with("last-login-") {
            collect_client_compat_profile(&["./tests/config/last-login/"], profile, &mut failures)
                .await;
        } else if matches!(profile, "api-error" | "api-error-production") {
            collect_client_compat_profile(&["./tests/config/api-error/"], profile, &mut failures)
                .await;
        } else if profile.starts_with("request-security-") {
            collect_client_compat_profile(
                &["./tests/config/request-security/"],
                profile,
                &mut failures,
            )
            .await;
        } else if profile.starts_with("request-api-key-") {
            collect_client_compat_profile(
                &["./tests/config/request-api-key/"],
                profile,
                &mut failures,
            )
            .await;
        } else if profile == "native-dispatch" {
            collect_client_compat_profile(
                &["./tests/config/native-dispatch/"],
                profile,
                &mut failures,
            )
            .await;
        } else if profile == "native-passkey" {
            collect_client_compat_profile(
                &["./tests/phase8/passkey.test.ts"],
                profile,
                &mut failures,
            )
            .await;
        } else if profile == "native-two-factor" {
            collect_client_compat_profile(
                &["./tests/phase11", "./tests/phase12"],
                profile,
                &mut failures,
            )
            .await;
        } else if profile.starts_with("request-otp-") {
            collect_client_compat_profile(&["./tests/config/request-otp/"], profile, &mut failures)
                .await;
        } else if profile.starts_with("request-oauth-") {
            collect_client_compat_profile(
                &["./tests/config/request-oauth/"],
                profile,
                &mut failures,
            )
            .await;
        } else if profile.starts_with("request-two-factor-") {
            collect_client_compat_profile(
                &["./tests/config/request-two-factor/"],
                profile,
                &mut failures,
            )
            .await;
        } else if profile.starts_with("request-admin-") {
            collect_client_compat_profile(
                &["./tests/config/request-admin/"],
                profile,
                &mut failures,
            )
            .await;
        } else if profile.starts_with("request-organization-") {
            collect_client_compat_profile(
                &["./tests/config/request-organization/"],
                profile,
                &mut failures,
            )
            .await;
        } else if profile.starts_with("request-plugin-") {
            collect_client_compat_profile(
                &["./tests/config/request-plugin/"],
                profile,
                &mut failures,
            )
            .await;
        } else if profile.starts_with("request-change-email") {
            collect_client_compat_profile(
                &["./tests/config/change-email/"],
                profile,
                &mut failures,
            )
            .await;
        } else if profile.starts_with("request-query-") {
            collect_client_compat_profile(
                &["./tests/config/request-query/"],
                profile,
                &mut failures,
            )
            .await;
        } else if profile.starts_with("request-record-") {
            collect_client_compat_profile(
                &["./tests/config/request-record/"],
                profile,
                &mut failures,
            )
            .await;
        } else if profile.starts_with("trailing-slashes-") {
            collect_client_compat_profile(
                &["./tests/config/trailing-slashes/"],
                profile,
                &mut failures,
            )
            .await;
        } else if profile.starts_with("username-") {
            collect_client_compat_profile(
                &["./tests/config/username-options/"],
                profile,
                &mut failures,
            )
            .await;
        } else if profile.starts_with("stateless-") {
            collect_client_compat_profile(&["./tests/config/stateless/"], profile, &mut failures)
                .await;
        } else if profile.starts_with("custom-session") {
            collect_client_compat_profile(
                &["./tests/config/custom-session/"],
                profile,
                &mut failures,
            )
            .await;
        } else if profile.starts_with("two-factor-") && profile != "two-factor-context" {
            collect_client_compat_profile(
                &["./tests/config/two-factor-options/"],
                profile,
                &mut failures,
            )
            .await;
        } else {
            collect_client_compat_profile(
                &[&format!("./tests/config/{profile}/")],
                profile,
                &mut failures,
            )
            .await;
        }
    }
    assert!(
        failures.is_empty(),
        "Client compatibility profiles failed: {}",
        failures
            .iter()
            .map(|(profile, _)| profile.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
}

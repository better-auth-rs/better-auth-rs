#![expect(
    clippy::panic,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test harness code must fail on orchestration errors or invalid checked-in fixture fields"
)]

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::OnceLock;
use std::time::Duration;

struct ManagedChild {
    label: &'static str,
    child: Child,
}

impl ManagedChild {
    fn new(label: &'static str, child: Child) -> Self {
        Self { label, child }
    }

    fn try_wait(&mut self) -> Option<ExitStatus> {
        self.child
            .try_wait()
            .unwrap_or_else(|error| panic!("failed to inspect {} process: {error}", self.label))
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn allocate_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|error| panic!("failed to allocate local port: {error}"))
        .local_addr()
        .unwrap_or_else(|error| panic!("failed to read allocated port: {error}"))
        .port()
}

async fn wait_for_health(port: u16, child: &mut ManagedChild, timeout: Duration) {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap_or_else(|error| panic!("failed to build reqwest client: {error}"));

    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if let Some(status) = child.try_wait() {
            panic!("{} exited before becoming healthy: {}", child.label, status);
        }

        if client
            .get(format!("http://127.0.0.1:{port}/__health"))
            .send()
            .await
            .map(|response| response.status().is_success())
            .unwrap_or(false)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    panic!(
        "{} server did not become healthy on port {} within {:?}",
        child.label, port, timeout
    );
}

fn start_oidc_server(port: u16) -> ManagedChild {
    let child = Command::new("bun")
        .args(["run", "oidc-server.ts"])
        .current_dir(project_root().join("compat-tests/reference-server"))
        .env("PORT", port.to_string())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to start OIDC issuer: {error}"));
    ManagedChild::new("oidc-issuer", child)
}

fn start_reference_server(port: u16, profile: &str, oidc_url: &str) -> ManagedChild {
    let child = proxy_environment(&mut Command::new("bun"), profile, port)
        .args(["run", "server.ts"])
        .current_dir(project_root().join("compat-tests/reference-server"))
        .env("PORT", port.to_string())
        .env("COMPAT_PROFILE", profile)
        .env("COMPAT_OIDC_URL", oidc_url)
        .env("NO_PROXY", "localhost,127.0.0.1")
        .env("no_proxy", "localhost,127.0.0.1")
        .stdout(Stdio::inherit())
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

fn start_rust_compat_server(
    binary: &Path,
    port: u16,
    profile: &str,
    oidc_url: &str,
) -> ManagedChild {
    let child = proxy_environment(&mut Command::new(binary), profile, port)
        .current_dir(project_root())
        .env("PORT", port.to_string())
        .env("COMPAT_PROFILE", profile)
        .env("COMPAT_OIDC_URL", oidc_url)
        .env("NO_PROXY", "localhost,127.0.0.1")
        .env("no_proxy", "localhost,127.0.0.1")
        .stdout(Stdio::inherit())
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

fn proxy_environment<'a>(command: &'a mut Command, profile: &str, port: u16) -> &'a mut Command {
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
            let _ = command.env(
                key,
                value
                    .as_str()
                    .expect("environment string")
                    .replace("{base}", &format!("http://localhost:{port}")),
            );
        }
        let _ = command.env(
            "COMPAT_PROXY_OPTIONS",
            case["options"]
                .to_string()
                .replace("{base}", &format!("http://localhost:{port}")),
        );
    }
    command
}

fn run_bun_phase_suite(
    paths: &[&str],
    ts_port: u16,
    rust_port: u16,
    profile: &str,
    oidc_url: &str,
) {
    let output = Command::new("bun")
        .arg("test")
        .args(paths)
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
        panic!("Bun phase suite failed.\nstdout:\n{stdout}\n\nstderr:\n{stderr}");
    }
}

async fn run_client_compat(paths: &[&str]) {
    run_client_compat_profile(paths, "default").await;
}

async fn run_client_compat_profile(paths: &[&str], profile: &str) {
    let binary = rust_compat_binary();
    let oidc_port = allocate_port();
    let oidc_url = format!("http://127.0.0.1:{oidc_port}");

    let mut oidc_server = start_oidc_server(oidc_port);
    wait_for_health(oidc_port, &mut oidc_server, Duration::from_secs(20)).await;
    let ts_port = allocate_port();
    let mut ts_server = start_reference_server(ts_port, profile, &oidc_url);
    wait_for_health(ts_port, &mut ts_server, Duration::from_secs(20)).await;
    let rust_port = allocate_port();
    let mut rust_server = start_rust_compat_server(binary, rust_port, profile, &oidc_url);
    wait_for_health(rust_port, &mut rust_server, Duration::from_secs(90)).await;

    run_bun_phase_suite(paths, ts_port, rust_port, profile, &oidc_url);
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
    for profile in [
        "organization-callbacks",
        "organization-custom-team",
        "organization-extended",
        "organization-cache",
        "organization-jwt",
        "organization-limits",
        "organization-no-ac",
        "organization-fields",
        "organization-core-fields",
        "organization-invitation-options",
        "organization-invitation-unverified",
        "api-key-zero",
        "device-custom",
        "device-collision",
        "device-rate-limit",
        "device-rate-window",
        "device-bearer",
        "email-otp",
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
    ] {
        if std::env::var("COMPAT_TEST_PROFILE").is_ok_and(|selected| selected != profile) {
            continue;
        }
        if profile == "oauth-proxy-env" {
            let cases: Vec<serde_json::Value> = serde_json::from_str(include_str!(
                "../compat-tests/client-tests/tests/config/oauth-proxy-env/cases.json"
            ))
            .expect("proxy environment cases");
            for (index, case) in cases.iter().enumerate() {
                println!("OAuth proxy environment: {}", case["name"]);
                run_client_compat_profile(
                    &["./tests/config/oauth-proxy-env/"],
                    &format!("{profile}:{index}"),
                )
                .await;
            }
        } else {
            run_client_compat_profile(&[&format!("./tests/config/{profile}/")], profile).await;
        }
    }
}

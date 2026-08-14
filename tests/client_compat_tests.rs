#![expect(
    clippy::panic,
    reason = "test harness code should panic on orchestration failures"
)]

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
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

fn start_reference_server(port: u16) -> ManagedChild {
    let child = Command::new("bun")
        .args(["run", "server.ts"])
        .current_dir(project_root().join("compat-tests/reference-server"))
        .env("PORT", port.to_string())
        .env("NO_PROXY", "localhost,127.0.0.1")
        .env("no_proxy", "localhost,127.0.0.1")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to start Bun reference server: {error}"));

    ManagedChild::new("ts-reference", child)
}

fn start_rust_compat_server(port: u16) -> ManagedChild {
    let child = Command::new("cargo")
        .args([
            "run",
            "--manifest-path",
            "compat-tests/rust-server/Cargo.toml",
        ])
        .current_dir(project_root())
        .env("PORT", port.to_string())
        .env("NO_PROXY", "localhost,127.0.0.1")
        .env("no_proxy", "localhost,127.0.0.1")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to start Rust compat server: {error}"));

    ManagedChild::new("rust-compat", child)
}

fn run_bun_phase_suite(paths: &[&str], ts_port: u16, rust_port: u16) {
    let output = Command::new("bun")
        .arg("test")
        .args(paths)
        .current_dir(project_root().join("compat-tests/client-tests"))
        .env("AUTH_BASE_URL_TS", format!("http://localhost:{ts_port}"))
        .env(
            "AUTH_BASE_URL_RUST",
            format!("http://localhost:{rust_port}"),
        )
        .env("NO_PROXY", "localhost,127.0.0.1")
        .env("no_proxy", "localhost,127.0.0.1")
        .output()
        .unwrap_or_else(|error| panic!("failed to run Bun phase suite: {error}"));

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("Bun phase suite failed.\nstdout:\n{stdout}\n\nstderr:\n{stderr}");
    }
}

async fn run_client_compat(paths: &[&str]) {
    let ts_port = allocate_port();
    let rust_port = allocate_port();

    let mut ts_server = start_reference_server(ts_port);
    let mut rust_server = start_rust_compat_server(rust_port);

    wait_for_health(ts_port, &mut ts_server, Duration::from_secs(20)).await;
    wait_for_health(rust_port, &mut rust_server, Duration::from_secs(90)).await;

    run_bun_phase_suite(paths, ts_port, rust_port);
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

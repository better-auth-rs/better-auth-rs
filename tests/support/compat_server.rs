use std::io::{BufRead, BufReader};
use std::process::{Child, ExitStatus};
use std::time::Duration;

pub(crate) struct ManagedChild {
    label: &'static str,
    child: Child,
    port: tokio::sync::oneshot::Receiver<Result<u16, String>>,
    started_at: tokio::time::Instant,
    output: Option<std::thread::JoinHandle<()>>,
}

impl ManagedChild {
    pub(crate) fn new(label: &'static str, mut child: Child) -> Self {
        let stdout = child.stdout.take().expect("server stdout is piped");
        let (sender, port) = tokio::sync::oneshot::channel();
        let output = std::thread::spawn(move || {
            let mut sender = Some(sender);
            for line in BufReader::new(stdout).lines() {
                let line = match line {
                    Ok(line) => line,
                    Err(error) => {
                        if let Some(sender) = sender.take() {
                            let _ =
                                sender.send(Err(format!("failed to read {label} stdout: {error}")));
                        }
                        break;
                    }
                };
                println!("{line}");
                if let Some(value) = line.strip_prefix("COMPAT_SERVER_PORT=")
                    && let Some(sender) = sender.take()
                {
                    let _ =
                        sender.send(value.parse::<u16>().map_err(|error| {
                            format!("invalid {label} bound port {value:?}: {error}")
                        }));
                }
            }
        });
        Self {
            label,
            child,
            port,
            started_at: tokio::time::Instant::now(),
            output: Some(output),
        }
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
        if let Some(output) = self.output.take() {
            let _ = output.join();
        }
    }
}

pub(crate) async fn wait_for_health(
    child: &mut ManagedChild,
    timeout: Duration,
) -> Result<u16, String> {
    let deadline = child.started_at + timeout;
    let port = tokio::time::timeout_at(deadline, &mut child.port)
        .await
        .map_err(|_| {
            format!(
                "{} did not report its bound port within {timeout:?}",
                child.label
            )
        })?
        .map_err(|_| {
            format!(
                "{} closed stdout before reporting its bound port",
                child.label
            )
        })??;
    if port == 0 {
        return Err(format!("{} reported an unassigned port", child.label));
    }
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|error| format!("failed to build reqwest client: {error}"))?;

    while tokio::time::Instant::now() < deadline {
        if let Some(status) = child.try_wait() {
            return Err(format!(
                "{} exited before becoming healthy: {}",
                child.label, status
            ));
        }

        if client
            .get(format!("http://127.0.0.1:{port}/__health"))
            .send()
            .await
            .map(|response| response.status().is_success())
            .unwrap_or(false)
        {
            return Ok(port);
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    Err(format!(
        "{} server did not become healthy on port {} within {:?}",
        child.label, port, timeout
    ))
}

use better_auth_core::AuthConfig;
use serde_json::{Value, json};

pub(super) fn init_payload(
    config: &AuthConfig,
    plugins: &[&str],
    before: bool,
    after: bool,
    secondary: bool,
) -> Value {
    let environment = if std::env::var("NODE_ENV").is_ok_and(|value| value == "production") {
        "production"
    } else if std::env::var("CI").is_ok_and(|value| !value.is_empty() && value != "false") {
        "ci"
    } else if std::env::var("NODE_ENV").is_ok_and(|value| value == "test") {
        "test"
    } else {
        "development"
    };
    json!({
        "config": {
            "plugins": plugins,
            "hooks": {"before":before,"after":after},
            "secondaryStorage":secondary,
            "logger": {"disabled":config.logger.disabled,"level":config.logger.level.as_str(),"log":config.logger.log.is_some()},
            "trustedOrigins":config.trusted_origins.as_static().map(<[String]>::len),
        },
        "runtime":{"name":"rust","version":serde_json::Value::Null},
        "environment":environment,
    })
}

/// Start the init report before plugin initialization without awaiting a pending transport.
pub(super) async fn start_init(
    telemetry: better_auth_core::observability::telemetry::Telemetry,
    payload: Value,
) -> better_auth_core::AuthResult<()> {
    use std::{future::poll_fn, task::Poll};
    let mut task = Box::pin(async move { telemetry.publish("init", payload).await });
    match poll_fn(|cx| Poll::Ready(task.as_mut().poll(cx))).await {
        Poll::Ready(result) => result,
        Poll::Pending => {
            drop(tokio::spawn(async move {
                if let Err(error) = task.await {
                    better_auth_core::observability::logger::current().error(
                        "Telemetry serialization failed",
                        &[better_auth_core::observability::LogArgument::Error(&error)],
                    );
                }
            }));
            Ok(())
        }
    }
}

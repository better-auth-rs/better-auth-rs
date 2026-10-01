use std::io::IsTerminal;

use serde_json::{Map, Value, json};

use super::is_test;

const CI_KEYS: &[&str] = &[
    "BUILD_ID",
    "BUILD_NUMBER",
    "CI",
    "CI_APP_ID",
    "CI_BUILD_ID",
    "CI_BUILD_NUMBER",
    "CI_NAME",
    "CONTINUOUS_INTEGRATION",
    "RUN_ID",
];
const VENDORS: &[(&str, &[&str])] = &[
    ("cloudflare", &["CF_PAGES", "CF_PAGES_URL", "CF_ACCOUNT_ID"]),
    ("vercel", &["VERCEL", "VERCEL_URL", "VERCEL_ENV"]),
    ("netlify", &["NETLIFY", "NETLIFY_URL"]),
    (
        "render",
        &[
            "RENDER",
            "RENDER_URL",
            "RENDER_INTERNAL_HOSTNAME",
            "RENDER_SERVICE_ID",
        ],
    ),
    (
        "aws",
        &[
            "AWS_LAMBDA_FUNCTION_NAME",
            "AWS_EXECUTION_ENV",
            "LAMBDA_TASK_ROOT",
        ],
    ),
    (
        "gcp",
        &[
            "GOOGLE_CLOUD_FUNCTION_NAME",
            "GOOGLE_CLOUD_PROJECT",
            "GCP_PROJECT",
            "K_SERVICE",
        ],
    ),
    (
        "azure",
        &[
            "AZURE_FUNCTION_NAME",
            "FUNCTIONS_WORKER_RUNTIME",
            "WEBSITE_INSTANCE_ID",
            "WEBSITE_SITE_NAME",
        ],
    ),
    ("deno-deploy", &["DENO_DEPLOYMENT_ID", "DENO_REGION"]),
    ("fly-io", &["FLY_APP_NAME", "FLY_REGION", "FLY_ALLOC_ID"]),
    (
        "railway",
        &["RAILWAY_STATIC_URL", "RAILWAY_ENVIRONMENT_NAME"],
    ),
    ("heroku", &["DYNO", "HEROKU_APP_NAME"]),
    (
        "digitalocean",
        &["DO_DEPLOYMENT_ID", "DO_APP_NAME", "DIGITALOCEAN"],
    ),
    ("koyeb", &["KOYEB", "KOYEB_DEPLOYMENT_ID", "KOYEB_APP_NAME"]),
];

fn environment() -> &'static str {
    if std::env::var("NODE_ENV").is_ok_and(|value| value == "production") {
        "production"
    } else if !std::env::var("CI").is_ok_and(|value| value == "false")
        && CI_KEYS.iter().any(|key| std::env::var_os(key).is_some())
    {
        "ci"
    } else if is_test() {
        "test"
    } else {
        "development"
    }
}

fn vendor() -> Option<&'static str> {
    VENDORS.iter().find_map(|(vendor, keys)| {
        keys.iter()
            .any(|key| std::env::var_os(key).is_some_and(|value| !value.is_empty()))
            .then_some(*vendor)
    })
}

fn package_manager() -> Option<Value> {
    let agent = std::env::var("npm_config_user_agent").ok()?;
    if agent.is_empty() {
        return None;
    }
    let spec = agent
        .split_once(' ')
        .map_or(agent.as_str(), |(first, _)| first);
    let (name, version) = spec.rsplit_once('/').unwrap_or(("", spec));
    Some(json!({"name": if name == "npminstall" { "cnpm" } else { name }, "version": version}))
}

pub(super) fn initialization_metadata() -> Map<String, Value> {
    let platform = match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        platform => platform,
    };
    let architecture = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x64",
        "x86" => "ia32",
        architecture => architecture,
    };
    let mut system_info = Map::from_iter([
        ("deploymentVendor".into(), json!(vendor())),
        ("systemPlatform".into(), json!(platform)),
        ("systemArchitecture".into(), json!(architecture)),
    ]);
    // Rust's standard library does not expose the upstream hardware and container detectors.
    for key in [
        "systemRelease",
        "cpuCount",
        "cpuModel",
        "cpuSpeed",
        "memory",
        "isWSL",
        "isDocker",
    ] {
        let _ = system_info.insert(key.into(), Value::Null);
    }
    if std::io::stdout().is_terminal() {
        let _ = system_info.insert("isTTY".into(), Value::Bool(true));
    }
    let mut metadata = Map::from_iter([
        ("runtime".into(), json!({"name":"rust","version":null})),
        ("environment".into(), json!(environment())),
        ("systemInfo".into(), Value::Object(system_info)),
    ]);
    if let Some(manager) = package_manager() {
        let _ = metadata.insert("packageManager".into(), manager);
    }
    metadata
}

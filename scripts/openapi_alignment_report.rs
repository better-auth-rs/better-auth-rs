use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use chrono::Utc;
use clap::Parser;
use serde::Serialize;
use serde_json::{Map, Value};

type DynError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Debug, Parser)]
#[command(
    name = "openapi_alignment_report",
    about = "Compare two OpenAPI specs and generate plugin-level alignment report"
)]
struct Cli {
    #[arg(long, value_name = "path")]
    reference: PathBuf,

    #[arg(long, value_name = "path")]
    target: PathBuf,

    #[arg(long, value_name = "path")]
    output_json: Option<PathBuf>,

    #[arg(long, value_name = "path")]
    output_md: Option<PathBuf>,

    #[arg(long, default_value_t = 20)]
    list_limit: usize,

    #[arg(long)]
    fail_on_default_missing: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize)]
struct OperationKey {
    method: String,
    path: String,
}

#[derive(Debug, Clone)]
struct OperationInfo {
    plugin: String,
    request_schema: Option<Value>,
    response_schema: Option<Value>,
}

#[derive(Debug, Serialize)]
struct Report {
    timestamp: String,
    reference: ReportInput,
    target: ReportInput,
    summary: Summary,
    gates: Gates,
    plugins: Vec<PluginReport>,
    top_missing: Vec<String>,
    top_extra: Vec<String>,
    top_schema_mismatch: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ReportInput {
    path: String,
    operations: usize,
}

#[derive(Debug, Serialize)]
struct Summary {
    matched_operations: usize,
    missing_operations: usize,
    extra_operations: usize,
    route_coverage_pct: f64,
    schema_mismatch_operations: usize,
    schema_compatibility_pct: f64,
}

#[derive(Debug, Serialize)]
struct Gates {
    default_plugin_complete: bool,
}

#[derive(Debug, Serialize)]
struct PluginReport {
    plugin: String,
    reference_operations: usize,
    matched_operations: usize,
    missing_operations: usize,
    extra_operations: usize,
    schema_mismatch_operations: usize,
    route_coverage_pct: f64,
    schema_compatibility_pct: f64,
    missing_examples: Vec<String>,
    extra_examples: Vec<String>,
    schema_mismatch_examples: Vec<String>,
}

#[derive(Default)]
struct PluginAccumulator {
    reference_operations: usize,
    matched_operations: usize,
    missing: Vec<OperationKey>,
    extra: Vec<OperationKey>,
    schema_mismatch: Vec<OperationKey>,
}

fn main() -> Result<(), DynError> {
    let cli = Cli::parse();

    let reference_spec = load_openapi(&cli.reference)?;
    let target_spec = load_openapi(&cli.target)?;

    let reference_ops = extract_operations(&reference_spec)?;
    let target_ops = extract_operations(&target_spec)?;

    let mut reference_keys = BTreeSet::new();
    let mut target_keys = BTreeSet::new();
    for key in reference_ops.keys() {
        reference_keys.insert(key.clone());
    }
    for key in target_ops.keys() {
        target_keys.insert(key.clone());
    }

    let mut missing = Vec::new();
    let mut extra = Vec::new();
    let mut schema_mismatches = Vec::new();

    let mut plugin_acc: BTreeMap<String, PluginAccumulator> = BTreeMap::new();

    for key in &reference_keys {
        let reference_info = reference_ops.get(key).ok_or_else(|| {
            format!(
                "internal error: missing reference op {}/{}",
                key.method, key.path
            )
        })?;

        let plugin_name = reference_info.plugin.clone();
        let entry = plugin_acc.entry(plugin_name).or_default();
        entry.reference_operations += 1;

        match target_ops.get(key) {
            Some(target_info) => {
                entry.matched_operations += 1;

                if !schema_compatible(reference_info, target_info) {
                    schema_mismatches.push(key.clone());
                    entry.schema_mismatch.push(key.clone());
                }
            }
            None => {
                missing.push(key.clone());
                entry.missing.push(key.clone());
            }
        }
    }

    for key in &target_keys {
        if reference_ops.contains_key(key) {
            continue;
        }

        extra.push(key.clone());

        let target_plugin = target_ops
            .get(key)
            .map(|v| v.plugin.clone())
            .unwrap_or_else(|| "Unknown".to_string());
        let entry = plugin_acc.entry(target_plugin).or_default();
        entry.extra.push(key.clone());
    }

    let matched = reference_keys.len().saturating_sub(missing.len());
    let route_coverage_pct = pct(matched, reference_keys.len());
    let schema_compatibility_pct = pct(matched.saturating_sub(schema_mismatches.len()), matched);

    let mut plugin_reports = Vec::new();
    for (plugin, acc) in &plugin_acc {
        let route_plugin_pct = pct(acc.matched_operations, acc.reference_operations);
        let schema_plugin_pct = pct(
            acc.matched_operations
                .saturating_sub(acc.schema_mismatch.len()),
            acc.matched_operations,
        );

        plugin_reports.push(PluginReport {
            plugin: plugin.clone(),
            reference_operations: acc.reference_operations,
            matched_operations: acc.matched_operations,
            missing_operations: acc.missing.len(),
            extra_operations: acc.extra.len(),
            schema_mismatch_operations: acc.schema_mismatch.len(),
            route_coverage_pct: route_plugin_pct,
            schema_compatibility_pct: schema_plugin_pct,
            missing_examples: render_keys(&acc.missing, cli.list_limit),
            extra_examples: render_keys(&acc.extra, cli.list_limit),
            schema_mismatch_examples: render_keys(&acc.schema_mismatch, cli.list_limit),
        });
    }

    plugin_reports.sort_by(|a, b| a.plugin.cmp(&b.plugin));

    let default_missing = plugin_reports
        .iter()
        .find(|r| r.plugin == "Default")
        .map(|r| r.missing_operations)
        .unwrap_or(0);

    let report = Report {
        timestamp: Utc::now().to_rfc3339(),
        reference: ReportInput {
            path: cli.reference.to_string_lossy().into_owned(),
            operations: reference_keys.len(),
        },
        target: ReportInput {
            path: cli.target.to_string_lossy().into_owned(),
            operations: target_keys.len(),
        },
        summary: Summary {
            matched_operations: matched,
            missing_operations: missing.len(),
            extra_operations: extra.len(),
            route_coverage_pct,
            schema_mismatch_operations: schema_mismatches.len(),
            schema_compatibility_pct,
        },
        gates: Gates {
            default_plugin_complete: default_missing == 0,
        },
        plugins: plugin_reports,
        top_missing: render_keys(&missing, cli.list_limit),
        top_extra: render_keys(&extra, cli.list_limit),
        top_schema_mismatch: render_keys(&schema_mismatches, cli.list_limit),
    };

    if let Some(path) = &cli.output_json {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_string_pretty(&report)?)?;
        eprintln!("[ok] wrote json report: {}", path.display());
    }

    let markdown = render_markdown(&report);
    if let Some(path) = &cli.output_md {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, markdown.as_bytes())?;
        eprintln!("[ok] wrote markdown report: {}", path.display());
    }

    if cli.output_md.is_none() {
        println!("{markdown}");
    }

    if cli.fail_on_default_missing && !report.gates.default_plugin_complete {
        return Err("Gate failed: Default plugin is not complete".into());
    }

    Ok(())
}

fn load_openapi(path: &PathBuf) -> Result<Value, DynError> {
    let raw = fs::read_to_string(path)?;

    if let Ok(v) = serde_json::from_str::<Value>(&raw) {
        return Ok(v);
    }

    let v: Value = serde_yaml::from_str(&raw)?;
    Ok(v)
}

fn extract_operations(spec: &Value) -> Result<BTreeMap<OperationKey, OperationInfo>, DynError> {
    let paths = spec
        .get("paths")
        .and_then(Value::as_object)
        .ok_or("OpenAPI spec missing paths object")?;

    let mut ops = BTreeMap::new();

    for (path, methods) in paths {
        let Some(methods_obj) = methods.as_object() else {
            continue;
        };

        for (method, operation) in methods_obj {
            if !is_http_method(method) {
                continue;
            }
            let Some(op_obj) = operation.as_object() else {
                continue;
            };

            let key = OperationKey {
                method: method.to_uppercase(),
                path: path.clone(),
            };

            let plugin = op_obj
                .get("tags")
                .and_then(Value::as_array)
                .and_then(|tags| tags.iter().find_map(Value::as_str))
                .unwrap_or("Default")
                .to_string();

            let request_schema = extract_request_schema(operation);
            let response_schema = extract_response_schema(operation);

            ops.insert(
                key,
                OperationInfo {
                    plugin,
                    request_schema,
                    response_schema,
                },
            );
        }
    }

    Ok(ops)
}

fn is_http_method(method: &str) -> bool {
    matches!(
        method,
        "get" | "post" | "put" | "delete" | "patch" | "options" | "head" | "trace"
    )
}

fn extract_request_schema(operation: &Value) -> Option<Value> {
    operation
        .get("requestBody")
        .and_then(|v| v.get("content"))
        .and_then(extract_content_schema)
}

fn extract_response_schema(operation: &Value) -> Option<Value> {
    let responses = operation.get("responses")?.as_object()?;

    let mut response_keys: Vec<&String> = responses.keys().filter(|k| k.starts_with('2')).collect();
    response_keys.sort();

    for code in response_keys {
        let response = responses.get(code)?;
        if let Some(schema) = response.get("content").and_then(extract_content_schema) {
            return Some(schema);
        }
    }

    None
}

fn extract_content_schema(content: &Value) -> Option<Value> {
    let content_obj = content.as_object()?;

    if let Some(schema) = content_obj
        .get("application/json")
        .and_then(|media| media.get("schema"))
    {
        return Some(schema.clone());
    }

    for media in content_obj.values() {
        if let Some(schema) = media.get("schema") {
            return Some(schema.clone());
        }
    }

    None
}

fn schema_compatible(reference: &OperationInfo, target: &OperationInfo) -> bool {
    values_equal(
        reference.request_schema.as_ref(),
        target.request_schema.as_ref(),
    ) && values_equal(
        reference.response_schema.as_ref(),
        target.response_schema.as_ref(),
    )
}

fn values_equal(left: Option<&Value>, right: Option<&Value>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(a), Some(b)) => canonicalize(a) == canonicalize(b),
        _ => false,
    }
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));

            let mut out = Map::new();
            for (key, val) in entries {
                out.insert(key.clone(), canonicalize(val));
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(canonicalize).collect()),
        _ => value.clone(),
    }
}

fn pct(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        100.0
    } else {
        (numerator as f64 / denominator as f64) * 100.0
    }
}

fn render_keys(keys: &[OperationKey], limit: usize) -> Vec<String> {
    keys.iter()
        .take(limit)
        .map(|k| format!("{} {}", k.method, k.path))
        .collect()
}

fn render_markdown(report: &Report) -> String {
    let mut out = String::new();

    out.push_str("# OpenAPI Alignment Report\n\n");
    out.push_str(&format!("- Timestamp: `{}`\n", report.timestamp));
    out.push_str(&format!("- Reference: `{}`\n", report.reference.path));
    out.push_str(&format!("- Target: `{}`\n\n", report.target.path));

    out.push_str("## Summary\n\n");
    out.push_str(&format!(
        "- Reference operations: {}\n",
        report.reference.operations
    ));
    out.push_str(&format!(
        "- Target operations: {}\n",
        report.target.operations
    ));
    out.push_str(&format!(
        "- Matched / Missing / Extra: {} / {} / {}\n",
        report.summary.matched_operations,
        report.summary.missing_operations,
        report.summary.extra_operations
    ));
    out.push_str(&format!(
        "- Route coverage: `{:.2}%`\n",
        report.summary.route_coverage_pct
    ));
    out.push_str(&format!(
        "- Schema compatibility: `{:.2}%` (mismatches: {})\n",
        report.summary.schema_compatibility_pct, report.summary.schema_mismatch_operations
    ));
    out.push_str(&format!(
        "- Gate `Default complete`: `{}`\n\n",
        report.gates.default_plugin_complete
    ));

    out.push_str("## Plugin Breakdown\n\n");
    out.push_str(
        "| Plugin | Ref | Matched | Missing | Extra | SchemaMismatch | Route% | Schema% |\n",
    );
    out.push_str("|---|---:|---:|---:|---:|---:|---:|---:|\n");
    for p in &report.plugins {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {:.2}% | {:.2}% |\n",
            p.plugin,
            p.reference_operations,
            p.matched_operations,
            p.missing_operations,
            p.extra_operations,
            p.schema_mismatch_operations,
            p.route_coverage_pct,
            p.schema_compatibility_pct
        ));
    }
    out.push('\n');

    out.push_str("## Top Missing\n\n");
    if report.top_missing.is_empty() {
        out.push_str("- None\n\n");
    } else {
        for item in &report.top_missing {
            out.push_str(&format!("- {}\n", item));
        }
        out.push('\n');
    }

    out.push_str("## Top Extra\n\n");
    if report.top_extra.is_empty() {
        out.push_str("- None\n\n");
    } else {
        for item in &report.top_extra {
            out.push_str(&format!("- {}\n", item));
        }
        out.push('\n');
    }

    out.push_str("## Top Schema Mismatch\n\n");
    if report.top_schema_mismatch.is_empty() {
        out.push_str("- None\n");
    } else {
        for item in &report.top_schema_mismatch {
            out.push_str(&format!("- {}\n", item));
        }
    }

    out
}

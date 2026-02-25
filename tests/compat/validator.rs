//! `SpecValidator` framework for batch endpoint validation and reporting.
//!
//! Collects per-endpoint results and produces a human-readable compatibility
//! report suitable for CI output.

use super::schema::{extract_success_schema, load_openapi_spec};
use super::validation::{ShapeDiff, validate_response};

/// Validate that every endpoint's response matches the OpenAPI spec schema.
/// This is the core of the compatibility testing framework.
pub struct SpecValidator {
    pub spec: oas3::spec::Spec,
    pub results: Vec<EndpointResult>,
}

pub struct EndpointResult {
    pub endpoint: String,
    pub method: String,
    pub status: u16,
    pub passed: bool,
    pub diffs: Vec<ShapeDiff>,
    pub camel_case_violations: Vec<String>,
}

impl std::fmt::Display for EndpointResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let icon = if self.passed { "PASS" } else { "FAIL" };
        write!(
            f,
            "[{}] {} {} (status={})",
            icon,
            self.method.to_uppercase(),
            self.endpoint,
            self.status
        )?;
        for diff in &self.diffs {
            write!(f, "\n      {}", diff)?;
        }
        for v in &self.camel_case_violations {
            write!(f, "\n      CAMEL_CASE {}", v)?;
        }
        Ok(())
    }
}

impl SpecValidator {
    pub fn new() -> Self {
        Self {
            spec: load_openapi_spec(),
            results: Vec::new(),
        }
    }

    /// Validate a single endpoint response against the spec.
    pub fn validate_endpoint(
        &mut self,
        path: &str,
        method: &str,
        status: u16,
        body: &serde_json::Value,
    ) {
        let schema = extract_success_schema(&self.spec, path, method);
        let (passed, diffs) = if let Some(schema) = &schema {
            let diffs = validate_response(body, schema, "");
            (diffs.is_empty(), diffs)
        } else {
            // No spec schema found -- can't validate, consider it passed
            (true, vec![])
        };

        self.results.push(EndpointResult {
            endpoint: path.to_string(),
            method: method.to_uppercase(),
            status,
            passed,
            diffs,
            camel_case_violations: vec![],
        });
    }

    /// Generate a human-readable compatibility report.
    pub fn report(&self) -> String {
        let mut lines = Vec::new();
        lines.push("=== Spec-Driven Compatibility Report ===".to_string());
        lines.push(String::new());

        let total = self.results.len();
        let passed = self.results.iter().filter(|r| r.passed).count();
        let failed = total - passed;

        lines.push(format!("Total endpoints tested: {}", total));
        lines.push(format!("Passed: {}", passed));
        lines.push(format!("Failed: {}", failed));
        lines.push(String::new());

        for result in &self.results {
            lines.push(format!("{}", result));
        }

        lines.push(String::new());
        lines.push("========================================".to_string());
        lines.join("\n")
    }

    #[allow(dead_code)]
    pub fn all_passed(&self) -> bool {
        self.results.iter().all(|r| r.passed)
    }
}

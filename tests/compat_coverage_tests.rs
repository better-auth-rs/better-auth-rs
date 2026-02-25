//! Route coverage analysis — compares spec endpoints against implementation.

mod compat;

use std::collections::{BTreeMap, HashSet};

use better_auth::types::HttpMethod;

use compat::helpers::*;
use compat::schema::load_openapi_spec;

/// Analyze which endpoints from the reference spec are implemented.
#[tokio::test]
async fn test_route_coverage_analysis() {
    let spec = load_openapi_spec();
    let auth = create_test_auth().await;

    // Collect reference endpoints from the typed spec
    let paths = spec.paths.as_ref().expect("spec must have paths");

    let mut ref_endpoints: BTreeMap<String, HashSet<String>> = BTreeMap::new();
    for (path, path_item) in paths {
        let mut method_set = HashSet::new();
        if path_item.get.is_some() {
            method_set.insert("get".to_string());
        }
        if path_item.post.is_some() {
            method_set.insert("post".to_string());
        }
        if path_item.put.is_some() {
            method_set.insert("put".to_string());
        }
        if path_item.delete.is_some() {
            method_set.insert("delete".to_string());
        }
        if path_item.patch.is_some() {
            method_set.insert("patch".to_string());
        }
        if !method_set.is_empty() {
            ref_endpoints.insert(path.clone(), method_set);
        }
    }

    // Collect implemented endpoints
    let mut impl_endpoints: BTreeMap<String, HashSet<String>> = BTreeMap::new();

    // Core routes
    for (path, method) in &[
        ("/ok", "get"),
        ("/error", "get"),
        ("/reference/openapi.json", "get"),
        ("/update-user", "post"),
        ("/delete-user", "delete"),
        ("/change-email", "post"),
        ("/delete-user/callback", "get"),
    ] {
        impl_endpoints
            .entry(path.to_string())
            .or_default()
            .insert(method.to_string());
    }

    // Plugin routes
    for plugin in auth.plugins() {
        for route in plugin.routes() {
            let method_str = match route.method {
                HttpMethod::Get => "get",
                HttpMethod::Post => "post",
                HttpMethod::Put => "put",
                HttpMethod::Delete => "delete",
                HttpMethod::Patch => "patch",
                HttpMethod::Options => "options",
                HttpMethod::Head => "head",
            };
            impl_endpoints
                .entry(route.path.clone())
                .or_default()
                .insert(method_str.to_string());
        }
    }

    // Compute coverage
    let mut covered = 0;
    let mut missing = Vec::new();
    let total: usize = ref_endpoints.values().map(|m| m.len()).sum();

    for (path, methods) in &ref_endpoints {
        for method in methods {
            if impl_endpoints.get(path).is_some_and(|m| m.contains(method)) {
                covered += 1;
            } else {
                missing.push(format!("{} {}", method.to_uppercase(), path));
            }
        }
    }

    let coverage_pct = if total > 0 {
        (covered as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    // Print structured coverage report
    eprintln!("\n╔══════════════════════════════════════════════════════╗");
    eprintln!("║  Route Coverage Analysis                             ║");
    eprintln!("╚══════════════════════════════════════════════════════╝\n");
    eprintln!("Reference endpoints:  {}", total);
    eprintln!("Implemented:          {}", covered);
    eprintln!("Missing:              {}", missing.len());
    eprintln!("Coverage:             {:.1}%\n", coverage_pct);

    if !missing.is_empty() {
        eprintln!("--- Missing endpoints (from reference spec) ---");
        // Group by plugin/category
        let mut categorized: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for m in &missing {
            let path_part = m.split_whitespace().nth(1).unwrap_or(m);
            let category = if path_part.contains("two-factor") {
                "Two-Factor"
            } else if path_part.contains("passkey") {
                "Passkey"
            } else if path_part.contains("organization")
                || path_part.contains("invitation")
                || path_part.contains("member")
            {
                "Organization"
            } else if path_part.contains("admin")
                || path_part.contains("ban")
                || path_part.contains("impersonate")
            {
                "Admin"
            } else if path_part.contains("api-key") {
                "API Key"
            } else if path_part.contains("sign-in")
                || path_part.contains("sign-up")
                || path_part.contains("callback")
            {
                "Auth"
            } else if path_part.contains("session") {
                "Session"
            } else {
                "Other"
            };
            categorized
                .entry(category.to_string())
                .or_default()
                .push(m.clone());
        }

        for (category, endpoints) in &categorized {
            eprintln!("\n  [{}]", category);
            for ep in endpoints {
                eprintln!("    [ ] {}", ep);
            }
        }
    }

    eprintln!("\n══════════════════════════════════════════════════════\n");
}

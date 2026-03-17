#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "architecture guard tests intentionally fail fast on fixture traversal and string-scan assumptions"
)]

use std::fs;
use std::path::{Path, PathBuf};

fn collect_files(root: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).expect("directory should be readable") {
        let entry = entry.expect("directory entry should be readable");
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, files);
            continue;
        }

        let extension = path.extension().and_then(std::ffi::OsStr::to_str);
        if matches!(extension, Some("rs" | "md" | "mdx")) {
            files.push(path);
        }
    }
}

fn collect_rust_files(root: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).expect("directory should be readable") {
        let entry = entry.expect("directory entry should be readable");
        let path = entry.path();
        if path.is_dir() {
            collect_rust_files(&path, files);
            continue;
        }

        if path.extension().and_then(std::ffi::OsStr::to_str) == Some("rs") {
            files.push(path);
        }
    }
}

fn is_behavior_marker_exempt(path: &Path) -> bool {
    let text = path.to_string_lossy();
    text.ends_with("tests/architecture_guard_tests.rs")
        || text.ends_with("tests/client_compat_tests.rs")
        || text.ends_with("tests/wire_compat_smoke_tests.rs")
        || text.contains("/tests/compat")
        || text.contains("/tests/compat/")
        || text.ends_with("tests/compatibility_tests.rs")
}

fn is_phase0_3_strict_marker_target(path: &Path) -> bool {
    let text = path.to_string_lossy();
    text.ends_with("tests/integration_tests.rs")
        || text.ends_with("tests/axum_integration_tests.rs")
        || text.ends_with("crates/api/src/plugins/email_password.rs")
        || text.ends_with("crates/api/tests/account_oauth_tests.rs")
}

fn has_test_attribute(line: &str) -> bool {
    matches!(line.trim(), "#[test]" | "#[tokio::test]")
}

#[test]
fn legacy_persistence_symbols_are_gone_from_tracked_sources() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let guard_file = root.join("tests/architecture_guard_tests.rs");
    let banned = [
        "DatabaseAdapter",
        "AuthDatabase",
        "SeaOrmStore",
        "UserOps",
        "SessionOps",
        "AccountOps",
        "VerificationOps",
        "OrganizationOps",
        "MemberOps",
        "InvitationOps",
        "TwoFactorOps",
        "ApiKeyOps",
        "PasskeyOps",
    ];
    let mut files = Vec::new();

    for relative in ["crates", "src", "tests", "docs", "examples"] {
        collect_files(&root.join(relative), &mut files);
    }

    let mut violations = Vec::new();
    for path in files {
        if path == guard_file {
            continue;
        }
        let content = fs::read_to_string(&path).expect("source file should be readable");
        for symbol in &banned {
            if content.contains(symbol) {
                violations.push(format!("{} -> {}", path.display(), symbol));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "legacy persistence symbols remain:\n{}",
        violations.join("\n")
    );
}

#[test]
fn behavior_tests_must_include_behavior_source_comments() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();

    for relative in [
        "tests",
        "src",
        "crates/api/src",
        "crates/api/tests",
        "crates/core/src",
    ] {
        collect_rust_files(&root.join(relative), &mut files);
    }

    let mut violations = Vec::new();
    for path in files {
        if is_behavior_marker_exempt(&path) || !is_phase0_3_strict_marker_target(&path) {
            continue;
        }

        let content = fs::read_to_string(&path).expect("source file should be readable");
        let lines: Vec<&str> = content.lines().collect();

        for (index, line) in lines.iter().enumerate() {
            if !has_test_attribute(line) {
                continue;
            }

            let mut has_marker = false;
            for candidate in lines[..index].iter().rev() {
                let trimmed = candidate.trim();
                if trimmed.is_empty() {
                    if has_marker {
                        break;
                    }
                    continue;
                }
                if trimmed.starts_with("// Upstream reference:")
                    || trimmed.starts_with("// Upstream source:")
                    || trimmed.starts_with("// Rust-specific surface:")
                {
                    has_marker = true;
                    continue;
                }
                if trimmed.starts_with("//") {
                    continue;
                }
                break;
            }

            if !has_marker {
                violations.push(format!("{}:{}", path.display(), index + 1));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "behavior tests missing source/surface comments:\n{}",
        violations.join("\n")
    );
}

#[test]
fn upstream_markers_must_not_use_broad_bundle_patterns() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();

    for relative in [
        "tests",
        "src",
        "crates/api/src",
        "crates/api/tests",
        "crates/core/src",
    ] {
        collect_rust_files(&root.join(relative), &mut files);
    }

    let banned_fragments = [
        "packages/better-auth/src/api/routes/{",
        "packages/better-auth/src/plugins/{",
        ".*.test.ts",
        ".test.ts and ",
    ];

    let mut violations = Vec::new();
    for path in files {
        if is_behavior_marker_exempt(&path) || !is_phase0_3_strict_marker_target(&path) {
            continue;
        }

        let content = fs::read_to_string(&path).expect("source file should be readable");
        for (index, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if !trimmed.starts_with("// Upstream reference:")
                && !trimmed.starts_with("// Upstream source:")
            {
                continue;
            }

            for fragment in &banned_fragments {
                if trimmed.contains(fragment) {
                    violations.push(format!("{}:{} -> {}", path.display(), index + 1, trimmed));
                    break;
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "broad upstream markers remain:\n{}",
        violations.join("\n")
    );
}

#[test]
fn stale_test_drift_phrasing_is_gone() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let guard_file = root.join("tests/architecture_guard_tests.rs");
    let banned = [
        "Acceptable deviation",
        "superset of the TS responses",
        "changed from DELETE",
        "in addition to GET",
    ];
    let mut files = Vec::new();

    for relative in [
        "tests",
        "src",
        "crates/api/src",
        "crates/api/tests",
        "crates/core/src",
    ] {
        collect_rust_files(&root.join(relative), &mut files);
    }

    let mut violations = Vec::new();
    for path in files {
        if path == guard_file {
            continue;
        }
        let content = fs::read_to_string(&path).expect("source file should be readable");
        for phrase in &banned {
            if content.contains(phrase) {
                violations.push(format!("{} -> {}", path.display(), phrase));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "stale test drift phrasing remains:\n{}",
        violations.join("\n")
    );
}

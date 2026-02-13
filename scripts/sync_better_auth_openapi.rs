use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use chrono::Utc;
use clap::{Parser, ValueEnum};
use serde::Serialize;
use serde_json::Value;

type DynError = Box<dyn std::error::Error + Send + Sync + 'static>;

const DEFAULT_REPO_URL: &str = "https://github.com/better-auth/better-auth.git";
const GENERATOR_TEMPLATE_REL_PATH: &str = "scripts/generate-openapi-matrix.mjs";

#[derive(Debug, Parser)]
#[command(
    name = "sync_better_auth_openapi",
    about = "Clone a pinned better-auth ref and export OpenAPI specs for multiple auth profiles"
)]
struct Cli {
    #[arg(long = "repo-url", default_value = DEFAULT_REPO_URL)]
    repo_url: String,

    #[arg(long = "ref", value_name = "git-ref")]
    git_ref: String,

    #[arg(long = "repo-dir", default_value = ".cache/better-auth-upstream")]
    repo_dir: PathBuf,

    #[arg(long = "output-dir", default_value = "reference/upstream-openapi")]
    output_dir: PathBuf,

    #[arg(
        long,
        value_name = "list",
        value_delimiter = ',',
        default_value = "core,aligned-rs"
    )]
    profiles: Vec<Profile>,

    #[arg(long)]
    skip_install: bool,

    #[arg(long)]
    skip_build: bool,

    #[arg(long)]
    keep_generator: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Profile {
    #[value(name = "core")]
    Core,
    #[value(name = "aligned-rs", alias = "aligned_rs", alias = "aligned")]
    AlignedRs,
    #[value(name = "all-in", alias = "all_in", alias = "allin")]
    AllIn,
}

impl Profile {
    fn as_str(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::AlignedRs => "aligned-rs",
            Self::AllIn => "all-in",
        }
    }
}

#[derive(Debug, Serialize)]
struct Manifest {
    generated_at: String,
    repo_url: String,
    git_ref: String,
    commit: String,
    repo_dir: String,
    profiles: Vec<ManifestProfile>,
}

#[derive(Debug, Serialize)]
struct ManifestProfile {
    name: String,
    json: String,
    yaml: String,
}

fn main() -> Result<(), DynError> {
    let options = Cli::parse();

    ensure_command_available("git")?;
    ensure_command_available("node")?;
    ensure_command_available("pnpm")?;

    let repo_dir = options.repo_dir.clone();
    let output_dir = options.output_dir.clone();

    clone_or_update_repo(&options.repo_url, &repo_dir)?;
    checkout_ref(&repo_dir, &options.git_ref)?;
    let commit = git_rev_parse_head(&repo_dir)?;

    if !options.skip_install {
        run_checked(
            "pnpm",
            &["install", "--no-frozen-lockfile"],
            Some(&repo_dir),
        )?;
    }
    if !options.skip_build {
        run_checked("pnpm", &["build"], Some(&repo_dir))?;
    }

    fs::create_dir_all(&output_dir)?;
    let js_workdir = resolve_js_workdir(&repo_dir);
    let generator_path = write_generator_script(&js_workdir)?;
    let generator_arg = generator_path
        .strip_prefix(&js_workdir)
        .unwrap_or(&generator_path)
        .to_string_lossy()
        .into_owned();

    let mut manifest_profiles = Vec::new();
    for profile in options.profiles {
        let json_path = output_dir.join(format!("openapi.{}.json", profile.as_str()));
        let yaml_path = output_dir.join(format!("openapi.{}.yaml", profile.as_str()));

        run_checked(
            "node",
            &[
                generator_arg.as_str(),
                "--profile",
                profile.as_str(),
                "--output",
                json_path.to_string_lossy().as_ref(),
            ],
            Some(&js_workdir),
        )?;

        convert_json_to_yaml(&json_path, &yaml_path)?;

        manifest_profiles.push(ManifestProfile {
            name: profile.as_str().to_string(),
            json: json_path.to_string_lossy().into_owned(),
            yaml: yaml_path.to_string_lossy().into_owned(),
        });
    }

    let manifest = Manifest {
        generated_at: Utc::now().to_rfc3339(),
        repo_url: options.repo_url,
        git_ref: options.git_ref,
        commit,
        repo_dir: repo_dir.to_string_lossy().into_owned(),
        profiles: manifest_profiles,
    };

    let manifest_path = output_dir.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)?;

    if !options.keep_generator {
        let _ = fs::remove_file(&generator_path);
    }

    eprintln!(
        "[done] OpenAPI matrix generated in {}",
        output_dir.display()
    );
    eprintln!("[done] Manifest: {}", manifest_path.display());
    Ok(())
}

fn ensure_command_available(cmd: &str) -> Result<(), DynError> {
    let status = Command::new("bash")
        .arg("-lc")
        .arg(r#"command -v "$1" >/dev/null 2>&1"#)
        .arg("bash")
        .arg(cmd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("Required command `{cmd}` is not available in PATH").into())
    }
}

fn clone_or_update_repo(repo_url: &str, repo_dir: &Path) -> Result<(), DynError> {
    if repo_dir.join(".git").exists() {
        run_checked(
            "git",
            &["fetch", "--tags", "--prune", "origin"],
            Some(repo_dir),
        )?;
        return Ok(());
    }

    if let Some(parent) = repo_dir.parent() {
        fs::create_dir_all(parent)?;
    }

    run_checked(
        "git",
        &[
            "clone",
            "--filter=blob:none",
            repo_url,
            repo_dir.to_string_lossy().as_ref(),
        ],
        None,
    )?;

    Ok(())
}

fn checkout_ref(repo_dir: &Path, git_ref: &str) -> Result<(), DynError> {
    run_checked("git", &["checkout", "--detach", git_ref], Some(repo_dir))
}

fn git_rev_parse_head(repo_dir: &Path) -> Result<String, DynError> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo_dir)
        .output()?;

    if !output.status.success() {
        return Err("Failed to resolve HEAD commit".into());
    }

    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

fn write_generator_script(js_workdir: &Path) -> Result<PathBuf, DynError> {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join(GENERATOR_TEMPLATE_REL_PATH);
    if !source.exists() {
        return Err(format!("Generator template not found: {}", source.display()).into());
    }

    let generator_dir = js_workdir.join(".tmp");
    fs::create_dir_all(&generator_dir)?;
    let generator_path = generator_dir.join("generate-openapi-matrix.mjs");
    fs::copy(source, &generator_path)?;
    Ok(generator_path)
}

fn resolve_js_workdir(repo_dir: &Path) -> PathBuf {
    let candidate = repo_dir.join("packages/better-auth");
    if candidate.join("package.json").exists() {
        candidate
    } else {
        repo_dir.to_path_buf()
    }
}

fn convert_json_to_yaml(json_path: &Path, yaml_path: &Path) -> Result<(), DynError> {
    let json_raw = fs::read_to_string(json_path)?;
    let json_value: Value = serde_json::from_str(&json_raw)?;
    let yaml = serde_yaml::to_string(&json_value)?;
    fs::write(yaml_path, yaml)?;
    Ok(())
}

fn run_checked(program: &str, args: &[&str], cwd: Option<&Path>) -> Result<(), DynError> {
    eprintln!("$ {} {}", program, display_args(args));

    let mut command = Command::new(program);
    command.args(args);
    if let Some(dir) = cwd {
        command.current_dir(dir);
    }

    let status = command
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("Command failed: {} {}", program, display_args(args)).into())
    }
}

fn display_args(args: &[&str]) -> String {
    args.iter()
        .map(quote_if_needed)
        .collect::<Vec<_>>()
        .join(" ")
}

fn quote_if_needed(value: &&str) -> String {
    if value.contains(' ') {
        format!("\"{value}\"")
    } else {
        (*value).to_string()
    }
}

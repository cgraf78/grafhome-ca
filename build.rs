use std::collections::HashSet;
use std::process::Command;
use std::{
    fs,
    path::{Path, PathBuf},
};

fn output(command: &mut Command) -> Option<String> {
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn valid_commit(value: &str) -> bool {
    value.len() >= 8 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 15
        && bytes[0..8].iter().all(|byte| byte.is_ascii_digit())
        && bytes[8] == b'-'
        && bytes[9..15].iter().all(|byte| byte.is_ascii_digit())
}

fn valid_version(value: &str) -> bool {
    let parts = value.split('-').collect::<Vec<_>>();
    parts.len() == 3
        && parts[0].len() == 8
        && parts[1].len() == 6
        && parts[2].len() == 8
        && parts[0].bytes().all(|byte| byte.is_ascii_digit())
        && parts[1].bytes().all(|byte| byte.is_ascii_digit())
        && parts[2].bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Track the checkout's HEAD and the branch storage it points to.
fn watch_git_head() {
    let Some(head) = git_path("HEAD").filter(|path| path.is_file()) else {
        watch_git_head_without_git();
        return;
    };
    println!("cargo:rerun-if-changed={}", head.display());
    if git_output(&["rev-parse", "--show-ref-format"]).as_deref() == Some("reftable") {
        watch_reftable();
        return;
    }
    // Git before 2.39 can still report the leaf ref recursively.
    let Some(mut reference) =
        symbolic_target("HEAD").or_else(|| git_output(&["symbolic-ref", "--quiet", "HEAD"]))
    else {
        return;
    };

    // Git resolves the shared branch and packed refs correctly in linked worktrees.
    if let Some(packed) = git_path("packed-refs").filter(|path| path.is_file()) {
        println!("cargo:rerun-if-changed={}", packed.display());
    }
    let mut visited = HashSet::new();
    while visited.insert(reference.clone()) {
        let Some(loose) = git_path(&reference) else {
            return;
        };
        // A packed-only branch gets a loose ref on its next update. Watch the
        // containing directory until then, since Cargo always reruns on missing paths.
        if let Some(existing) = loose.ancestors().find(|path| path.exists()) {
            println!("cargo:rerun-if-changed={}", existing.display());
        }
        let Some(target) = symbolic_target(&reference) else {
            break;
        };
        reference = target;
    }
}

/// Follow one hop so retargeting an intermediate symbolic branch triggers a build.
fn symbolic_target(reference: &str) -> Option<String> {
    git_output(&["symbolic-ref", "--quiet", "--no-recurse", reference])
}

/// Reftable stores branch refs in the common index and linked HEADs in a local index.
fn watch_reftable() {
    const INDEX: &str = "reftable/tables.list";
    let local = git_path(INDEX).filter(|path| path.is_file());
    if let Some(path) = &local {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    if let Some(common) = git_output(&["rev-parse", "--git-common-dir"])
        .map(|directory| PathBuf::from(directory).join(INDEX))
        .filter(|path| path.is_file() && Some(path) != local.as_ref())
    {
        println!("cargo:rerun-if-changed={}", common.display());
    }
}

fn git_path(path: &str) -> Option<PathBuf> {
    git_output(&["rev-parse", "--git-path", path]).map(PathBuf::from)
}

fn git_output(args: &[&str]) -> Option<String> {
    output(git_command().args(args))
}

/// Keep shell-based tool launchers from sourcing the caller's startup files.
fn tool_command(name: &str) -> Command {
    let mut command = Command::new(name);
    command.env_remove("BASH_ENV").env_remove("ENV");
    command
}

/// Keep Git discovery scoped to the build checkout.
fn git_command() -> Command {
    let mut command = tool_command("git");
    // Git hooks and wrappers can export metadata for a different checkout.
    // Clear the repository-local variables reported by git rev-parse --local-env-vars
    // before reading HEAD, its storage paths, or a commit timestamp.
    for name in [
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
        "GIT_DIR",
        "GIT_GRAFT_FILE",
        "GIT_IMPLICIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_NO_REPLACE_OBJECTS",
        "GIT_OBJECT_DIRECTORY",
        "GIT_PREFIX",
        "GIT_REPLACE_REF_BASE",
        "GIT_SHALLOW_FILE",
        "GIT_WORK_TREE",
    ] {
        command.env_remove(name);
    }
    // Cargo runs in the crate root. An exported snapshot must use its own
    // explicit commit or the existing fallback, independent of its parent.
    if !Path::new(".git").exists() {
        command.env("GIT_DIR", ".git");
    }
    command
}

/// Retain the existing filesystem fallback for builds that cannot query Git.
fn watch_git_head_without_git() {
    let git_path = Path::new(".git");
    let head_path = if git_path.is_dir() {
        git_path.join("HEAD")
    } else {
        let Ok(git_file) = fs::read_to_string(git_path) else {
            return;
        };
        let Some(path) = git_file.trim().strip_prefix("gitdir: ") else {
            return;
        };
        Path::new(path).join("HEAD")
    };

    println!("cargo:rerun-if-changed={}", head_path.display());
    let Ok(head) = fs::read_to_string(&head_path) else {
        return;
    };
    if let Some(reference) = head.trim().strip_prefix("ref: ") {
        let ref_path = head_path
            .parent()
            .unwrap_or_else(|| Path::new(".git"))
            .join(reference);
        println!("cargo:rerun-if-changed={}", ref_path.display());
    }
}

fn commit() -> String {
    println!("cargo:rerun-if-env-changed=GRAFHOME_CA_BUILD_COMMIT");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
    watch_git_head();

    std::env::var("GRAFHOME_CA_BUILD_COMMIT")
        .ok()
        .or_else(|| std::env::var("GITHUB_SHA").ok())
        .or_else(|| git_output(&["rev-parse", "HEAD"]))
        .filter(|value| valid_commit(value))
        .unwrap_or_else(|| "00000000".to_owned())
}

fn tag_version(commit: &str) -> Option<String> {
    println!("cargo:rerun-if-env-changed=GITHUB_REF_TYPE");
    println!("cargo:rerun-if-env-changed=GITHUB_REF_NAME");
    println!("cargo:rerun-if-env-changed=GITHUB_REF");

    let tag = if std::env::var("GITHUB_REF_TYPE").ok().as_deref() == Some("tag") {
        std::env::var("GITHUB_REF_NAME").ok()
    } else {
        std::env::var("GITHUB_REF")
            .ok()
            .and_then(|value| value.strip_prefix("refs/tags/").map(str::to_owned))
    }?;

    if !valid_version(&tag) {
        panic!("release tag must look like YYYYMMDD-HHMMSS-<8hex> (got {tag})");
    }
    let suffix = tag.rsplit('-').next().unwrap_or_default();
    if &commit[..8] != suffix {
        panic!(
            "release tag commit suffix {suffix} does not match build commit {}",
            &commit[..8]
        );
    }
    Some(tag)
}

fn timestamp(commit: &str) -> String {
    println!("cargo:rerun-if-env-changed=GRAFHOME_CA_BUILD_TIMESTAMP");

    if let Ok(value) = std::env::var("GRAFHOME_CA_BUILD_TIMESTAMP") {
        if !valid_timestamp(&value) {
            panic!("GRAFHOME_CA_BUILD_TIMESTAMP must look like YYYYMMDD-HHMMSS");
        }
        return value;
    }

    output(git_command().env("TZ", "UTC").args([
        "show",
        "-s",
        "--date=format-local:%Y%m%d-%H%M%S",
        "--format=%cd",
        commit,
    ]))
    .or_else(|| output(tool_command("date").args(["-u", "+%Y%m%d-%H%M%S"])))
    .filter(|value| valid_timestamp(value))
    .unwrap_or_else(|| "19700101-000000".to_owned())
}

fn version(commit: &str) -> String {
    println!("cargo:rerun-if-env-changed=GRAFHOME_CA_BUILD_VERSION");

    if let Ok(value) = std::env::var("GRAFHOME_CA_BUILD_VERSION") {
        if !valid_version(&value) {
            panic!("GRAFHOME_CA_BUILD_VERSION must look like YYYYMMDD-HHMMSS-<8hex>");
        }
        let suffix = value.rsplit('-').next().unwrap_or_default();
        if &commit[..8] != suffix {
            panic!(
                "GRAFHOME_CA_BUILD_VERSION commit suffix {suffix} does not match build commit {}",
                &commit[..8]
            );
        }
        return value;
    }

    tag_version(commit).unwrap_or_else(|| format!("{}-{}", timestamp(commit), &commit[..8]))
}

fn main() {
    let commit = commit();
    let version = version(&commit);

    println!("cargo:rustc-env=GRAFHOME_CA_BUILD_COMMIT={commit}");
    println!("cargo:rustc-env=GRAFHOME_CA_BUILD_VERSION={version}");
    println!("cargo:rustc-env=GRAFHOME_CA_CLI_VERSION={version}");
}

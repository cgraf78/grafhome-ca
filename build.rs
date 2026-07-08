use std::process::Command;

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

fn commit() -> String {
    println!("cargo:rerun-if-env-changed=GRAFHOME_CA_BUILD_COMMIT");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");

    std::env::var("GRAFHOME_CA_BUILD_COMMIT")
        .ok()
        .or_else(|| std::env::var("GITHUB_SHA").ok())
        .or_else(|| output(Command::new("git").args(["rev-parse", "HEAD"])))
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

    output(Command::new("git").env("TZ", "UTC").args([
        "show",
        "-s",
        "--date=format-local:%Y%m%d-%H%M%S",
        "--format=%cd",
        commit,
    ]))
    .or_else(|| output(Command::new("date").args(["-u", "+%Y%m%d-%H%M%S"])))
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

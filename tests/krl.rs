#![cfg(unix)]

use std::path::Path;
use std::process::{Command, Output};

use tempfile::tempdir;

#[test]
fn plain_public_key_krl_revokes_current_and_renewed_certificates() {
    let dir = tempdir().unwrap();
    let ca = dir.path().join("ca");
    let user = dir.path().join("user");
    run_ok(
        Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&ca),
    );
    run_ok(
        Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&user),
    );

    sign(&ca, &user, 1);
    let certificate = dir.path().join("user-cert.pub");
    let krl = dir.path().join("revoked.krl");
    run_ok(
        Command::new("ssh-keygen")
            .args(["-k", "-f"])
            .arg(&krl)
            .arg(dir.path().join("user.pub")),
    );
    run_ok(
        Command::new("ssh-keygen")
            .args(["-Q", "-l", "-f"])
            .arg(&krl),
    );

    assert_revoked(&krl, &dir.path().join("user.pub"));
    assert_revoked(&krl, &certificate);

    std::fs::remove_file(&certificate).unwrap();
    sign(&ca, &user, 2);
    assert_revoked(&krl, &certificate);
}

#[test]
fn plain_host_key_krl_revokes_current_and_renewed_host_certificates() {
    let dir = tempdir().unwrap();
    let ca = dir.path().join("ca");
    let host = dir.path().join("host");
    run_ok(
        Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&ca),
    );
    run_ok(
        Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&host),
    );

    sign_host(&ca, &host, 1);
    let certificate = dir.path().join("host-cert.pub");
    let krl = dir.path().join("revoked-hosts.krl");
    run_ok(
        Command::new("ssh-keygen")
            .args(["-k", "-f"])
            .arg(&krl)
            .arg(dir.path().join("host.pub")),
    );

    assert_revoked(&krl, &certificate);
    std::fs::remove_file(&certificate).unwrap();
    sign_host(&ca, &host, 2);
    assert_revoked(&krl, &certificate);
}

#[test]
fn empty_krl_is_valid_and_queryable() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("empty");
    let krl = dir.path().join("empty.krl");
    std::fs::write(&source, "").unwrap();

    run_ok(
        Command::new("ssh-keygen")
            .args(["-k", "-f"])
            .arg(&krl)
            .arg(&source),
    );
    run_ok(
        Command::new("ssh-keygen")
            .args(["-Q", "-l", "-f"])
            .arg(&krl),
    );
    assert!(!std::fs::read(&krl).unwrap().is_empty());
}

fn sign(ca: &Path, key: &Path, serial: u64) {
    run_ok(
        Command::new("ssh-keygen")
            .args(["-q", "-s"])
            .arg(ca)
            .args(["-I", "grafhome-test", "-n", "alice", "-V", "-1m:+1h", "-z"])
            .arg(serial.to_string())
            .arg(format!("{}.pub", key.display())),
    );
}

fn sign_host(ca: &Path, key: &Path, serial: u64) {
    run_ok(
        Command::new("ssh-keygen")
            .args(["-q", "-h", "-s"])
            .arg(ca)
            .args([
                "-I",
                "grafhome-host-test",
                "-n",
                "host.example.test",
                "-V",
                "-1m:+1h",
                "-z",
            ])
            .arg(serial.to_string())
            .arg(format!("{}.pub", key.display())),
    );
}

fn assert_revoked(krl: &Path, key: &Path) {
    let output = Command::new("ssh-keygen")
        .args(["-Q", "-f"])
        .arg(krl)
        .arg(key)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "expected {} to be revoked: {}",
        key.display(),
        diagnostics(&output)
    );
}

fn run_ok(command: &mut Command) {
    let output = command.output().unwrap();
    assert!(output.status.success(), "{}", diagnostics(&output));
}

fn diagnostics(output: &Output) -> String {
    format!(
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

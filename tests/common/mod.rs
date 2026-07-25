//! Shared helpers for integration tests that drive real OpenSSH tooling.
//!
//! Each integration test binary compiles its own copy of this module, so items
//! a given binary does not use are expected to be unused there.
#![allow(dead_code)]
#![cfg(unix)]

use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Whether a certificate certifies a host key or a user key.
pub enum CertKind {
    User,
    Host,
}

/// Resolve a real system executable from the inherited `PATH`.
///
/// Fixture shims are only ever prepended to a *child's* `PATH`, so the test
/// process itself still sees the genuine tools and cannot resolve its own
/// fakes. The executable bit is required so a same-named data file earlier in
/// `PATH` cannot shadow the tool and fail later with a bare exit code 126.
pub fn real_program(name: &str) -> PathBuf {
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|dir| dir.join(name))
        .find(|candidate| {
            candidate
                .metadata()
                .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        })
        .unwrap_or_else(|| panic!("{name} must be installed to run this test"))
}

/// Shell source for a shim that logs its arguments and then execs the real
/// `ssh-keygen`.
///
/// Callers use this to run genuine OpenSSH cryptography through `grafhome-ca`
/// while keeping the recorded call log that fixture assertions rely on. The
/// blanket passthrough is sound because `apply host` only invokes `-k` and
/// `-Q`; a flow that inspects fixture stub keys with `-L` would need a
/// selective shim instead. The resolved path is single-quoted because it is
/// spliced into shell source.
pub fn real_ssh_keygen_shim() -> String {
    format!(
        r#"#!/bin/sh
set -eu
printf 'ssh-keygen args=%s\n' "$*" >> "$FAKE_LOG"
exec '{}' "$@"
"#,
        real_program("ssh-keygen").display()
    )
}

pub fn ssh_keygen(args: &[&OsStr]) -> Output {
    Command::new(real_program("ssh-keygen"))
        .args(args)
        .output()
        .unwrap()
}

/// Generate an unencrypted ed25519 key pair at `path` and `<path>.pub`.
pub fn generate_key(path: &Path) {
    let output = ssh_keygen(&[
        "-q".as_ref(),
        "-t".as_ref(),
        "ed25519".as_ref(),
        "-N".as_ref(),
        "".as_ref(),
        "-C".as_ref(),
        "grafhome-revocation-test".as_ref(),
        "-f".as_ref(),
        path.as_ref(),
    ]);
    assert!(output.status.success(), "{output:?}");
}

/// Public key in the canonical `<type> <base64>` form policy requires, which
/// omits the trailing comment `ssh-keygen` writes.
pub fn canonical_public_key(private_key: &Path) -> String {
    let text = fs::read_to_string(public_key_path(private_key)).unwrap();
    let mut fields = text.split_whitespace();
    let algorithm = fields.next().expect("public key algorithm");
    let material = fields.next().expect("public key material");
    format!("{algorithm} {material}")
}

/// OpenSSH SHA-256 fingerprint of `<private_key>.pub`, in the form policy
/// records and validates against the public key.
pub fn key_fingerprint(private_key: &Path) -> String {
    let output = ssh_keygen(&[
        "-l".as_ref(),
        "-f".as_ref(),
        public_key_path(private_key).as_ref(),
    ]);
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .nth(1)
        .expect("fingerprint field")
        .to_owned()
}

pub fn public_key_path(private_key: &Path) -> PathBuf {
    PathBuf::from(format!("{}.pub", private_key.display()))
}

pub fn certificate_path(private_key: &Path) -> PathBuf {
    PathBuf::from(format!("{}-cert.pub", private_key.display()))
}

/// Sign `key` with `ca`, writing `<key>-cert.pub`.
///
/// `serial` is explicit because revocation must hold across reissue: a later
/// certificate for a revoked key carries a fresh serial.
pub fn sign_certificate(ca: &Path, key: &Path, principal: &str, serial: u64, kind: CertKind) {
    let mut args: Vec<&OsStr> = vec!["-q".as_ref()];
    if matches!(kind, CertKind::Host) {
        args.push("-h".as_ref());
    }
    let serial = serial.to_string();
    let public_key = public_key_path(key);
    args.extend_from_slice(&[
        "-s".as_ref(),
        ca.as_ref(),
        "-I".as_ref(),
        "grafhome-revocation-test".as_ref(),
        "-n".as_ref(),
        principal.as_ref(),
        "-V".as_ref(),
        "-1m:+1h".as_ref(),
        "-z".as_ref(),
        serial.as_ref(),
        public_key.as_ref(),
    ]);
    let output = ssh_keygen(&args);
    assert!(output.status.success(), "{output:?}");
}

/// Ask OpenSSH whether `krl` revokes the single key or certificate in `key`.
///
/// `ssh-keygen -Q` exits 1 if *any* queried key is revoked and 0 only when all
/// are still allowed, so this helper deliberately queries one file at a time.
/// The per-key status line is checked as well because a usage error also exits
/// 1, which would otherwise read as a revocation.
pub fn krl_revokes(krl: &Path, key: &Path) -> bool {
    let output = ssh_keygen(&["-Q".as_ref(), "-f".as_ref(), krl.as_ref(), key.as_ref()]);
    let report = String::from_utf8_lossy(&output.stdout).into_owned();
    match output.status.code() {
        Some(1) if report.contains("REVOKED") => true,
        Some(0) if report.contains(": ok") => false,
        _ => panic!("could not query {}: {output:?}", krl.display()),
    }
}

/// Assert `krl` is a KRL OpenSSH accepts, which a plain-text key list is not.
pub fn assert_valid_krl(krl: &Path) {
    let output = ssh_keygen(&["-Q".as_ref(), "-l".as_ref(), "-f".as_ref(), krl.as_ref()]);
    assert!(
        output.status.success(),
        "{} is not a valid KRL: {output:?}",
        krl.display()
    );
}

//! Shared helpers for integration tests that drive real OpenSSH tooling.
//!
//! Each integration test binary compiles its own copy of this module, so items
//! a given binary does not use are expected to be unused there.
#![allow(dead_code)]
#![cfg(unix)]

use std::ffi::OsStr;
use std::fs;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Whether a certificate certifies a host key or a user key.
pub enum CertKind {
    User,
    Host,
}

/// Directories that hold `sshd` on distributions that keep it out of an
/// unprivileged `PATH`.
const SBIN_DIRS: [&str; 4] = ["/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/libexec"];

/// Resolve a real system executable from the inherited `PATH`.
///
/// Fixture shims are only ever prepended to a *child's* `PATH`, so the test
/// process itself still sees the genuine tools and cannot resolve its own
/// fakes. The executable bit is required so a same-named data file earlier in
/// `PATH` cannot shadow the tool and fail later with a bare exit code 126.
pub fn real_program(name: &str) -> PathBuf {
    find_program(name).unwrap_or_else(|| panic!("{name} must be installed to run this test"))
}

/// Locate `sshd`, which unprivileged accounts frequently cannot reach through
/// `PATH` alone. `sshd` refuses to daemonize unless it was started through an
/// absolute path, so callers need the resolved location either way.
pub fn find_sshd() -> Option<PathBuf> {
    find_program("sshd").or_else(|| {
        SBIN_DIRS
            .iter()
            .map(|dir| Path::new(dir).join("sshd"))
            .find(|candidate| is_executable(candidate))
    })
}

fn find_program(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|dir| dir.join(name))
        .find(|candidate| is_executable(candidate))
}

fn is_executable(candidate: &Path) -> bool {
    candidate
        .metadata()
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
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

/// A throwaway `sshd` listening on the loopback interface.
///
/// The server runs as the invoking account rather than root, so it can only
/// authenticate that same account. That is the arrangement Termux uses on a
/// phone, and it lets the test exercise a genuine server without privileges.
pub struct SshServer {
    child: Child,
    port: u16,
    log: PathBuf,
}

impl SshServer {
    /// Start `sshd` with `config` and wait until it answers on its port.
    pub fn start(sshd: &Path, config: &Path, port: u16, log: PathBuf) -> Self {
        let handle = fs::File::create(&log).unwrap();
        // sshd refuses to daemonize unless it was started through an absolute
        // path, so callers resolve the binary before getting here.
        let child = Command::new(sshd)
            .arg("-D")
            .arg("-e")
            .arg("-f")
            .arg(config)
            .stdin(Stdio::null())
            .stdout(Stdio::from(handle.try_clone().unwrap()))
            .stderr(Stdio::from(handle))
            .spawn()
            .unwrap_or_else(|err| panic!("could not start {}: {err}", sshd.display()));
        let mut server = Self { child, port, log };
        server.wait_until_listening();
        server
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn log(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Wait for sshd's own readiness line rather than for the port to accept.
    ///
    /// The port is only reserved by binding and releasing it, so another
    /// process can win the race. A successful connection would then prove
    /// nothing about which server answered; sshd announcing the port it bound
    /// is both a readiness and an identity signal, and it turns a collision
    /// into an early exit this loop reports verbatim.
    fn wait_until_listening(&mut self) {
        let ready = format!("Server listening on 127.0.0.1 port {}.", self.port);
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!("sshd exited early with {status}: {}", self.log());
            }
            if self.log().contains(&ready) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("sshd did not listen on port {}: {}", self.port, self.log());
    }
}

impl Drop for SshServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Reserve a loopback port by binding and immediately releasing it.
pub fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

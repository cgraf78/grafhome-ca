//! Grafhome CA policy, enrollment, and certificate CLI.

use std::collections::{BTreeMap, BTreeSet};
#[cfg(unix)]
use std::fs::File;
use std::io::{BufRead, IsTerminal, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};
use std::time::Duration;

use clap::{Parser, Subcommand};
use fs2::FileExt;
use grafhome_ca::enrollment::{
    HostGrant, HostRequest, UserGrant, UserRequest, host_provisioner_name,
    parse_host_provisioner_name, parse_user_provisioner_name, user_provisioner_host_suffix,
    user_provisioner_name, user_provisioner_prefix,
};
use grafhome_ca::executable::{root_step_bin, user_step_bin};
use grafhome_ca::model::SiteModel;
use grafhome_ca::policy::{
    ENDPOINT_ROLE_CA_API, ENDPOINT_ROLE_CA_ORIGIN, Endpoint, Host, PROVISIONER_ROLE_HOST_BOOTSTRAP,
    PROVISIONER_ROLE_USER_ENROLLMENT, Provisioner, STEP_EFFECTIVE_UNLIMITED_TTL, SshRole,
    UNLIMITED_TTL, User, UserClient, ca_policy_field, duration_at_most, host_policy_field,
    user_policy_field, valid_step_duration_expression,
};

const USER_KEY_NAME: &str = "id_ed25519";
const LOCAL_HOST_ENV: &str = "GRAFHOME_CA_LOCAL_HOST";
const LOCAL_USER_ENV: &str = "GRAFHOME_CA_LOCAL_USER";
const SYSTEM_SSH_DIR: &str = "GRAFHOME_CA_SYSTEM_SSH_DIR";
const AUTH_PRINCIPALS_FILE: &str = "GRAFHOME_CA_AUTH_PRINCIPALS_FILE";
const AUTHORIZED_KEYS_DIRECTIVE: &str = "GRAFHOME_CA_AUTHORIZED_KEYS_DIRECTIVE";
const STRICT_MODES: &str = "GRAFHOME_CA_STRICT_MODES";
const HOST_SSH_KEYGEN_BIN: &str = "GRAFHOME_CA_HOST_SSH_KEYGEN_BIN";
const HOST_SSHD_BIN: &str = "GRAFHOME_CA_HOST_SSHD_BIN";
const HOST_SSH_RELOAD_BIN: &str = "GRAFHOME_CA_HOST_SSH_RELOAD_BIN";
const HOST_SSH_SERVICE_DIR: &str = "GRAFHOME_CA_HOST_SSH_SERVICE_DIR";
#[cfg(target_os = "android")]
const ANDROID_RENEWAL_CREDENTIAL_NAME: &str = "renewal-password.secret";
const DEFAULT_ENROLLMENT_TOKEN_TTL: &str = "15m";
const CA_HEALTH_RETRY_ATTEMPTS: usize = 30;
const CA_HEALTH_RETRY_DELAY: Duration = Duration::from_secs(1);
const CA_HEALTH_CONSECUTIVE_SUCCESSES: usize = 2;
const CA_REACHABILITY_TIMEOUT: Duration = Duration::from_secs(3);
#[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
const SYSTEMD_RENEWAL_CREDENTIAL_NAME: &str = "grafhome-ca-renewal";

macro_rules! outln {
    ($($arg:tt)*) => {
        write_stdout(format_args!($($arg)*))?
    };
}

#[derive(Debug, Parser)]
#[command(name = "grafhome-ca")]
#[command(about = "Grafhome CA policy, enrollment, and certificate tooling")]
#[command(version = grafhome_ca::version::cli())]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print the generated build version.
    Version,
    /// Validate site config and policy.
    Check {
        /// Site config root containing config/ and policy/.
        #[arg(long, value_name = "DIR")]
        config_root: Option<PathBuf>,
    },
    /// Render non-secret deployment files into a staging directory.
    Render {
        /// Site config root containing config/ and policy/.
        #[arg(long, value_name = "DIR")]
        config_root: Option<PathBuf>,
        /// Output directory for rendered staging files.
        #[arg(long, required_unless_present = "dry_run")]
        out_dir: Option<PathBuf>,
        /// Show rendered paths without writing files.
        #[arg(long)]
        dry_run: bool,
        /// Remove stale files under the output directory before writing.
        #[arg(long, conflicts_with = "dry_run")]
        clean: bool,
    },
    /// Export public CA trust material into a staging directory.
    Export {
        /// Site config root containing config/ and policy/.
        #[arg(long, value_name = "DIR")]
        config_root: Option<PathBuf>,
        /// Output directory for exported public trust material.
        #[arg(long, required_unless_present = "dry_run")]
        out_dir: Option<PathBuf>,
        /// Show exported paths without writing files.
        #[arg(long)]
        dry_run: bool,
    },
    /// Print a JSON fixture with JWK placeholders materialized for tests.
    #[command(hide = true)]
    MaterializeTestCaFixture {
        /// Site config root containing config/ and policy/.
        #[arg(long, value_name = "DIR")]
        config_root: Option<PathBuf>,
    },
    /// Materialize runtime JWK provisioners into a rendered CA config.
    Materialize {
        /// Site config root containing config/ and policy/.
        #[arg(long, value_name = "DIR")]
        config_root: Option<PathBuf>,
        /// Live Smallstep ca.json created by `step ca init`.
        #[arg(long, value_name = "FILE")]
        live_ca_json: PathBuf,
        /// Staged rendered ca.json containing runtime placeholders.
        #[arg(long, value_name = "FILE")]
        staged_ca_json: PathBuf,
        /// Directory containing encrypted JWK files named <provisioner>.pub.json and <provisioner>.priv.json.
        #[arg(long, value_name = "DIR")]
        jwk_dir: PathBuf,
        /// Write materialized ca.json to this file with owner-only permissions.
        #[arg(long, value_name = "FILE")]
        out_file: PathBuf,
    },
    /// Run an explicit one-time state migration.
    Migrate {
        #[command(subcommand)]
        command: MigrateCommand,
    },
    /// Apply current policy to a local host.
    Apply {
        #[command(subcommand)]
        command: ApplyCommand,
    },
    /// Approve a public enrollment request on the CA origin.
    Approve {
        #[command(subcommand)]
        command: ApproveCommand,
    },
    /// Enroll a host or user using a grant read from stdin by default.
    Enroll {
        #[command(subcommand)]
        command: EnrollCommand,
    },
    /// Renew a host or user SSH certificate.
    Renew {
        #[command(subcommand)]
        command: RenewCommand,
    },
    /// Disable future issuance and renewal for a host or user.
    Revoke {
        #[command(subcommand)]
        command: RevokeCommand,
    },
    /// Report enrollment and local renewal readiness from live CA state.
    Status {
        /// Site config root containing config/ and policy/.
        #[arg(long, value_name = "DIR")]
        config_root: Option<PathBuf>,
        /// Policy user. With no filters, defaults to GRAFHOME_CA_LOCAL_USER, then the current non-root account.
        #[arg(long)]
        user: Option<String>,
        /// Policy host. With no filters, defaults to GRAFHOME_CA_LOCAL_HOST, then the short local hostname.
        #[arg(long)]
        host: Option<String>,
        /// Print nothing and exit unsuccessfully when the requested enrollment is absent.
        #[arg(long)]
        quiet: bool,
        /// Also require the local credential material needed for unattended renewal.
        #[arg(long)]
        renewable: bool,
    },
}

#[derive(Debug, Subcommand)]
enum MigrateCommand {
    /// Convert legacy six-file policy into the canonical host-centric layout.
    Policy {
        /// Legacy site config root containing config/ and policy/.
        #[arg(long, value_name = "DIR")]
        config_root: Option<PathBuf>,
        /// New policy directory to create atomically.
        #[arg(long, value_name = "DIR")]
        out_dir: PathBuf,
    },
    /// Prepare enrollment signing JWK files with separate passwords for materialization.
    EnrollmentProvisionerKeys {
        /// Site config root containing config/ and policy/.
        #[arg(long, value_name = "DIR")]
        config_root: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum ApplyCommand {
    /// Reconcile live Smallstep CA policy with site policy.
    Ca {
        /// Site config root containing config/ and policy/.
        #[arg(long, value_name = "DIR")]
        config_root: Option<PathBuf>,
        /// Show affected authority and provisioner policy without changing the CA.
        #[arg(long)]
        dry_run: bool,
    },
    /// Reconcile this host's Grafhome-managed OpenSSH policy.
    Host {
        /// Site config root containing config/ and policy/.
        #[arg(long, value_name = "DIR")]
        config_root: Option<PathBuf>,
        /// Local policy host identity instead of hostname or environment inference.
        #[arg(long)]
        host: Option<String>,
        /// Show changes without writing files or reloading SSH.
        #[arg(long)]
        dry_run: bool,
        /// Exit successfully when this host has no local renewal enrollment.
        #[arg(long)]
        if_enrolled: bool,
        /// Suppress routine success and no-op output while preserving errors.
        #[arg(long, conflicts_with = "dry_run")]
        quiet: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ApproveCommand {
    /// Approve a public host enrollment request.
    Host {
        /// Site config root containing config/ and policy/.
        #[arg(long, value_name = "DIR")]
        config_root: Option<PathBuf>,
        /// Read the public enrollment request from this file instead of stdin.
        #[arg(long, value_name = "FILE")]
        request_file: Option<PathBuf>,
        /// Enrollment token lifetime.
        #[arg(long)]
        ttl: Option<String>,
        /// SSH host certificate lifetime.
        #[arg(long)]
        cert_ttl: Option<String>,
        /// Approve without an interactive confirmation (for automation).
        #[arg(long)]
        yes: bool,
    },
    /// Approve a public user enrollment request.
    User {
        /// Site config root containing config/ and policy/.
        #[arg(long, value_name = "DIR")]
        config_root: Option<PathBuf>,
        /// Read the public enrollment request from this file instead of stdin.
        #[arg(long, value_name = "FILE")]
        request_file: Option<PathBuf>,
        /// Enrollment token lifetime.
        #[arg(long)]
        ttl: Option<String>,
        /// SSH user certificate lifetime.
        #[arg(long, conflicts_with = "effectively_infinite")]
        cert_ttl: Option<String>,
        /// Issue the allowlisted user/client an effectively-infinite certificate.
        #[arg(long)]
        effectively_infinite: bool,
        /// Approve without an interactive confirmation (for automation).
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
enum EnrollCommand {
    /// Enroll this host.
    Host {
        /// Site config root containing config/ and policy/.
        #[arg(long, value_name = "DIR")]
        config_root: Option<PathBuf>,
        /// Host policy name. Defaults to GRAFHOME_CA_LOCAL_HOST, then the short local hostname.
        #[arg(long)]
        host: Option<String>,
        /// Read the host enrollment grant from this file instead of stdin.
        #[arg(long, value_name = "FILE")]
        grant_file: Option<PathBuf>,
        /// Emit the public request and exit instead of waiting for a grant.
        #[arg(long)]
        request_only: bool,
        /// Rebuild and reprint the pending request without replacing enrollment keys.
        #[arg(long, conflicts_with = "grant_file")]
        restart: bool,
    },
    /// Start or complete user enrollment on this client host.
    User {
        /// Site config root containing config/ and policy/.
        #[arg(long, value_name = "DIR")]
        config_root: Option<PathBuf>,
        /// User policy name. Defaults to GRAFHOME_CA_LOCAL_USER, then the current account.
        #[arg(long)]
        user: Option<String>,
        /// Client host policy name. Defaults to GRAFHOME_CA_LOCAL_HOST, then the short local hostname.
        #[arg(long)]
        host: Option<String>,
        /// Complete enrollment using this grant instead of reading stdin.
        #[arg(long, value_name = "FILE")]
        grant_file: Option<PathBuf>,
        /// Read the user-owned provisioner password from this file instead of stdin.
        #[arg(long, value_name = "FILE")]
        password_file: Option<PathBuf>,
        /// Emit the public request and exit instead of waiting for a grant.
        #[arg(long)]
        request_only: bool,
        /// Rebuild and reprint the pending request without replacing enrollment keys.
        #[arg(long, conflicts_with = "grant_file")]
        restart: bool,
    },
}

#[derive(Debug, Subcommand)]
enum RenewCommand {
    /// Renew this host's SSH certificate.
    Host {
        /// Site config root containing config/ and policy/.
        #[arg(long, value_name = "DIR")]
        config_root: Option<PathBuf>,
        /// Host policy name. Defaults to GRAFHOME_CA_LOCAL_HOST, then the short local hostname.
        #[arg(long)]
        host: Option<String>,
        /// Exit successfully without output unless this host is enrolled and renewable.
        #[arg(long)]
        if_enrolled: bool,
        /// Exit successfully without output while the configured CA endpoint is unreachable.
        #[arg(long)]
        if_reachable: bool,
        /// Suppress successful renewal output. Errors are still reported.
        #[arg(long)]
        quiet: bool,
    },
    /// Renew this user's SSH certificate.
    User {
        /// Site config root containing config/ and policy/.
        #[arg(long, value_name = "DIR")]
        config_root: Option<PathBuf>,
        /// User policy name. Defaults to GRAFHOME_CA_LOCAL_USER, then the current account.
        #[arg(long)]
        user: Option<String>,
        /// Client host policy name. Defaults to GRAFHOME_CA_LOCAL_HOST, then the short local hostname.
        #[arg(long)]
        host: Option<String>,
        /// Read the user-owned provisioner password from this file instead of stored credentials.
        #[arg(long, value_name = "FILE")]
        password_file: Option<PathBuf>,
        /// Exit successfully without output unless this user is enrolled and renewable.
        #[arg(long)]
        if_enrolled: bool,
        /// Exit successfully without output while the configured CA endpoint is unreachable.
        #[arg(long)]
        if_reachable: bool,
        /// Suppress successful renewal output. Errors are still reported.
        #[arg(long)]
        quiet: bool,
    },
}

#[derive(Debug, Subcommand)]
enum RevokeCommand {
    /// Disable issuance and renewal for one host.
    Host {
        /// Site config root containing config/ and policy/.
        #[arg(long, value_name = "DIR")]
        config_root: Option<PathBuf>,
        /// Policy host to revoke.
        #[arg(long)]
        host: String,
    },
    /// Disable issuance and renewal for one user's enrolled clients.
    User {
        /// Site config root containing config/ and policy/.
        #[arg(long, value_name = "DIR")]
        config_root: Option<PathBuf>,
        /// Policy user to revoke.
        #[arg(long)]
        user: String,
        /// Revoke only the client on this host. Omit to revoke every client.
        #[arg(long)]
        host: Option<String>,
    },
}

fn main() {
    if let Err(error) = run() {
        eprintln!("grafhome-ca: {error}");
        std::process::exit(1);
    }
}

fn run() -> grafhome_ca::Result<()> {
    match Cli::parse().command {
        Command::Version => {
            outln!("grafhome-ca {}", grafhome_ca::version::cli());
            Ok(())
        }
        Command::Check { config_root } => {
            let config_root = resolve_config_root(config_root)?;
            let model = SiteModel::load(&config_root)?;
            grafhome_ca::schema::validate_config_root(&config_root)?;
            outln!(
                "ok: config and policy valid; ca_api={} ca_origin={}",
                model
                    .policy
                    .endpoint(ENDPOINT_ROLE_CA_API)
                    .expect("validated endpoint")
                    .url(),
                model
                    .policy
                    .endpoint(ENDPOINT_ROLE_CA_ORIGIN)
                    .expect("validated endpoint")
                    .url()
            );
            Ok(())
        }
        Command::Render {
            config_root,
            out_dir,
            dry_run,
            clean,
        } => {
            let config_root = resolve_config_root(config_root)?;
            let model = SiteModel::load(&config_root)?;
            grafhome_ca::schema::validate_config_root(&config_root)?;
            let files = grafhome_ca::render::render(&model)?;
            if dry_run {
                for file in &files {
                    outln!("{:04o}\t{}", file.mode, file.path.display());
                }
            } else {
                let out_dir = out_dir.expect("clap requires --out-dir unless --dry-run");
                if clean {
                    grafhome_ca::render::write_clean(&files, &out_dir)?;
                } else {
                    grafhome_ca::render::write(&files, &out_dir)?;
                }
                outln!("rendered {} files under {}", files.len(), out_dir.display());
            }
            Ok(())
        }
        Command::Export {
            config_root,
            out_dir,
            dry_run,
        } => {
            let config_root = resolve_config_root(config_root)?;
            let model = SiteModel::load(&config_root)?;
            grafhome_ca::schema::validate_config_root(&config_root)?;
            if dry_run {
                let files = grafhome_ca::public_material::planned_files();
                for file in &files {
                    outln!("{:04o}\t{}", file.mode, file.path.display());
                }
            } else {
                let out_dir = out_dir.expect("clap requires --out-dir unless --dry-run");
                let files = grafhome_ca::public_material::collect(&model)?;
                grafhome_ca::public_material::write(&files, &out_dir)?;
                outln!(
                    "exported {} public files under {}",
                    files.len(),
                    out_dir.display()
                );
            }
            Ok(())
        }
        Command::MaterializeTestCaFixture { config_root } => {
            let config_root = resolve_config_root(config_root)?;
            let model = SiteModel::load(&config_root)?;
            grafhome_ca::schema::validate_config_root(&config_root)?;
            outln!(
                "{}",
                grafhome_ca::render::materialize_test_ca_fixture_json(&model)?
            );
            Ok(())
        }
        Command::Materialize {
            config_root,
            live_ca_json,
            staged_ca_json,
            jwk_dir,
            out_file,
        } => {
            let model = load_root_model(config_root, "materialize", false)?;
            with_ca_lock(&model, || {
                let step_bin = root_step_bin(&model)?;
                let text = grafhome_ca::runtime_provisioners::materialize(
                    &model,
                    &live_ca_json,
                    &staged_ca_json,
                    &jwk_dir,
                    &step_bin,
                )?;
                write_secret_file(&out_file, text.as_bytes())
            })
        }
        Command::Migrate {
            command: MigrateCommand::EnrollmentProvisionerKeys { config_root },
        } => {
            let model = load_root_model(config_root, "migrate enrollment provisioner keys", false)?;
            with_ca_lock(&model, || migrate_enrollment_provisioner_keys(&model))
        }
        Command::Migrate {
            command:
                MigrateCommand::Policy {
                    config_root,
                    out_dir,
                },
        } => {
            let config_root = resolve_config_root(config_root)?;
            if grafhome_ca::policy::format(&config_root)? != grafhome_ca::policy::Format::Legacy {
                return Err(grafhome_ca::Error::Validation {
                    field: "migrate policy".to_owned(),
                    message: "source already uses the canonical policy format".to_owned(),
                });
            }
            let model = load_valid_model_from_root(&config_root)?;
            grafhome_ca::policy::write_canonical(&model.policy, &out_dir)?;
            outln!("migrated canonical policy to {}", out_dir.display());
            outln!("note: legacy TOML comments are not preserved; review the generated policy");
            Ok(())
        }
        Command::Apply {
            command:
                ApplyCommand::Ca {
                    config_root,
                    dry_run,
                },
        } => {
            let model = load_root_model(config_root, "apply ca", false)?;
            apply_ca_policy(&model, dry_run)
        }
        Command::Apply {
            command:
                ApplyCommand::Host {
                    config_root,
                    host,
                    dry_run,
                    if_enrolled,
                    quiet,
                },
        } => {
            let model = load_host_model(config_root, "apply host", true)?;
            let host = resolve_host(host.as_deref())?;
            if if_enrolled && !local_renewal_ready(&model, None, Some(&host))? {
                return Ok(());
            }
            apply_host_policy(&model, &host, dry_run, quiet)
        }
        Command::Approve {
            command:
                ApproveCommand::Host {
                    config_root,
                    request_file,
                    ttl,
                    cert_ttl,
                    yes,
                },
        } => {
            let model = load_root_model(config_root, "approve host", false)?;
            let mut stdin = std::io::stdin().lock();
            let text = read_document_or_file(
                request_file.as_deref(),
                &mut stdin,
                "public host enrollment request",
            )?;
            let request: HostRequest =
                parse_enrollment_document(&text, "public host enrollment request")?;
            if !yes {
                confirm_host_approval(&request)?;
            }
            approve_host_enrollment(&model, &request, ttl.as_deref(), cert_ttl.as_deref())
        }
        Command::Enroll {
            command:
                EnrollCommand::Host {
                    config_root,
                    host,
                    grant_file,
                    request_only,
                    restart,
                },
        } => {
            let model = load_host_model(config_root, "enroll host", !request_only)?;
            enroll_host_flow(
                &model,
                host.as_deref(),
                grant_file.as_deref(),
                request_only,
                restart,
            )
        }
        Command::Renew {
            command:
                RenewCommand::Host {
                    config_root,
                    host,
                    if_enrolled,
                    if_reachable,
                    quiet,
                },
        } => {
            let model = load_host_model(config_root, "renew host", false)?;
            let host = resolve_host(host.as_deref())?;
            if if_enrolled && !local_renewal_ready(&model, None, Some(&host))? {
                return Ok(());
            }
            let Some(_lock) = try_renewal_lock(&host_renewal_lock_path(&model))? else {
                return renewal_already_running("host", if_enrolled || if_reachable || quiet);
            };
            if if_reachable && !ca_api_reachable(&model)? {
                return Ok(());
            }
            if if_enrolled && !status(&model, None, Some(&host), true, false)? {
                return Ok(());
            }
            let step_bin = root_step_bin(&model)?;
            if !ssh_certificate_needs_renewal(&step_bin, &host_cert_path(&model))? {
                return Ok(());
            }
            renew_host(&model, &host, quiet)
        }
        Command::Enroll {
            command:
                EnrollCommand::User {
                    config_root,
                    user,
                    host,
                    grant_file,
                    password_file,
                    request_only,
                    restart,
                },
        } => {
            let model = load_valid_model(config_root)?;
            enroll_user_flow(
                &model,
                user.as_deref(),
                host.as_deref(),
                grant_file.as_deref(),
                password_file.as_deref(),
                request_only,
                restart,
            )
        }
        Command::Approve {
            command:
                ApproveCommand::User {
                    config_root,
                    request_file,
                    ttl,
                    cert_ttl,
                    effectively_infinite,
                    yes,
                },
        } => {
            let model = load_root_model(config_root, "approve user", false)?;
            let mut stdin = std::io::stdin().lock();
            let text = read_document_or_file(
                request_file.as_deref(),
                &mut stdin,
                "public enrollment request",
            )?;
            let request: UserRequest =
                parse_enrollment_document(&text, "public enrollment request")?;
            request.validate()?;
            let approved_cert_ttl = user_approval_cert_ttl(
                &model,
                &request,
                cert_ttl.as_deref(),
                effectively_infinite,
            )?;
            if !yes {
                if effectively_infinite {
                    confirm_effectively_infinite_user_approval(&request)?;
                } else {
                    confirm_user_approval(&request)?;
                }
            }
            approve_user_enrollment(
                &model,
                &request,
                ttl.as_deref(),
                &approved_cert_ttl,
                effectively_infinite,
            )
        }
        Command::Revoke {
            command:
                RevokeCommand::User {
                    config_root,
                    user,
                    host,
                },
        } => {
            let model = load_root_model(config_root, "revoke user", false)?;
            revoke_user(&model, &user, host.as_deref())
        }
        Command::Revoke {
            command: RevokeCommand::Host { config_root, host },
        } => {
            let model = load_root_model(config_root, "revoke host", false)?;
            revoke_host(&model, &host)
        }
        Command::Status {
            config_root,
            user,
            host,
            quiet,
            renewable,
        } => {
            let (user, host) = resolve_status_scope(user, host)?;
            let mut model = load_valid_model(config_root)?;
            if user.is_none() && host.is_some() {
                localize_termux_host_model(&mut model)?;
            }
            let enrolled = status(&model, user.as_deref(), host.as_deref(), quiet, renewable)?;
            if quiet && !enrolled {
                std::process::exit(1);
            }
            Ok(())
        }
        Command::Renew {
            command:
                RenewCommand::User {
                    config_root,
                    user,
                    host,
                    password_file,
                    if_enrolled,
                    if_reachable,
                    quiet,
                },
        } => {
            let model = load_valid_model(config_root)?;
            let mut stdin = std::io::stdin().lock();
            let user = resolve_user(user.as_deref())?;
            let host = resolve_host(host.as_deref())?;
            let mut stored_password = None;
            if if_enrolled {
                match user_local_renewal_readiness(&model, &user, &host, password_file.is_none())? {
                    UserLocalRenewalReadiness::NotEnrolled => return Ok(()),
                    UserLocalRenewalReadiness::Ready { password } => {
                        stored_password = password;
                    }
                    UserLocalRenewalReadiness::CredentialUnavailable(error) => {
                        return Err(error);
                    }
                }
            }
            let Some(_lock) = try_renewal_lock(&user_renewal_lock_path(&model)?)? else {
                return renewal_already_running("user", if_enrolled || if_reachable || quiet);
            };
            if if_reachable && !ca_api_reachable(&model)? {
                return Ok(());
            }
            if if_enrolled && !status(&model, Some(&user), Some(&host), true, false)? {
                return Ok(());
            }
            if !user_certificate_needs_renewal(&model, &user, &host)? {
                return Ok(());
            }
            let password = match password_file.as_deref() {
                Some(file) => read_password_or_file(Some(file), &mut stdin, "renewal password")?,
                None => match stored_password {
                    Some(password) => password,
                    None => lookup_renewal_password(&user, &host)?,
                },
            };
            renew_user(&model, &user, Some(&host), &password, quiet)
        }
    }
}

fn resolve_config_root(config_root: Option<PathBuf>) -> grafhome_ca::Result<PathBuf> {
    match config_root {
        Some(path) => Ok(path),
        None => SiteModel::default_config_root(),
    }
}

fn load_valid_model(config_root: Option<PathBuf>) -> grafhome_ca::Result<SiteModel> {
    let config_root = resolve_config_root(config_root)?;
    load_valid_model_from_root(&config_root)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TermuxHostRuntime {
    home: PathBuf,
    prefix: PathBuf,
}

impl TermuxHostRuntime {
    fn detect() -> grafhome_ca::Result<Option<Self>> {
        if !termux_host_runtime_enabled() {
            return Ok(None);
        }
        let home = validate_termux_owned_directory(
            &required_absolute_env_path("HOME", "Termux host runtime")?,
            "HOME",
        )?;
        let prefix = validate_termux_owned_directory(
            &required_absolute_env_path("PREFIX", "Termux host runtime")?,
            "PREFIX",
        )?;
        validate_termux_tree(
            &home,
            &home.join(".config/grafhome/host-step"),
            "host credential directory",
        )?;
        validate_termux_tree(
            &home,
            &home.join(".ssh/grafhome"),
            "authorized principals directory",
        )?;
        validate_termux_tree(
            &prefix,
            &prefix.join("etc/ssh"),
            "OpenSSH configuration directory",
        )?;
        for executable in ["step-cli", "ssh-keygen", "sshd", "sv"] {
            validate_termux_executable(&prefix, executable)?;
        }
        Ok(Some(Self { home, prefix }))
    }

    fn localize(&self, model: &mut SiteModel) {
        let values = &mut model.deployment.values;
        values.insert(
            "GRAFHOME_CA_SERVER_STEPPATH".to_owned(),
            self.home
                .join(".config/grafhome/host-step")
                .to_string_lossy()
                .into_owned(),
        );
        values.insert(
            "GRAFHOME_CA_SSH_TRUST_DIR".to_owned(),
            self.prefix
                .join("etc/ssh/grafhome")
                .to_string_lossy()
                .into_owned(),
        );
        values.insert(
            "GRAFHOME_CA_AUTH_PRINCIPALS_DIR".to_owned(),
            self.home
                .join(".ssh/grafhome")
                .to_string_lossy()
                .into_owned(),
        );
        values.insert(
            AUTH_PRINCIPALS_FILE.to_owned(),
            self.home
                .join(".ssh/grafhome/termux-owner")
                .to_string_lossy()
                .into_owned(),
        );
        values.insert(
            AUTHORIZED_KEYS_DIRECTIVE.to_owned(),
            "AuthorizedKeysFile none".to_owned(),
        );
        values.insert(STRICT_MODES.to_owned(), "no".to_owned());
        values.insert(
            "GRAFHOME_CA_ROOT_STEP_BIN".to_owned(),
            self.prefix
                .join("bin/step-cli")
                .to_string_lossy()
                .into_owned(),
        );
        values.insert(
            "GRAFHOME_CA_HOST_KEY_PATH".to_owned(),
            self.prefix
                .join("etc/ssh/ssh_host_ed25519_key")
                .to_string_lossy()
                .into_owned(),
        );
        values.insert(
            SYSTEM_SSH_DIR.to_owned(),
            self.prefix.join("etc/ssh").to_string_lossy().into_owned(),
        );
        values.insert(
            HOST_SSH_KEYGEN_BIN.to_owned(),
            self.prefix
                .join("bin/ssh-keygen")
                .to_string_lossy()
                .into_owned(),
        );
        values.insert(
            HOST_SSHD_BIN.to_owned(),
            self.prefix.join("bin/sshd").to_string_lossy().into_owned(),
        );
        values.insert(
            HOST_SSH_RELOAD_BIN.to_owned(),
            self.prefix.join("bin/sv").to_string_lossy().into_owned(),
        );
        values.insert(
            HOST_SSH_SERVICE_DIR.to_owned(),
            self.prefix
                .join("var/service")
                .to_string_lossy()
                .into_owned(),
        );
    }

    fn prepare_private_directory(&self, directory: &Path, field: &str) -> grafhome_ca::Result<()> {
        let relative =
            directory
                .strip_prefix(&self.home)
                .map_err(|_| grafhome_ca::Error::Validation {
                    field: field.to_owned(),
                    message: format!("path must remain beneath HOME: {}", directory.display()),
                })?;
        let mut current = self.home.clone();
        for component in relative.components() {
            let std::path::Component::Normal(name) = component else {
                return Err(grafhome_ca::Error::Validation {
                    field: field.to_owned(),
                    message: format!(
                        "path must contain only normal components: {}",
                        directory.display()
                    ),
                });
            };
            current.push(name);
            let created = match std::fs::create_dir(&current) {
                Ok(()) => true,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
                Err(source) => return Err(grafhome_ca::Error::io(&current, source)),
            };
            let metadata = std::fs::symlink_metadata(&current)
                .map_err(|source| grafhome_ca::Error::io(&current, source))?;
            if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                return Err(grafhome_ca::Error::Validation {
                    field: field.to_owned(),
                    message: format!("path must be a real directory: {}", current.display()),
                });
            }
            #[cfg(unix)]
            if created {
                std::fs::set_permissions(&current, std::fs::Permissions::from_mode(0o700))
                    .map_err(|source| grafhome_ca::Error::io(&current, source))?;
            }
        }
        validate_termux_tree(&self.home, directory, field)
    }

    fn prepare_policy_directories(&self) -> grafhome_ca::Result<()> {
        let ssh_dir = self.home.join(".ssh");
        let principals_dir = ssh_dir.join("grafhome");
        let system_ssh_dir = self.prefix.join("etc/ssh");
        let directories = [
            (&ssh_dir, true),
            (&principals_dir, true),
            (&system_ssh_dir.join("grafhome"), true),
            (&system_ssh_dir.join("sshd_config.d"), false),
            (&system_ssh_dir.join("ssh_config.d"), false),
        ];
        for (path, normalize_mode) in directories {
            let created = match std::fs::create_dir(path) {
                Ok(()) => true,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
                Err(source) => return Err(grafhome_ca::Error::io(path, source)),
            };
            let metadata = std::fs::symlink_metadata(path)
                .map_err(|source| grafhome_ca::Error::io(path, source))?;
            if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                return Err(grafhome_ca::Error::Validation {
                    field: "Termux host runtime".to_owned(),
                    message: format!(
                        "authorized principals path must be a real directory: {}",
                        path.display()
                    ),
                });
            }
            #[cfg(unix)]
            if created || normalize_mode {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                    .map_err(|source| grafhome_ca::Error::io(path, source))?;
            }
        }
        validate_termux_tree(
            &self.home,
            &principals_dir,
            "authorized principals directory",
        )?;
        validate_termux_tree(
            &self.prefix,
            &system_ssh_dir,
            "OpenSSH configuration directory",
        )
    }
}

fn termux_host_runtime_enabled() -> bool {
    cfg!(target_os = "android") && nonempty_env("TERMUX_VERSION").is_some()
}

fn required_absolute_env_path(name: &str, field: &str) -> grafhome_ca::Result<PathBuf> {
    let path = std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| grafhome_ca::Error::Validation {
            field: field.to_owned(),
            message: format!("{name} must be set to an absolute path"),
        })?;
    if !path.is_absolute() {
        return Err(grafhome_ca::Error::Validation {
            field: field.to_owned(),
            message: format!("{name} must be set to an absolute path"),
        });
    }
    Ok(path)
}

fn validate_termux_owned_directory(path: &Path, name: &str) -> grafhome_ca::Result<PathBuf> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|source| grafhome_ca::Error::io(path, source))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(grafhome_ca::Error::Validation {
            field: "Termux host runtime".to_owned(),
            message: format!("{name} must name a real directory, not a symlink"),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let uid = rustix::process::geteuid().as_raw();
        if metadata.uid() != uid || metadata.permissions().mode() & 0o022 != 0 {
            return Err(grafhome_ca::Error::Validation {
                field: "Termux host runtime".to_owned(),
                message: format!(
                    "{name} must be owned by the invoking user and not writable by group or others"
                ),
            });
        }
    }
    std::fs::canonicalize(path).map_err(|source| grafhome_ca::Error::io(path, source))
}

fn validate_termux_descendant(root: &Path, path: &Path, name: &str) -> grafhome_ca::Result<()> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| grafhome_ca::Error::Validation {
            field: "Termux host runtime".to_owned(),
            message: format!("{name} must remain beneath {}", root.display()),
        })?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        let metadata = match std::fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(source) => return Err(grafhome_ca::Error::io(&current, source)),
        };
        if metadata.file_type().is_symlink() {
            return Err(grafhome_ca::Error::Validation {
                field: "Termux host runtime".to_owned(),
                message: format!("{name} must not contain symlinks: {}", current.display()),
            });
        }
        validate_termux_owned_metadata(&current, &metadata, name)?;
    }
    Ok(())
}

fn validate_termux_tree(root: &Path, path: &Path, name: &str) -> grafhome_ca::Result<()> {
    validate_termux_descendant(root, path, name)?;
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => return Err(grafhome_ca::Error::io(path, source)),
    };
    if !metadata.file_type().is_dir() {
        return Err(grafhome_ca::Error::Validation {
            field: "Termux host runtime".to_owned(),
            message: format!("{name} must be a directory: {}", path.display()),
        });
    }
    validate_termux_tree_entries(path, name)
}

fn validate_termux_tree_entries(path: &Path, name: &str) -> grafhome_ca::Result<()> {
    for entry in std::fs::read_dir(path).map_err(|source| grafhome_ca::Error::io(path, source))? {
        let entry = entry.map_err(|source| grafhome_ca::Error::io(path, source))?;
        let entry_path = entry.path();
        let metadata = std::fs::symlink_metadata(&entry_path)
            .map_err(|source| grafhome_ca::Error::io(&entry_path, source))?;
        if metadata.file_type().is_symlink() {
            return Err(grafhome_ca::Error::Validation {
                field: "Termux host runtime".to_owned(),
                message: format!("{name} must not contain symlinks: {}", entry_path.display()),
            });
        }
        validate_termux_owned_metadata(&entry_path, &metadata, name)?;
        if metadata.file_type().is_dir() {
            validate_termux_tree_entries(&entry_path, name)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_termux_owned_metadata(
    path: &Path,
    metadata: &std::fs::Metadata,
    name: &str,
) -> grafhome_ca::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let uid = rustix::process::geteuid().as_raw();
    if metadata.uid() != uid || metadata.permissions().mode() & 0o022 != 0 {
        return Err(grafhome_ca::Error::Validation {
            field: "Termux host runtime".to_owned(),
            message: format!(
                "{name} must be owned by the invoking user and not writable by group or others: {}",
                path.display()
            ),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_termux_owned_metadata(
    _path: &Path,
    _metadata: &std::fs::Metadata,
    _name: &str,
) -> grafhome_ca::Result<()> {
    Ok(())
}

fn validate_termux_executable(prefix: &Path, name: &str) -> grafhome_ca::Result<()> {
    let path = prefix.join("bin").join(name);
    validate_termux_descendant(prefix, &path, &format!("Termux executable {name}"))?;
    let metadata =
        std::fs::symlink_metadata(&path).map_err(|source| grafhome_ca::Error::io(&path, source))?;
    if !metadata.file_type().is_file() {
        return Err(grafhome_ca::Error::Validation {
            field: "Termux host runtime".to_owned(),
            message: format!("{} must be a regular file", path.display()),
        });
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(grafhome_ca::Error::Validation {
            field: "Termux host runtime".to_owned(),
            message: format!("{} must be executable", path.display()),
        });
    }
    Ok(())
}

fn localize_termux_host_model(model: &mut SiteModel) -> grafhome_ca::Result<()> {
    if let Some(runtime) = TermuxHostRuntime::detect()? {
        runtime.localize(model);
    }
    Ok(())
}

fn load_host_model(
    config_root: Option<PathBuf>,
    command: &str,
    requires_install_root: bool,
) -> grafhome_ca::Result<SiteModel> {
    let mut config_root = resolve_config_root(config_root)?;
    #[cfg(unix)]
    let trusted_uid = rustix::process::geteuid().as_raw();
    #[cfg(not(unix))]
    let trusted_uid = 0;
    let runtime = TermuxHostRuntime::detect()?;
    match runtime.as_ref() {
        Some(runtime) => {
            config_root = grafhome_ca::provenance::validate_config_root_beneath(
                &config_root,
                trusted_uid,
                &runtime.home,
            )?;
        }
        None => grafhome_ca::provenance::validate_config_root(&config_root, trusted_uid)?,
    }
    if runtime.is_none() {
        require_root_or_isolated_test(&config_root, trusted_uid, command, requires_install_root)?;
    }
    let mut model = load_valid_model_from_root(&config_root)?;
    if let Some(runtime) = runtime {
        runtime.localize(&mut model);
    }
    Ok(model)
}

fn load_root_model(
    config_root: Option<PathBuf>,
    command: &str,
    requires_install_root: bool,
) -> grafhome_ca::Result<SiteModel> {
    let config_root = resolve_config_root(config_root)?;
    #[cfg(unix)]
    let trusted_uid = rustix::process::geteuid().as_raw();
    #[cfg(not(unix))]
    let trusted_uid = 0;
    grafhome_ca::provenance::validate_config_root(&config_root, trusted_uid)?;
    require_root_or_isolated_test(&config_root, trusted_uid, command, requires_install_root)?;
    load_valid_model_from_root(&config_root)
}

fn require_root_or_isolated_test(
    config_root: &Path,
    trusted_uid: u32,
    command: &str,
    requires_install_root: bool,
) -> grafhome_ca::Result<()> {
    if trusted_uid == 0 {
        return Ok(());
    }
    let config_parent = config_root.parent().ok_or_else(|| root_required(command))?;
    let sandbox = if requires_install_root {
        let install_root = std::env::var_os("GRAFHOME_CA_INSTALL_ROOT")
            .map(PathBuf::from)
            .ok_or_else(|| root_required(command))?;
        install_root
            .parent()
            .ok_or_else(|| root_required(command))?
            .to_path_buf()
    } else {
        config_parent.to_path_buf()
    };
    let sandbox = std::fs::canonicalize(&sandbox).map_err(|_| root_required(command))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let metadata = std::fs::metadata(&sandbox).map_err(|_| root_required(command))?;
        if metadata.uid() != trusted_uid || metadata.permissions().mode() & 0o022 != 0 {
            return Err(root_required(command));
        }
    }

    let config_root = std::fs::canonicalize(config_root).map_err(|_| root_required(command))?;
    if !config_root.starts_with(&sandbox) {
        return Err(root_required(command));
    }
    let deployment =
        grafhome_ca::config::Deployment::load(config_root.join("config/deployment.env"))?;
    for key in [
        "GRAFHOME_CA_STATE_DIR",
        "GRAFHOME_CA_SERVER_STEPPATH",
        "GRAFHOME_CA_ROOT_STEP_BIN",
        "GRAFHOME_CA_HELPER_BIN",
        "GRAFHOME_CA_HOST_KEY_PATH",
        "GRAFHOME_CA_PASSWORD_FILE",
    ] {
        let path = Path::new(&deployment.values[key]);
        if !path.is_absolute() {
            return Err(root_required(command));
        }
        let resolved = resolve_location(path).map_err(|_| root_required(command))?;
        if !resolved.starts_with(&sandbox) {
            return Err(root_required(command));
        }
    }
    for executable in ["chmod", "chown", "ssh-keygen", "sshd", "systemctl"] {
        let resolved = resolve_executable(executable).ok_or_else(|| root_required(command))?;
        if !resolved.starts_with(&sandbox) {
            return Err(root_required(command));
        }
    }
    Ok(())
}

fn resolve_executable(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
        .and_then(|candidate| std::fs::canonicalize(candidate).ok())
}

fn resolve_location(path: &Path) -> std::io::Result<PathBuf> {
    let mut existing = path;
    let mut missing = Vec::new();
    while !existing.exists() {
        let name = existing.file_name().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "path has no existing ancestor",
            )
        })?;
        missing.push(name.to_owned());
        existing = existing.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "path has no existing ancestor",
            )
        })?;
    }
    let mut resolved = std::fs::canonicalize(existing)?;
    for component in missing.into_iter().rev() {
        resolved.push(component);
    }
    Ok(resolved)
}

fn root_required(command: &str) -> grafhome_ca::Error {
    grafhome_ca::Error::Validation {
        field: command.to_owned(),
        message: "must be run as root".to_owned(),
    }
}

fn load_valid_model_from_root(config_root: &Path) -> grafhome_ca::Result<SiteModel> {
    let model = SiteModel::load(config_root)?;
    grafhome_ca::schema::validate_config_root(config_root)?;
    Ok(model)
}

fn write_stdout(args: std::fmt::Arguments<'_>) -> grafhome_ca::Result<()> {
    let mut stdout = std::io::stdout().lock();
    if let Err(source) = stdout.write_fmt(args) {
        return handle_stdout_error(source);
    }
    if let Err(source) = stdout.write_all(b"\n") {
        return handle_stdout_error(source);
    }
    Ok(())
}

fn handle_stdout_error(source: std::io::Error) -> grafhome_ca::Result<()> {
    if source.kind() == std::io::ErrorKind::BrokenPipe {
        Ok(())
    } else {
        Err(grafhome_ca::Error::io("<stdout>", source))
    }
}

fn process(program: &str) -> ProcessCommand {
    ProcessCommand::new(program)
}

fn run_capture(command: &mut ProcessCommand) -> grafhome_ca::Result<Vec<u8>> {
    run_capture_redacted(command, &[])
}

fn run_capture_redacted(
    command: &mut ProcessCommand,
    redactions: &[&str],
) -> grafhome_ca::Result<Vec<u8>> {
    let debug = redacted_command(command, redactions);
    let output = command.output().map_err(|source| {
        grafhome_ca::Error::io(command.get_program().to_string_lossy().into_owned(), source)
    })?;
    if !output.status.success() {
        let stderr = redact_text(&String::from_utf8_lossy(&output.stderr), redactions);
        return Err(grafhome_ca::Error::Validation {
            field: "command".to_owned(),
            message: format!(
                "{debug} failed with {}; stderr: {}",
                output.status,
                stderr.trim()
            ),
        });
    }
    Ok(output.stdout)
}

fn run_status(command: &mut ProcessCommand) -> grafhome_ca::Result<()> {
    run_status_redacted(command, &[])
}

fn run_status_with_retries(
    label: &str,
    attempts: usize,
    delay: Duration,
    consecutive_successes_required: usize,
    mut build_command: impl FnMut() -> ProcessCommand,
) -> grafhome_ca::Result<()> {
    if attempts == 0 {
        return Err(grafhome_ca::Error::Validation {
            field: "command".to_owned(),
            message: format!("{label} was configured with zero attempts"),
        });
    }
    if consecutive_successes_required == 0 {
        return Err(grafhome_ca::Error::Validation {
            field: "command".to_owned(),
            message: format!("{label} was configured with zero required successes"),
        });
    }
    let mut last_error = None;
    let mut consecutive_successes = 0;
    for attempt in 1..=attempts {
        match run_capture_redacted(&mut build_command(), &[]) {
            Ok(_) => {
                consecutive_successes += 1;
                if consecutive_successes == consecutive_successes_required {
                    return Ok(());
                }
                if attempt < attempts {
                    std::thread::sleep(delay);
                }
            }
            Err(error) => {
                consecutive_successes = 0;
                last_error = Some(error.to_string());
                if attempt < attempts {
                    std::thread::sleep(delay);
                }
            }
        }
    }
    Err(grafhome_ca::Error::Validation {
        field: "command".to_owned(),
        message: format!(
            "{label} did not succeed after {attempts} attempts; last error: {}",
            last_error.unwrap_or_else(|| {
                format!(
                    "only {consecutive_successes} consecutive successful check(s), expected {consecutive_successes_required}"
                )
            })
        ),
    })
}

fn run_status_redacted(
    command: &mut ProcessCommand,
    redactions: &[&str],
) -> grafhome_ca::Result<()> {
    let debug = redacted_command(command, redactions);
    if redactions.iter().any(|value| !value.is_empty()) {
        let output = command.output().map_err(|source| {
            grafhome_ca::Error::io(command.get_program().to_string_lossy().into_owned(), source)
        })?;
        write_redacted_stream(std::io::stdout().lock(), &output.stdout, redactions)?;
        write_redacted_stream(std::io::stderr().lock(), &output.stderr, redactions)?;
        if !output.status.success() {
            return Err(grafhome_ca::Error::Validation {
                field: "command".to_owned(),
                message: format!("{debug} failed with {}", output.status),
            });
        }
        return Ok(());
    }
    let status = command.stdin(Stdio::null()).status().map_err(|source| {
        grafhome_ca::Error::io(command.get_program().to_string_lossy().into_owned(), source)
    })?;
    if !status.success() {
        return Err(grafhome_ca::Error::Validation {
            field: "command".to_owned(),
            message: format!("{debug} failed with {status}"),
        });
    }
    Ok(())
}

fn run_status_quiet(
    command: &mut ProcessCommand,
    redactions: &[&str],
    quiet: bool,
) -> grafhome_ca::Result<()> {
    if !quiet {
        return run_status_redacted(command, redactions);
    }
    let debug = redacted_command(command, redactions);
    let output = command.output().map_err(|source| {
        grafhome_ca::Error::io(command.get_program().to_string_lossy().into_owned(), source)
    })?;
    if !output.status.success() {
        let stderr = redact_text(&String::from_utf8_lossy(&output.stderr), redactions);
        return Err(grafhome_ca::Error::Validation {
            field: "command".to_owned(),
            message: format!(
                "{debug} failed with {}; stderr: {}",
                output.status,
                stderr.trim()
            ),
        });
    }
    Ok(())
}

fn write_redacted_stream(
    mut writer: impl Write,
    content: &[u8],
    redactions: &[&str],
) -> grafhome_ca::Result<()> {
    if content.is_empty() {
        return Ok(());
    }
    let text = String::from_utf8_lossy(content);
    let text = redact_text(&text, redactions);
    writer
        .write_all(text.as_bytes())
        .map_err(|source| grafhome_ca::Error::io("<process output>", source))
}

fn redacted_command(command: &ProcessCommand, redactions: &[&str]) -> String {
    redact_text(&format!("{command:?}"), redactions)
}

fn redact_text(text: &str, redactions: &[&str]) -> String {
    redactions
        .iter()
        .filter(|value| !value.is_empty())
        .fold(text.to_owned(), |text, value| {
            text.replace(value, "[REDACTED]")
        })
}

fn read_secret_or_file(
    file: Option<&Path>,
    stdin: &mut impl BufRead,
    label: &str,
) -> grafhome_ca::Result<String> {
    let value = read_text_or_file(file, stdin, label)?;
    if value.is_empty() {
        return Err(grafhome_ca::Error::Validation {
            field: label.to_owned(),
            message: "value must not be empty".to_owned(),
        });
    }
    Ok(value)
}

fn read_password_or_file(
    file: Option<&Path>,
    stdin: &mut impl BufRead,
    label: &str,
) -> grafhome_ca::Result<String> {
    if let Some(file) = file {
        return read_secret_or_file(Some(file), stdin, label);
    }
    if std::io::stdin().is_terminal() {
        let value = rpassword::prompt_password(format!("{label}: "))
            .map_err(|source| grafhome_ca::Error::io("<stdin>", source))?;
        if value.is_empty() {
            return Err(grafhome_ca::Error::Validation {
                field: label.to_owned(),
                message: "value must not be empty".to_owned(),
            });
        }
        return Ok(value);
    }
    read_secret_or_file(None, stdin, label)
}

fn read_text_or_file(
    file: Option<&Path>,
    stdin: &mut impl BufRead,
    label: &str,
) -> grafhome_ca::Result<String> {
    let mut value = String::new();
    if let Some(file) = file {
        std::fs::File::open(file)
            .map_err(|source| grafhome_ca::Error::io(file, source))?
            .read_to_string(&mut value)
            .map_err(|source| grafhome_ca::Error::io(file, source))?;
    } else {
        eprint!("{label}: ");
        std::io::stderr()
            .flush()
            .map_err(|source| grafhome_ca::Error::io("<stderr>", source))?;
        stdin
            .read_line(&mut value)
            .map_err(|source| grafhome_ca::Error::io("<stdin>", source))?;
    }
    let value = value.trim_end_matches(['\r', '\n']).to_owned();
    if value.is_empty() {
        return Err(grafhome_ca::Error::Validation {
            field: label.to_owned(),
            message: "value must not be empty".to_owned(),
        });
    }
    Ok(value)
}

fn read_document_or_file(
    file: Option<&Path>,
    stdin: &mut impl BufRead,
    label: &str,
) -> grafhome_ca::Result<String> {
    let mut value = String::new();
    if let Some(file) = file {
        std::fs::File::open(file)
            .map_err(|source| grafhome_ca::Error::io(file, source))?
            .read_to_string(&mut value)
            .map_err(|source| grafhome_ca::Error::io(file, source))?;
    } else {
        let interactive = std::io::stdin().is_terminal();
        if interactive {
            eprint!("{label} (paste and press Enter): ");
        } else {
            eprint!("{label}: ");
        }
        std::io::stderr()
            .flush()
            .map_err(|source| grafhome_ca::Error::io("<stderr>", source))?;
        if interactive {
            value = read_interactive_terminal_document()?;
        } else {
            stdin
                .read_to_string(&mut value)
                .map_err(|source| grafhome_ca::Error::io("<stdin>", source))?;
        }
    }
    let value = value.trim_end_matches(['\r', '\n']).to_owned();
    if value.is_empty() {
        return Err(grafhome_ca::Error::Validation {
            field: label.to_owned(),
            message: "value must not be empty".to_owned(),
        });
    }
    Ok(value)
}

/// Read through the first complete enrollment document from a byte stream.
#[cfg(test)]
fn read_interactive_document(stdin: &mut impl Read) -> grafhome_ca::Result<String> {
    read_terminal_document(stdin, None, None)
}

/// Read a pasted document without the kernel's canonical line-size limit.
fn read_interactive_terminal_document() -> grafhome_ca::Result<String> {
    let mut terminal = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|source| grafhome_ca::Error::io("/dev/tty", source))?;
    let mode = NoncanonicalTerminalMode::enter(&terminal)?;
    let result = read_terminal_document(
        &mut terminal,
        Some(mode.interrupt_byte),
        Some(mode.eof_byte),
    );
    drop(mode);
    result
}

/// Restores terminal settings when document input finishes or unwinds.
struct NoncanonicalTerminalMode {
    terminal: rustix::fd::OwnedFd,
    original: rustix::termios::Termios,
    interrupt_byte: u8,
    eof_byte: u8,
}

impl NoncanonicalTerminalMode {
    fn enter(terminal: &std::fs::File) -> grafhome_ca::Result<Self> {
        use rustix::termios::{LocalModes, OptionalActions, SpecialCodeIndex};

        let original = rustix::termios::tcgetattr(terminal)
            .map_err(|source| grafhome_ca::Error::io("terminal attributes", source.into()))?;
        let interrupt_byte = original.special_codes[SpecialCodeIndex::VINTR];
        let eof_byte = original.special_codes[SpecialCodeIndex::VEOF];
        let terminal = rustix::io::dup(terminal)
            .map_err(|source| grafhome_ca::Error::io("/dev/tty", source.into()))?;
        let mut noncanonical = original.clone();
        noncanonical
            .local_modes
            .remove(LocalModes::ICANON | LocalModes::ISIG);
        noncanonical.special_codes[SpecialCodeIndex::VMIN] = 1;
        noncanonical.special_codes[SpecialCodeIndex::VTIME] = 0;
        rustix::termios::tcsetattr(&terminal, OptionalActions::Now, &noncanonical)
            .map_err(|source| grafhome_ca::Error::io("terminal attributes", source.into()))?;
        Ok(Self {
            terminal,
            original,
            interrupt_byte,
            eof_byte,
        })
    }
}

impl Drop for NoncanonicalTerminalMode {
    fn drop(&mut self) {
        let _ = rustix::termios::tcsetattr(
            &self.terminal,
            rustix::termios::OptionalActions::Now,
            &self.original,
        );
    }
}

fn read_terminal_document(
    input: &mut impl Read,
    interrupt_byte: Option<u8>,
    eof_byte: Option<u8>,
) -> grafhome_ca::Result<String> {
    let mut value = Vec::new();
    let mut complete = false;
    // Avoid consuming bytes after the terminating Enter. They belong to the
    // shell or to a later prompt, not to this document.
    let mut buffer = [0_u8; 1];
    loop {
        let bytes_read = input
            .read(&mut buffer)
            .map_err(|source| grafhome_ca::Error::io("<stdin>", source))?;
        if bytes_read == 0 {
            break;
        }
        for byte in &buffer[..bytes_read] {
            if Some(*byte) == interrupt_byte {
                return Err(grafhome_ca::Error::io(
                    "<stdin>",
                    std::io::Error::new(std::io::ErrorKind::Interrupted, "input interrupted"),
                ));
            }
            if Some(*byte) == eof_byte {
                return terminal_document_string(value);
            }
            if complete && matches!(*byte, b'\r' | b'\n') {
                value.push(*byte);
                return terminal_document_string(value);
            }
            value.push(*byte);
            if *byte == b'}' {
                complete = std::str::from_utf8(&value).is_ok_and(|text| {
                    parse_enrollment_document::<serde_json::Value>(text, "<stdin>").is_ok()
                });
            }
        }
    }
    terminal_document_string(value)
}

fn terminal_document_string(value: Vec<u8>) -> grafhome_ca::Result<String> {
    String::from_utf8(value).map_err(|error| grafhome_ca::Error::Validation {
        field: "<stdin>".to_owned(),
        message: format!("input was not valid UTF-8: {error}"),
    })
}

fn required_endpoint<'a>(model: &'a SiteModel, role: &str) -> grafhome_ca::Result<&'a Endpoint> {
    model
        .policy
        .endpoint(role)
        .ok_or_else(|| grafhome_ca::Error::Validation {
            field: ca_policy_field("endpoints", role, "role"),
            message: "missing required endpoint".to_owned(),
        })
}

fn ca_api_reachable(model: &SiteModel) -> grafhome_ca::Result<bool> {
    endpoint_reachable_with(
        required_endpoint(model, ENDPOINT_ROLE_CA_API)?,
        |address, timeout| TcpStream::connect_timeout(address, timeout).map(drop),
    )
}

fn endpoint_reachable_with(
    endpoint: &Endpoint,
    connect: impl FnOnce(&SocketAddr, Duration) -> std::io::Result<()>,
) -> grafhome_ca::Result<bool> {
    let address =
        endpoint
            .address
            .parse::<IpAddr>()
            .map_err(|error| grafhome_ca::Error::Validation {
                field: ca_policy_field("endpoints", &endpoint.role, "address"),
                message: format!("invalid IP address {}: {error}", endpoint.address),
            })?;
    let address = SocketAddr::new(address, endpoint.port);
    match connect(&address, CA_REACHABILITY_TIMEOUT) {
        Ok(()) => Ok(true),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::HostUnreachable
                    | std::io::ErrorKind::NetworkUnreachable
            ) =>
        {
            Ok(false)
        }
        Err(source) => Err(grafhome_ca::Error::io(
            format!("CA reachability probe {address}"),
            source,
        )),
    }
}

fn required_host<'a>(model: &'a SiteModel, host: &str) -> grafhome_ca::Result<&'a Host> {
    model
        .policy
        .host(host)
        .ok_or_else(|| grafhome_ca::Error::Validation {
            field: host_policy_field(host, "host"),
            message: "unknown host".to_owned(),
        })
}

fn active_user<'a>(model: &'a SiteModel, user: &str) -> grafhome_ca::Result<&'a User> {
    let user = model
        .policy
        .user(user)
        .ok_or_else(|| grafhome_ca::Error::Validation {
            field: user_policy_field(user, "user"),
            message: "unknown user".to_owned(),
        })?;
    if !user.status.is_active() {
        return Err(grafhome_ca::Error::Validation {
            field: user_policy_field(&user.user, "status"),
            message: "user must be active".to_owned(),
        });
    }
    Ok(user)
}

fn required_provisioner<'a>(
    model: &'a SiteModel,
    role: &str,
) -> grafhome_ca::Result<&'a Provisioner> {
    model
        .policy
        .provisioners
        .iter()
        .find(|entry| entry.role == role && entry.status.is_active())
        .ok_or_else(|| grafhome_ca::Error::Validation {
            field: ca_policy_field("provisioners", role, "role"),
            message: "missing active provisioner role".to_owned(),
        })
}

fn required_user_client<'a>(
    model: &'a SiteModel,
    user: &str,
    host: &str,
) -> grafhome_ca::Result<&'a UserClient> {
    model
        .policy
        .user_clients
        .iter()
        .find(|client| client.user == user && client.host == host && client.status.is_active())
        .ok_or_else(|| grafhome_ca::Error::Validation {
            field: host_policy_field(host, &format!("user_access.{user}.enrollment")),
            message: "missing active user client for user and host".to_owned(),
        })
}

fn select_single_user_client<'a>(
    model: &'a SiteModel,
    user: &str,
) -> grafhome_ca::Result<&'a UserClient> {
    let mut clients = model.policy.active_user_clients(user);
    let Some(client) = clients.next() else {
        return Err(grafhome_ca::Error::Validation {
            field: format!("policy/hosts:user_access.{user}.enrollment"),
            message: "user has no active client hosts".to_owned(),
        });
    };
    if clients.next().is_some() {
        return Err(grafhome_ca::Error::Validation {
            field: format!("policy/hosts:user_access.{user}.enrollment"),
            message: "user has multiple active client hosts; pass --host".to_owned(),
        });
    }
    Ok(client)
}

fn checked_ttl(field: &str, ttl: &str) -> grafhome_ca::Result<String> {
    if !valid_step_duration_expression(ttl) {
        return Err(grafhome_ca::Error::Validation {
            field: field.to_owned(),
            message: "duration must use Smallstep units such as 15m, 24h, 1.5h, or 2h45m"
                .to_owned(),
        });
    }
    Ok(ttl.to_owned())
}

fn ca_root_cert_path(model: &SiteModel) -> PathBuf {
    PathBuf::from(model.deployment.ca_steppath()).join("certs/root_ca.crt")
}

fn server_root_cert_path(model: &SiteModel) -> PathBuf {
    PathBuf::from(&model.deployment.values["GRAFHOME_CA_SERVER_STEPPATH"]).join("certs/root_ca.crt")
}

fn host_public_key_path(model: &SiteModel) -> PathBuf {
    PathBuf::from(format!(
        "{}.pub",
        model.deployment.values["GRAFHOME_CA_HOST_KEY_PATH"]
    ))
}

fn host_cert_path(model: &SiteModel) -> PathBuf {
    PathBuf::from(format!(
        "{}-cert.pub",
        model.deployment.values["GRAFHOME_CA_HOST_KEY_PATH"]
    ))
}

fn normalize_regular_file_mode(path: &Path, field: &str, mode: u32) -> grafhome_ca::Result<()> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|source| grafhome_ca::Error::io(path, source))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(grafhome_ca::Error::Validation {
            field: field.to_owned(),
            message: format!("output must be a regular file: {}", path.display()),
        });
    }
    #[cfg(unix)]
    {
        let expected_uid = rustix::process::geteuid().as_raw();
        if metadata.uid() != expected_uid {
            return Err(grafhome_ca::Error::Validation {
                field: field.to_owned(),
                message: format!(
                    "output must be owned by uid {expected_uid}: {}",
                    path.display()
                ),
            });
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|source| grafhome_ca::Error::io(path, source))?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    Ok(())
}

fn normalize_host_certificate_mode(model: &SiteModel) -> grafhome_ca::Result<()> {
    normalize_regular_file_mode(&host_cert_path(model), "host certificate", 0o644)
}

fn home_dir() -> grafhome_ca::Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| grafhome_ca::Error::Validation {
            field: "HOME".to_owned(),
            message: "HOME must be set for user enrollment commands".to_owned(),
        })
}

fn user_steppath(model: &SiteModel) -> grafhome_ca::Result<PathBuf> {
    Ok(home_dir()?.join(&model.deployment.values["GRAFHOME_CA_USER_STEPPATH"]))
}

fn user_root_cert_path(model: &SiteModel) -> grafhome_ca::Result<PathBuf> {
    Ok(user_steppath(model)?.join("certs/root_ca.crt"))
}

fn user_private_key_path() -> grafhome_ca::Result<PathBuf> {
    Ok(home_dir()?.join(".ssh").join(USER_KEY_NAME))
}

fn user_public_key_path() -> grafhome_ca::Result<PathBuf> {
    Ok(PathBuf::from(format!(
        "{}.pub",
        user_private_key_path()?.display()
    )))
}

fn user_cert_path() -> grafhome_ca::Result<PathBuf> {
    Ok(PathBuf::from(format!(
        "{}-cert.pub",
        user_private_key_path()?.display()
    )))
}

fn user_identity_paths() -> grafhome_ca::Result<[PathBuf; 3]> {
    Ok([
        user_private_key_path()?,
        user_public_key_path()?,
        user_cert_path()?,
    ])
}

fn user_client_material_dir(user: &str, host: &str) -> grafhome_ca::Result<PathBuf> {
    Ok(home_dir()?
        .join(".config/grafhome-ca/users")
        .join(user)
        .join("hosts")
        .join(host))
}

fn host_material_dir(model: &SiteModel, host: &str) -> PathBuf {
    PathBuf::from(&model.deployment.values["GRAFHOME_CA_SERVER_STEPPATH"])
        .join("secrets/hosts")
        .join(host)
}

fn enrollment_provisioner_dir(model: &SiteModel) -> PathBuf {
    PathBuf::from(&model.deployment.values["GRAFHOME_CA_STATE_DIR"]).join("secrets/provisioners")
}

fn enrollment_provisioner_private_key(model: &SiteModel, name: &str) -> PathBuf {
    enrollment_provisioner_dir(model).join(format!("{name}.priv.json"))
}

fn enrollment_provisioner_public_key(model: &SiteModel, name: &str) -> PathBuf {
    enrollment_provisioner_dir(model).join(format!("{name}.pub.json"))
}

fn enrollment_provisioner_password(model: &SiteModel, name: &str) -> PathBuf {
    enrollment_provisioner_dir(model).join(format!("{name}.password"))
}

fn enrollment_provisioner_credential(
    model: &SiteModel,
    name: &str,
) -> grafhome_ca::Result<(PathBuf, PathBuf)> {
    enrollment_provisioner_credential_in(model, &enrollment_provisioner_dir(model), name)
}

fn enrollment_provisioner_credential_in(
    model: &SiteModel,
    directory: &Path,
    name: &str,
) -> grafhome_ca::Result<(PathBuf, PathBuf)> {
    let private_key = directory.join(format!("{name}.priv.json"));
    let password = directory.join(format!("{name}.password"));
    for path in [&private_key, &password] {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|source| grafhome_ca::Error::io(path, source))?;
        if !metadata.file_type().is_file() {
            return Err(grafhome_ca::Error::Validation {
                field: path.display().to_string(),
                message: "enrollment provisioner credential must be a regular file".to_owned(),
            });
        }
        #[cfg(unix)]
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(grafhome_ca::Error::Validation {
                field: path.display().to_string(),
                message:
                    "enrollment provisioner credential must not be accessible by group or others"
                        .to_owned(),
            });
        }
        if std::fs::read(path)
            .map_err(|source| grafhome_ca::Error::io(path, source))?
            .is_empty()
        {
            return Err(grafhome_ca::Error::Validation {
                field: path.display().to_string(),
                message: "enrollment provisioner credential must not be empty".to_owned(),
            });
        }
    }
    let enrollment_password =
        std::fs::read(&password).map_err(|source| grafhome_ca::Error::io(&password, source))?;
    let intermediate_password_path =
        Path::new(&model.deployment.values["GRAFHOME_CA_PASSWORD_FILE"]);
    let intermediate_password = std::fs::read(intermediate_password_path)
        .map_err(|source| grafhome_ca::Error::io(intermediate_password_path, source))?;
    if enrollment_password == intermediate_password {
        return Err(grafhome_ca::Error::Validation {
            field: password.display().to_string(),
            message:
                "enrollment provisioner password must differ from the intermediate CA password"
                    .to_owned(),
        });
    }
    Ok((private_key, password))
}

fn live_provisioners<'a>(
    live: &'a serde_json::Value,
    ca_json: &Path,
) -> grafhome_ca::Result<&'a [serde_json::Value]> {
    live.pointer("/authority/provisioners")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| grafhome_ca::Error::Validation {
            field: format!("{}:authority.provisioners", ca_json.display()),
            message: "expected provisioners array".to_owned(),
        })
}

fn unique_live_provisioner<'a>(
    provisioners: &'a [serde_json::Value],
    name: &str,
    ca_json: &Path,
) -> grafhome_ca::Result<&'a serde_json::Value> {
    let matches = provisioners
        .iter()
        .filter(|item| item.get("name").and_then(serde_json::Value::as_str) == Some(name))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [live] => Ok(*live),
        [] => Err(grafhome_ca::Error::Validation {
            field: format!("{}:authority.provisioners", ca_json.display()),
            message: format!("live enrollment provisioner {name} is missing"),
        }),
        _ => Err(grafhome_ca::Error::Validation {
            field: format!("{}:authority.provisioners", ca_json.display()),
            message: format!("live enrollment provisioner {name} is duplicated"),
        }),
    }
}

fn migrate_enrollment_provisioner_keys(model: &SiteModel) -> grafhome_ca::Result<()> {
    let ca_json = PathBuf::from(model.deployment.ca_steppath()).join("config/ca.json");
    let text = std::fs::read_to_string(&ca_json)
        .map_err(|source| grafhome_ca::Error::io(&ca_json, source))?;
    let live: serde_json::Value =
        serde_json::from_str(&text).map_err(|source| grafhome_ca::Error::Json {
            path: ca_json.clone(),
            source,
        })?;
    let provisioners = live_provisioners(&live, &ca_json)?;
    let directory = enrollment_provisioner_dir(model);
    let directory_existed = directory.exists();
    let directory_parent = directory
        .parent()
        .expect("enrollment provisioner directory has a parent");
    let directory_parent_existed = directory_parent.exists();
    std::fs::create_dir_all(&directory)
        .map_err(|source| grafhome_ca::Error::io(&directory, source))?;
    #[cfg(unix)]
    {
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .map_err(|source| grafhome_ca::Error::io(&directory, source))?;
        if !directory_parent_existed {
            let state_dir = directory_parent
                .parent()
                .expect("CA secrets directory has a parent");
            File::open(state_dir)
                .and_then(|parent| parent.sync_all())
                .map_err(|source| grafhome_ca::Error::io(state_dir, source))?;
        }
        if !directory_existed {
            File::open(directory_parent)
                .and_then(|parent| parent.sync_all())
                .map_err(|source| grafhome_ca::Error::io(directory_parent, source))?;
        }
    }
    let old_password = Path::new(&model.deployment.values["GRAFHOME_CA_PASSWORD_FILE"]);
    let step_bin = root_step_bin(model)?;

    for role in [
        PROVISIONER_ROLE_HOST_BOOTSTRAP,
        PROVISIONER_ROLE_USER_ENROLLMENT,
    ] {
        let policy = required_provisioner(model, role)?;
        let public_path = enrollment_provisioner_public_key(model, &policy.name);
        let private_path = enrollment_provisioner_private_key(model, &policy.name);
        let password_path = enrollment_provisioner_password(model, &policy.name);
        let live = unique_live_provisioner(provisioners, &policy.name, &ca_json)?;
        let public = live
            .get("key")
            .ok_or_else(|| grafhome_ca::Error::Validation {
                field: format!("{}:{}:key", ca_json.display(), policy.name),
                message: "live enrollment provisioner public JWK is missing".to_owned(),
            })?;
        if password_path.exists() {
            grafhome_ca::runtime_provisioners::validate_enrollment_provisioner_key_files(
                model,
                &directory,
                &policy.name,
                public,
                Path::new(&step_bin),
            )?;
            outln!(
                "{} enrollment provisioner key already migrated",
                policy.name
            );
            continue;
        }
        let encrypted = live
            .get("encryptedKey")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| grafhome_ca::Error::Validation {
                field: format!("{}:{}:encryptedKey", ca_json.display(), policy.name),
                message:
                    "live encrypted key is unavailable; restore it from backup before migration"
                        .to_owned(),
            })?;

        let temp = tempfile::Builder::new()
            .prefix(".grafhome-ca-enrollment-key-migration-")
            .tempdir_in(&directory)
            .map_err(|source| grafhome_ca::Error::io(&directory, source))?;
        let source = temp.path().join("source.jwe");
        let plaintext = temp.path().join("plaintext.jwk");
        let migrated = temp.path().join("migrated.jwe");
        let new_password = temp.path().join("password");
        write_secret_file(&source, encrypted.as_bytes())?;
        run_status(
            process(&step_bin)
                .arg("crypto")
                .arg("key")
                .arg("format")
                .arg(&source)
                .arg("--jwk")
                .arg("--password-file")
                .arg(old_password)
                .arg("--out")
                .arg(&plaintext)
                .arg("--insecure")
                .arg("--no-password"),
        )?;
        let password = run_capture(
            process(&step_bin)
                .arg("crypto")
                .arg("rand")
                .arg("--format")
                .arg("hex")
                .arg("64"),
        )?;
        if password.is_empty()
            || password
                == std::fs::read(old_password)
                    .map_err(|source| grafhome_ca::Error::io(old_password, source))?
        {
            return Err(grafhome_ca::Error::Validation {
                field: "step crypto rand".to_owned(),
                message: "did not generate a distinct enrollment provisioner password".to_owned(),
            });
        }
        write_secret_file(&new_password, &password)?;
        let private: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&plaintext)
                .map_err(|source| grafhome_ca::Error::io(&plaintext, source))?,
        )
        .map_err(|source| grafhome_ca::Error::Json {
            path: plaintext.clone(),
            source,
        })?;
        let public_material = grafhome_ca::runtime_provisioners::validate_public_jwk(
            public,
            &format!("{}:{}:key", ca_json.display(), policy.name),
        )?;
        let private_material = grafhome_ca::runtime_provisioners::jwk_public_material(
            &private,
            &plaintext.display().to_string(),
        )?;
        if private_material != public_material {
            return Err(grafhome_ca::Error::Validation {
                field: format!("{}:{}:key", ca_json.display(), policy.name),
                message: "live public JWK does not match its encrypted private key".to_owned(),
            });
        }
        run_status(
            process(&step_bin)
                .arg("crypto")
                .arg("key")
                .arg("format")
                .arg(&plaintext)
                .arg("--jwk")
                .arg("--password-file")
                .arg(&new_password)
                .arg("--out")
                .arg(&migrated),
        )?;

        let public = serde_json::to_vec_pretty(public).expect("public JWK serializes");
        let migrated =
            std::fs::read(&migrated).map_err(|source| grafhome_ca::Error::io(&migrated, source))?;
        write_secret_file_atomic(&public_path, &public)?;
        write_secret_file_atomic(&private_path, &migrated)?;
        write_secret_file_atomic(&password_path, &password)?;
        grafhome_ca::runtime_provisioners::validate_enrollment_provisioner_key_files(
            model,
            &directory,
            &policy.name,
            live.get("key").expect("live public key was validated"),
            Path::new(&step_bin),
        )?;
        outln!("migrated {} enrollment provisioner key", policy.name);
    }
    Ok(())
}

fn host_enrollment_request_path(model: &SiteModel, host: &str) -> PathBuf {
    host_material_dir(model, host).join("pending-enrollment.json")
}

fn bootstrap_trust(
    step_bin: &str,
    steppath: &Path,
    ca_url: &str,
    fingerprint: &str,
) -> grafhome_ca::Result<()> {
    run_status(
        process(step_bin)
            .env("STEPPATH", steppath)
            .arg("ca")
            .arg("bootstrap")
            .arg("--ca-url")
            .arg(ca_url)
            .arg("--fingerprint")
            .arg(fingerprint)
            .arg("--force"),
    )?;
    run_status(
        process(step_bin)
            .env("STEPPATH", steppath)
            .arg("ca")
            .arg("health")
            .arg("--ca-url")
            .arg(ca_url),
    )
}

fn parse_enrollment_document<T: serde::de::DeserializeOwned>(
    text: &str,
    label: &str,
) -> grafhome_ca::Result<T> {
    let text =
        text.trim_matches(|character: char| character.is_whitespace() || character == '\u{feff}');
    let document = strip_enrollment_label(text).unwrap_or_else(|| {
        // Preserve paste-from-terminal convenience when a labeled one-line document
        // is surrounded by prompts or informational output.
        text.lines()
            .rev()
            .find_map(|line| strip_enrollment_label(line.trim()))
            .unwrap_or(text)
    });
    match serde_json::from_str(document) {
        Ok(value) => Ok(value),
        Err(source) => {
            let line_document = text
                .lines()
                .rev()
                .find_map(|line| strip_enrollment_label(line.trim()));
            if let Some(line_document) = line_document
                && line_document != document
            {
                return serde_json::from_str(line_document).map_err(|source| {
                    grafhome_ca::Error::Json {
                        path: PathBuf::from(label),
                        source,
                    }
                });
            }
            Err(grafhome_ca::Error::Json {
                path: PathBuf::from(label),
                source,
            })
        }
    }
}

fn strip_enrollment_label(text: &str) -> Option<&str> {
    let (prefix, document) = text.split_once(':')?;
    if prefix.trim().eq_ignore_ascii_case("REQUEST") || prefix.trim().eq_ignore_ascii_case("GRANT")
    {
        Some(document.trim())
    } else {
        None
    }
}

fn resolve_user(user: Option<&str>) -> grafhome_ca::Result<String> {
    user.map(ToOwned::to_owned)
        .or_else(|| nonempty_env(LOCAL_USER_ENV))
        .or_else(|| std::env::var("USER").ok())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| grafhome_ca::Error::Validation {
            field: "user enrollment".to_owned(),
            message: format!("could not determine the user; pass --user or set {LOCAL_USER_ENV}"),
        })
}

fn resolve_host(host: Option<&str>) -> grafhome_ca::Result<String> {
    if let Some(host) = host {
        return Ok(host.to_owned());
    }
    if let Some(host) = nonempty_env(LOCAL_HOST_ENV) {
        return Ok(host);
    }
    if let Ok(host) = std::env::var("HOSTNAME")
        && !host.trim().is_empty()
    {
        return Ok(host.split('.').next().unwrap_or(&host).to_owned());
    }
    let output = run_capture(&mut process("hostname"))?;
    let host = String::from_utf8_lossy(&output).trim().to_owned();
    if host.is_empty() {
        return Err(grafhome_ca::Error::Validation {
            field: "user enrollment".to_owned(),
            message: format!(
                "could not determine the client host; pass --host or set {LOCAL_HOST_ENV}"
            ),
        });
    }
    Ok(host.split('.').next().unwrap_or(&host).to_owned())
}

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn enrollment_request_path(user: &str, host: &str) -> grafhome_ca::Result<PathBuf> {
    Ok(user_client_material_dir(user, host)?.join("pending-enrollment.json"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExistingIdentityChoice {
    Use,
    Replace,
    Cancel,
}

fn prepare_existing_user_identity(
    paths: &[PathBuf],
    choose: impl FnOnce(&[PathBuf], bool) -> grafhome_ca::Result<ExistingIdentityChoice>,
    validate: impl FnOnce(&Path, &Path) -> grafhome_ca::Result<()>,
) -> grafhome_ca::Result<bool> {
    let mut existing = Vec::new();
    for path in paths {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_dir() => {
                return Err(grafhome_ca::Error::Validation {
                    field: path.display().to_string(),
                    message: "refusing to replace an SSH identity path that is a directory"
                        .to_owned(),
                });
            }
            Ok(_) => existing.push(path.clone()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(grafhome_ca::Error::io(path, source)),
        }
    }
    if existing.is_empty() {
        return Ok(true);
    }
    let reusable = paths.len() >= 2 && paths[0].is_file() && paths[1].is_file();
    match choose(&existing, reusable)? {
        ExistingIdentityChoice::Use if reusable => {
            validate(&paths[0], &paths[1])?;
            Ok(false)
        }
        ExistingIdentityChoice::Use => Err(grafhome_ca::Error::Validation {
            field: "user enrollment SSH identity".to_owned(),
            message: "cannot use the existing identity because both id_ed25519 and id_ed25519.pub are required"
                .to_owned(),
        }),
        ExistingIdentityChoice::Replace => {
            for path in existing {
                std::fs::remove_file(&path)
                    .map_err(|source| grafhome_ca::Error::io(&path, source))?;
            }
            Ok(true)
        }
        ExistingIdentityChoice::Cancel => Err(grafhome_ca::Error::Validation {
            field: "user enrollment SSH identity".to_owned(),
            message: "enrollment cancelled; existing SSH identity files were not changed"
                .to_owned(),
        }),
    }
}

fn validate_user_identity_pair(private_key: &Path, public_key: &Path) -> grafhome_ca::Result<()> {
    let derived = run_capture(process("ssh-keygen").arg("-y").arg("-f").arg(private_key))?;
    let configured = std::fs::read_to_string(public_key)
        .map_err(|source| grafhome_ca::Error::io(public_key, source))?;
    if !ssh_public_keys_match(&String::from_utf8_lossy(&derived), &configured) {
        return Err(grafhome_ca::Error::Validation {
            field: "user enrollment SSH identity".to_owned(),
            message: format!(
                "{} does not match {}; replace the identity or repair the public key",
                public_key.display(),
                private_key.display()
            ),
        });
    }
    Ok(())
}

fn ssh_public_keys_match(derived: &str, configured: &str) -> bool {
    let derived_fields: Vec<_> = derived.split_whitespace().take(2).collect();
    let configured_fields: Vec<_> = configured.split_whitespace().take(2).collect();
    derived_fields.len() == 2 && derived_fields == configured_fields
}

fn choose_existing_user_identity(
    existing: &[PathBuf],
    reusable: bool,
) -> grafhome_ca::Result<ExistingIdentityChoice> {
    eprintln!("The default OpenSSH identity already exists:");
    for path in existing {
        eprintln!("  {}", path.display());
    }
    if !reusable {
        eprintln!("Both id_ed25519 and id_ed25519.pub are required to reuse the identity.");
    }
    eprintln!("Replacing it may break unrelated SSH access that uses this key.");
    loop {
        let prompt = if reusable {
            "Use existing, replace, or cancel? [U/r/c] "
        } else {
            "Replace or cancel? [r/C] "
        };
        let answer = prompt_tty(prompt)?;
        match answer.trim().to_ascii_lowercase().as_str() {
            "" | "u" | "use" if reusable => return Ok(ExistingIdentityChoice::Use),
            "r" | "replace" => return Ok(ExistingIdentityChoice::Replace),
            "" | "c" | "cancel" => return Ok(ExistingIdentityChoice::Cancel),
            _ => eprintln!("Enter use, replace, or cancel."),
        }
    }
}

fn prepare_user_identity() -> grafhome_ca::Result<(PathBuf, bool)> {
    let paths = user_identity_paths()?;
    let generate = prepare_existing_user_identity(
        &paths,
        choose_existing_user_identity,
        validate_user_identity_pair,
    )?;
    Ok((paths[0].clone(), generate))
}

fn ensure_user_keys(
    model: &SiteModel,
    user_name: &str,
    host: &str,
    password: &str,
) -> grafhome_ca::Result<UserRequest> {
    let user = active_user(model, user_name)?;
    let client = required_user_client(model, &user.user, host)?;
    let private_key = user_private_key_path()?;
    let ssh_dir = private_key
        .parent()
        .ok_or_else(|| grafhome_ca::Error::Validation {
            field: "user key path".to_owned(),
            message: "missing parent directory".to_owned(),
        })?;
    std::fs::create_dir_all(ssh_dir).map_err(|source| grafhome_ca::Error::io(ssh_dir, source))?;
    #[cfg(unix)]
    std::fs::set_permissions(ssh_dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|source| grafhome_ca::Error::io(ssh_dir, source))?;
    let (private_key, generate) = prepare_user_identity()?;
    if generate {
        run_status(
            process("ssh-keygen")
                .arg("-t")
                .arg("ed25519")
                .arg("-N")
                .arg("")
                .arg("-f")
                .arg(&private_key),
        )?;
    }

    let material_dir = user_client_material_dir(&user.user, &client.host)?;
    std::fs::create_dir_all(&material_dir)
        .map_err(|source| grafhome_ca::Error::io(&material_dir, source))?;
    #[cfg(unix)]
    std::fs::set_permissions(&material_dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|source| grafhome_ca::Error::io(&material_dir, source))?;
    let public_jwk = material_dir.join("provisioner.pub.json");
    let private_jwk = material_dir.join("provisioner.priv.json");
    if !private_jwk.exists() {
        let step_bin = user_step_bin()?;
        with_password_file(&material_dir, password, |password_file| {
            run_status(
                process(&step_bin)
                    .arg("crypto")
                    .arg("jwk")
                    .arg("create")
                    .arg(&public_jwk)
                    .arg(&private_jwk)
                    .arg("--password-file")
                    .arg(password_file),
            )
        })?;
    } else {
        validate_renewal_password(&material_dir, &private_jwk, password)?;
    }
    #[cfg(unix)]
    {
        normalize_regular_file_mode(&private_jwk, "user renewal private JWK", 0o600)?;
        normalize_regular_file_mode(&public_jwk, "user renewal public JWK", 0o644)?;
    }
    user_request_from_material(model, &user.user, &client.host)
}

fn user_request_from_material(
    model: &SiteModel,
    user_name: &str,
    host: &str,
) -> grafhome_ca::Result<UserRequest> {
    let user = active_user(model, user_name)?;
    let client = required_user_client(model, &user.user, host)?;
    let private_key = user_private_key_path()?;
    let public_key = user_public_key_path()?;
    let material_dir = user_client_material_dir(&user.user, &client.host)?;
    let private_jwk = material_dir.join("provisioner.priv.json");
    let public_jwk = material_dir.join("provisioner.pub.json");
    for path in [&private_key, &public_key, &private_jwk, &public_jwk] {
        if !path.is_file() {
            return Err(grafhome_ca::Error::Validation {
                field: "enroll user --restart".to_owned(),
                message: format!(
                    "cannot restart because {} is missing; run enroll user without --restart",
                    path.display()
                ),
            });
        }
    }
    let ssh_public_key = std::fs::read_to_string(&public_key)
        .map_err(|source| grafhome_ca::Error::io("SSH public key", source))?;
    let renewal_public_jwk = serde_json::from_str(
        &std::fs::read_to_string(&public_jwk)
            .map_err(|source| grafhome_ca::Error::io(&public_jwk, source))?,
    )
    .map_err(|source| grafhome_ca::Error::Json {
        path: public_jwk,
        source,
    })?;
    let request = UserRequest::new(
        &user.user,
        &client.host,
        ssh_public_key.trim(),
        renewal_public_jwk,
    );
    request.validate()?;
    Ok(request)
}

fn validate_renewal_password(
    material_dir: &Path,
    private_jwk: &Path,
    password: &str,
) -> grafhome_ca::Result<()> {
    let step_bin = user_step_bin()?;
    with_password_file(material_dir, password, |password_file| {
        let input = std::fs::File::open(private_jwk)
            .map_err(|source| grafhome_ca::Error::io(private_jwk, source))?;
        let output = process(&step_bin)
            .arg("crypto")
            .arg("jwe")
            .arg("decrypt")
            .arg("--password-file")
            .arg(password_file)
            .stdin(Stdio::from(input))
            .output()
            .map_err(|source| grafhome_ca::Error::io(&step_bin, source))?;
        if !output.status.success() {
            return Err(grafhome_ca::Error::Validation {
                field: "renewal password".to_owned(),
                message: "does not unlock the existing renewal credential".to_owned(),
            });
        }
        Ok(())
    })
}

fn confirm_user_approval(request: &UserRequest) -> grafhome_ca::Result<()> {
    confirm_approval(
        &format!("{}@{}", request.user, request.host),
        "approve user",
    )
}

fn confirm_effectively_infinite_user_approval(request: &UserRequest) -> grafhome_ca::Result<()> {
    let fingerprint = ssh_public_key_fingerprint(&request.ssh_public_key)?;
    eprintln!("{}", effectively_infinite_warning(request, &fingerprint));
    require_effectively_infinite_confirmation(confirm_tty(
        "Approve effectively-infinite certificate? [y/N] ",
    )?)
}

fn effectively_infinite_warning(request: &UserRequest, fingerprint: &str) -> String {
    format!(
        "WARNING: effectively-infinite SSH user certificate\nUser: {}\nClient host: {}\nSSH key: {fingerprint}\nCA-side revocation will not invalidate this certificate; immediate revocation requires OpenSSH RevokedKeys distribution.",
        request.user, request.host
    )
}

fn require_effectively_infinite_confirmation(approved: bool) -> grafhome_ca::Result<()> {
    if approved {
        Ok(())
    } else {
        Err(grafhome_ca::Error::Validation {
            field: "approve user".to_owned(),
            message: "effectively-infinite certificate was not approved".to_owned(),
        })
    }
}

fn ssh_public_key_fingerprint(public_key: &str) -> grafhome_ca::Result<String> {
    let mut file = tempfile::NamedTempFile::new()
        .map_err(|source| grafhome_ca::Error::io("<temporary SSH public key>", source))?;
    file.write_all(public_key.as_bytes())
        .map_err(|source| grafhome_ca::Error::io(file.path(), source))?;
    let output = run_capture(process("ssh-keygen").arg("-lf").arg(file.path()))?;
    let output = String::from_utf8_lossy(&output);
    output
        .split_whitespace()
        .nth(1)
        .map(str::to_owned)
        .ok_or_else(|| grafhome_ca::Error::Validation {
            field: "enrollment request SSH key".to_owned(),
            message: "ssh-keygen returned no fingerprint".to_owned(),
        })
}

fn confirm_host_approval(request: &HostRequest) -> grafhome_ca::Result<()> {
    confirm_approval(&request.host, "approve host")
}

fn confirm_approval(identity: &str, command: &str) -> grafhome_ca::Result<()> {
    eprintln!("Enrollment request: {identity}");
    if confirm_tty("Approve enrollment? [y/N] ")? {
        Ok(())
    } else {
        Err(grafhome_ca::Error::Validation {
            field: command.to_owned(),
            message: "enrollment was not approved".to_owned(),
        })
    }
}

fn confirm_tty(prompt: &str) -> grafhome_ca::Result<bool> {
    let answer = prompt_tty(prompt)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "YES"))
}

fn prompt_tty(prompt: &str) -> grafhome_ca::Result<String> {
    eprint!("{prompt}");
    std::io::stderr()
        .flush()
        .map_err(|source| grafhome_ca::Error::io("<stderr>", source))?;
    let mut terminal = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|source| grafhome_ca::Error::io("/dev/tty", source))?;
    let mut answer = String::new();
    std::io::BufReader::new(&mut terminal)
        .read_line(&mut answer)
        .map_err(|source| grafhome_ca::Error::io("/dev/tty", source))?;
    Ok(answer)
}

fn enroll_user_flow(
    model: &SiteModel,
    user: Option<&str>,
    host: Option<&str>,
    grant_file: Option<&Path>,
    password_file: Option<&Path>,
    request_only: bool,
    restart: bool,
) -> grafhome_ca::Result<()> {
    let user = resolve_user(user)?;
    let host = resolve_host(host)?;
    let pending_path = enrollment_request_path(&user, &host)?;
    if restart {
        let request = user_request_from_material(model, &user, &host)?;
        publish_user_request(&pending_path, &request, true)?;
        if request_only {
            return Ok(());
        }
        eprintln!("Waiting for the enrollment grant.");
    } else if !pending_path.exists() && grant_file.is_none() {
        let mut stdin = std::io::stdin().lock();
        let (password, should_store) = match password_file {
            Some(file) => (
                read_password_or_file(Some(file), &mut stdin, "renewal password")?,
                false,
            ),
            None => match lookup_renewal_password(&user, &host) {
                Ok(password) => {
                    eprintln!("Using the stored renewal credential for {user}@{host}.");
                    (password, false)
                }
                Err(_) => (
                    read_password_or_file(None, &mut stdin, "renewal password")?,
                    true,
                ),
            },
        };
        let request = ensure_user_keys(model, &user, &host, &password)?;
        if should_store {
            store_renewal_password(&user, &host, &password)?;
        }
        publish_user_request(&pending_path, &request, false)?;
        if request_only {
            return Ok(());
        }
        eprintln!("Waiting for the enrollment grant.");
    }

    let pending_text = std::fs::read_to_string(&pending_path)
        .map_err(|source| grafhome_ca::Error::io(&pending_path, source))?;
    let request: UserRequest = parse_enrollment_document(&pending_text, "pending enrollment")?;
    let mut stdin = std::io::stdin().lock();
    let grant_text = read_document_or_file(grant_file, &mut stdin, "user enrollment grant")?;
    let grant: UserGrant = parse_enrollment_document(&grant_text, "user enrollment grant")?;
    grant.validate()?;
    if grant.user != request.user
        || grant.host != request.host
        || grant.ssh_public_key.trim() != request.ssh_public_key.trim()
        || grant.renewal_public_jwk != request.renewal_public_jwk
    {
        return Err(grafhome_ca::Error::Validation {
            field: "user enrollment grant".to_owned(),
            message: "grant does not match this client host's pending request".to_owned(),
        });
    }
    validate_grant_ca_url(model, &grant.ca_url, "user enrollment grant")?;
    let step_bin = user_step_bin()?;
    bootstrap_trust(
        &step_bin,
        &user_steppath(model)?,
        &grant.ca_url,
        &grant.root_fingerprint,
    )?;
    issue_user_certificate(model, &user, &host, &grant.token)?;
    let password = match password_file {
        Some(file) => read_password_or_file(Some(file), &mut stdin, "renewal password")?,
        None => lookup_renewal_password(&user, &host)?,
    };
    if grant.preserves_initial_certificate() {
        verify_user_renewal(model, &user, &host, &password)?;
    } else {
        renew_user(model, &user, Some(&host), &password, false)?;
    }
    std::fs::remove_file(&pending_path)
        .map_err(|source| grafhome_ca::Error::io(&pending_path, source))?;
    outln!("User enrollment complete: {user}@{host}");
    Ok(())
}

fn publish_user_request(
    pending_path: &Path,
    request: &UserRequest,
    restarted: bool,
) -> grafhome_ca::Result<()> {
    let text = serde_json::to_string(request).expect("enrollment request serializes");
    write_secret_file_atomic(pending_path, text.as_bytes())?;
    let action = if restarted { "Restarted" } else { "Created" };
    eprintln!(
        "{action} a public enrollment request for {}@{}.",
        request.user, request.host
    );
    eprintln!("Copy the REQUEST line to: sudo grafhome-ca approve user");
    outln!("REQUEST:{text}");
    std::io::stdout()
        .flush()
        .map_err(|source| grafhome_ca::Error::io("<stdout>", source))
}

fn approve_user_enrollment(
    model: &SiteModel,
    request: &UserRequest,
    token_ttl: Option<&str>,
    cert_ttl: &str,
    effectively_infinite: bool,
) -> grafhome_ca::Result<()> {
    request.validate()?;
    if let Some(ttl) = token_ttl {
        checked_ttl("approve user.ttl", ttl)?;
    }
    let public_jwk =
        serde_json::to_string(&request.renewal_public_jwk).expect("public renewal JWK serializes");
    let token = authorize_user(model, &request.user, &request.host, &public_jwk, || {
        create_user_token(
            model,
            &request.user,
            &request.host,
            token_ttl,
            Some(cert_ttl),
        )
    })?;
    let fingerprint = ca_fingerprint(model)?;
    let mut grant = UserGrant::new(
        request,
        required_endpoint(model, ENDPOINT_ROLE_CA_API)?.url(),
        fingerprint,
        String::from_utf8_lossy(&token).trim(),
    );
    if effectively_infinite {
        grant.mark_effectively_infinite_certificate();
    }
    eprintln!("Approved {}@{}.", request.user, request.host);
    eprintln!("Copy the GRANT line back to the pending enroll user command.");
    outln!(
        "GRANT:{}",
        serde_json::to_string(&grant).expect("user grant serializes")
    );
    Ok(())
}

fn user_approval_cert_ttl(
    model: &SiteModel,
    request: &UserRequest,
    cert_ttl: Option<&str>,
    effectively_infinite: bool,
) -> grafhome_ca::Result<String> {
    let user = active_user(model, &request.user)?;
    let client = required_user_client(model, &request.user, &request.host)?;
    let provisioner = required_provisioner(model, PROVISIONER_ROLE_USER_ENROLLMENT)?;

    if effectively_infinite {
        if !client.allow_effectively_infinite_cert {
            return Err(grafhome_ca::Error::Validation {
                field: format!(
                    "policy/hosts/{}.toml:user_access.{}.enrollment.allow_effectively_infinite_cert",
                    request.host, request.user
                ),
                message: "effectively-infinite certificate approval is not allowed".to_owned(),
            });
        }
        if provisioner.max_ttl != UNLIMITED_TTL {
            return Err(grafhome_ca::Error::Validation {
                field: ca_policy_field("provisioners", &provisioner.role, "max_ttl"),
                message: "effectively-infinite approval requires max_ttl = \"unlimited\""
                    .to_owned(),
            });
        }
        return Ok(STEP_EFFECTIVE_UNLIMITED_TTL.to_owned());
    }

    let cert_ttl = checked_ttl("approve user.cert_ttl", cert_ttl.unwrap_or(&user.cert_ttl))?;
    let renewal_max_ttl = model.policy.renewal_max_ttl(provisioner);
    if !duration_at_most(&cert_ttl, renewal_max_ttl) {
        return Err(grafhome_ca::Error::Validation {
            field: "approve user.cert_ttl".to_owned(),
            message: format!(
                "must not exceed renewal_max_ttl ({}) without --effectively-infinite",
                renewal_max_ttl
            ),
        });
    }
    Ok(cert_ttl)
}

fn ensure_host_keys(model: &SiteModel, host_name: &str) -> grafhome_ca::Result<HostRequest> {
    required_host(model, host_name)?;
    let material_dir = host_material_dir(model, host_name);
    if let Some(runtime) = TermuxHostRuntime::detect()? {
        runtime.prepare_private_directory(&material_dir, "host credential directory")?;
    } else {
        std::fs::create_dir_all(&material_dir)
            .map_err(|source| grafhome_ca::Error::io(&material_dir, source))?;
        #[cfg(unix)]
        std::fs::set_permissions(&material_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|source| grafhome_ca::Error::io(&material_dir, source))?;
    }
    let public_jwk = material_dir.join("provisioner.pub.json");
    let private_jwk = material_dir.join("provisioner.priv.json");
    let password_file = material_dir.join("renewal-password");
    if !private_jwk.exists() {
        let password = random_secret()?;
        write_secret_file_atomic(&password_file, password.as_bytes())?;
        let step_bin = root_step_bin(model)?;
        run_status(
            process(&step_bin)
                .arg("crypto")
                .arg("jwk")
                .arg("create")
                .arg(&public_jwk)
                .arg(&private_jwk)
                .arg("--password-file")
                .arg(&password_file),
        )?;
    } else if !password_file.exists() || !public_jwk.exists() {
        return Err(grafhome_ca::Error::Validation {
            field: material_dir.display().to_string(),
            message: "incomplete host renewal credential; remove this directory and enroll again"
                .to_owned(),
        });
    }
    #[cfg(unix)]
    {
        normalize_regular_file_mode(&private_jwk, "host renewal private JWK", 0o600)?;
        normalize_regular_file_mode(&public_jwk, "host renewal public JWK", 0o644)?;
    }
    host_request_from_material(model, host_name)
}

fn host_request_from_material(
    model: &SiteModel,
    host_name: &str,
) -> grafhome_ca::Result<HostRequest> {
    required_host(model, host_name)?;
    let material_dir = host_material_dir(model, host_name);
    let private_jwk = material_dir.join("provisioner.priv.json");
    let public_jwk = material_dir.join("provisioner.pub.json");
    let password_file = material_dir.join("renewal-password");
    let public_key = host_public_key_path(model);
    for path in [&public_key, &private_jwk, &public_jwk, &password_file] {
        if !path.is_file() {
            return Err(grafhome_ca::Error::Validation {
                field: "enroll host --restart".to_owned(),
                message: format!(
                    "cannot restart because {} is missing; run enroll host without --restart",
                    path.display()
                ),
            });
        }
    }
    let ssh_public_key = std::fs::read_to_string(&public_key)
        .map_err(|source| grafhome_ca::Error::io(&public_key, source))?;
    let renewal_public_jwk = serde_json::from_str(
        &std::fs::read_to_string(&public_jwk)
            .map_err(|source| grafhome_ca::Error::io(&public_jwk, source))?,
    )
    .map_err(|source| grafhome_ca::Error::Json {
        path: public_jwk,
        source,
    })?;
    let request = HostRequest::new(host_name, ssh_public_key.trim(), renewal_public_jwk);
    request.validate()?;
    Ok(request)
}

fn random_secret() -> grafhome_ca::Result<String> {
    let mut bytes = [0_u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|source| grafhome_ca::Error::io("/dev/urandom", source))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn enroll_host_flow(
    model: &SiteModel,
    host: Option<&str>,
    grant_file: Option<&Path>,
    request_only: bool,
    restart: bool,
) -> grafhome_ca::Result<()> {
    let host = resolve_host(host)?;
    let pending_path = host_enrollment_request_path(model, &host);
    if restart {
        let request = host_request_from_material(model, &host)?;
        publish_host_request(&pending_path, &request, true)?;
        if request_only {
            return Ok(());
        }
        eprintln!("Waiting for the enrollment grant.");
    } else if !pending_path.exists() && grant_file.is_none() {
        let request = ensure_host_keys(model, &host)?;
        publish_host_request(&pending_path, &request, false)?;
        if request_only {
            return Ok(());
        }
        eprintln!("Waiting for the enrollment grant.");
    }

    let request_text = std::fs::read_to_string(&pending_path)
        .map_err(|source| grafhome_ca::Error::io(&pending_path, source))?;
    let request: HostRequest = parse_enrollment_document(&request_text, "pending enrollment")?;
    let mut stdin = std::io::stdin().lock();
    let grant_text = read_document_or_file(grant_file, &mut stdin, "host enrollment grant")?;
    let grant: HostGrant = parse_enrollment_document(&grant_text, "host enrollment grant")?;
    grant.validate()?;
    if grant.host != request.host
        || grant.ssh_public_key.trim() != request.ssh_public_key.trim()
        || grant.renewal_public_jwk != request.renewal_public_jwk
    {
        return Err(grafhome_ca::Error::Validation {
            field: "host enrollment grant".to_owned(),
            message: "grant does not match this host's pending request".to_owned(),
        });
    }
    validate_grant_ca_url(model, &grant.ca_url, "host enrollment grant")?;
    complete_host_enrollment(model, &grant)?;
    renew_host(model, &host, false)?;
    std::fs::remove_file(&pending_path)
        .map_err(|source| grafhome_ca::Error::io(&pending_path, source))?;
    Ok(())
}

fn publish_host_request(
    pending_path: &Path,
    request: &HostRequest,
    restarted: bool,
) -> grafhome_ca::Result<()> {
    let text = serde_json::to_string(request).expect("host enrollment request serializes");
    write_secret_file_atomic(pending_path, text.as_bytes())?;
    let action = if restarted { "Restarted" } else { "Created" };
    eprintln!(
        "{action} a public host enrollment request for {}.",
        request.host
    );
    eprintln!("Copy the REQUEST line to: sudo grafhome-ca approve host");
    outln!("REQUEST:{text}");
    std::io::stdout()
        .flush()
        .map_err(|source| grafhome_ca::Error::io("<stdout>", source))
}

fn approve_host_enrollment(
    model: &SiteModel,
    request: &HostRequest,
    token_ttl: Option<&str>,
    cert_ttl: Option<&str>,
) -> grafhome_ca::Result<()> {
    request.validate()?;
    if let Some(ttl) = token_ttl {
        checked_ttl("approve host.ttl", ttl)?;
    }
    if let Some(ttl) = cert_ttl {
        checked_ttl("approve host.cert_ttl", ttl)?;
    }
    required_host(model, &request.host)?;
    let public_jwk =
        serde_json::to_string(&request.renewal_public_jwk).expect("public renewal JWK serializes");
    let token = authorize_host(model, &request.host, &public_jwk, || {
        create_host_token(model, &request.host, token_ttl, cert_ttl)
    })?;
    let grant = HostGrant::new(
        request,
        required_endpoint(model, ENDPOINT_ROLE_CA_API)?.url(),
        ca_fingerprint(model)?,
        String::from_utf8_lossy(&token).trim(),
    );
    eprintln!("Approved {}.", request.host);
    eprintln!("Copy the GRANT line back to the pending enroll host command.");
    outln!(
        "GRANT:{}",
        serde_json::to_string(&grant).expect("host grant serializes")
    );
    Ok(())
}

fn complete_host_enrollment(model: &SiteModel, grant: &HostGrant) -> grafhome_ca::Result<()> {
    grant.validate()?;
    required_host(model, &grant.host)?;
    let step_bin = root_step_bin(model)?;
    bootstrap_trust(
        &step_bin,
        Path::new(&model.deployment.values["GRAFHOME_CA_SERVER_STEPPATH"]),
        &grant.ca_url,
        &grant.root_fingerprint,
    )?;
    enroll_host(model, &grant.host, &grant.token)?;
    let desired = desired_host_ssh_files(model, &grant.host, &grant.ca_url)?;
    with_host_policy_lock(model, || {
        apply_host_policy_locked(model, &grant.host, &desired, true, true)
    })?;
    outln!("Host enrollment complete: {}", grant.host);
    Ok(())
}

fn validate_grant_ca_url(model: &SiteModel, ca_url: &str, field: &str) -> grafhome_ca::Result<()> {
    let expected = required_endpoint(model, ENDPOINT_ROLE_CA_API)?.url();
    if ca_url == expected {
        Ok(())
    } else {
        Err(grafhome_ca::Error::Validation {
            field: field.to_owned(),
            message: format!("CA URL {ca_url} does not match configured CA URL {expected}"),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HostPolicyFile {
    mode: u32,
    content: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostPolicyChange {
    Create,
    Update,
    Remove,
}

fn desired_host_ssh_files(
    model: &SiteModel,
    host_name: &str,
    ca_url: &str,
) -> grafhome_ca::Result<BTreeMap<PathBuf, HostPolicyFile>> {
    let host = required_host(model, host_name)?;
    let ssh_system_dir = system_ssh_dir(model);
    let trust_dir = Path::new(&model.deployment.values["GRAFHOME_CA_SSH_TRUST_DIR"]);
    let auth_dir = Path::new(&model.deployment.values["GRAFHOME_CA_AUTH_PRINCIPALS_DIR"]);
    let step_bin = root_step_bin(model)?;
    let steppath = Path::new(&model.deployment.values["GRAFHOME_CA_SERVER_STEPPATH"]);
    let root = server_root_cert_path(model);
    let user_ca_keys = if host.has_ssh_role(SshRole::Server) {
        String::from_utf8_lossy(&run_capture(
            process(&step_bin)
                .env("STEPPATH", steppath)
                .arg("ssh")
                .arg("config")
                .arg("--roots")
                .arg("--ca-url")
                .arg(ca_url)
                .arg("--root")
                .arg(&root),
        )?)
        .into_owned()
    } else {
        String::new()
    };
    let host_ca_keys = if host.has_ssh_role(SshRole::Client) {
        String::from_utf8_lossy(&run_capture(
            process(&step_bin)
                .env("STEPPATH", steppath)
                .arg("ssh")
                .arg("config")
                .arg("--host")
                .arg("--roots")
                .arg("--ca-url")
                .arg(ca_url)
                .arg("--root")
                .arg(&root),
        )?)
        .into_owned()
    } else {
        String::new()
    };
    let known_hosts = known_hosts_from_roots(model, &host_ca_keys);
    let mut desired = BTreeMap::new();
    for file in grafhome_ca::render::render(model)? {
        let Some(target) = rendered_host_target(&file.path, host_name) else {
            continue;
        };
        let target_path = Path::new(&target);
        if !target_path.starts_with(ssh_system_dir)
            && !target_path.starts_with(trust_dir)
            && !target_path.starts_with(auth_dir)
        {
            continue;
        }
        let content = if target.ends_with("/user_ca_keys.pem") {
            &user_ca_keys
        } else if target.ends_with("/ssh_known_hosts") {
            &known_hosts
        } else {
            &file.content
        };
        let target = install_target(&target);
        if desired
            .insert(
                target.clone(),
                HostPolicyFile {
                    mode: file.mode,
                    content: content.as_bytes().to_vec(),
                },
            )
            .is_some()
        {
            return Err(grafhome_ca::Error::Validation {
                field: target.display().to_string(),
                message: "host policy rendered the same target more than once".to_owned(),
            });
        }
    }
    Ok(desired)
}

fn apply_ca_policy(model: &SiteModel, dry_run: bool) -> grafhome_ca::Result<()> {
    let local_host = resolve_host(None)?;
    let ca_origin = required_endpoint(model, ENDPOINT_ROLE_CA_ORIGIN)?;
    if local_host != ca_origin.target {
        return Err(grafhome_ca::Error::Validation {
            field: "apply ca".to_owned(),
            message: format!(
                "must be run on CA origin {}; local host is {local_host}",
                ca_origin.target
            ),
        });
    }
    let ca_json = PathBuf::from(model.deployment.ca_steppath()).join("config/ca.json");
    if dry_run {
        let result = grafhome_ca::runtime_provisioners::reconcile_claims(model, &ca_json)?;
        print_ca_policy_changes(result.authority_policy_updated, &result.updated, true)?;
        return Ok(());
    }

    with_ca_lock(model, || {
        let result = grafhome_ca::runtime_provisioners::reconcile_claims(model, &ca_json)?;
        if !result.authority_policy_updated && result.updated.is_empty() {
            outln!("CA policy already current.");
            return Ok(());
        }
        install_ca_json_with_rollback(
            model,
            &ca_json,
            result.config.as_bytes(),
            required_endpoint(model, ENDPOINT_ROLE_CA_API)?.url(),
            || Ok(()),
        )?;
        print_ca_policy_changes(result.authority_policy_updated, &result.updated, false)?;
        Ok(())
    })
}

fn print_ca_policy_changes(
    authority_policy_updated: bool,
    updated: &[String],
    dry_run: bool,
) -> grafhome_ca::Result<()> {
    if !authority_policy_updated && updated.is_empty() {
        outln!("CA policy already current.");
        return Ok(());
    }
    if authority_policy_updated {
        outln!("update\tauthority.policy");
    }
    for name in updated {
        outln!("update\t{name}");
    }
    let action = if dry_run { "Would apply" } else { "Applied" };
    match (authority_policy_updated, updated.is_empty()) {
        (true, true) => outln!("{action} CA authority policy."),
        (true, false) => outln!(
            "{action} CA authority policy and policy for {} provisioner(s).",
            updated.len()
        ),
        (false, _) => outln!("{action} CA policy to {} provisioner(s).", updated.len()),
    }
    Ok(())
}

fn apply_host_policy(
    model: &SiteModel,
    host_name: &str,
    dry_run: bool,
    quiet: bool,
) -> grafhome_ca::Result<()> {
    let ca_url = required_endpoint(model, ENDPOINT_ROLE_CA_API)?.url();
    let desired = desired_host_ssh_files(model, host_name, &ca_url)?;
    if dry_run {
        let changes = host_policy_changes(model, &desired)?;
        print_host_policy_changes(host_name, &changes, true, false)?;
        return Ok(());
    }

    with_host_policy_lock(model, || {
        apply_host_policy_locked(model, host_name, &desired, quiet, false)
    })
}

fn apply_host_policy_locked(
    model: &SiteModel,
    host_name: &str,
    desired: &BTreeMap<PathBuf, HostPolicyFile>,
    quiet: bool,
    validate_when_current: bool,
) -> grafhome_ca::Result<()> {
    let changes = host_policy_changes(model, desired)?;
    if changes.is_empty() {
        if validate_when_current {
            validate_and_reload_ssh(model)?;
        }
        if !quiet {
            outln!("Host policy already current: {host_name}");
        }
        return Ok(());
    }

    let mut previous = BTreeMap::new();
    for path in changes.keys() {
        previous.insert(path.clone(), read_host_policy_file(path)?);
    }

    let apply = (|| -> grafhome_ca::Result<()> {
        for (path, change) in &changes {
            match change {
                HostPolicyChange::Create | HostPolicyChange::Update => {
                    let file = desired.get(path).expect("changed desired file exists");
                    write_public_file_atomic(path, &file.content, file.mode)?;
                }
                HostPolicyChange::Remove => remove_host_policy_file(path)?,
            }
        }
        validate_and_reload_ssh(model)
    })();

    if let Err(error) = apply {
        let rollback =
            restore_host_policy_files(&previous).and_then(|()| validate_and_reload_ssh(model));
        return Err(grafhome_ca::Error::Validation {
            field: "apply host".to_owned(),
            message: match rollback {
                Ok(()) => format!("{error}; restored the previous host policy"),
                Err(rollback_error) => {
                    format!("{error}; rollback failed: {rollback_error}")
                }
            },
        });
    }

    print_host_policy_changes(host_name, &changes, false, quiet)
}

fn host_policy_changes(
    model: &SiteModel,
    desired: &BTreeMap<PathBuf, HostPolicyFile>,
) -> grafhome_ca::Result<BTreeMap<PathBuf, HostPolicyChange>> {
    let managed = host_policy_managed_paths(model, desired)?;
    let mut changes = BTreeMap::new();
    for path in managed {
        let current = read_host_policy_file(&path)?;
        match (current.as_ref(), desired.get(&path)) {
            (None, Some(_)) => {
                changes.insert(path, HostPolicyChange::Create);
            }
            (Some(current), Some(wanted)) if current != wanted => {
                changes.insert(path, HostPolicyChange::Update);
            }
            (Some(_), None) => {
                changes.insert(path, HostPolicyChange::Remove);
            }
            _ => {}
        }
    }
    Ok(changes)
}

fn host_policy_managed_paths(
    model: &SiteModel,
    desired: &BTreeMap<PathBuf, HostPolicyFile>,
) -> grafhome_ca::Result<BTreeSet<PathBuf>> {
    let trust_dir = &model.deployment.values["GRAFHOME_CA_SSH_TRUST_DIR"];
    let auth_dir = install_target(&model.deployment.values["GRAFHOME_CA_AUTH_PRINCIPALS_DIR"]);
    let ssh_system_dir = system_ssh_dir(model);
    let mut paths = desired.keys().cloned().collect::<BTreeSet<_>>();
    for path in [
        format!(
            "{}/sshd_config.d/grafhome-ca.conf",
            ssh_system_dir.display()
        ),
        format!("{}/ssh_config.d/grafhome-ca.conf", ssh_system_dir.display()),
        format!("{trust_dir}/user_ca_keys.pem"),
        format!("{trust_dir}/revoked_user_certs"),
        format!("{trust_dir}/ssh_known_hosts"),
    ] {
        paths.insert(install_target(&path));
    }

    let entries = match std::fs::read_dir(&auth_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(paths),
        Err(source) => return Err(grafhome_ca::Error::io(&auth_dir, source)),
    };
    for entry in entries {
        let entry = entry.map_err(|source| grafhome_ca::Error::io(&auth_dir, source))?;
        let file_type = entry
            .file_type()
            .map_err(|source| grafhome_ca::Error::io(entry.path(), source))?;
        if !file_type.is_file() {
            return Err(grafhome_ca::Error::Validation {
                field: entry.path().display().to_string(),
                message: "the Grafhome-managed principals directory may contain only regular files"
                    .to_owned(),
            });
        }
        paths.insert(entry.path());
    }
    Ok(paths)
}

fn read_host_policy_file(path: &Path) -> grafhome_ca::Result<Option<HostPolicyFile>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(grafhome_ca::Error::io(path, source)),
    };
    if !metadata.file_type().is_file() {
        return Err(grafhome_ca::Error::Validation {
            field: path.display().to_string(),
            message: "managed host policy target is not a regular file".to_owned(),
        });
    }
    Ok(Some(HostPolicyFile {
        mode: metadata.permissions().mode() & 0o7777,
        content: std::fs::read(path).map_err(|source| grafhome_ca::Error::io(path, source))?,
    }))
}

fn remove_host_policy_file(path: &Path) -> grafhome_ca::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(grafhome_ca::Error::io(path, source)),
    }
}

fn restore_host_policy_files(
    previous: &BTreeMap<PathBuf, Option<HostPolicyFile>>,
) -> grafhome_ca::Result<()> {
    for (path, file) in previous {
        match file {
            Some(file) => write_public_file_atomic(path, &file.content, file.mode)?,
            None => remove_host_policy_file(path)?,
        }
    }
    Ok(())
}

fn validate_and_reload_ssh(model: &SiteModel) -> grafhome_ca::Result<()> {
    run_status_quiet(
        process(host_program(model, HOST_SSHD_BIN, "sshd")).arg("-t"),
        &[],
        true,
    )?;
    reload_ssh(model)
}

fn print_host_policy_changes(
    host_name: &str,
    changes: &BTreeMap<PathBuf, HostPolicyChange>,
    dry_run: bool,
    quiet: bool,
) -> grafhome_ca::Result<()> {
    if quiet {
        return Ok(());
    }
    if changes.is_empty() {
        outln!("Host policy already current: {host_name}");
        return Ok(());
    }
    for (path, change) in changes {
        let verb = match change {
            HostPolicyChange::Create => "create",
            HostPolicyChange::Update => "update",
            HostPolicyChange::Remove => "remove",
        };
        outln!("{verb}\t{}", path.display());
    }
    if dry_run {
        outln!(
            "Would apply {} host policy change(s) for {host_name}",
            changes.len()
        );
    } else {
        outln!(
            "Applied {} host policy change(s) for {host_name}",
            changes.len()
        );
    }
    Ok(())
}

fn with_host_policy_lock<T>(
    model: &SiteModel,
    action: impl FnOnce() -> grafhome_ca::Result<T>,
) -> grafhome_ca::Result<T> {
    if let Some(runtime) = TermuxHostRuntime::detect()? {
        runtime.prepare_policy_directories()?;
    }
    let trust_dir = install_target(&model.deployment.values["GRAFHOME_CA_SSH_TRUST_DIR"]);
    std::fs::create_dir_all(&trust_dir)
        .map_err(|source| grafhome_ca::Error::io(&trust_dir, source))?;
    let path = trust_dir.join(".apply.lock");
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).mode(0o600);
    let file = options
        .open(&path)
        .map_err(|source| grafhome_ca::Error::io(&path, source))?;
    file.lock_exclusive()
        .map_err(|source| grafhome_ca::Error::io(&path, source))?;
    action()
}

fn rendered_host_target(path: &Path, expected_host: &str) -> Option<String> {
    let mut components = path.components();
    if components.next()?.as_os_str() != "hosts" || components.next()?.as_os_str() != expected_host
    {
        return None;
    }
    Some(format!(
        "/{}",
        components
            .map(|component| component.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/")
    ))
}

fn known_hosts_from_roots(model: &SiteModel, roots: &str) -> String {
    let mut principals = model
        .policy
        .hosts
        .iter()
        .filter(|host| host.has_ssh_role(SshRole::Server))
        .flat_map(|host| host.principals.iter().map(String::as_str))
        .collect::<Vec<_>>();
    principals.sort_unstable();
    principals.dedup();
    roots
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|key| format!("@cert-authority {} {key}\n", principals.join(",")))
        .collect()
}

fn install_target(target: &str) -> PathBuf {
    match std::env::var_os("GRAFHOME_CA_INSTALL_ROOT") {
        Some(root) => PathBuf::from(root).join(target.trim_start_matches('/')),
        None => PathBuf::from(target),
    }
}

fn system_ssh_dir(model: &SiteModel) -> &Path {
    model
        .deployment
        .values
        .get(SYSTEM_SSH_DIR)
        .map(Path::new)
        .unwrap_or_else(|| Path::new("/etc/ssh"))
}

fn host_program<'a>(model: &'a SiteModel, key: &str, fallback: &'a str) -> &'a str {
    model
        .deployment
        .values
        .get(key)
        .map(String::as_str)
        .unwrap_or(fallback)
}

fn write_public_file_atomic(path: &Path, content: &[u8], mode: u32) -> grafhome_ca::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| grafhome_ca::Error::Validation {
            field: path.display().to_string(),
            message: "path must have a parent directory".to_owned(),
        })?;
    std::fs::create_dir_all(parent).map_err(|source| grafhome_ca::Error::io(parent, source))?;
    let mut file = tempfile::Builder::new()
        .prefix(".grafhome-ca-install-")
        .tempfile_in(parent)
        .map_err(|source| grafhome_ca::Error::io(parent, source))?;
    file.write_all(content)
        .map_err(|source| grafhome_ca::Error::io(file.path(), source))?;
    file.as_file_mut()
        .sync_all()
        .map_err(|source| grafhome_ca::Error::io(file.path(), source))?;
    #[cfg(unix)]
    std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(mode))
        .map_err(|source| grafhome_ca::Error::io(file.path(), source))?;
    file.persist(path)
        .map_err(|error| grafhome_ca::Error::io(path, error.error))?;
    Ok(())
}

fn ca_fingerprint(model: &SiteModel) -> grafhome_ca::Result<String> {
    let step_bin = root_step_bin(model)?;
    let output = run_capture(
        process(&step_bin)
            .arg("certificate")
            .arg("fingerprint")
            .arg(ca_root_cert_path(model)),
    )?;
    let value = String::from_utf8_lossy(&output).trim().to_owned();
    if value.is_empty() {
        return Err(grafhome_ca::Error::Validation {
            field: "CA root fingerprint".to_owned(),
            message: "step returned an empty fingerprint".to_owned(),
        });
    }
    Ok(value)
}

fn create_host_token(
    model: &SiteModel,
    host: &str,
    token_ttl: Option<&str>,
    cert_ttl: Option<&str>,
) -> grafhome_ca::Result<Vec<u8>> {
    let host = required_host(model, host)?;
    let ca_api = required_endpoint(model, ENDPOINT_ROLE_CA_API)?;
    let provisioner = required_provisioner(model, PROVISIONER_ROLE_HOST_BOOTSTRAP)?;
    let token_ttl = checked_ttl(
        "create-host-token.ttl",
        token_ttl.unwrap_or(DEFAULT_ENROLLMENT_TOKEN_TTL),
    )?;
    let cert_ttl = checked_ttl(
        "create-host-token.cert_ttl",
        cert_ttl.unwrap_or(&provisioner.default_ttl),
    )?;
    let step_bin = root_step_bin(model)?;
    let (provisioner_key, provisioner_password) =
        enrollment_provisioner_credential(model, &provisioner.name)?;
    let mut command = process(&step_bin);
    command
        .env("STEPPATH", model.deployment.ca_steppath())
        .arg("ca")
        .arg("token")
        .arg(&host.host)
        .arg("--ssh")
        .arg("--host");
    for principal in &host.principals {
        command.arg("--principal").arg(principal);
    }
    command
        .arg("--not-after")
        .arg(token_ttl)
        .arg("--cert-not-after")
        .arg(cert_ttl)
        .arg("--issuer")
        .arg(&provisioner.name)
        .arg("--key")
        .arg(provisioner_key)
        .arg("--password-file")
        .arg(provisioner_password)
        .arg("--ca-url")
        .arg(ca_api.url())
        .arg("--root")
        .arg(ca_root_cert_path(model));
    run_capture(&mut command)
}

fn enroll_host(model: &SiteModel, host: &str, token: &str) -> grafhome_ca::Result<()> {
    let host = required_host(model, host)?;
    let ca_api = required_endpoint(model, ENDPOINT_ROLE_CA_API)?;
    let step_bin = root_step_bin(model)?;
    run_status_redacted(
        process(&step_bin)
            .env(
                "STEPPATH",
                &model.deployment.values["GRAFHOME_CA_SERVER_STEPPATH"],
            )
            .arg("ssh")
            .arg("certificate")
            .arg(&host.host)
            .arg(host_public_key_path(model))
            .arg("--host")
            .arg("--sign")
            .arg("--token")
            .arg(token)
            .arg("--ca-url")
            .arg(ca_api.url())
            .arg("--root")
            .arg(server_root_cert_path(model))
            .arg("--force"),
        &[token],
    )?;
    normalize_host_certificate_mode(model)?;
    run_status(
        process(host_program(model, HOST_SSH_KEYGEN_BIN, "ssh-keygen"))
            .arg("-L")
            .arg("-f")
            .arg(host_cert_path(model)),
    )?;
    run_status(process(host_program(model, HOST_SSHD_BIN, "sshd")).arg("-t"))?;
    reload_ssh(model)
}

fn renew_host(model: &SiteModel, host_name: &str, quiet: bool) -> grafhome_ca::Result<()> {
    let host = required_host(model, host_name)?;
    let ca_api = required_endpoint(model, ENDPOINT_ROLE_CA_API)?;
    let host_policy = required_provisioner(model, PROVISIONER_ROLE_HOST_BOOTSTRAP)?;
    let material_dir = host_material_dir(model, &host.host);
    let private_jwk = material_dir.join("provisioner.priv.json");
    let password_file = material_dir.join("renewal-password");
    if !private_jwk.exists() || !password_file.exists() {
        return Err(grafhome_ca::Error::Validation {
            field: material_dir.display().to_string(),
            message: "host renewal credential is missing; run enroll host".to_owned(),
        });
    }
    let step_bin = root_step_bin(model)?;
    let mut token_command = process(&step_bin);
    token_command
        .env(
            "STEPPATH",
            &model.deployment.values["GRAFHOME_CA_SERVER_STEPPATH"],
        )
        .arg("ca")
        .arg("token")
        .arg(&host.host)
        .arg("--ssh")
        .arg("--host");
    for principal in &host.principals {
        token_command.arg("--principal").arg(principal);
    }
    let token = run_capture(
        token_command
            .arg("--not-after")
            .arg("5m")
            .arg("--cert-not-after")
            .arg(host_policy.renewal_default_ttl())
            .arg("--issuer")
            .arg(host_provisioner_name(&host.host))
            .arg("--key")
            .arg(&private_jwk)
            .arg("--password-file")
            .arg(&password_file)
            .arg("--ca-url")
            .arg(ca_api.url())
            .arg("--root")
            .arg(server_root_cert_path(model)),
    )?;
    let token = String::from_utf8(token).map_err(|error| grafhome_ca::Error::Validation {
        field: "step ca token".to_owned(),
        message: format!("token output was not UTF-8: {error}"),
    })?;
    run_status_quiet(
        process(&step_bin)
            .env(
                "STEPPATH",
                &model.deployment.values["GRAFHOME_CA_SERVER_STEPPATH"],
            )
            .arg("ssh")
            .arg("certificate")
            .arg(&host.host)
            .arg(host_public_key_path(model))
            .arg("--host")
            .arg("--sign")
            .arg("--token")
            .arg(token.trim())
            .arg("--ca-url")
            .arg(ca_api.url())
            .arg("--root")
            .arg(server_root_cert_path(model))
            .arg("--force"),
        &[token.trim()],
        quiet,
    )?;
    normalize_host_certificate_mode(model)?;
    run_status_quiet(
        process(host_program(model, HOST_SSH_KEYGEN_BIN, "ssh-keygen"))
            .arg("-L")
            .arg("-f")
            .arg(host_cert_path(model)),
        &[],
        quiet,
    )?;
    run_status_quiet(
        process(host_program(model, HOST_SSHD_BIN, "sshd")).arg("-t"),
        &[],
        quiet,
    )?;
    reload_ssh(model)
}

fn create_user_token(
    model: &SiteModel,
    user: &str,
    host: &str,
    token_ttl: Option<&str>,
    cert_ttl: Option<&str>,
) -> grafhome_ca::Result<Vec<u8>> {
    let user = active_user(model, user)?;
    required_user_client(model, &user.user, host)?;
    let ca_api = required_endpoint(model, ENDPOINT_ROLE_CA_API)?;
    let token_ttl = checked_ttl(
        "create-user-token.ttl",
        token_ttl.unwrap_or(DEFAULT_ENROLLMENT_TOKEN_TTL),
    )?;
    let cert_ttl = checked_ttl(
        "create-user-token.cert_ttl",
        cert_ttl.unwrap_or(&user.cert_ttl),
    )?;
    let step_bin = root_step_bin(model)?;
    let (provisioner_key, provisioner_password) =
        enrollment_provisioner_credential(model, &user.provisioner)?;
    run_capture(
        process(&step_bin)
            .env("STEPPATH", model.deployment.ca_steppath())
            .arg("ca")
            .arg("token")
            .arg(&user.principal)
            .arg("--ssh")
            .arg("--principal")
            .arg(&user.principal)
            .arg("--not-after")
            .arg(token_ttl)
            .arg("--cert-not-after")
            .arg(cert_ttl)
            .arg("--issuer")
            .arg(&user.provisioner)
            .arg("--key")
            .arg(provisioner_key)
            .arg("--password-file")
            .arg(provisioner_password)
            .arg("--ca-url")
            .arg(ca_api.url())
            .arg("--root")
            .arg(ca_root_cert_path(model)),
    )
}

fn issue_user_certificate(
    model: &SiteModel,
    user_name: &str,
    host: &str,
    token: &str,
) -> grafhome_ca::Result<()> {
    let step_bin = user_step_bin()?;
    let user = active_user(model, user_name)?;
    required_user_client(model, &user.user, host)?;
    let ca_api = required_endpoint(model, ENDPOINT_ROLE_CA_API)?;
    let public_key = user_public_key_path()?;
    let cert = user_cert_path()?;
    run_status_redacted(
        process(&step_bin)
            .env("STEPPATH", user_steppath(model)?)
            .arg("ssh")
            .arg("certificate")
            .arg(&user.principal)
            .arg(&public_key)
            .arg("--sign")
            .arg("--token")
            .arg(token)
            .arg("--ca-url")
            .arg(ca_api.url())
            .arg("--root")
            .arg(user_root_cert_path(model)?)
            .arg("--force")
            .arg("--no-agent"),
        &[token],
    )?;
    run_status(process("ssh-keygen").arg("-L").arg("-f").arg(&cert))?;
    Ok(())
}

fn authorize_user<T>(
    model: &SiteModel,
    user_name: &str,
    host: &str,
    public_key: &str,
    after_activate: impl FnOnce() -> grafhome_ca::Result<T>,
) -> grafhome_ca::Result<T> {
    with_ca_lock(model, move || {
        authorize_user_locked(model, user_name, host, public_key, after_activate)
    })
}

fn authorize_user_locked<T>(
    model: &SiteModel,
    user_name: &str,
    host: &str,
    public_key: &str,
    after_activate: impl FnOnce() -> grafhome_ca::Result<T>,
) -> grafhome_ca::Result<T> {
    let user = active_user(model, user_name)?;
    let client = required_user_client(model, &user.user, host)?;
    let ca_api = required_endpoint(model, ENDPOINT_ROLE_CA_API)?;
    let provisioner = user_provisioner_name(&user.user, &client.host);
    let template_dir = PathBuf::from(model.deployment.ca_steppath()).join("templates/ssh");
    let template_file = template_dir.join(format!("{provisioner}.tpl"));
    std::fs::create_dir_all(&template_dir)
        .map_err(|source| grafhome_ca::Error::io(&template_dir, source))?;
    std::fs::write(&template_file, user_ssh_template(&user.principal))
        .map_err(|source| grafhome_ca::Error::io(&template_file, source))?;
    let ca_json = PathBuf::from(model.deployment.ca_steppath()).join("config/ca.json");
    let result = with_temp_file(&template_dir, public_key.as_bytes(), |public_key_file| {
        let text = grafhome_ca::runtime_provisioners::reconcile_user_client(
            model,
            &ca_json,
            public_key_file,
            &provisioner,
            &template_file.display().to_string(),
        )?;
        install_ca_json_with_rollback(
            model,
            &ca_json,
            text.as_bytes(),
            ca_api.url(),
            after_activate,
        )
    });
    match result {
        Ok(value) => {
            outln!("authorized provisioner: {provisioner}");
            Ok(value)
        }
        Err(error) => {
            let _ = std::fs::remove_file(&template_file);
            Err(error)
        }
    }
}

fn authorize_host<T>(
    model: &SiteModel,
    host_name: &str,
    public_key: &str,
    after_activate: impl FnOnce() -> grafhome_ca::Result<T>,
) -> grafhome_ca::Result<T> {
    with_ca_lock(model, move || {
        authorize_host_locked(model, host_name, public_key, after_activate)
    })
}

fn authorize_host_locked<T>(
    model: &SiteModel,
    host_name: &str,
    public_key: &str,
    after_activate: impl FnOnce() -> grafhome_ca::Result<T>,
) -> grafhome_ca::Result<T> {
    let host = required_host(model, host_name)?;
    let ca_api = required_endpoint(model, ENDPOINT_ROLE_CA_API)?;
    let provisioner = host_provisioner_name(&host.host);
    let template_dir = PathBuf::from(model.deployment.ca_steppath()).join("templates/ssh");
    let template_file = template_dir.join(format!("{provisioner}.tpl"));
    std::fs::create_dir_all(&template_dir)
        .map_err(|source| grafhome_ca::Error::io(&template_dir, source))?;
    std::fs::write(&template_file, host_ssh_template(host))
        .map_err(|source| grafhome_ca::Error::io(&template_file, source))?;
    let ca_json = PathBuf::from(model.deployment.ca_steppath()).join("config/ca.json");
    let result = with_temp_file(&template_dir, public_key.as_bytes(), |public_key_file| {
        let text = grafhome_ca::runtime_provisioners::reconcile_host(
            model,
            &ca_json,
            public_key_file,
            &provisioner,
            &template_file.display().to_string(),
        )?;
        install_ca_json_with_rollback(
            model,
            &ca_json,
            text.as_bytes(),
            ca_api.url(),
            after_activate,
        )
    });
    match result {
        Ok(value) => {
            outln!("authorized provisioner: {provisioner}");
            Ok(value)
        }
        Err(error) => {
            let _ = std::fs::remove_file(&template_file);
            Err(error)
        }
    }
}

fn revoke_user(model: &SiteModel, user_name: &str, host: Option<&str>) -> grafhome_ca::Result<()> {
    if user_name.trim().is_empty() {
        return Err(grafhome_ca::Error::Validation {
            field: "revoke user.user".to_owned(),
            message: "user must not be empty".to_owned(),
        });
    }
    with_ca_lock(model, || {
        let ca_json = PathBuf::from(model.deployment.ca_steppath()).join("config/ca.json");
        let (text, removed) = match host {
            Some(host) => grafhome_ca::runtime_provisioners::remove_exact(
                &ca_json,
                &user_provisioner_name(user_name, host),
            )?,
            None => grafhome_ca::runtime_provisioners::remove_user(
                &ca_json,
                &user_provisioner_prefix(user_name),
            )?,
        };
        finish_revocation(
            model,
            &ca_json,
            text,
            !removed.is_empty(),
            &format!("user {user_name}"),
        )?;
        let mut templates = removed;
        match host {
            Some(host) => templates.push(user_provisioner_name(user_name, host)),
            None => templates.extend(matching_provisioner_templates(model, |name| {
                parse_user_provisioner_name(name).is_some_and(|(user, _)| user == user_name)
            })?),
        }
        remove_provisioner_templates(model, &templates)
    })
}

fn revoke_host(model: &SiteModel, host_name: &str) -> grafhome_ca::Result<()> {
    if host_name.trim().is_empty() {
        return Err(grafhome_ca::Error::Validation {
            field: "revoke host.host".to_owned(),
            message: "host must not be empty".to_owned(),
        });
    }
    let provisioner = host_provisioner_name(host_name);
    with_ca_lock(model, || {
        let ca_json = PathBuf::from(model.deployment.ca_steppath()).join("config/ca.json");
        let (text, removed) = grafhome_ca::runtime_provisioners::remove_host(
            &ca_json,
            &provisioner,
            &user_provisioner_host_suffix(host_name),
        )?;
        finish_revocation(
            model,
            &ca_json,
            text,
            !removed.is_empty(),
            &format!("host {host_name}"),
        )?;
        let mut templates = removed;
        templates.push(provisioner.clone());
        templates.extend(matching_provisioner_templates(model, |name| {
            parse_user_provisioner_name(name).is_some_and(|(_, host)| host == host_name)
        })?);
        remove_provisioner_templates(model, &templates)
    })
}

fn status(
    model: &SiteModel,
    user: Option<&str>,
    host: Option<&str>,
    quiet: bool,
    renewable: bool,
) -> grafhome_ca::Result<bool> {
    if renewable && !local_renewal_ready(model, user, host)? {
        if !quiet {
            let identity = match (user, host) {
                (Some(user), Some(host)) => format!("user {user} on {host}"),
                (None, Some(host)) => format!("host {host}"),
                _ => "requested enrollment".to_owned(),
            };
            outln!("{identity}: not renewable locally");
        }
        return Ok(false);
    }
    let Some(names) = remote_provisioner_names(model, user, quiet)? else {
        return Ok(false);
    };
    let mut users = names
        .iter()
        .filter_map(|name| parse_user_provisioner_name(name))
        .collect::<Vec<_>>();
    users.sort();

    match (user, host) {
        (Some(user), Some(host)) => {
            let enrolled = users
                .iter()
                .any(|(item_user, item_host)| item_user == user && item_host == host);
            if !quiet {
                outln!(
                    "user {user} on {host}: {}",
                    if enrolled { "enrolled" } else { "not enrolled" }
                );
            }
            Ok(enrolled)
        }
        (Some(user), None) => {
            let hosts = users
                .iter()
                .filter(|(item_user, _)| item_user == user)
                .map(|(_, item_host)| item_host.as_str())
                .collect::<Vec<_>>();
            if !quiet {
                if hosts.is_empty() {
                    outln!("user {user}: not enrolled");
                } else {
                    outln!("user {user}: enrolled on {}", hosts.join(","));
                }
            }
            Ok(!hosts.is_empty())
        }
        (None, Some(host)) => {
            let host_enrolled = names
                .iter()
                .filter_map(|name| parse_host_provisioner_name(name))
                .any(|item_host| item_host == host);
            let host_users = users
                .iter()
                .filter(|(_, item_host)| item_host == host)
                .map(|(item_user, _)| item_user.as_str())
                .collect::<Vec<_>>();
            if !quiet {
                outln!(
                    "host {host}: {}; users: {}",
                    if host_enrolled {
                        "enrolled"
                    } else {
                        "not enrolled"
                    },
                    if host_users.is_empty() {
                        "none".to_owned()
                    } else {
                        host_users.join(",")
                    }
                );
            }
            Ok(host_enrolled)
        }
        (None, None) => unreachable!("status scope is inferred before lookup"),
    }
}

fn resolve_status_scope(
    user: Option<String>,
    host: Option<String>,
) -> grafhome_ca::Result<(Option<String>, Option<String>)> {
    if user.is_some() || host.is_some() {
        return Ok((user, host));
    }
    let host = Some(resolve_host(None)?);
    let user = if nonempty_env(LOCAL_USER_ENV).is_none()
        && std::env::var("USER").as_deref() == Ok("root")
    {
        None
    } else {
        Some(resolve_user(None)?)
    };
    Ok((user, host))
}

fn local_renewal_ready(
    model: &SiteModel,
    user: Option<&str>,
    host: Option<&str>,
) -> grafhome_ca::Result<bool> {
    let Some(host) = host else {
        return Err(grafhome_ca::Error::Validation {
            field: "status --renewable".to_owned(),
            message: "requires --host".to_owned(),
        });
    };
    match user {
        Some(user) => match user_local_renewal_readiness(model, user, host, true)? {
            UserLocalRenewalReadiness::NotEnrolled => Ok(false),
            UserLocalRenewalReadiness::Ready { .. } => Ok(true),
            UserLocalRenewalReadiness::CredentialUnavailable(error) => Err(error),
        },
        None => Ok(server_root_cert_path(model).is_file()
            && host_material_dir(model, host)
                .join("provisioner.priv.json")
                .is_file()),
    }
}

enum UserLocalRenewalReadiness {
    NotEnrolled,
    Ready { password: Option<String> },
    CredentialUnavailable(grafhome_ca::Error),
}

fn user_local_renewal_readiness(
    model: &SiteModel,
    user: &str,
    host: &str,
    require_stored_credential: bool,
) -> grafhome_ca::Result<UserLocalRenewalReadiness> {
    let enrollment_material_present = user_root_cert_path(model)?.is_file()
        && user_client_material_dir(user, host)?
            .join("provisioner.priv.json")
            .is_file();
    if !enrollment_material_present {
        return Ok(UserLocalRenewalReadiness::NotEnrolled);
    }
    if !require_stored_credential {
        return Ok(UserLocalRenewalReadiness::Ready { password: None });
    }
    Ok(match lookup_renewal_password(user, host) {
        Ok(password) => UserLocalRenewalReadiness::Ready {
            password: Some(password),
        },
        Err(error) => UserLocalRenewalReadiness::CredentialUnavailable(error),
    })
}

fn remote_provisioner_names(
    model: &SiteModel,
    user: Option<&str>,
    quiet: bool,
) -> grafhome_ca::Result<Option<Vec<String>>> {
    #[derive(serde::Deserialize)]
    struct RemoteProvisioner {
        name: String,
    }

    let ca_api = required_endpoint(model, ENDPOINT_ROLE_CA_API)?;
    let Some((root, user_owned)) = status_root_cert_path(model, user)? else {
        if quiet {
            return Ok(None);
        }
        return Err(grafhome_ca::Error::Validation {
            field: "status trust root".to_owned(),
            message: "no locally pinned CA root is installed; this machine is not enrolled"
                .to_owned(),
        });
    };
    let step_bin = if user_owned {
        user_step_bin()?
    } else {
        root_step_bin(model)?
    };
    let output = run_capture(
        process(&step_bin)
            .arg("ca")
            .arg("provisioner")
            .arg("list")
            .arg("--ca-url")
            .arg(ca_api.url())
            .arg("--root")
            .arg(root),
    )?;
    let provisioners: Vec<RemoteProvisioner> =
        serde_json::from_slice(&output).map_err(|source| grafhome_ca::Error::Json {
            path: PathBuf::from("<step ca provisioner list>"),
            source,
        })?;
    let mut names = Vec::with_capacity(provisioners.len());
    for (index, provisioner) in provisioners.into_iter().enumerate() {
        if provisioner.name.trim().is_empty() {
            return Err(grafhome_ca::Error::Validation {
                field: "step ca provisioner list".to_owned(),
                message: format!("provisioner entry {index} has an empty name"),
            });
        }
        names.push(provisioner.name);
    }
    Ok(Some(names))
}

fn status_root_cert_path(
    model: &SiteModel,
    _user: Option<&str>,
) -> grafhome_ca::Result<Option<(PathBuf, bool)>> {
    let user_root = user_root_cert_path(model)?;
    let server_root = server_root_cert_path(model);
    let ca_root = ca_root_cert_path(model);
    let candidates = if std::env::var("USER").as_deref() == Ok("root") {
        [(ca_root, false), (server_root, false), (user_root, true)]
    } else {
        [(user_root, true), (ca_root, false), (server_root, false)]
    };
    for (path, user_owned) in candidates {
        if path.is_file() {
            return Ok(Some((path, user_owned)));
        }
    }
    Ok(None)
}

fn host_renewal_lock_path(model: &SiteModel) -> PathBuf {
    PathBuf::from(&model.deployment.values["GRAFHOME_CA_SERVER_STEPPATH"])
        .join(".grafhome-ca-renew-host.lock")
}

fn user_renewal_lock_path(model: &SiteModel) -> grafhome_ca::Result<PathBuf> {
    Ok(user_steppath(model)?.join(".grafhome-ca-renew-user.lock"))
}

fn try_renewal_lock(path: &Path) -> grafhome_ca::Result<Option<std::fs::File>> {
    let parent = path
        .parent()
        .expect("renewal lock path has a parent directory");
    std::fs::create_dir_all(parent).map_err(|source| grafhome_ca::Error::io(parent, source))?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options
        .open(path)
        .map_err(|source| grafhome_ca::Error::io(path, source))?;
    match file.try_lock_exclusive() {
        Ok(()) => Ok(Some(file)),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(source) => Err(grafhome_ca::Error::io(path, source)),
    }
}

fn renewal_already_running(scope: &str, silent: bool) -> grafhome_ca::Result<()> {
    if silent {
        Ok(())
    } else {
        Err(grafhome_ca::Error::Validation {
            field: format!("renew {scope}"),
            message: "another renewal is already running".to_owned(),
        })
    }
}

fn with_ca_lock<T>(
    model: &SiteModel,
    action: impl FnOnce() -> grafhome_ca::Result<T>,
) -> grafhome_ca::Result<T> {
    let path = PathBuf::from(model.deployment.ca_steppath()).join("config/.grafhome-ca.lock");
    let parent = path.parent().expect("CA lock path has a parent");
    std::fs::create_dir_all(parent).map_err(|source| grafhome_ca::Error::io(parent, source))?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options
        .open(&path)
        .map_err(|source| grafhome_ca::Error::io(&path, source))?;
    file.lock_exclusive()
        .map_err(|source| grafhome_ca::Error::io(&path, source))?;
    action()
}

fn remove_provisioner_templates(model: &SiteModel, names: &[String]) -> grafhome_ca::Result<()> {
    let template_dir = PathBuf::from(model.deployment.ca_steppath()).join("templates/ssh");
    let mut names = names.to_vec();
    names.sort();
    names.dedup();
    for name in &names {
        let path = template_dir.join(format!("{name}.tpl"));
        match std::fs::remove_file(&path) {
            Ok(()) => outln!("removed template: {}", path.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(grafhome_ca::Error::io(&path, source)),
        }
    }
    Ok(())
}

fn matching_provisioner_templates(
    model: &SiteModel,
    matches: impl Fn(&str) -> bool,
) -> grafhome_ca::Result<Vec<String>> {
    let template_dir = PathBuf::from(model.deployment.ca_steppath()).join("templates/ssh");
    let entries = match std::fs::read_dir(&template_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => return Err(grafhome_ca::Error::io(&template_dir, source)),
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| grafhome_ca::Error::io(&template_dir, source))?;
        let file_name = entry.file_name();
        let Some(name) = file_name
            .to_str()
            .and_then(|name| name.strip_suffix(".tpl"))
        else {
            continue;
        };
        if matches(name) {
            names.push(name.to_owned());
        }
    }
    Ok(names)
}

fn finish_revocation(
    model: &SiteModel,
    ca_json: &Path,
    text: String,
    removed: bool,
    identity: &str,
) -> grafhome_ca::Result<()> {
    if removed {
        install_ca_json_with_rollback(
            model,
            ca_json,
            text.as_bytes(),
            required_endpoint(model, ENDPOINT_ROLE_CA_API)?.url(),
            || Ok(()),
        )?;
        outln!("Revoked {identity}: future issuance and renewal are disabled.");
    } else {
        outln!("{identity} is already revoked or was never enrolled.");
    }
    outln!("Existing SSH certificates remain valid until their current expiry.");
    Ok(())
}

fn install_ca_json_with_rollback<T>(
    model: &SiteModel,
    ca_json: &Path,
    content: &[u8],
    ca_url: String,
    after_activate: impl FnOnce() -> grafhome_ca::Result<T>,
) -> grafhome_ca::Result<T> {
    let previous =
        std::fs::read(ca_json).map_err(|source| grafhome_ca::Error::io(ca_json, source))?;
    let backup = ca_json_backup_path(ca_json);
    write_secret_file(&backup, &previous)?;
    write_secret_file_atomic(ca_json, content)?;
    let step_bin = root_step_bin(model)?;
    let activate = || -> grafhome_ca::Result<()> {
        install_ca_json_permissions(model, ca_json)?;
        run_status_quiet(
            process("systemctl").arg("restart").arg("step-ca.service"),
            &[],
            true,
        )?;
        run_status_quiet(
            process("systemctl").arg("is-active").arg("step-ca.service"),
            &[],
            true,
        )?;
        run_status_with_retries(
            "step ca health",
            CA_HEALTH_RETRY_ATTEMPTS,
            CA_HEALTH_RETRY_DELAY,
            CA_HEALTH_CONSECUTIVE_SUCCESSES,
            || {
                let mut command = process(&step_bin);
                command
                    .arg("ca")
                    .arg("health")
                    .arg("--ca-url")
                    .arg(&ca_url)
                    .arg("--root")
                    .arg(ca_root_cert_path(model));
                command
            },
        )
    };
    let result = activate().and_then(|()| after_activate());
    let value = match result {
        Ok(value) => value,
        Err(error) => {
            let rollback = (|| -> grafhome_ca::Result<()> {
                write_secret_file_atomic(ca_json, &previous)?;
                install_ca_json_permissions(model, ca_json)?;
                run_status_quiet(
                    process("systemctl").arg("restart").arg("step-ca.service"),
                    &[],
                    true,
                )?;
                run_status_quiet(
                    process("systemctl").arg("is-active").arg("step-ca.service"),
                    &[],
                    true,
                )
            })();
            return Err(grafhome_ca::Error::Validation {
                field: "CA update".to_owned(),
                message: match rollback {
                    Ok(()) => format!(
                        "{error}; restored previous ca.json from {}",
                        backup.display()
                    ),
                    Err(rollback_error) => format!(
                        "{error}; rollback failed after writing backup {}: {rollback_error}",
                        backup.display()
                    ),
                },
            });
        }
    };
    outln!("backup ca.json: {}", backup.display());
    Ok(value)
}

fn install_ca_json_permissions(model: &SiteModel, ca_json: &Path) -> grafhome_ca::Result<()> {
    run_status(
        process("chown")
            .arg(format!(
                "{}:{}",
                model.deployment.values["GRAFHOME_CA_SERVICE_USER"],
                model.deployment.values["GRAFHOME_CA_SERVICE_USER"]
            ))
            .arg(ca_json),
    )?;
    run_status(process("chmod").arg("0640").arg(ca_json))
}

fn ca_json_backup_path(ca_json: &Path) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    ca_json.with_file_name(format!(
        "{}.grafhome-ca-backup-{stamp}-{}",
        ca_json
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("ca.json"),
        std::process::id()
    ))
}

fn renew_user(
    model: &SiteModel,
    user_name: &str,
    host: Option<&str>,
    password: &str,
    quiet: bool,
) -> grafhome_ca::Result<()> {
    let user = active_user(model, user_name)?;
    let client = match host {
        Some(host) => required_user_client(model, &user.user, host)?,
        None => select_single_user_client(model, &user.user)?,
    };
    renew_user_certificate(
        model,
        user,
        client,
        password,
        &user_public_key_path()?,
        &user_cert_path()?,
        quiet,
    )
}

fn verify_user_renewal(
    model: &SiteModel,
    user_name: &str,
    host: &str,
    password: &str,
) -> grafhome_ca::Result<()> {
    let user = active_user(model, user_name)?;
    let client = required_user_client(model, &user.user, host)?;
    let material_dir = user_client_material_dir(&user.user, &client.host)?;
    let temp = tempfile::Builder::new()
        .prefix(".grafhome-ca-renewal-check-")
        .tempdir_in(&material_dir)
        .map_err(|source| grafhome_ca::Error::io(&material_dir, source))?;
    let public_key = temp.path().join("id_ed25519.pub");
    std::fs::copy(user_public_key_path()?, &public_key)
        .map_err(|source| grafhome_ca::Error::io(&public_key, source))?;
    let certificate = temp.path().join("id_ed25519-cert.pub");
    renew_user_certificate(
        model,
        user,
        client,
        password,
        &public_key,
        &certificate,
        false,
    )
}

fn renew_user_certificate(
    model: &SiteModel,
    user: &User,
    client: &UserClient,
    password: &str,
    public_key: &Path,
    certificate: &Path,
    quiet: bool,
) -> grafhome_ca::Result<()> {
    let step_bin = user_step_bin()?;
    let ca_api = required_endpoint(model, ENDPOINT_ROLE_CA_API)?;
    let provisioner = user_provisioner_name(&user.user, &client.host);
    let material_dir = user_client_material_dir(&user.user, &client.host)?;
    let private_jwk = material_dir.join("provisioner.priv.json");
    let token = with_password_file(&material_dir, password, |password_file| {
        run_capture(
            process(&step_bin)
                .env("STEPPATH", user_steppath(model)?)
                .arg("ca")
                .arg("token")
                .arg(&user.principal)
                .arg("--ssh")
                .arg("--principal")
                .arg(&user.principal)
                .arg("--not-after")
                .arg("5m")
                .arg("--cert-not-after")
                .arg(&user.cert_ttl)
                .arg("--issuer")
                .arg(&provisioner)
                .arg("--key")
                .arg(&private_jwk)
                .arg("--password-file")
                .arg(password_file)
                .arg("--ca-url")
                .arg(ca_api.url())
                .arg("--root")
                .arg(user_root_cert_path(model)?),
        )
    })?;
    let token = String::from_utf8(token).map_err(|error| grafhome_ca::Error::Validation {
        field: "step ca token".to_owned(),
        message: format!("token output was not UTF-8: {error}"),
    })?;
    run_status_quiet(
        process(&step_bin)
            .env("STEPPATH", user_steppath(model)?)
            .arg("ssh")
            .arg("certificate")
            .arg(&user.principal)
            .arg(public_key)
            .arg("--sign")
            .arg("--token")
            .arg(token.trim())
            .arg("--ca-url")
            .arg(ca_api.url())
            .arg("--root")
            .arg(user_root_cert_path(model)?)
            .arg("--force")
            .arg("--no-agent"),
        &[token.trim()],
        quiet,
    )?;
    run_status_quiet(
        process("ssh-keygen").arg("-L").arg("-f").arg(certificate),
        &[],
        quiet,
    )
}

fn user_certificate_needs_renewal(
    model: &SiteModel,
    user_name: &str,
    host: &str,
) -> grafhome_ca::Result<bool> {
    let user = active_user(model, user_name)?;
    required_user_client(model, &user.user, host)?;
    let step_bin = user_step_bin()?;
    ssh_certificate_needs_renewal(&step_bin, &user_cert_path()?)
}

fn ssh_certificate_needs_renewal(step_bin: &str, certificate: &Path) -> grafhome_ca::Result<bool> {
    let output = process(step_bin)
        .arg("ssh")
        .arg("needs-renewal")
        .arg(certificate)
        .output()
        .map_err(|source| grafhome_ca::Error::io(step_bin, source))?;
    match output.status.code() {
        Some(0 | 2) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(grafhome_ca::Error::Validation {
            field: "SSH certificate renewal check".to_owned(),
            message: format!(
                "step ssh needs-renewal failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        }),
    }
}

#[cfg(target_os = "macos")]
fn store_renewal_password(user: &str, host: &str, password: &str) -> grafhome_ca::Result<()> {
    store_macos_keychain_password(user, host, password)?;
    eprintln!("Stored the renewal password in macOS Keychain.");
    Ok(())
}

#[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
fn store_renewal_password(user: &str, host: &str, password: &str) -> grafhome_ca::Result<()> {
    // The systemd copy is the unattended backend. Store it first so a failed
    // enrollment cannot leave a Secret Service item that looks renewable but
    // becomes unavailable after a headless reboot.
    let systemd_mode = store_systemd_credential(user, host, password)?;
    let stored_in_keyring = try_store_secret_service(user, host, password);
    if stored_in_keyring {
        eprintln!("Stored the renewal password in the system keyring and as {systemd_mode}.");
    } else {
        eprintln!("Stored the renewal password as {systemd_mode}.");
    }
    Ok(())
}

#[cfg(target_os = "android")]
fn store_renewal_password(user: &str, host: &str, password: &str) -> grafhome_ca::Result<()> {
    let path = renewal_credential_path(user, host)?;
    store_app_private_credential(&path, password)?;
    eprintln!(
        "Stored the renewal password in an owner-only file inside Termux's Android app sandbox."
    );
    Ok(())
}

#[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
fn try_store_secret_service(user: &str, host: &str, password: &str) -> bool {
    let child = process("secret-tool")
        .arg("store")
        .arg("--label=Grafhome CA renewal")
        .arg("service")
        .arg("grafhome-ca")
        .arg("user")
        .arg(user)
        .arg("host")
        .arg(host)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(_) => return false,
    };
    if let Err(source) = child
        .stdin
        .as_mut()
        .expect("piped secret-tool stdin")
        .write_all(password.as_bytes())
    {
        if source.kind() == std::io::ErrorKind::BrokenPipe {
            let _ = child.wait();
            return false;
        }
        let _ = child.wait();
        return false;
    }
    let Ok(output) = child.wait_with_output() else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    true
}

#[cfg(target_os = "macos")]
fn lookup_renewal_password(user: &str, host: &str) -> grafhome_ca::Result<String> {
    lookup_macos_keychain_password(user, host)
}

#[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
fn lookup_renewal_password(user: &str, host: &str) -> grafhome_ca::Result<String> {
    match lookup_systemd_credential(user, host) {
        Ok(password) => Ok(password),
        Err(systemd_error) => {
            // Secret Service is a recovery copy. Prefer the unattended systemd
            // credential so a stale keyring item cannot override it.
            lookup_secret_service(user, host).ok_or(systemd_error)
        }
    }
}

#[cfg(target_os = "android")]
fn lookup_renewal_password(user: &str, host: &str) -> grafhome_ca::Result<String> {
    let path = renewal_credential_path(user, host)?;
    read_app_private_credential(&path)?.ok_or_else(|| grafhome_ca::Error::Validation {
        field: "renewal credential storage".to_owned(),
        message: format!(
            "no usable renewal password found for {user}@{host}; rerun enrollment or use --password-file"
        ),
    })
}

#[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
fn lookup_secret_service(user: &str, host: &str) -> Option<String> {
    let output = process("secret-tool")
        .arg("lookup")
        .arg("service")
        .arg("grafhome-ca")
        .arg("user")
        .arg(user)
        .arg("host")
        .arg(host)
        .output();
    let output = match output {
        Ok(output) => output,
        Err(_) => return None,
    };
    let password = String::from_utf8_lossy(&output.stdout)
        .trim_end_matches(['\r', '\n'])
        .to_owned();
    if !output.status.success() || password.is_empty() {
        return None;
    }
    Some(password)
}

#[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
fn renewal_credential_path(user: &str, host: &str) -> grafhome_ca::Result<PathBuf> {
    Ok(user_client_material_dir(user, host)?.join("renewal-password.cred"))
}

#[cfg(target_os = "android")]
fn renewal_credential_path(user: &str, host: &str) -> grafhome_ca::Result<PathBuf> {
    Ok(user_client_material_dir(user, host)?.join(ANDROID_RENEWAL_CREDENTIAL_NAME))
}

#[cfg(any(target_os = "android", test))]
fn store_app_private_credential(path: &Path, password: &str) -> grafhome_ca::Result<()> {
    if password.is_empty() {
        return Err(grafhome_ca::Error::Validation {
            field: "renewal credential storage".to_owned(),
            message: "refusing to store an empty renewal password".to_owned(),
        });
    }
    write_secret_file_atomic(path, password.as_bytes())
}

#[cfg(any(target_os = "android", test))]
fn read_app_private_credential(path: &Path) -> grafhome_ca::Result<Option<String>> {
    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let descriptor = match rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(rustix::io::Errno::LOOP) => {
            return Err(grafhome_ca::Error::Validation {
                field: "renewal credential storage".to_owned(),
                message: format!(
                    "{} must be a regular file, not a symbolic link",
                    path.display()
                ),
            });
        }
        Err(source) => {
            return Err(grafhome_ca::Error::io(
                path,
                std::io::Error::from_raw_os_error(source.raw_os_error()),
            ));
        }
    };
    let mut file = std::fs::File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|source| grafhome_ca::Error::io(path, source))?;
    if !metadata.file_type().is_file() {
        return Err(grafhome_ca::Error::Validation {
            field: "renewal credential storage".to_owned(),
            message: format!("{} must be a regular file", path.display()),
        });
    }
    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode();
        if metadata.uid() != rustix::process::geteuid().as_raw() || mode & 0o077 != 0 {
            return Err(grafhome_ca::Error::Validation {
                field: "renewal credential storage".to_owned(),
                message: format!(
                    "{} must be owned by the current user and inaccessible to group and other users",
                    path.display()
                ),
            });
        }
    }
    let mut password = String::new();
    file.read_to_string(&mut password)
        .map_err(|source| grafhome_ca::Error::io(path, source))?;
    if password.is_empty() {
        return Err(grafhome_ca::Error::Validation {
            field: "renewal credential storage".to_owned(),
            message: format!("{} contains an empty renewal password", path.display()),
        });
    }
    Ok(Some(password))
}

#[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SystemdCredentialMode {
    User,
    Tpm,
}

#[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
impl std::fmt::Display for SystemdCredentialMode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User => formatter.write_str("an encrypted systemd user credential"),
            Self::Tpm => formatter.write_str("an encrypted TPM-bound systemd credential"),
        }
    }
}

#[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
impl SystemdCredentialMode {
    /// @brief Add encryption arguments for this credential format.
    fn encrypt_args(self, command: &mut ProcessCommand) {
        match self {
            Self::User => {
                command.arg("--user");
            }
            Self::Tpm => {
                // systemd before version 256 has no user-scoped credentials.
                // File mode still scopes access to this user, while TPM-only
                // encryption keeps copied home-directory data confidential.
                // Avoid fixed PCR binding so routine firmware and Secure Boot
                // database updates do not strand the renewal credential.
                command.arg("--with-key=tpm2").arg("--tpm2-pcrs=");
            }
        }
    }

    /// @brief Add decryption arguments for this credential format.
    fn decrypt_args(self, command: &mut ProcessCommand) {
        if self == Self::User {
            command.arg("--user");
        }
    }
}

#[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
fn store_systemd_credential(
    user: &str,
    host: &str,
    password: &str,
) -> grafhome_ca::Result<SystemdCredentialMode> {
    let path = renewal_credential_path(user, host)?;
    let parent = path.parent().expect("credential path has a parent");
    std::fs::create_dir_all(parent).map_err(|source| grafhome_ca::Error::io(parent, source))?;
    let temporary = parent.join(format!(".renewal-password.cred-{}", std::process::id()));
    remove_file_if_present(&temporary)?;

    let user_error =
        match try_encrypt_systemd_credential(SystemdCredentialMode::User, &temporary, password) {
            Ok(()) => {
                finalize_systemd_credential(&temporary, &path)?;
                return Ok(SystemdCredentialMode::User);
            }
            Err(message) => message,
        };

    // A failed command may have created a partial output. Never let it become
    // input to the compatibility attempt or remain beside private key material.
    remove_file_if_present(&temporary)?;
    let tpm_error =
        match try_encrypt_systemd_credential(SystemdCredentialMode::Tpm, &temporary, password) {
            Ok(()) => {
                finalize_systemd_credential(&temporary, &path)?;
                return Ok(SystemdCredentialMode::Tpm);
            }
            Err(message) => message,
        };
    remove_file_if_present(&temporary)?;

    Err(grafhome_ca::Error::Validation {
        field: "renewal credential storage".to_owned(),
        message: format!(
            "could not create the encrypted systemd credential required for unattended renewal; \
             user-scoped credential: {user_error}; legacy TPM credential: {tpm_error}. \
             Use systemd 256 or newer, or grant this user access to the TPM resource manager \
             (commonly by adding it to the tss group). As an explicit fallback, pass the same \
             owner-only --password-file to enrollment and scheduled renewal"
        ),
    })
}

#[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
fn try_encrypt_systemd_credential(
    mode: SystemdCredentialMode,
    path: &Path,
    password: &str,
) -> Result<(), String> {
    let mut command = process("systemd-creds");
    command.arg("encrypt");
    mode.encrypt_args(&mut command);
    command
        .arg("--quiet")
        .arg(format!("--name={SYSTEMD_RENEWAL_CREDENTIAL_NAME}"))
        .arg("-")
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|source| format!("could not start systemd-creds: {source}"))?;
    let write_result = child
        .stdin
        .take()
        .expect("piped systemd-creds stdin")
        .write_all(password.as_bytes());
    let output = child
        .wait_with_output()
        .map_err(|source| format!("could not wait for systemd-creds: {source}"))?;
    if !output.status.success() {
        return Err(backend_command_error(
            &output.stderr,
            "systemd-creds encryption failed without an error message",
            &[password],
        ));
    }
    write_result.map_err(|source| format!("could not write to systemd-creds: {source}"))
}

#[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
fn finalize_systemd_credential(temporary: &Path, path: &Path) -> grafhome_ca::Result<()> {
    let result = (|| {
        #[cfg(unix)]
        std::fs::set_permissions(temporary, std::fs::Permissions::from_mode(0o600))
            .map_err(|source| grafhome_ca::Error::io(temporary, source))?;
        std::fs::rename(temporary, path).map_err(|source| grafhome_ca::Error::io(path, source))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}

#[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
fn lookup_systemd_credential(user: &str, host: &str) -> grafhome_ca::Result<String> {
    let path = renewal_credential_path(user, host)?;
    let user_error = match try_decrypt_systemd_credential(SystemdCredentialMode::User, &path) {
        Ok(password) => return Ok(password),
        Err(message) => message,
    };
    let tpm_error = match try_decrypt_systemd_credential(SystemdCredentialMode::Tpm, &path) {
        Ok(password) => return Ok(password),
        Err(message) => message,
    };
    Err(grafhome_ca::Error::Validation {
        field: "renewal credential storage".to_owned(),
        message: format!(
            "no usable renewal password found for {user}@{host}; user-scoped credential: \
             {user_error}; legacy TPM credential: {tpm_error}. Rerun enrollment or use \
             --password-file"
        ),
    })
}

#[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
fn try_decrypt_systemd_credential(
    mode: SystemdCredentialMode,
    path: &Path,
) -> Result<String, String> {
    let mut command = process("systemd-creds");
    command.arg("decrypt");
    mode.decrypt_args(&mut command);
    let output = command
        .arg("--quiet")
        .arg(format!("--name={SYSTEMD_RENEWAL_CREDENTIAL_NAME}"))
        .arg(path)
        .arg("-")
        .output()
        .map_err(|source| format!("could not start systemd-creds: {source}"))?;
    let password = String::from_utf8_lossy(&output.stdout)
        .trim_end_matches(['\r', '\n'])
        .to_owned();
    if !output.status.success() || password.is_empty() {
        return Err(backend_command_error(
            &output.stderr,
            "systemd-creds did not return a credential",
            &[],
        ));
    }
    Ok(password)
}

#[cfg(not(target_os = "android"))]
fn backend_command_error(stderr: &[u8], fallback: &str, redactions: &[&str]) -> String {
    let message = redact_text(&String::from_utf8_lossy(stderr), redactions)
        .trim()
        .to_owned();
    if message.is_empty() {
        fallback.to_owned()
    } else {
        message
    }
}

#[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
fn remove_file_if_present(path: &Path) -> grafhome_ca::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(grafhome_ca::Error::io(path, source)),
    }
}

#[cfg(target_os = "macos")]
const MACOS_KEYCHAIN_SERVICE: &str = "net.grafhome.ca.renewal";

#[cfg(target_os = "macos")]
fn renewal_credential_account(user: &str, host: &str) -> String {
    format!("{user}@{host}")
}

#[cfg(target_os = "macos")]
fn store_macos_keychain_password(
    user: &str,
    host: &str,
    password: &str,
) -> grafhome_ca::Result<()> {
    let account = renewal_credential_account(user, host);
    let password_hex = password
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    // Interactive mode keeps the secret out of argv. Using Apple's stable
    // security tool as the creator also keeps unattended access valid when
    // the grafhome-ca binary is replaced by a later unsigned release.
    let command = format!(
        "add-generic-password -U -a {account} -s {MACOS_KEYCHAIN_SERVICE} -X {password_hex}\n"
    );
    let mut child = process("security")
        .arg("-i")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| grafhome_ca::Error::io("security", source))?;
    child
        .stdin
        .as_mut()
        .expect("piped security stdin")
        .write_all(command.as_bytes())
        .map_err(|source| grafhome_ca::Error::io("security stdin", source))?;
    let output = child
        .wait_with_output()
        .map_err(|source| grafhome_ca::Error::io("security", source))?;
    if !output.status.success() {
        return Err(grafhome_ca::Error::Validation {
            field: "renewal credential storage".to_owned(),
            message: format!(
                "macOS Keychain could not store the renewal password: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        });
    }
    let stored = lookup_macos_keychain_password(user, host)?;
    if stored != password {
        return Err(grafhome_ca::Error::Validation {
            field: "renewal credential storage".to_owned(),
            message: "macOS Keychain did not return the password that was just stored".to_owned(),
        });
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn lookup_macos_keychain_password(user: &str, host: &str) -> grafhome_ca::Result<String> {
    let account = renewal_credential_account(user, host);
    let output = process("security")
        .arg("find-generic-password")
        .arg("-a")
        .arg(&account)
        .arg("-s")
        .arg(MACOS_KEYCHAIN_SERVICE)
        .arg("-w")
        .output()
        .map_err(|source| grafhome_ca::Error::io("security", source))?;
    let password = String::from_utf8_lossy(&output.stdout)
        .trim_end_matches(['\r', '\n'])
        .to_owned();
    if !output.status.success() || password.is_empty() {
        let detail = backend_command_error(
            &output.stderr,
            "security did not return a renewal password",
            &[],
        );
        return Err(grafhome_ca::Error::Validation {
            field: "renewal credential storage".to_owned(),
            message: format!(
                "no usable renewal password found in macOS Keychain for {user}@{host}; {detail}. Rerun enrollment or use --password-file"
            ),
        });
    }
    Ok(password)
}

fn with_password_file<T>(
    dir: &Path,
    password: &str,
    action: impl FnOnce(&Path) -> grafhome_ca::Result<T>,
) -> grafhome_ca::Result<T> {
    with_temp_file(dir, password.as_bytes(), action)
}

fn with_temp_file<T>(
    dir: &Path,
    content: &[u8],
    action: impl FnOnce(&Path) -> grafhome_ca::Result<T>,
) -> grafhome_ca::Result<T> {
    std::fs::create_dir_all(dir).map_err(|source| grafhome_ca::Error::io(dir, source))?;
    let mut file = tempfile::Builder::new()
        .prefix(".grafhome-ca-")
        .tempfile_in(dir)
        .map_err(|source| grafhome_ca::Error::io(dir, source))?;
    #[cfg(unix)]
    std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600))
        .map_err(|source| grafhome_ca::Error::io(file.path(), source))?;
    file.write_all(content)
        .map_err(|source| grafhome_ca::Error::io(file.path(), source))?;
    file.as_file_mut()
        .sync_all()
        .map_err(|source| grafhome_ca::Error::io(file.path(), source))?;
    action(file.path())
}

fn reload_ssh(model: &SiteModel) -> grafhome_ca::Result<()> {
    if let Some(sv) = model.deployment.values.get(HOST_SSH_RELOAD_BIN) {
        let service_dir = &model.deployment.values[HOST_SSH_SERVICE_DIR];
        return run_status_quiet(
            process(sv)
                .env("SVDIR", service_dir)
                .arg("hup")
                .arg("sshd"),
            &[],
            true,
        )
        .map_err(|error| grafhome_ca::Error::Validation {
                field: "SSH reload".to_owned(),
                message: format!(
                    "could not signal the Termux sshd service with `sv hup sshd`: {error}; install termux-services and enable sshd with `sv-enable sshd`"
                ),
            });
    }
    if cfg!(target_os = "macos") {
        return run_status_quiet(
            process("launchctl")
                .arg("kickstart")
                .arg("-k")
                .arg("system/com.openssh.sshd"),
            &[],
            true,
        )
        .map_err(|error| grafhome_ca::Error::Validation {
            field: "SSH reload".to_owned(),
            message: format!(
                "could not restart the macOS sshd launchd job with `launchctl kickstart -k system/com.openssh.sshd`: {error}; enable Remote Login in System Settings > General > Sharing"
            ),
        });
    }
    let sshd_error = match run_status_quiet(
        process("systemctl").arg("reload").arg("sshd.service"),
        &[],
        true,
    ) {
        Ok(()) => return Ok(()),
        Err(error) => error,
    };
    let ssh_error = match run_status_quiet(
        process("systemctl").arg("reload").arg("ssh.service"),
        &[],
        true,
    ) {
        Ok(()) => return Ok(()),
        Err(error) => error,
    };
    Err(grafhome_ca::Error::Validation {
        field: "SSH reload".to_owned(),
        message: format!(
            "neither sshd.service nor ssh.service could be reloaded; sshd.service: {sshd_error}; ssh.service: {ssh_error}"
        ),
    })
}

fn user_ssh_template(principal: &str) -> String {
    let principal_json = serde_json::to_string(principal).expect("principal string serializes");
    format!(
        "{{\n  \"type\": \"user\",\n  \"keyId\": {{{{ toJson .KeyID }}}},\n  \"principals\": [{principal_json}],\n  \"criticalOptions\": {{{{ toJson .CriticalOptions }}}},\n  \"extensions\": {{{{ toJson .Extensions }}}}\n}}\n"
    )
}

fn host_ssh_template(host: &Host) -> String {
    let principals = host
        .principals
        .iter()
        .map(String::as_str)
        .map(|principal| serde_json::to_string(principal).expect("principal serializes"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{{\n  \"type\": \"host\",\n  \"keyId\": {{{{ toJson .KeyID }}}},\n  \"principals\": [{principals}],\n  \"criticalOptions\": {{{{ toJson .CriticalOptions }}}},\n  \"extensions\": {{{{ toJson .Extensions }}}}\n}}\n"
    )
}

fn write_secret_file(path: &Path, content: &[u8]) -> grafhome_ca::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| grafhome_ca::Error::Validation {
            field: path.display().to_string(),
            message: "path must have a parent directory".to_owned(),
        })?;
    std::fs::create_dir_all(parent).map_err(|source| grafhome_ca::Error::io(parent, source))?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|source| grafhome_ca::Error::io(path, source))?;
    file.write_all(content)
        .map_err(|source| grafhome_ca::Error::io(path, source))?;
    file.sync_all()
        .map_err(|source| grafhome_ca::Error::io(path, source))?;
    #[cfg(unix)]
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|source| grafhome_ca::Error::io(path, source))?;
    Ok(())
}

fn write_secret_file_atomic(path: &Path, content: &[u8]) -> grafhome_ca::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| grafhome_ca::Error::Validation {
            field: path.display().to_string(),
            message: "path must have a parent directory".to_owned(),
        })?;
    std::fs::create_dir_all(parent).map_err(|source| grafhome_ca::Error::io(parent, source))?;
    let mut file = tempfile::Builder::new()
        .prefix(".grafhome-ca-atomic-")
        .tempfile_in(parent)
        .map_err(|source| grafhome_ca::Error::io(parent, source))?;
    #[cfg(unix)]
    std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600))
        .map_err(|source| grafhome_ca::Error::io(file.path(), source))?;
    file.write_all(content)
        .map_err(|source| grafhome_ca::Error::io(file.path(), source))?;
    file.as_file_mut()
        .sync_all()
        .map_err(|source| grafhome_ca::Error::io(file.path(), source))?;
    let temp_path = file.into_temp_path();
    std::fs::rename(&temp_path, path).map_err(|source| grafhome_ca::Error::io(path, source))?;
    // The password file is the migration completion marker. Persist the
    // directory entry as well as file contents so success survives power loss.
    #[cfg(unix)]
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| grafhome_ca::Error::io(parent, source))?;
    let _ = temp_path.close();
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::io::{BufRead, Cursor, Error, ErrorKind, Write};
    use std::net::SocketAddr;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::thread;

    use tempfile::tempdir;

    use super::{
        CA_REACHABILITY_TIMEOUT, Endpoint, ExistingIdentityChoice, NoncanonicalTerminalMode,
        TermuxHostRuntime, effectively_infinite_warning, endpoint_reachable_with,
        normalize_regular_file_mode, parse_enrollment_document, prepare_existing_user_identity,
        read_app_private_credential, read_interactive_document, read_terminal_document,
        renewal_already_running, require_effectively_infinite_confirmation, ssh_public_keys_match,
        store_app_private_credential, try_renewal_lock, validate_grant_ca_url,
    };

    #[cfg(unix)]
    #[test]
    fn regular_file_mode_normalization_rejects_symlink_outputs() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("target");
        let output = dir.path().join("output");
        fs::write(&target, "content\n").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&target, &output).unwrap();

        let error = normalize_regular_file_mode(&output, "test output", 0o644)
            .unwrap_err()
            .to_string();

        assert!(error.contains("output must be a regular file"));
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn termux_private_directories_ignore_a_permissive_umask() {
        const CHILD: &str = "GRAFHOME_CA_TERMUX_DIRECTORY_UMASK_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tests::termux_private_directories_ignore_a_permissive_umask",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }

        let previous_umask = rustix::process::umask(rustix::fs::Mode::empty());
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        fs::create_dir(&home).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        let runtime = TermuxHostRuntime {
            home: home.clone(),
            prefix: dir.path().join("prefix"),
        };
        let material = home.join(".config/grafhome/host-step/secrets/hosts/phone");

        runtime
            .prepare_private_directory(&material, "host credential directory")
            .unwrap();

        for path in material.ancestors().take_while(|path| *path != home) {
            let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{}", path.display());
        }
        rustix::process::umask(previous_umask);
    }

    fn test_endpoint(address: &str) -> Endpoint {
        Endpoint {
            role: "ca_api".to_owned(),
            dns_name: "ca.example.test".to_owned(),
            target: "proxy-host".to_owned(),
            address: address.to_owned(),
            port: 8443,
            scheme: "https".to_owned(),
        }
    }

    #[test]
    fn reachability_uses_configured_address_and_bounded_timeout() {
        let reachable =
            endpoint_reachable_with(&test_endpoint("192.0.2.21"), |address, timeout| {
                assert_eq!(address, &"192.0.2.21:8443".parse::<SocketAddr>().unwrap());
                assert_eq!(timeout, CA_REACHABILITY_TIMEOUT);
                Ok(())
            })
            .unwrap();

        assert!(reachable);
    }

    #[test]
    fn reachability_treats_connect_failure_as_offline() {
        let reachable = endpoint_reachable_with(&test_endpoint("192.0.2.21"), |_, _| {
            Err(Error::new(ErrorKind::TimedOut, "offline"))
        })
        .unwrap();

        assert!(!reachable);
    }

    #[test]
    fn reachability_rejects_invalid_policy_address() {
        let error = endpoint_reachable_with(&test_endpoint("not-an-ip"), |_, _| Ok(()))
            .unwrap_err()
            .to_string();

        assert!(error.contains("policy/ca.toml:endpoints.ca_api.address"));
        assert!(error.contains("invalid IP address"));
    }

    #[test]
    fn reachability_reports_unexpected_local_socket_error() {
        let error = endpoint_reachable_with(&test_endpoint("192.0.2.21"), |_, _| {
            Err(Error::new(ErrorKind::PermissionDenied, "blocked locally"))
        })
        .unwrap_err()
        .to_string();

        assert!(error.contains("CA reachability probe 192.0.2.21:8443"));
        assert!(error.contains("blocked locally"));
    }

    #[test]
    fn reachability_reports_local_address_exhaustion() {
        let error = endpoint_reachable_with(&test_endpoint("192.0.2.21"), |_, _| {
            Err(Error::new(
                ErrorKind::AddrNotAvailable,
                "no local address available",
            ))
        })
        .unwrap_err()
        .to_string();

        assert!(error.contains("CA reachability probe 192.0.2.21:8443"));
        assert!(error.contains("no local address available"));
    }

    #[test]
    fn jwk_public_material_supports_smallstep_key_types_and_ignores_metadata() {
        for (jwk, expected) in [
            (
                serde_json::json!({
                    "kty": "EC", "crv": "P-256", "x": "ec-x", "y": "ec-y",
                    "kid": "metadata", "d": "private"
                }),
                serde_json::json!({"kty": "EC", "crv": "P-256", "x": "ec-x", "y": "ec-y"}),
            ),
            (
                serde_json::json!({
                    "kty": "OKP", "crv": "Ed25519", "x": "okp-x", "alg": "EdDSA"
                }),
                serde_json::json!({"kty": "OKP", "crv": "Ed25519", "x": "okp-x"}),
            ),
            (
                serde_json::json!({"kty": "RSA", "n": "modulus", "e": "AQAB", "use": "sig"}),
                serde_json::json!({"kty": "RSA", "n": "modulus", "e": "AQAB"}),
            ),
        ] {
            assert_eq!(
                grafhome_ca::runtime_provisioners::jwk_public_material(&jwk, "test JWK").unwrap(),
                expected
            );
        }
    }

    #[test]
    fn jwk_public_material_rejects_unsupported_and_incomplete_keys() {
        let unsupported = grafhome_ca::runtime_provisioners::jwk_public_material(
            &serde_json::json!({"kty": "oct", "k": "secret"}),
            "test JWK",
        )
        .unwrap_err()
        .to_string();
        assert!(unsupported.contains("unsupported JWK type oct"));

        let incomplete = grafhome_ca::runtime_provisioners::jwk_public_material(
            &serde_json::json!({"kty": "EC", "crv": "P-256", "x": "ec-x"}),
            "test JWK",
        )
        .unwrap_err()
        .to_string();
        assert!(incomplete.contains("must have a string y"));
    }

    #[test]
    fn effectively_infinite_manual_approval_warns_and_defaults_to_denial() {
        let request = grafhome_ca::enrollment::UserRequest::new(
            "alice",
            "laptop",
            "ssh-ed25519 AAAA alice@laptop",
            serde_json::json!({"kty": "OKP", "crv": "Ed25519", "x": "public"}),
        );
        let warning = effectively_infinite_warning(&request, "SHA256:fingerprint");

        assert!(warning.contains("User: alice"));
        assert!(warning.contains("Client host: laptop"));
        assert!(warning.contains("SSH key: SHA256:fingerprint"));
        assert!(warning.contains("RevokedKeys"));
        assert!(require_effectively_infinite_confirmation(true).is_ok());
        assert!(
            require_effectively_infinite_confirmation(false)
                .unwrap_err()
                .to_string()
                .contains("was not approved")
        );
    }

    #[test]
    fn renewal_lock_prevents_overlap_and_releases_with_file_drop() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("renew.lock");
        let first = try_renewal_lock(&path).unwrap().unwrap();

        assert!(try_renewal_lock(&path).unwrap().is_none());
        drop(first);
        assert!(try_renewal_lock(&path).unwrap().is_some());
    }

    #[test]
    fn renewal_contention_is_silent_only_for_scheduled_mode() {
        assert!(renewal_already_running("user", true).is_ok());
        let error = renewal_already_running("user", false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("renew user: another renewal is already running"));
    }

    #[test]
    fn app_private_credential_round_trips_with_owner_only_permissions() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("renewal-password.secret");

        store_app_private_credential(&path, "first-password").unwrap();
        store_app_private_credential(&path, "replacement-password").unwrap();

        assert_eq!(
            read_app_private_credential(&path).unwrap().as_deref(),
            Some("replacement-password")
        );
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn app_private_credential_reports_missing_file() {
        let dir = tempdir().unwrap();

        assert_eq!(
            read_app_private_credential(&dir.path().join("missing")).unwrap(),
            None
        );
    }

    #[test]
    fn app_private_credential_rejects_empty_password() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("renewal-password.secret");

        let error = store_app_private_credential(&path, "")
            .unwrap_err()
            .to_string();

        assert!(error.contains("empty renewal password"));
        assert!(!path.exists());
    }

    #[test]
    fn app_private_credential_rejects_empty_stored_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("renewal-password.secret");
        fs::write(&path, "").unwrap();
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let error = read_app_private_credential(&path).unwrap_err().to_string();

        assert!(error.contains("contains an empty renewal password"));
    }

    #[cfg(unix)]
    #[test]
    fn app_private_credential_rejects_group_readable_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("renewal-password.secret");
        fs::write(&path, "password").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();

        let error = read_app_private_credential(&path).unwrap_err().to_string();

        assert!(error.contains("inaccessible to group and other users"));
    }

    #[cfg(unix)]
    #[test]
    fn app_private_credential_rejects_symbolic_link() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let target = dir.path().join("target");
        let path = dir.path().join("renewal-password.secret");
        fs::write(&target, "password").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &path).unwrap();

        let error = read_app_private_credential(&path).unwrap_err().to_string();

        assert!(error.contains("must be a regular file"));
    }

    #[test]
    fn cancelling_identity_selection_preserves_every_file() {
        let dir = tempdir().unwrap();
        let paths = [
            dir.path().join("id_ed25519"),
            dir.path().join("id_ed25519.pub"),
            dir.path().join("id_ed25519-cert.pub"),
        ];
        for (index, path) in paths.iter().enumerate() {
            fs::write(path, format!("original-{index}")).unwrap();
        }

        let error = prepare_existing_user_identity(
            &paths,
            |_, _| Ok(ExistingIdentityChoice::Cancel),
            |_, _| unreachable!(),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("existing SSH identity files were not changed"));
        for (index, path) in paths.iter().enumerate() {
            assert_eq!(
                fs::read_to_string(path).unwrap(),
                format!("original-{index}")
            );
        }
    }

    #[test]
    fn replacing_identity_removes_the_existing_set() {
        let dir = tempdir().unwrap();
        let paths = [
            dir.path().join("id_ed25519"),
            dir.path().join("id_ed25519.pub"),
            dir.path().join("id_ed25519-cert.pub"),
        ];
        for path in &paths {
            fs::write(path, "original").unwrap();
        }

        let generate = prepare_existing_user_identity(
            &paths,
            |existing, reusable| {
                assert_eq!(existing, paths);
                assert!(reusable);
                Ok(ExistingIdentityChoice::Replace)
            },
            |_, _| unreachable!(),
        )
        .unwrap();

        assert!(generate);
        assert!(paths.iter().all(|path| !path.exists()));
    }

    #[test]
    fn using_identity_preserves_files_and_validates_the_pair() {
        let dir = tempdir().unwrap();
        let paths = [
            dir.path().join("id_ed25519"),
            dir.path().join("id_ed25519.pub"),
            dir.path().join("id_ed25519-cert.pub"),
        ];
        for path in &paths {
            fs::write(path, "original").unwrap();
        }
        let mut validated = false;

        let generate = prepare_existing_user_identity(
            &paths,
            |existing, reusable| {
                assert_eq!(existing, paths);
                assert!(reusable);
                Ok(ExistingIdentityChoice::Use)
            },
            |private, public| {
                assert_eq!(private, paths[0]);
                assert_eq!(public, paths[1]);
                validated = true;
                Ok(())
            },
        )
        .unwrap();

        assert!(!generate);
        assert!(validated);
        assert!(paths.iter().all(|path| path.exists()));
    }

    #[test]
    fn using_identity_requires_both_key_files() {
        let dir = tempdir().unwrap();
        let paths = [
            dir.path().join("id_ed25519"),
            dir.path().join("id_ed25519.pub"),
            dir.path().join("id_ed25519-cert.pub"),
        ];
        fs::write(&paths[0], "private").unwrap();

        let error = prepare_existing_user_identity(
            &paths,
            |_, reusable| {
                assert!(!reusable);
                Ok(ExistingIdentityChoice::Use)
            },
            |_, _| unreachable!(),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("both id_ed25519 and id_ed25519.pub are required"));
        assert!(paths[0].exists());
    }

    #[test]
    fn identity_pair_validation_accepts_matching_keys_with_different_comments() {
        assert!(ssh_public_keys_match(
            "ssh-ed25519 AAAAkey derived-comment\n",
            "ssh-ed25519 AAAAkey configured-comment\n"
        ));
    }

    #[test]
    fn identity_pair_validation_rejects_mismatched_or_malformed_keys() {
        assert!(!ssh_public_keys_match(
            "ssh-ed25519 AAAAderived\n",
            "ssh-ed25519 AAAAconfigured\n"
        ));
        assert!(!ssh_public_keys_match("ssh-ed25519", "ssh-ed25519"));
    }

    #[test]
    fn identity_selection_rejects_a_directory() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("id_ed25519");
        fs::create_dir(&path).unwrap();
        let mut prompted = false;

        let error = prepare_existing_user_identity(
            &[path],
            |_, _| {
                prompted = true;
                Ok(ExistingIdentityChoice::Replace)
            },
            |_, _| unreachable!(),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("path that is a directory"));
        assert!(!prompted);
    }

    #[test]
    fn grant_ca_url_must_match_configured_ca() {
        let config_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/site-config");
        let model = grafhome_ca::model::SiteModel::load(config_root).expect("example model");

        let error =
            validate_grant_ca_url(&model, "https://attacker.example", "user enrollment grant")
                .unwrap_err()
                .to_string();

        assert!(error.contains("does not match configured CA URL https://ca.example.test"));
    }

    #[test]
    fn interactive_document_returns_after_one_complete_line() {
        let mut input = Cursor::new("REQUEST: {\"version\": 1}\nnot part of the document\n");

        let document = read_interactive_document(&mut input).unwrap();

        assert_eq!(document, "REQUEST: {\"version\": 1}\n");
        let mut remaining = String::new();
        input.read_line(&mut remaining).unwrap();
        assert_eq!(remaining, "not part of the document\n");
    }

    #[test]
    fn interactive_document_waits_for_complete_multiline_json() {
        let mut input = Cursor::new("GRANT: {\n  \"version\": 1\n}\nafter\n");

        let document = read_interactive_document(&mut input).unwrap();

        assert_eq!(document, "GRANT: {\n  \"version\": 1\n}\n");
        let mut remaining = String::new();
        input.read_line(&mut remaining).unwrap();
        assert_eq!(remaining, "after\n");
    }

    #[test]
    fn interactive_document_accepts_copied_text_before_labeled_json() {
        let mut input = Cursor::new("copy this line:\nREQUEST: {\"version\": 1}\nafter\n");

        let document = read_interactive_document(&mut input).unwrap();

        assert_eq!(document, "copy this line:\nREQUEST: {\"version\": 1}\n");
    }

    #[test]
    fn noncanonical_terminal_reads_document_larger_than_macos_line_limit() {
        use rustix::termios::LocalModes;

        let pty = rustix_openpty::openpty(None, None).unwrap();
        let mut terminal = File::from(pty.user);
        let controller = File::from(pty.controller);
        let mut original = rustix::termios::tcgetattr(&terminal).unwrap();
        assert!(original.local_modes.contains(LocalModes::ICANON));
        original.local_modes.remove(LocalModes::ECHO);
        rustix::termios::tcsetattr(&terminal, rustix::termios::OptionalActions::Now, &original)
            .unwrap();
        let mode = NoncanonicalTerminalMode::enter(&terminal).unwrap();
        let payload = "x".repeat(2_048);
        let document = format!("GRANT:{{\"token\":\"{payload}\"}}");
        let pasted = format!("{document}\n");
        let mut writer = controller.try_clone().unwrap();
        let pasted_for_writer = pasted.clone();
        let writer = thread::spawn(move || writer.write_all(pasted_for_writer.as_bytes()).unwrap());

        let actual = read_terminal_document(
            &mut terminal,
            Some(mode.interrupt_byte),
            Some(mode.eof_byte),
        )
        .unwrap();
        drop(mode);
        writer.join().unwrap();

        assert_eq!(actual, pasted);
        let restored = rustix::termios::tcgetattr(&terminal).unwrap();
        assert!(restored.local_modes.contains(LocalModes::ICANON));
    }

    #[test]
    fn interrupted_noncanonical_terminal_restores_original_mode() {
        use rustix::termios::LocalModes;

        let pty = rustix_openpty::openpty(None, None).unwrap();
        let mut terminal = File::from(pty.user);
        let mut controller = File::from(pty.controller);
        let original = rustix::termios::tcgetattr(&terminal).unwrap();
        assert!(original.local_modes.contains(LocalModes::ICANON));
        let mode = NoncanonicalTerminalMode::enter(&terminal).unwrap();
        controller.write_all(&[mode.interrupt_byte]).unwrap();

        let error = read_terminal_document(
            &mut terminal,
            Some(mode.interrupt_byte),
            Some(mode.eof_byte),
        )
        .unwrap_err();
        drop(mode);

        assert!(error.to_string().contains("input interrupted"));
        let restored = rustix::termios::tcgetattr(&terminal).unwrap();
        assert!(restored.local_modes.contains(LocalModes::ICANON));
    }

    #[test]
    fn enrollment_document_accepts_bare_json_with_surrounding_whitespace() {
        let value: serde_json::Value =
            parse_enrollment_document("\n\t {\"version\": 1} \r\n", "document").unwrap();

        assert_eq!(value["version"], 1);
    }

    #[test]
    fn enrollment_document_accepts_request_label_and_multiline_json() {
        let value: serde_json::Value =
            parse_enrollment_document("  request :  {\n  \"version\": 1\n}  \n", "document")
                .unwrap();

        assert_eq!(value["version"], 1);
    }

    #[test]
    fn enrollment_document_accepts_grant_label_with_terminal_output() {
        let value: serde_json::Value = parse_enrollment_document(
            "Waiting for input...\n  GRANT: {\"version\": 1}  \nshell prompt",
            "document",
        )
        .unwrap();

        assert_eq!(value["version"], 1);
    }

    #[test]
    fn enrollment_document_accepts_request_label_before_terminal_output() {
        let value: serde_json::Value = parse_enrollment_document(
            "REQUEST: {\"version\": 1}\nWaiting for the enrollment grant...",
            "document",
        )
        .unwrap();

        assert_eq!(value["version"], 1);
    }

    #[test]
    fn enrollment_document_accepts_grant_label_before_terminal_output() {
        let value: serde_json::Value =
            parse_enrollment_document("GRANT: {\"version\": 1}\nshell prompt", "document").unwrap();

        assert_eq!(value["version"], 1);
    }

    #[test]
    fn enrollment_document_rejects_unknown_labels() {
        let error =
            parse_enrollment_document::<serde_json::Value>("TOKEN: {\"version\": 1}", "document")
                .unwrap_err();

        assert!(error.to_string().contains("document"));
    }
}

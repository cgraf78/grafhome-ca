//! Grafhome CA repository and lifecycle CLI.

use std::io::{BufRead, IsTerminal, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};
use std::time::Duration;

use clap::{Parser, Subcommand};
use grafhome_ca::model::SiteModel;
use grafhome_ca::policy::{ClientDevice, Endpoint, Host, Provisioner, User};

const USER_STEP_BIN: &str = "step";
const CA_HEALTH_RETRY_ATTEMPTS: usize = 30;
const CA_HEALTH_RETRY_DELAY: Duration = Duration::from_secs(1);
const CA_HEALTH_CONSECUTIVE_SUCCESSES: usize = 2;

macro_rules! outln {
    ($($arg:tt)*) => {
        write_stdout(format_args!($($arg)*))?
    };
}

#[derive(Debug, Parser)]
#[command(name = "grafhome-ca")]
#[command(about = "Grafhome CA policy and lifecycle tooling")]
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
    /// Run doctor checks.
    Doctor {
        /// Restrict doctor to site config and policy validation.
        #[arg(long)]
        config_only: bool,
        /// Site config root containing config/ and policy/.
        #[arg(long, value_name = "DIR")]
        config_root: Option<PathBuf>,
    },
    /// Show derived endpoint URLs.
    Endpoints {
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
        #[arg(long)]
        out_dir: PathBuf,
        /// Show rendered paths without writing files.
        #[arg(long)]
        dry_run: bool,
        /// Remove stale files under the output directory before writing.
        #[arg(long)]
        clean: bool,
    },
    /// Export public CA trust material into a staging directory.
    ExportPublic {
        /// Site config root containing config/ and policy/.
        #[arg(long, value_name = "DIR")]
        config_root: Option<PathBuf>,
        /// Output directory for exported public trust material.
        #[arg(long)]
        out_dir: PathBuf,
        /// Show exported paths without writing files.
        #[arg(long)]
        dry_run: bool,
    },
    /// Print a JSON fixture with JWK placeholders materialized for tests.
    MaterializeTestCaFixture {
        /// Site config root containing config/ and policy/.
        #[arg(long, value_name = "DIR")]
        config_root: Option<PathBuf>,
    },
    /// Materialize runtime JWK provisioners into a rendered CA config.
    MaterializeRuntimeProvisioners {
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
    /// Add a constrained user/client-host JWK provisioner to a Smallstep CA config.
    #[command(hide = true)]
    AddUserDeviceProvisioner {
        /// Existing Smallstep ca.json.
        #[arg(long, value_name = "FILE")]
        ca_json: PathBuf,
        /// Public JWK generated on the enrolled user device.
        #[arg(long, value_name = "FILE")]
        public_key: PathBuf,
        /// Provisioner name to add.
        #[arg(long)]
        name: String,
        /// SSH certificate template file on the CA origin.
        #[arg(long, value_name = "FILE")]
        ssh_template: String,
        /// Default user SSH certificate lifetime.
        #[arg(long)]
        default_ttl: String,
        /// Maximum user SSH certificate lifetime.
        #[arg(long)]
        max_ttl: String,
        /// Write updated ca.json to this file with owner-only permissions.
        #[arg(long, value_name = "FILE")]
        out_file: PathBuf,
    },
    /// Produce a structured lifecycle plan without executing it.
    Plan {
        /// Site config root containing config/ and policy/.
        #[arg(long, value_name = "DIR")]
        config_root: Option<PathBuf>,
        /// Emit JSON instead of text.
        #[arg(long)]
        json: bool,
        #[command(subcommand)]
        command: PlanCommand,
    },
    /// Print the trusted CA root fingerprint from the local CA state.
    CaFingerprint {
        /// Site config root containing config/ and policy/.
        #[arg(long, value_name = "DIR")]
        config_root: Option<PathBuf>,
    },
    /// Bootstrap CA trust for the current user. Reads the fingerprint from stdin by default.
    BootstrapClient {
        /// Site config root containing config/ and policy/.
        #[arg(long, value_name = "DIR")]
        config_root: Option<PathBuf>,
        /// Read the trusted root fingerprint from this file instead of stdin.
        #[arg(long, value_name = "FILE")]
        fingerprint_file: Option<PathBuf>,
    },
    /// Bootstrap CA trust for a root-run host. Reads the fingerprint from stdin by default.
    BootstrapHostTrust {
        /// Site config root containing config/ and policy/.
        #[arg(long, value_name = "DIR")]
        config_root: Option<PathBuf>,
        /// Read the trusted root fingerprint from this file instead of stdin.
        #[arg(long, value_name = "FILE")]
        fingerprint_file: Option<PathBuf>,
    },
    /// Create a short-lived host enrollment token and print it.
    CreateHostToken {
        /// Site config root containing config/ and policy/.
        #[arg(long, value_name = "DIR")]
        config_root: Option<PathBuf>,
        /// Host policy name.
        #[arg(long)]
        host: String,
        /// Enrollment token lifetime.
        #[arg(long)]
        ttl: Option<String>,
        /// SSH host certificate lifetime.
        #[arg(long)]
        cert_ttl: Option<String>,
    },
    /// Enroll this host using a short-lived token read from stdin by default.
    EnrollHost {
        /// Site config root containing config/ and policy/.
        #[arg(long, value_name = "DIR")]
        config_root: Option<PathBuf>,
        /// Host policy name.
        #[arg(long)]
        host: String,
        /// Read the host enrollment token from this file instead of stdin.
        #[arg(long, value_name = "FILE")]
        token_file: Option<PathBuf>,
    },
    /// Create a short-lived user enrollment token and print it.
    CreateUserToken {
        /// Site config root containing config/ and policy/.
        #[arg(long, value_name = "DIR")]
        config_root: Option<PathBuf>,
        /// User policy name.
        #[arg(long)]
        user: String,
        /// Client host policy name.
        #[arg(long)]
        host: String,
        /// Enrollment token lifetime.
        #[arg(long)]
        ttl: Option<String>,
        /// SSH user certificate lifetime.
        #[arg(long)]
        cert_ttl: Option<String>,
    },
    /// Enroll this user on one client host. Reads token then password from stdin by default.
    EnrollUser {
        /// Site config root containing config/ and policy/.
        #[arg(long, value_name = "DIR")]
        config_root: Option<PathBuf>,
        /// User policy name.
        #[arg(long)]
        user: String,
        /// Client host policy name.
        #[arg(long)]
        host: String,
        /// Read the user enrollment token from this file instead of stdin.
        #[arg(long, value_name = "FILE")]
        token_file: Option<PathBuf>,
        /// Read the user-owned provisioner password from this file instead of stdin.
        #[arg(long, value_name = "FILE")]
        password_file: Option<PathBuf>,
    },
    /// Authorize a user refresh provisioner for one client host on the CA origin.
    AuthorizeUser {
        /// Site config root containing config/ and policy/.
        #[arg(long, value_name = "DIR")]
        config_root: Option<PathBuf>,
        /// User policy name.
        #[arg(long)]
        user: String,
        /// Client host policy name.
        #[arg(long)]
        host: String,
        /// Public JWK generated by `enroll-user`. Reads from stdin by default.
        #[arg(long, value_name = "FILE")]
        public_key: Option<PathBuf>,
    },
    /// Refresh this user's SSH certificate. Reads the user-owned password from stdin by default.
    SshEnsure {
        /// Site config root containing config/ and policy/.
        #[arg(long, value_name = "DIR")]
        config_root: Option<PathBuf>,
        /// User policy name.
        #[arg(long)]
        user: String,
        /// Client host policy name. Required when the user has multiple active client hosts.
        #[arg(long)]
        host: Option<String>,
        /// Read the user-owned provisioner password from this file instead of stdin.
        #[arg(long, value_name = "FILE")]
        password_file: Option<PathBuf>,
    },
    /// Initialize the CA. Live mutation is intentionally gated.
    InitCa {
        /// Site config root containing config/ and policy/.
        #[arg(long, value_name = "DIR")]
        config_root: Option<PathBuf>,
        /// Print planned actions without touching live CA state.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, Subcommand)]
enum PlanCommand {
    /// Plan CA initialization.
    InitCa,
    /// Plan first-time host bootstrap.
    HostBootstrap {
        /// Host policy name.
        #[arg(long)]
        host: String,
    },
    /// Plan host certificate renewal.
    HostRenew {
        /// Host policy name.
        #[arg(long)]
        host: String,
    },
    /// Plan certificate renewal for every managed SSH server host.
    HostRenewAll,
    /// Plan CA state backup and restore-test.
    BackupCa,
    /// Plan live non-mutating rollout verification.
    VerifyLive {
        /// Limit verification to one host's SSH rollout checks.
        #[arg(long)]
        host: Option<String>,
    },
    /// Plan proxy X.509 certificate issuance or renewal.
    ProxyCert,
    /// Plan creation of a short-lived host enrollment token.
    CreateHostToken {
        /// Host policy name.
        #[arg(long)]
        host: String,
        /// Enrollment token lifetime.
        #[arg(long)]
        ttl: Option<String>,
        /// SSH host certificate lifetime.
        #[arg(long)]
        cert_ttl: Option<String>,
    },
    /// Plan host enrollment using a short-lived token.
    EnrollHost {
        /// Host policy name.
        #[arg(long)]
        host: String,
    },
    /// Plan creation of a short-lived user enrollment token.
    CreateUserToken {
        /// User policy name.
        #[arg(long)]
        user: String,
        /// Client host policy name.
        #[arg(long)]
        host: String,
        /// Enrollment token lifetime.
        #[arg(long)]
        ttl: Option<String>,
        /// SSH user certificate lifetime.
        #[arg(long)]
        cert_ttl: Option<String>,
    },
    /// Plan user enrollment using a short-lived token.
    EnrollUser {
        /// User policy name.
        #[arg(long)]
        user: String,
        /// Client host policy name.
        #[arg(long)]
        host: String,
    },
    /// Plan local user certificate refresh before SSH.
    SshEnsure {
        /// User policy name.
        #[arg(long)]
        user: String,
        /// Client host policy name. Required when the user has multiple active client hosts.
        #[arg(long)]
        host: Option<String>,
    },
    /// Plan policy edits for a new host.
    AddHost {
        /// New host policy name.
        #[arg(long)]
        host: String,
    },
    /// Plan policy edits for a new user.
    AddUser {
        /// New user policy name.
        #[arg(long)]
        user: String,
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
                    .endpoint("ca_api")
                    .expect("validated endpoint")
                    .url(),
                model
                    .policy
                    .endpoint("ca_origin")
                    .expect("validated endpoint")
                    .url()
            );
            Ok(())
        }
        Command::Doctor {
            config_only,
            config_root,
        } => {
            if !config_only {
                return Err(grafhome_ca::Error::Validation {
                    field: "doctor".to_owned(),
                    message: "live doctor is not implemented; use --config-only".to_owned(),
                });
            }
            let config_root = resolve_config_root(config_root)?;
            SiteModel::load(&config_root)?;
            grafhome_ca::schema::validate_config_root(&config_root)?;
            outln!("ok: config-only doctor passed");
            Ok(())
        }
        Command::Endpoints { config_root } => {
            let config_root = resolve_config_root(config_root)?;
            let model = SiteModel::load(&config_root)?;
            for endpoint in &model.policy.endpoints {
                outln!("{}\t{}\t{}", endpoint.role, endpoint.target, endpoint.url());
            }
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
                if clean {
                    grafhome_ca::render::write_clean(&files, &out_dir)?;
                } else {
                    grafhome_ca::render::write(&files, &out_dir)?;
                }
                outln!("rendered {} files under {}", files.len(), out_dir.display());
            }
            Ok(())
        }
        Command::ExportPublic {
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
        Command::MaterializeRuntimeProvisioners {
            config_root,
            live_ca_json,
            staged_ca_json,
            jwk_dir,
            out_file,
        } => {
            let config_root = resolve_config_root(config_root)?;
            let model = SiteModel::load(&config_root)?;
            grafhome_ca::schema::validate_config_root(&config_root)?;
            let text = grafhome_ca::runtime_provisioners::materialize(
                &model,
                &live_ca_json,
                &staged_ca_json,
                &jwk_dir,
            )?;
            write_secret_file(&out_file, text.as_bytes())?;
            Ok(())
        }
        Command::AddUserDeviceProvisioner {
            ca_json,
            public_key,
            name,
            ssh_template,
            default_ttl,
            max_ttl,
            out_file,
        } => {
            let text = grafhome_ca::runtime_provisioners::add_user_device(
                &ca_json,
                &public_key,
                &name,
                &ssh_template,
                &default_ttl,
                &max_ttl,
            )?;
            write_secret_file(&out_file, text.as_bytes())?;
            Ok(())
        }
        Command::Plan {
            config_root,
            json,
            command,
        } => {
            let config_root = resolve_config_root(config_root)?;
            let model = SiteModel::load(&config_root)?;
            grafhome_ca::schema::validate_config_root(&config_root)?;
            let plan = match command {
                PlanCommand::InitCa => grafhome_ca::lifecycle::init_ca(&model)?,
                PlanCommand::HostBootstrap { host } => {
                    grafhome_ca::lifecycle::host_bootstrap(&model, &host)?
                }
                PlanCommand::HostRenew { host } => {
                    grafhome_ca::lifecycle::host_renew(&model, &host)?
                }
                PlanCommand::HostRenewAll => grafhome_ca::lifecycle::host_renew_all(&model)?,
                PlanCommand::BackupCa => grafhome_ca::lifecycle::backup_ca(&model)?,
                PlanCommand::VerifyLive { host } => {
                    grafhome_ca::lifecycle::verify_live(&model, host.as_deref())?
                }
                PlanCommand::ProxyCert => grafhome_ca::lifecycle::proxy_cert(&model)?,
                PlanCommand::CreateHostToken {
                    host,
                    ttl,
                    cert_ttl,
                } => grafhome_ca::lifecycle::create_host_token(
                    &model,
                    &host,
                    ttl.as_deref(),
                    cert_ttl.as_deref(),
                )?,
                PlanCommand::EnrollHost { host } => {
                    grafhome_ca::lifecycle::enroll_host(&model, &host)?
                }
                PlanCommand::CreateUserToken {
                    user,
                    host,
                    ttl,
                    cert_ttl,
                } => grafhome_ca::lifecycle::create_user_token(
                    &model,
                    &user,
                    &host,
                    ttl.as_deref(),
                    cert_ttl.as_deref(),
                )?,
                PlanCommand::EnrollUser { user, host } => {
                    grafhome_ca::lifecycle::enroll_user(&model, &user, &host)?
                }
                PlanCommand::SshEnsure { user, host } => {
                    grafhome_ca::lifecycle::ssh_ensure(&model, &user, host.as_deref())?
                }
                PlanCommand::AddHost { host } => grafhome_ca::lifecycle::add_host(&model, &host)?,
                PlanCommand::AddUser { user } => grafhome_ca::lifecycle::add_user(&model, &user)?,
            };
            grafhome_ca::schema::validate_lifecycle_plan(&plan)?;
            if json {
                outln!(
                    "{}",
                    serde_json::to_string_pretty(&plan).expect("plan serializes")
                );
            } else {
                print_plan(&plan)?;
            }
            Ok(())
        }
        Command::CaFingerprint { config_root } => {
            let model = load_valid_model(config_root)?;
            let output = run_capture(
                process(&model.deployment.values["GRAFHOME_CA_ROOT_STEP_BIN"])
                    .arg("certificate")
                    .arg("fingerprint")
                    .arg(ca_root_cert_path(&model)),
            )?;
            write_raw_stdout(&output)
        }
        Command::BootstrapClient {
            config_root,
            fingerprint_file,
        } => {
            let model = load_valid_model(config_root)?;
            let mut stdin = std::io::stdin().lock();
            let fingerprint = read_secret_or_file(
                fingerprint_file.as_deref(),
                &mut stdin,
                "trusted root fingerprint",
            )?;
            bootstrap_trust(
                USER_STEP_BIN,
                &user_steppath(&model)?,
                &required_endpoint(&model, "ca_api")?.url(),
                &fingerprint,
            )
        }
        Command::BootstrapHostTrust {
            config_root,
            fingerprint_file,
        } => {
            let model = load_valid_model(config_root)?;
            let mut stdin = std::io::stdin().lock();
            let fingerprint = read_secret_or_file(
                fingerprint_file.as_deref(),
                &mut stdin,
                "trusted root fingerprint",
            )?;
            bootstrap_trust(
                &model.deployment.values["GRAFHOME_CA_ROOT_STEP_BIN"],
                Path::new(&model.deployment.values["GRAFHOME_CA_SERVER_STEPPATH"]),
                &required_endpoint(&model, "ca_api")?.url(),
                &fingerprint,
            )
        }
        Command::CreateHostToken {
            config_root,
            host,
            ttl,
            cert_ttl,
        } => {
            let model = load_valid_model(config_root)?;
            let output = create_host_token(&model, &host, ttl.as_deref(), cert_ttl.as_deref())?;
            write_raw_stdout(&output)
        }
        Command::EnrollHost {
            config_root,
            host,
            token_file,
        } => {
            let model = load_valid_model(config_root)?;
            let mut stdin = std::io::stdin().lock();
            let token =
                read_secret_or_file(token_file.as_deref(), &mut stdin, "host enrollment token")?;
            enroll_host(&model, &host, &token)
        }
        Command::CreateUserToken {
            config_root,
            user,
            host,
            ttl,
            cert_ttl,
        } => {
            let model = load_valid_model(config_root)?;
            let output =
                create_user_token(&model, &user, &host, ttl.as_deref(), cert_ttl.as_deref())?;
            write_raw_stdout(&output)
        }
        Command::EnrollUser {
            config_root,
            user,
            host,
            token_file,
            password_file,
        } => {
            let model = load_valid_model(config_root)?;
            let mut stdin = std::io::stdin().lock();
            let token =
                read_secret_or_file(token_file.as_deref(), &mut stdin, "user enrollment token")?;
            let password = read_password_or_file(
                password_file.as_deref(),
                &mut stdin,
                "user provisioner password",
            )?;
            enroll_user(&model, &user, &host, &token, &password)
        }
        Command::AuthorizeUser {
            config_root,
            user,
            host,
            public_key,
        } => {
            let model = load_valid_model(config_root)?;
            let mut stdin = std::io::stdin().lock();
            let public_key =
                read_document_or_file(public_key.as_deref(), &mut stdin, "public JWK")?;
            authorize_user(&model, &user, &host, &public_key)
        }
        Command::SshEnsure {
            config_root,
            user,
            host,
            password_file,
        } => {
            let model = load_valid_model(config_root)?;
            let mut stdin = std::io::stdin().lock();
            let password = read_password_or_file(
                password_file.as_deref(),
                &mut stdin,
                "user provisioner password",
            )?;
            ssh_ensure(&model, &user, host.as_deref(), &password)
        }
        Command::InitCa {
            config_root,
            dry_run,
        } => {
            if dry_run {
                let config_root = resolve_config_root(config_root)?;
                let model = SiteModel::load(&config_root)?;
                grafhome_ca::schema::validate_config_root(&config_root)?;
                let plan = grafhome_ca::lifecycle::init_ca(&model)?;
                grafhome_ca::schema::validate_lifecycle_plan(&plan)?;
                print_plan(&plan)?;
                Ok(())
            } else {
                Err(grafhome_ca::Error::Validation {
                    field: "init-ca".to_owned(),
                    message:
                        "refusing live CA initialization before rollout phase; rerun with --dry-run"
                            .to_owned(),
                })
            }
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
    let model = SiteModel::load(&config_root)?;
    grafhome_ca::schema::validate_config_root(&config_root)?;
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

fn write_raw_stdout(content: &[u8]) -> grafhome_ca::Result<()> {
    let mut stdout = std::io::stdout().lock();
    if let Err(source) = stdout.write_all(content) {
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
        match run_status(&mut build_command()) {
            Ok(()) => {
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
        eprint!("{label}: ");
        std::io::stderr()
            .flush()
            .map_err(|source| grafhome_ca::Error::io("<stderr>", source))?;
        stdin
            .read_to_string(&mut value)
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

fn required_endpoint<'a>(model: &'a SiteModel, role: &str) -> grafhome_ca::Result<&'a Endpoint> {
    model
        .policy
        .endpoint(role)
        .ok_or_else(|| grafhome_ca::Error::Validation {
            field: format!("policy/endpoints.tsv:{role}"),
            message: "missing required endpoint".to_owned(),
        })
}

fn required_host<'a>(model: &'a SiteModel, host: &str) -> grafhome_ca::Result<&'a Host> {
    model
        .policy
        .host(host)
        .ok_or_else(|| grafhome_ca::Error::Validation {
            field: format!("policy/hosts.tsv:{host}"),
            message: "unknown host".to_owned(),
        })
}

fn active_user<'a>(model: &'a SiteModel, user: &str) -> grafhome_ca::Result<&'a User> {
    let user = model
        .policy
        .user(user)
        .ok_or_else(|| grafhome_ca::Error::Validation {
            field: format!("policy/users.tsv:{user}"),
            message: "unknown user".to_owned(),
        })?;
    if user.status != "active" {
        return Err(grafhome_ca::Error::Validation {
            field: format!("policy/users.tsv:{}.status", user.user),
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
        .find(|entry| entry.role == role && entry.status == "active")
        .ok_or_else(|| grafhome_ca::Error::Validation {
            field: format!("policy/provisioners.tsv:{role}"),
            message: "missing active provisioner role".to_owned(),
        })
}

fn required_user_device<'a>(
    model: &'a SiteModel,
    user: &str,
    host: &str,
) -> grafhome_ca::Result<&'a ClientDevice> {
    model
        .policy
        .client_devices
        .iter()
        .find(|device| device.user == user && device.device == host && device.status == "active")
        .ok_or_else(|| grafhome_ca::Error::Validation {
            field: format!("policy/client-devices.tsv:{user}:{host}"),
            message: "missing active client device for user and host".to_owned(),
        })
}

fn select_single_user_device<'a>(
    model: &'a SiteModel,
    user: &str,
) -> grafhome_ca::Result<&'a ClientDevice> {
    let mut devices = model.policy.active_client_devices_for_user(user);
    let Some(device) = devices.next() else {
        return Err(grafhome_ca::Error::Validation {
            field: format!("policy/client-devices.tsv:{user}"),
            message: "user has no active client devices".to_owned(),
        });
    };
    if devices.next().is_some() {
        return Err(grafhome_ca::Error::Validation {
            field: format!("policy/client-devices.tsv:{user}"),
            message: "user has multiple active client devices; pass --host".to_owned(),
        });
    }
    Ok(device)
}

fn checked_ttl(field: &str, ttl: &str) -> grafhome_ca::Result<String> {
    if !valid_step_duration(ttl) {
        return Err(grafhome_ca::Error::Validation {
            field: field.to_owned(),
            message: "duration must use Smallstep units such as 15m, 24h, 1.5h, or 2h45m"
                .to_owned(),
        });
    }
    Ok(ttl.to_owned())
}

fn valid_step_duration(ttl: &str) -> bool {
    let bytes = ttl.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if index < bytes.len() && bytes[index] == b'.' {
            index += 1;
            let fraction_start = index;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
            if fraction_start == index {
                return false;
            }
        }
        if start == index {
            return false;
        }
        let unit_len = if bytes[index..].starts_with(b"ns")
            || bytes[index..].starts_with(b"us")
            || bytes[index..].starts_with(b"ms")
        {
            2
        } else if bytes[index..].starts_with(b"s")
            || bytes[index..].starts_with(b"m")
            || bytes[index..].starts_with(b"h")
        {
            1
        } else {
            return false;
        };
        index += unit_len;
    }
    index > 0
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

fn user_private_key_path(key_name: &str) -> grafhome_ca::Result<PathBuf> {
    Ok(home_dir()?.join(".ssh").join(key_name))
}

fn user_public_key_path(key_name: &str) -> grafhome_ca::Result<PathBuf> {
    Ok(PathBuf::from(format!(
        "{}.pub",
        user_private_key_path(key_name)?.display()
    )))
}

fn user_cert_path(key_name: &str) -> grafhome_ca::Result<PathBuf> {
    Ok(PathBuf::from(format!(
        "{}-cert.pub",
        user_private_key_path(key_name)?.display()
    )))
}

fn user_device_material_dir(user: &str, host: &str) -> grafhome_ca::Result<PathBuf> {
    Ok(home_dir()?
        .join(".config/grafhome-ca/users")
        .join(user)
        .join("hosts")
        .join(host))
}

fn user_device_provisioner_name(user: &str, host: &str) -> String {
    format!("grafhome-user-{user}-{host}")
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

fn create_host_token(
    model: &SiteModel,
    host: &str,
    token_ttl: Option<&str>,
    cert_ttl: Option<&str>,
) -> grafhome_ca::Result<Vec<u8>> {
    let host = required_host(model, host)?;
    let ca_api = required_endpoint(model, "ca_api")?;
    let provisioner = required_provisioner(model, "host_bootstrap")?;
    let token_ttl = checked_ttl(
        "create-host-token.ttl",
        token_ttl.unwrap_or(grafhome_ca::lifecycle::DEFAULT_ENROLLMENT_TOKEN_TTL),
    )?;
    let cert_ttl = checked_ttl(
        "create-host-token.cert_ttl",
        cert_ttl.unwrap_or(&provisioner.default_ttl),
    )?;
    let mut command = process(&model.deployment.values["GRAFHOME_CA_ROOT_STEP_BIN"]);
    command
        .env("STEPPATH", model.deployment.ca_steppath())
        .arg("ca")
        .arg("token")
        .arg(&host.host)
        .arg("--ssh")
        .arg("--host");
    for principal in split_list(&host.principals) {
        command.arg("--principal").arg(principal);
    }
    command
        .arg("--not-after")
        .arg(token_ttl)
        .arg("--cert-not-after")
        .arg(cert_ttl)
        .arg("--provisioner")
        .arg(&provisioner.name)
        .arg("--provisioner-password-file")
        .arg(&model.deployment.values["GRAFHOME_CA_PASSWORD_FILE"])
        .arg("--ca-url")
        .arg(ca_api.url())
        .arg("--root")
        .arg(ca_root_cert_path(model));
    run_capture(&mut command)
}

fn enroll_host(model: &SiteModel, host: &str, token: &str) -> grafhome_ca::Result<()> {
    let host = required_host(model, host)?;
    let ca_api = required_endpoint(model, "ca_api")?;
    run_status_redacted(
        process(&model.deployment.values["GRAFHOME_CA_ROOT_STEP_BIN"])
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
    run_status(
        process("ssh-keygen")
            .arg("-L")
            .arg("-f")
            .arg(host_cert_path(model)),
    )?;
    run_status(process("sshd").arg("-t"))?;
    reload_ssh()
}

fn create_user_token(
    model: &SiteModel,
    user: &str,
    host: &str,
    token_ttl: Option<&str>,
    cert_ttl: Option<&str>,
) -> grafhome_ca::Result<Vec<u8>> {
    let user = active_user(model, user)?;
    required_user_device(model, &user.user, host)?;
    let ca_api = required_endpoint(model, "ca_api")?;
    let token_ttl = checked_ttl(
        "create-user-token.ttl",
        token_ttl.unwrap_or(grafhome_ca::lifecycle::DEFAULT_ENROLLMENT_TOKEN_TTL),
    )?;
    let cert_ttl = checked_ttl(
        "create-user-token.cert_ttl",
        cert_ttl.unwrap_or(&user.cert_ttl),
    )?;
    run_capture(
        process(&model.deployment.values["GRAFHOME_CA_ROOT_STEP_BIN"])
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
            .arg("--provisioner")
            .arg(&user.provisioner)
            .arg("--provisioner-password-file")
            .arg(&model.deployment.values["GRAFHOME_CA_PASSWORD_FILE"])
            .arg("--ca-url")
            .arg(ca_api.url())
            .arg("--root")
            .arg(ca_root_cert_path(model)),
    )
}

fn enroll_user(
    model: &SiteModel,
    user_name: &str,
    host: &str,
    token: &str,
    password: &str,
) -> grafhome_ca::Result<()> {
    let user = active_user(model, user_name)?;
    let device = required_user_device(model, &user.user, host)?;
    let ca_api = required_endpoint(model, "ca_api")?;
    let private_key = user_private_key_path(&device.key_name)?;
    let public_key = user_public_key_path(&device.key_name)?;
    let cert = user_cert_path(&device.key_name)?;
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
    if !private_key.exists() {
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
    run_status_redacted(
        process(USER_STEP_BIN)
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

    let material_dir = user_device_material_dir(&user.user, &device.device)?;
    std::fs::create_dir_all(&material_dir)
        .map_err(|source| grafhome_ca::Error::io(&material_dir, source))?;
    #[cfg(unix)]
    std::fs::set_permissions(&material_dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|source| grafhome_ca::Error::io(&material_dir, source))?;
    let public_jwk = material_dir.join("provisioner.pub.json");
    let private_jwk = material_dir.join("provisioner.priv.json");
    if !private_jwk.exists() {
        with_password_file(&material_dir, password, |password_file| {
            run_status(
                process(USER_STEP_BIN)
                    .arg("crypto")
                    .arg("jwk")
                    .arg("create")
                    .arg(&public_jwk)
                    .arg(&private_jwk)
                    .arg("--password-file")
                    .arg(password_file),
            )
        })?;
    }
    #[cfg(unix)]
    {
        std::fs::set_permissions(&private_jwk, std::fs::Permissions::from_mode(0o600))
            .map_err(|source| grafhome_ca::Error::io(&private_jwk, source))?;
        std::fs::set_permissions(&public_jwk, std::fs::Permissions::from_mode(0o644))
            .map_err(|source| grafhome_ca::Error::io(&public_jwk, source))?;
    }
    outln!("user cert: {}", cert.display());
    outln!("user refresh public key: {}", public_jwk.display());
    let public_jwk_text = std::fs::read_to_string(&public_jwk)
        .map_err(|source| grafhome_ca::Error::io(&public_jwk, source))?;
    outln!("authorize renewal on the CA with:");
    outln!(
        "grafhome-ca authorize-user --user {} --host {} <<'GRAFHOME_CA_USER_RENEWAL_PUBLIC_KEY'",
        user.user,
        device.device
    );
    outln!("{}", public_jwk_text.trim_end());
    outln!("GRAFHOME_CA_USER_RENEWAL_PUBLIC_KEY");
    Ok(())
}

fn authorize_user(
    model: &SiteModel,
    user_name: &str,
    host: &str,
    public_key: &str,
) -> grafhome_ca::Result<()> {
    let user = active_user(model, user_name)?;
    let device = required_user_device(model, &user.user, host)?;
    let ca_api = required_endpoint(model, "ca_api")?;
    let user_enrollment = required_provisioner(model, "user_enrollment")?;
    let provisioner = user_device_provisioner_name(&user.user, &device.device);
    let template_dir = PathBuf::from(model.deployment.ca_steppath()).join("templates/ssh");
    let template_file = template_dir.join(format!("{provisioner}.tpl"));
    std::fs::create_dir_all(&template_dir)
        .map_err(|source| grafhome_ca::Error::io(&template_dir, source))?;
    std::fs::write(&template_file, user_ssh_template(&user.principal))
        .map_err(|source| grafhome_ca::Error::io(&template_file, source))?;
    let ca_json = PathBuf::from(model.deployment.ca_steppath()).join("config/ca.json");
    with_temp_file(&template_dir, public_key.as_bytes(), |public_key_file| {
        let text = grafhome_ca::runtime_provisioners::add_user_device(
            &ca_json,
            public_key_file,
            &provisioner,
            &template_file.display().to_string(),
            &user_enrollment.default_ttl,
            &user_enrollment.max_ttl,
        )?;
        install_ca_json_with_rollback(model, &ca_json, text.as_bytes(), ca_api.url())?;
        Ok(())
    })?;
    outln!("authorized provisioner: {provisioner}");
    Ok(())
}

fn install_ca_json_with_rollback(
    model: &SiteModel,
    ca_json: &Path,
    content: &[u8],
    ca_url: String,
) -> grafhome_ca::Result<()> {
    let previous =
        std::fs::read(ca_json).map_err(|source| grafhome_ca::Error::io(ca_json, source))?;
    let backup = ca_json_backup_path(ca_json);
    write_secret_file(&backup, &previous)?;
    write_secret_file_atomic(ca_json, content)?;
    let activate = || -> grafhome_ca::Result<()> {
        install_ca_json_permissions(model, ca_json)?;
        run_status(process("systemctl").arg("restart").arg("step-ca.service"))?;
        run_status(process("systemctl").arg("is-active").arg("step-ca.service"))?;
        run_status_with_retries(
            "step ca health",
            CA_HEALTH_RETRY_ATTEMPTS,
            CA_HEALTH_RETRY_DELAY,
            CA_HEALTH_CONSECUTIVE_SUCCESSES,
            || {
                let mut command = process(&model.deployment.values["GRAFHOME_CA_ROOT_STEP_BIN"]);
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
    if let Err(error) = activate() {
        let rollback = (|| -> grafhome_ca::Result<()> {
            write_secret_file_atomic(ca_json, &previous)?;
            install_ca_json_permissions(model, ca_json)?;
            run_status(process("systemctl").arg("restart").arg("step-ca.service"))?;
            run_status(process("systemctl").arg("is-active").arg("step-ca.service"))
        })();
        return Err(grafhome_ca::Error::Validation {
            field: "authorize-user".to_owned(),
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
    outln!("backup ca.json: {}", backup.display());
    Ok(())
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

fn ssh_ensure(
    model: &SiteModel,
    user_name: &str,
    host: Option<&str>,
    password: &str,
) -> grafhome_ca::Result<()> {
    let user = active_user(model, user_name)?;
    let device = match host {
        Some(host) => required_user_device(model, &user.user, host)?,
        None => select_single_user_device(model, &user.user)?,
    };
    let ca_api = required_endpoint(model, "ca_api")?;
    let provisioner = user_device_provisioner_name(&user.user, &device.device);
    let material_dir = user_device_material_dir(&user.user, &device.device)?;
    let private_jwk = material_dir.join("provisioner.priv.json");
    let token = with_password_file(&material_dir, password, |password_file| {
        run_capture(
            process(USER_STEP_BIN)
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
    run_status_redacted(
        process(USER_STEP_BIN)
            .env("STEPPATH", user_steppath(model)?)
            .arg("ssh")
            .arg("certificate")
            .arg(&user.principal)
            .arg(user_public_key_path(&device.key_name)?)
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
    )?;
    run_status(
        process("ssh-keygen")
            .arg("-L")
            .arg("-f")
            .arg(user_cert_path(&device.key_name)?),
    )
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

fn reload_ssh() -> grafhome_ca::Result<()> {
    if run_status(process("systemctl").arg("reload").arg("ssh")).is_ok() {
        return Ok(());
    }
    run_status(process("systemctl").arg("reload").arg("sshd"))
}

fn split_list(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
}

fn user_ssh_template(principal: &str) -> String {
    let principal_json = serde_json::to_string(principal).expect("principal string serializes");
    format!(
        "{{\n  \"type\": \"user\",\n  \"keyId\": {{{{ toJson .KeyID }}}},\n  \"principals\": [{principal_json}],\n  \"criticalOptions\": {{{{ toJson .CriticalOptions }}}},\n  \"extensions\": {{{{ toJson .Extensions }}}}\n}}\n"
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
    let _ = temp_path.close();
    Ok(())
}

fn print_plan(plan: &grafhome_ca::lifecycle::Plan) -> grafhome_ca::Result<()> {
    outln!("{}: {}", plan.operation, plan.summary);
    for step in &plan.steps {
        outln!("- {}: {}", step.id, step.summary);
        if !step.hosts.is_empty() {
            outln!("  hosts: {}", step.hosts.join(","));
        }
        for command in &step.commands {
            outln!("  command: {command}");
        }
        for file in &step.files {
            outln!("  file: {file}");
        }
        if step.manual {
            outln!("  manual: true");
        }
    }
    Ok(())
}

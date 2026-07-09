//! Grafhome CA repository and lifecycle CLI.

use std::io::Write;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use grafhome_ca::model::SiteModel;

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
    /// Plan user certificate issuance.
    UserLogin {
        /// User policy name.
        #[arg(long)]
        user: String,
        /// Client device policy name. Required when the user has multiple active devices.
        #[arg(long)]
        device: Option<String>,
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
                PlanCommand::UserLogin { user, device } => {
                    grafhome_ca::lifecycle::user_login(&model, &user, device.as_deref())?
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

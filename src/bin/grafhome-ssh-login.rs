//! Grafhome SSH user-login helper CLI.

use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "grafhome-ssh-login")]
#[command(about = "Prepare a Grafhome SSH user certificate")]
#[command(version = grafhome_ca::version::cli())]
struct Cli {
    /// Policy user to prepare. Defaults will be implemented after policy resolution lands.
    #[arg(long)]
    user: Option<String>,
    /// Only validate local arguments; do not invoke step or ssh-agent.
    #[arg(long)]
    dry_run: bool,
}

fn main() {
    let cli = Cli::parse();
    if cli.dry_run {
        let user = cli.user.as_deref().unwrap_or("<policy-default>");
        println!("dry-run: would prepare Grafhome SSH login for {user}");
        return;
    }

    eprintln!(
        "grafhome-ssh-login: live certificate issuance is not implemented yet; rerun with --dry-run"
    );
    std::process::exit(1);
}

//! Command-line entry point; all public commands are declared with clap.
mod logs;

use anyhow::{Context, Result, bail};
use certkite_client::config;
use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};

#[derive(Parser)]
#[command(
    name = "certkite",
    version,
    about = "Install and manage CertKite certificates on this server"
)]
struct Cli {
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,
    #[arg(long, global = true, default_value = "info", value_parser = ["error", "warn", "info", "debug", "trace"])]
    log_level: String,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the certificate client in the foreground.
    #[command(alias = "__daemon")]
    Run,
    /// Show local identity, service properties, and timestamped runtime state.
    Status(OutputArgs),
    /// Show local daemon logs, optionally following new records.
    Logs(logs::LogArgs),
    /// Check configuration, authentication, and deployment environments.
    Doctor(OutputArgs),
    /// Check or install a signed release from CertKite.
    Update(UpdateArgs),
    #[command(name = "__update-worker", hide = true)]
    UpdateWorker {
        #[arg(long)]
        job: PathBuf,
    },
}

#[derive(Args)]
struct OutputArgs {
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct UpdateArgs {
    #[arg(long)]
    check: bool,
    #[arg(long, value_name = "VERSION")]
    to: Option<String>,
    #[arg(long)]
    json: bool,
}

impl Cli {
    fn config_path(&self) -> Result<PathBuf> {
        self.config.clone().map_or_else(config::default_config, Ok)
    }
}

async fn service_state() -> Result<serde_json::Value> {
    anyhow::ensure!(cfg!(target_os = "linux"), "systemd requires Linux");
    let mut command = tokio::process::Command::new("/usr/bin/systemctl");
    if !config::is_system_installation() {
        command.arg("--user");
    }
    let output = tokio::time::timeout(
        Duration::from_secs(5),
        command
            .args([
                "show",
                "certkite.service",
                "--property=LoadState,ActiveState,SubState,MainPID,UnitFileState,Type,Result",
            ])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("systemd status timed out")??;
    anyhow::ensure!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8(output.stdout)?
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_owned(), json!(value)))
        .collect::<serde_json::Map<_, _>>()
        .into())
}

fn json_requested(command: &Commands) -> bool {
    match command {
        Commands::Status(args) | Commands::Doctor(args) => args.json,
        Commands::Update(args) => args.json,
        Commands::Logs(args) => args.json,
        _ => false,
    }
}

fn output(value: &impl Serialize) -> Result<()> {
    serde_json::to_writer_pretty(std::io::stdout().lock(), value)?;
    println!();
    Ok(())
}

async fn wait_for_update(
    path: &Path,
    pending_marker: &Path,
) -> Result<certkite_client::update::UpdateJob> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45 * 60);
    loop {
        let job: certkite_client::update::UpdateJob = certkite_client::state::read_json(path)?;
        let still_running = matches!(job.status.as_str(), "queued" | "running")
            || (job.status == "succeeded" && pending_marker.try_exists()?);
        if !still_running {
            return Ok(job);
        }
        if tokio::time::Instant::now() > deadline {
            bail!(
                "update result is incomplete; inspect its independent systemd unit and {}",
                path.display()
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn execute(
    cli: Cli,
    log_receiver: Option<tokio::sync::mpsc::Receiver<certkite_client::logging::LogEntry>>,
) -> Result<u8> {
    match &cli.command {
        Commands::Run => {
            certkite_client::daemon::run_with_logs(&cli.config_path()?, log_receiver).await?;
        }
        Commands::Logs(args) => logs::show(args).await?,
        Commands::Status(args) => {
            let snapshot = certkite_client::status()?;
            let service = service_state()
                .await
                .unwrap_or_else(|error| json!({"available":false,"error":error.to_string()}));
            if args.json {
                output(&json!({"client":snapshot,"systemd":service}))?;
            } else {
                println!("Installed version: {}", snapshot.installed_version);
                println!(
                    "Client ID: {}",
                    snapshot.client_id.as_deref().unwrap_or("not initialized")
                );
                if let Some(runtime) = snapshot.runtime {
                    println!(
                        "Last runtime: {} (PID {}), ready={}, connected={}, updated_at={}",
                        runtime.version,
                        runtime.pid,
                        runtime.ready,
                        runtime.connected,
                        runtime.updated_at
                    );
                    if let Some(result) = runtime.last_result {
                        println!("Last operation: {} — {}", result.target, result.message);
                    }
                } else {
                    println!("No runtime snapshot. Start the client with `certkite run`.");
                }
                println!("Systemd: {service}");
            }
        }
        Commands::Doctor(args) => {
            let report = certkite_client::doctor(&cli.config_path()?).await?;
            if args.json {
                output(&report)?;
            } else {
                for (name, check) in &report.checks {
                    println!(
                        "{} {name}: {}",
                        if check.ok { "OK" } else { "FAIL" },
                        check.message
                    );
                }
            }
            if !report.ok {
                return Ok(4);
            }
        }
        Commands::Update(args) => {
            if args.check {
                let check = certkite_client::update::check(args.to.as_deref()).await?;
                if args.json {
                    output(&check)?;
                } else {
                    println!(
                        "Installed: {}; release: {}; update available: {}",
                        check.current_version, check.manifest.version, check.available
                    );
                }
            } else if config::is_system_installation() {
                let job = certkite_client::update::launch(args.to.as_deref(), &cli.config_path()?)
                    .await?;
                if !args.json {
                    eprintln!(
                        "Update {} is running in an independent systemd unit.",
                        job.id
                    );
                }
                let pending = Path::new(config::SYSTEM_STATE).join("update-pending");
                let result = wait_for_update(&job.path, &pending).await?;
                let succeeded = result.status == "succeeded";
                if args.json {
                    output(&result)?;
                } else {
                    println!("Update {}: {}", result.id, result.status);
                    if let Some(error) = result.error {
                        eprintln!("{error}");
                    }
                }
                if !succeeded {
                    return Ok(1);
                }
            } else {
                let result = certkite_client::update::install_user(args.to.as_deref()).await?;
                if args.json {
                    output(&result)?;
                } else if result.available {
                    println!(
                        "Installed certkite {}. Restart the running client to use it.",
                        result.manifest.version
                    );
                } else {
                    println!("CertKite {} is already installed.", result.current_version);
                }
            }
        }
        Commands::UpdateWorker { job } => {
            let job = job.clone();
            tokio::task::spawn_blocking(move || certkite_client::update::worker(&job))
                .await
                .context("update worker terminated")??;
        }
    }
    Ok(0)
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let json = json_requested(&cli.command);
    let daemon = matches!(&cli.command, Commands::Run);
    // Dependency trace output may contain complete WebSocket certificate messages.
    let filter = format!(
        "warn,certkite_client={},certkite_deploy={},certkite_protocol={}",
        cli.log_level, cli.log_level, cli.log_level
    );
    if matches!(&cli.command, Commands::Run | Commands::Doctor(_))
        && let Err(error) = cli
            .config_path()
            .and_then(|path| config::Config::load(&path))
    {
        if json {
            if let Err(write_error) = output(
                &json!({"ok":false,"code":"configuration_invalid","message":format!("{error:#}")}),
            ) {
                eprintln!("{write_error}");
            }
        } else {
            eprintln!("{error:#}");
        }
        return ExitCode::from(3);
    }
    let log_receiver = if daemon && cfg!(target_os = "linux") {
        use tracing_subscriber::prelude::*;
        let setup = (|| -> Result<_> {
            let config = config::Config::load(&cli.config_path()?)?;
            let (layer, receiver) = certkite_client::logging::LogLayer::new(
                &config::state_directory()?,
                config.access_key(),
            )?;
            tracing_subscriber::registry()
                .with(tracing_subscriber::EnvFilter::new(filter.clone()))
                .with(layer)
                .try_init()
                .map_err(|error| anyhow::anyhow!("cannot initialize logging: {error}"))?;
            Ok(receiver)
        })();
        match setup {
            Ok(receiver) => Some(receiver),
            Err(error) => {
                eprintln!("{error:#}");
                return ExitCode::from(1);
            }
        }
    } else {
        if let Err(error) = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .with_ansi(false)
            .try_init()
        {
            eprintln!("cannot initialize logging: {error}");
            return ExitCode::from(1);
        }
        None
    };
    match execute(cli, log_receiver).await {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            if daemon {
                // The daemon's tracing sink sanitizes errors before stderr and disk output.
                tracing::error!(target: "certkite_client", error = %format!("{error:#}"), "command failed");
                return ExitCode::from(1);
            }
            if json {
                if let Err(write_error) = output(
                    &json!({"ok":false,"code":"operation_failed","message":format!("{error:#}")}),
                ) {
                    eprintln!("{write_error}");
                }
            } else {
                eprintln!("{error:#}");
            }
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clap_accepts_supported_operations_and_worker_handoff() {
        for args in [
            vec!["certkite", "run"],
            vec!["certkite", "__daemon"],
            vec!["certkite", "status", "--json"],
            vec![
                "certkite", "logs", "--follow", "--lines", "50", "--level", "warn", "--json",
            ],
            vec!["certkite", "doctor"],
            vec!["certkite", "update", "--check", "--to", "1.2.3"],
            vec![
                "certkite",
                "--config",
                "/etc/client.toml",
                "__update-worker",
                "--job",
                "/var/lib/certkite-client/update-test/job.json",
            ],
        ] {
            assert!(Cli::try_parse_from(args).is_ok());
        }
    }

    #[tokio::test]
    async fn update_success_waits_until_deployment_gate_is_removed() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let job_path = directory.path().join("job.json");
        let marker = directory.path().join("update-pending");
        std::fs::write(&marker, "pending").unwrap();
        certkite_client::state::write_json(&job_path, &json!({
            "id":"fixture", "path":job_path, "status":"succeeded", "error":null,
            "manifest":{"version":"0.2.0","platform":"fixture","url":"https://certkite.com/client/artifact","size":1,"sha256":"00"},
            "config":"/etc/certkite-client/config.toml", "previous_version":"0.1.0", "phase":"committed"
        })).unwrap();
        let pending = marker.clone();
        let task = tokio::spawn(async move { wait_for_update(&job_path, &pending).await });
        tokio::task::yield_now().await;
        assert!(
            !task.is_finished(),
            "success must not leave deployment permanently gated"
        );
        std::fs::remove_file(marker).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(result.status, "succeeded");
    }

    #[test]
    fn removed_and_incomplete_commands_are_usage_errors() {
        assert!(Cli::try_parse_from(["certkite", "service", "install"]).is_err());
        assert!(Cli::try_parse_from(["certkite", "service", "uninstall"]).is_err());
        assert!(Cli::try_parse_from(["certkite", "--log-level", "invalid", "__daemon"]).is_err());
        assert!(Cli::try_parse_from(["certkite", "service"]).is_err());
        assert!(Cli::try_parse_from(["certkite", "logs", "--lines", "0"]).is_err());
        assert!(Cli::try_parse_from(["certkite", "logs", "--lines", "1001"]).is_err());
    }
}

use anyhow::Result;
use certkite_client::{
    config,
    logging::{self, LogEntry},
};
use clap::Args;
use std::{io::Write, time::Duration};

#[derive(Args)]
pub struct LogArgs {
    /// Number of recent matching records (1–1000).
    #[arg(short = 'n', long, default_value = "100", value_parser = clap::value_parser!(u16).range(1..=1000))]
    lines: u16,
    /// Keep printing new records until Ctrl+C.
    #[arg(short = 'f', long)]
    follow: bool,
    /// Include only this severity.
    #[arg(long, value_parser = ["error", "warn", "info", "debug"])]
    level: Option<String>,
    /// Print one JSON object per line.
    #[arg(long)]
    pub json: bool,
}

fn print(entries: &[LogEntry], json: bool) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    for entry in entries {
        if json {
            serde_json::to_writer(&mut stdout, entry)?;
            writeln!(stdout)?;
        } else {
            writeln!(
                stdout,
                "{} {:5} {}",
                entry.timestamp, entry.level, entry.message
            )?;
        }
    }
    stdout.flush()?;
    Ok(())
}

pub async fn show(args: &LogArgs) -> Result<()> {
    let level = args.level.as_deref().map(str::to_ascii_uppercase);
    let directory = config::state_directory()?;
    let entries = logging::read(&directory, args.lines as usize, level.as_deref())?;
    print(&entries, args.json)?;
    if !args.follow {
        return Ok(());
    }
    let mut last_id = entries.last().map(|entry| entry.id.clone());
    loop {
        tokio::select! {
            result = tokio::signal::ctrl_c() => { result?; return Ok(()); },
            _ = tokio::time::sleep(Duration::from_millis(500)) => {}
        }
        let level = level.clone();
        let directory = directory.clone();
        let entries = tokio::task::spawn_blocking(move || {
            logging::read(&directory, logging::MAX_LINES, level.as_deref())
        })
        .await??;
        let start = last_id
            .as_ref()
            .and_then(|id| entries.iter().position(|entry| &entry.id == id))
            .map_or(0, |position| position + 1);
        print(&entries[start..], args.json)?;
        if let Some(entry) = entries.last() {
            last_id = Some(entry.id.clone());
        }
    }
}

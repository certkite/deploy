//! Bounded private JSON logs, tracing capture, and independent Core delivery.

use crate::{state, transport};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fmt::Write as _,
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc;
use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::{Layer, layer::Context as LayerContext};

const FILE_NAME: &str = "client.log";
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_MESSAGE_BYTES: usize = 8192;
/// Maximum number of records returned by a local query.
pub const MAX_LINES: usize = 1000;

/// One sanitized log record, shared by local and remote viewers.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LogEntry {
    pub id: String,
    pub timestamp: u64,
    pub level: String,
    pub message: String,
}

/// Tracing sink with bounded disk usage and a nonblocking remote queue.
pub struct LogLayer {
    directory: PathBuf,
    secret: String,
    lock: Mutex<()>,
    sender: mpsc::Sender<LogEntry>,
}

/// Remove credentials, PEM material and terminal controls before any output.
fn sanitize(message: &str, secret: &str) -> String {
    let message = if secret.is_empty() {
        message.to_owned()
    } else {
        message.replace(secret, "[redacted]")
    };
    let lower = message.to_ascii_lowercase();
    let assignments: String = lower
        .chars()
        .filter(|ch| !ch.is_whitespace() && !['\'', '"'].contains(ch))
        .collect();
    if lower.contains("-----begin ")
        || lower.contains("bearer ")
        || lower.contains("basic ")
        || [
            "accesskey",
            "access_key",
            "token",
            "password",
            "secret",
            "private_key",
            "authorization",
            "cookie",
        ]
        .iter()
        .any(|key| {
            assignments.contains(&format!("{key}=")) || assignments.contains(&format!("{key}:"))
        })
    {
        return "[redacted sensitive log message]".into();
    }
    let mut result = String::new();
    for ch in message.chars().filter(|ch| !ch.is_control()) {
        if result.len() + ch.len_utf8() > MAX_MESSAGE_BYTES {
            break;
        }
        result.push(ch);
    }
    result
}

impl LogLayer {
    /// Prepare the daemon's private store and a bounded delivery queue.
    pub fn new(directory: &Path, secret: &str) -> Result<(Self, mpsc::Receiver<LogEntry>)> {
        state::private_dir(directory)?;
        let (sender, receiver) = mpsc::channel(256);
        Ok((
            Self {
                directory: directory.into(),
                secret: secret.into(),
                lock: Mutex::new(()),
                sender,
            },
            receiver,
        ))
    }

    fn append(&self, entry: &LogEntry) -> Result<()> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| anyhow::anyhow!("log lock poisoned"))?;
        let _snapshot = state::lock(&self.directory.join("client-log.lock"), false)?;
        let path = self.directory.join(FILE_NAME);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.uid() == crate::config::effective_uid()
                && metadata.mode() & 0o077 == 0,
            "unsafe log file"
        );
        let mut bytes = serde_json::to_vec(entry)?;
        bytes.push(b'\n');
        if metadata.len() + bytes.len() as u64 > MAX_FILE_BYTES {
            drop(file);
            fs::rename(&path, self.directory.join("client.log.1"))?;
            file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&path)?;
        }
        file.write_all(&bytes)?;
        Ok(())
    }
}

#[derive(Default)]
struct Fields(String);
impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if !self.0.is_empty() {
            self.0.push(' ');
        }
        let _ = write!(self.0, "{}={value:?}", field.name());
    }
}
impl<S: Subscriber> Layer<S> for LogLayer {
    fn on_event(&self, event: &Event<'_>, _: LayerContext<'_, S>) {
        if !event.metadata().target().starts_with("certkite_") {
            return;
        }
        let mut fields = Fields::default();
        event.record(&mut fields);
        let entry = LogEntry {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            level: match *event.metadata().level() {
                tracing::Level::TRACE => "DEBUG".into(),
                level => level.to_string(),
            },
            message: sanitize(&fields.0, &self.secret),
        };
        eprintln!("{} {} {}", entry.timestamp, entry.level, entry.message);
        if let Err(error) = self.append(&entry) {
            eprintln!("cannot write client log: {error}");
        }
        if let Err(error) = self.sender.try_send(entry) {
            if matches!(error, mpsc::error::TrySendError::Full(_)) {
                // shortcut: offline overflow stays local; add durable replay if guaranteed delivery is required.
                eprintln!("Core log queue full; record retained locally");
            }
        }
    }
}

/// Read the latest matching records without following symlinks or unbounded files.
pub fn read(directory: &Path, lines: usize, level: Option<&str>) -> Result<Vec<LogEntry>> {
    ensure!(
        (1..=MAX_LINES).contains(&lines),
        "lines must be between 1 and {MAX_LINES}"
    );
    if !directory.try_exists()? {
        return Ok(Vec::new());
    }
    // The same cross-process lock covers both file reads and every append/rotation.
    let _snapshot = state::lock(&directory.join("client-log.lock"), false)?;
    let mut entries = std::collections::VecDeque::with_capacity(lines);
    for name in ["client.log.1", FILE_NAME] {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(directory.join(name))
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("cannot read client logs; try sudo"),
        };
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.uid() == crate::config::effective_uid()
                && metadata.mode() & 0o077 == 0
                && metadata.len() <= MAX_FILE_BYTES,
            "unsafe or oversized log file"
        );
        for line in BufReader::new(file).lines() {
            let line = line?;
            // A reader can observe the writer's final, incomplete record.
            let Ok(entry) = serde_json::from_str::<LogEntry>(&line) else {
                continue;
            };
            if level.is_some_and(|level| entry.level != level) {
                continue;
            }
            if entries.len() == lines {
                entries.pop_front();
            }
            entries.push_back(entry);
        }
    }
    Ok(entries.into_iter().collect())
}

/// Deliver logs independently of the deployment socket; retries never block publication.
pub async fn report(
    receiver: mpsc::Receiver<LogEntry>,
    client_id: String,
    access_key: String,
    shutdown: tokio::sync::oneshot::Receiver<()>,
) {
    let client = match transport::http_client() {
        Ok(client) => client,
        Err(_) => {
            eprintln!("cannot initialize Core log delivery; logs remain local");
            return;
        }
    };
    report_to(
        receiver,
        client_id,
        access_key,
        shutdown,
        client,
        "https://certkite.com/client/v1/logs",
    )
    .await;
}

async fn report_to(
    mut receiver: mpsc::Receiver<LogEntry>,
    client_id: String,
    access_key: String,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
    client: reqwest::Client,
    endpoint: &str,
) {
    loop {
        let entry = tokio::select! {
            entry = receiver.recv() => match entry { Some(entry) => entry, None => break },
            _ = &mut shutdown, if !receiver.is_closed() => { receiver.close(); continue; },
        };
        let body = serde_json::json!({"clientId": client_id, "timestamp": entry.timestamp, "level": entry.level, "message": entry.message, "version": crate::config::VERSION});
        let mut delivered = false;
        for attempt in 0..3 {
            let response = client
                .post(endpoint)
                .bearer_auth(&access_key)
                .json(&body)
                .timeout(std::time::Duration::from_secs(5))
                .send()
                .await;
            match response {
                Ok(response) if response.status().is_success() => {
                    delivered = true;
                    break;
                }
                Ok(response)
                    if response.status().is_client_error() && response.status().as_u16() != 429 =>
                {
                    break;
                }
                _ => {}
            }
            if attempt < 2 {
                tokio::time::sleep(std::time::Duration::from_secs(1 << attempt)).await;
            }
        }
        if !delivered {
            eprintln!("Core log delivery failed; record retained locally");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::prelude::*;

    #[test]
    fn captures_sanitized_logs_with_rotation_filtering_and_private_permissions() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(
            directory.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let (layer, _receiver) = LogLayer::new(directory.path(), "test-credential").unwrap();
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("connected test-credential");
            tracing::warn!("-----BEGIN PRIVATE KEY-----hidden-----END PRIVATE KEY-----");
            for _ in 0..300 {
                tracing::debug!("{}", "界".repeat(3000));
            }
            tracing::error!("final failure");
        });
        let entries = read(directory.path(), MAX_LINES, None).unwrap();
        assert_eq!(entries.len(), 303);
        assert_eq!(entries[0].message, "message=connected [redacted]");
        assert_eq!(entries[1].message, "[redacted sensitive log message]");
        assert_eq!(
            read(directory.path(), 1, None).unwrap()[0].id,
            entries.last().unwrap().id
        );
        assert!(entries.last().unwrap().message.contains("final failure"));
        assert_eq!(read(directory.path(), 10, Some("ERROR")).unwrap().len(), 1);
        for name in [FILE_NAME, "client.log.1"] {
            let path = directory.path().join(name);
            assert!(fs::metadata(&path).unwrap().len() <= MAX_FILE_BYTES);
            assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
            let source = fs::read_to_string(path).unwrap();
            assert!(!source.contains("test-credential"));
            assert!(!source.contains("PRIVATE KEY"));
            assert!(!source.contains("hidden"));
        }
        assert!(read(directory.path(), 0, None).is_err());
    }

    #[test]
    fn concurrent_rotation_keeps_snapshots_contiguous_and_follow_cursor_complete() {
        use std::sync::{
            Arc, Barrier,
            atomic::{AtomicBool, Ordering},
            mpsc as sync_mpsc,
        };
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(
            directory.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let (writer, _receiver) = LogLayer::new(directory.path(), "").unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let done = Arc::new(AtomicBool::new(false));
        let writer_barrier = barrier.clone();
        let writer_done = done.clone();
        let (checkpoint, progress) = sync_mpsc::channel();
        let (acknowledge, acknowledgements) = sync_mpsc::channel();
        let writer = std::thread::spawn(move || {
            writer_barrier.wait();
            for sequence in 0..1500 {
                writer
                    .append(&LogEntry {
                        id: sequence.to_string(),
                        timestamp: 1,
                        level: "INFO".into(),
                        message: "x".repeat(6000),
                    })
                    .unwrap();
                // Bound the reader's lag below retention; any missing record is a snapshot bug.
                if sequence % 100 == 99 {
                    checkpoint.send(sequence).unwrap();
                    acknowledgements.recv().unwrap();
                }
            }
            writer_done.store(true, Ordering::SeqCst);
        });
        barrier.wait();
        let mut next_sequence = 0;
        while !done.load(Ordering::SeqCst) {
            let entries = read(directory.path(), MAX_LINES, None).unwrap();
            for pair in entries.windows(2) {
                assert_eq!(
                    pair[0].id.parse::<usize>().unwrap() + 1,
                    pair[1].id.parse::<usize>().unwrap()
                );
            }
            for entry in entries {
                let sequence = entry.id.parse::<usize>().unwrap();
                if sequence >= next_sequence {
                    assert_eq!(
                        sequence, next_sequence,
                        "follow cursor skipped retained records"
                    );
                    next_sequence += 1;
                }
            }
            if let Ok(sequence) = progress.try_recv() {
                // The checkpoint may arrive after the snapshot; take another before releasing the writer.
                for entry in read(directory.path(), MAX_LINES, None).unwrap() {
                    let current = entry.id.parse::<usize>().unwrap();
                    if current >= next_sequence {
                        assert_eq!(current, next_sequence);
                        next_sequence += 1;
                    }
                }
                assert_eq!(next_sequence, sequence + 1);
                acknowledge.send(()).unwrap();
            }
            std::thread::yield_now();
        }
        writer.join().unwrap();
        assert_eq!(next_sequence, 1500);
        assert!(directory.path().join("client.log.1").exists());
    }

    #[tokio::test]
    async fn reporter_retries_and_drains_queued_records_with_header_authentication() {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/client/v1/logs", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            for status in [503, 204, 204] {
                let (socket, _) = listener.accept().await.unwrap();
                let mut reader = tokio::io::BufReader::new(socket);
                let mut headers = String::new();
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).await.unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    headers.push_str(&line);
                }
                assert!(headers.starts_with("POST /client/v1/logs HTTP/1.1"));
                assert!(
                    headers
                        .to_ascii_lowercase()
                        .contains("authorization: bearer test-key")
                );
                let length: usize = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .map(|value| value.trim().parse().unwrap())
                    })
                    .unwrap();
                let mut body = vec![0; length];
                reader.read_exact(&mut body).await.unwrap();
                let entry: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(entry["clientId"], "test-client");
                assert_eq!(entry["message"], "connected");
                assert!(entry.get("version").is_some());
                assert!(!String::from_utf8(body).unwrap().contains("test-key"));
                reader.get_mut().write_all(format!("HTTP/1.1 {status} Result\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
            }
        });
        let (sender, receiver) = mpsc::channel(2);
        for _ in 0..2 {
            sender
                .send(LogEntry {
                    id: uuid::Uuid::new_v4().to_string(),
                    timestamp: 1,
                    level: "INFO".into(),
                    message: "connected".into(),
                })
                .await
                .unwrap();
        }
        let (stop, shutdown) = tokio::sync::oneshot::channel();
        stop.send(()).unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            report_to(
                receiver,
                "test-client".into(),
                "test-key".into(),
                shutdown,
                reqwest::Client::new(),
                &endpoint,
            ),
        )
        .await
        .unwrap();
        server.await.unwrap();
    }

    #[test]
    fn rejects_symlinks_and_redacts_controls_and_credentials() {
        assert_eq!(
            sanitize("token=hidden", ""),
            "[redacted sensitive log message]"
        );
        assert_eq!(
            sanitize("Bearer hidden", ""),
            "[redacted sensitive log message]"
        );
        assert_eq!(sanitize("hello\n\x1bworld", ""), "helloworld");
        assert_eq!(
            sanitize("\"token\": \"hidden\"", ""),
            "[redacted sensitive log message]"
        );
        let directory = tempfile::tempdir().unwrap();
        let other = directory.path().join("other");
        fs::write(&other, "private").unwrap();
        std::os::unix::fs::symlink(other, directory.path().join(FILE_NAME)).unwrap();
        assert!(read(directory.path(), 10, None).is_err());
    }
}

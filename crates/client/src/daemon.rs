//! Foreground daemon with independent network and blocking deployment tasks.

use crate::{
    config::{Config, STATE_DIR, VERSION},
    identity::Identity,
    state::{self, RuntimeStatus},
    transport::{self, Socket},
};
use anyhow::{Context, Result, bail, ensure};
use certkite_protocol::{
    ClientMessage, ErrorCode, MAX_MESSAGE_BYTES, OperationResult, PROTOCOL_VERSION, ResultStatus,
    ServerMessage, TargetSummary,
};
use futures_util::{SinkExt, StreamExt};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::watch,
    task::JoinSet,
    time::{Instant, interval, timeout},
};
use tokio_tungstenite::tungstenite::Message;

/// Build identity embedded by the release workflow.
pub fn build_id() -> &'static str {
    option_env!("CERTKITE_BUILD_ID").unwrap_or(VERSION)
}

/// Run until SIGINT or SIGTERM, draining an in-progress publication before exit.
pub async fn run(config_path: &Path) -> Result<()> {
    ensure!(
        cfg!(target_os = "linux"),
        "the daemon requires Linux; use doctor for local diagnostics"
    );
    ensure!(
        crate::config::effective_uid() == 0,
        "the installed daemon must run as root"
    );
    let config = Arc::new(Config::load(config_path)?);
    let discovered = tokio::task::spawn_blocking(certkite_deploy::discover).await??;
    let targets = Arc::new(
        discovered
            .into_iter()
            .map(|target| (target.id, target.config))
            .collect::<BTreeMap<_, _>>(),
    );
    let directory = PathBuf::from(STATE_DIR);
    state::private_dir(&directory)?;
    let _singleton = state::lock(&directory.join("runtime.lock"), true)
        .context("another client is already running")?;
    crate::update::recover_pending()?;
    let identity = Identity::load_or_create(&directory)?;
    encode(&hello_message(&identity, &targets)?)?;
    let recovery_targets = targets.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        // The singleton protects startup recovery. An updater may hold deployment.lock
        // while waiting for this new process to become ready.
        for (name, target) in recovery_targets.iter() {
            certkite_deploy::recover(target)
                .with_context(|| format!("cannot recover target {name}"))?;
        }
        Ok(())
    })
    .await??;
    let mut status = RuntimeStatus {
        pid: std::process::id(),
        version: VERSION.into(),
        build_id: build_id().into(),
        started_at: state::now()?,
        updated_at: state::now()?,
        ready: true,
        ..Default::default()
    };
    save_status(&directory, &status).await?;
    let (shutdown_sender, mut shutdown) = watch::channel(false);
    let signal_task = tokio::spawn(async move {
        if let Err(error) = shutdown_signal().await {
            tracing::error!(%error, "cannot listen for shutdown");
        }
        if shutdown_sender.send(true).is_err() {
            tracing::debug!("shutdown listener already closed");
        }
    });
    notify_ready()?;
    let mut failures = 0u32;
    let outcome = async {
        loop {
            if *shutdown.borrow() {
                return Ok(());
            }
            let connection = tokio::select! {
                result = transport::connect(transport::CONNECT_URL, config.access_key()) => result,
                _ = shutdown.changed() => return Ok(()),
            };
            match connection {
                Ok(socket) => {
                    let started = Instant::now();
                    if let Err(error) = session(
                        socket,
                        config.clone(),
                        targets.clone(),
                        &identity,
                        &directory,
                        &mut status,
                        shutdown.clone(),
                    )
                    .await
                    {
                        tracing::warn!(error = %error, "connection ended");
                    }
                    if started.elapsed() > Duration::from_secs(60) {
                        failures = 0;
                    }
                }
                Err(_) => tracing::warn!("connection failed; check network and accessKey"),
            }
            status.connected = false;
            status.updated_at = state::now()?;
            save_status(&directory, &status).await?;
            if *shutdown.borrow() {
                return Ok(());
            }
            failures = failures.saturating_add(1);
            let base = 1u64 << failures.min(6);
            let jitter = u64::from(uuid::Uuid::new_v4().as_bytes()[0]) * 4;
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(base * 1000 + jitter)) => {},
                _ = shutdown.changed() => return Ok(()),
            }
        }
    }
    .await;
    signal_task.abort();
    status.ready = false;
    status.connected = false;
    status.updated_at = state::now()?;
    save_status(&directory, &status).await?;
    outcome
}

async fn shutdown_signal() -> Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result?,
        _ = terminate.recv() => {},
    }
    Ok(())
}

async fn save_status(directory: &Path, status: &RuntimeStatus) -> Result<()> {
    let path = directory.join("startup.json");
    let status = status.clone();
    tokio::task::spawn_blocking(move || state::write_json(&path, &status)).await?
}

fn encode(message: &ClientMessage) -> Result<String> {
    let encoded = serde_json::to_string(message)?;
    ensure!(
        encoded.len() <= MAX_MESSAGE_BYTES,
        "outbound protocol message exceeds {MAX_MESSAGE_BYTES} bytes"
    );
    Ok(encoded)
}

async fn send(socket: &mut Socket, message: &ClientMessage) -> Result<()> {
    let encoded = encode(message)?;
    timeout(
        Duration::from_secs(10),
        socket.send(Message::Text(encoded.into())),
    )
    .await
    .context("server write timed out")?
    .map_err(|_| anyhow::anyhow!("server connection closed while writing"))
}

pub(crate) async fn session(
    mut socket: Socket,
    config: Arc<Config>,
    targets: Arc<BTreeMap<String, certkite_deploy::TargetConfig>>,
    identity: &Identity,
    directory: &Path,
    status: &mut RuntimeStatus,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let client_id = identity.client_id.to_string();
    send(&mut socket, &hello_message(identity, &targets)?).await?;
    let greeting = tokio::select! {
        result = timeout(Duration::from_secs(15), receive_welcome(&mut socket)) => result.context("registration timed out")??,
        _ = shutdown.changed() => return Ok(()),
    };
    status.connected = true;
    status.last_seen_at = Some(state::now()?);
    status.updated_at = state::now()?;
    save_status(directory, status).await?;
    let mut heartbeat = interval(Duration::from_secs(greeting));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_received = Instant::now();
    let mut work: JoinSet<OperationResult> = JoinSet::new();
    let outcome: Result<()> = async {
        loop {
            tokio::select! {
                _ = shutdown.changed() => { break; },
                _ = heartbeat.tick() => {
                    ensure!(last_received.elapsed() < Duration::from_secs(greeting * 3), "server heartbeat timed out");
                    send(&mut socket, &ClientMessage::Heartbeat { client_id: client_id.clone(), timestamp: state::now()? }).await?;
                },
                result = work.join_next(), if !work.is_empty() => {
                    let result = result.context("operation task disappeared")?.context("operation task failed")?;
                    status.last_result = Some(result.clone());
                    status.updated_at = state::now()?;
                    save_status(directory, status).await?;
                    send(&mut socket, &ClientMessage::Result { client_id: client_id.clone(), result }).await?;
                },
                incoming = socket.next() => {
                    let frame = incoming.context("server disconnected")?.map_err(|_| anyhow::anyhow!("WebSocket read failed"))?;
                    match frame {
                        Message::Ping(payload) => {
                            timeout(Duration::from_secs(10), socket.send(Message::Pong(payload))).await??;
                            last_received = Instant::now();
                            continue;
                        },
                        Message::Pong(_) => { last_received = Instant::now(); continue; },
                        Message::Close(_) => break,
                        Message::Text(text) => {
                            let message = transport::decode(&text)?;
                            last_received = Instant::now();
                            status.last_seen_at = Some(state::now()?);
                            match message {
                                ServerMessage::Heartbeat {} => {},
                                ServerMessage::Deploy { .. } | ServerMessage::Test { .. } => {
                                    if !work.is_empty() {
                                        let result = failed_result(&message, ErrorCode::Busy, true, "another operation is running");
                                        send(&mut socket, &ClientMessage::Result { client_id: client_id.clone(), result }).await?;
                                    } else {
                                        let config = config.clone();
                                        let targets = targets.clone();
                                        let directory = directory.to_owned();
                                        work.spawn_blocking(move || execute(message, &config, &targets, &directory, Path::new(certkite_deploy::CERTIFICATE_ROOT)));
                                    }
                                },
                                ServerMessage::Error { .. } => bail!("server rejected the session"),
                                _ => bail!("unexpected server message after registration"),
                            }
                        },
                        _ => bail!("only JSON text messages are supported"),
                    }
                }
            }
        }
        Ok(())
    }.await;
    // Dropping spawn_blocking cannot cancel file publication; always wait for its result.
    while let Some(result) = work.join_next().await {
        let result = result.context("deployment task failed during disconnect")?;
        status.last_result = Some(result);
        status.updated_at = state::now()?;
        save_status(directory, status).await?;
    }
    outcome
}

async fn receive_welcome(socket: &mut Socket) -> Result<u64> {
    while let Some(frame) = socket.next().await {
        match frame.map_err(|_| anyhow::anyhow!("registration connection failed"))? {
            Message::Text(text) => match transport::decode(&text)? {
                ServerMessage::Welcome {
                    heartbeat_seconds, ..
                } => return Ok(heartbeat_seconds),
                _ => bail!("first server message must be welcome"),
            },
            Message::Ping(payload) => socket.send(Message::Pong(payload)).await?,
            Message::Pong(_) => {}
            _ => bail!("registration connection closed"),
        }
    }
    bail!("registration connection closed")
}

fn failed_result(
    message: &ServerMessage,
    code: ErrorCode,
    retryable: bool,
    explanation: &str,
) -> OperationResult {
    let (request_id, target, operation_id, generation) = match message {
        ServerMessage::Test { request_id, target } => {
            (request_id.clone(), target.clone(), None, None)
        }
        ServerMessage::Deploy {
            request_id,
            target,
            operation_id,
            generation,
            ..
        } => (
            request_id.clone(),
            target.clone(),
            Some(operation_id.clone()),
            Some(*generation),
        ),
        _ => unreachable!("only validated operations reach the executor"),
    };
    OperationResult {
        request_id,
        operation_id,
        target,
        generation,
        status: ResultStatus::Failed,
        code,
        retryable,
        message: explanation.into(),
        changed: None,
    }
}

fn domain_matches(site: &str, domain: &str) -> bool {
    let site = site.trim_end_matches('.').to_ascii_lowercase();
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    if site == domain {
        return true;
    }
    let Some(root) = site.strip_prefix("*.") else {
        return false;
    };
    domain.ends_with(&format!(".{root}"))
        && domain.matches('.').count() == root.matches('.').count() + 1
}

fn execute(
    message: ServerMessage,
    config: &Config,
    targets: &BTreeMap<String, certkite_deploy::TargetConfig>,
    directory: &Path,
    certificate_root: &Path,
) -> OperationResult {
    let mut result = failed_result(
        &message,
        ErrorCode::LocalPublishFailed,
        false,
        "local operation failed; inspect server logs",
    );
    let pending = directory.join("update-pending");
    if pending.exists() {
        return failed_result(&message, ErrorCode::Busy, true, "client is updating");
    }
    let _guard = match state::lock(&directory.join("deployment.lock"), true) {
        Ok(guard) => guard,
        Err(error) => {
            if error.chain().any(|cause| {
                cause
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::WouldBlock)
            }) {
                return failed_result(
                    &message,
                    ErrorCode::Busy,
                    true,
                    "another operation is running",
                );
            }
            tracing::error!(error = %error, "cannot lock local deployment state");
            return result;
        }
    };
    if pending.exists() {
        return failed_result(&message, ErrorCode::Busy, true, "client is updating");
    }
    let download_only = !targets.contains_key(&result.target);
    let files;
    let target = match targets.get(&result.target) {
        Some(target) => target,
        None if matches!(&message, ServerMessage::Deploy { .. }) => {
            if !certkite_protocol::valid_id(&result.target, 64) {
                return failed_result(
                    &message,
                    ErrorCode::InvalidRequest,
                    false,
                    "invalid target identifier",
                );
            }
            files = certkite_deploy::TargetConfig::Files {
                // Keep downloads away from service journals and configuration backups.
                directory: certificate_root.join("downloads").join(&result.target),
            };
            &files
        }
        None => {
            return failed_result(
                &message,
                ErrorCode::TargetUnavailable,
                false,
                "target is not available",
            );
        }
    };
    if let ServerMessage::Deploy { domain, .. } = &message
        && !target.domains().is_empty()
        && !target
            .domains()
            .iter()
            .any(|site| domain_matches(site, domain))
    {
        return failed_result(
            &message,
            ErrorCode::TargetUnavailable,
            false,
            "certificate domain does not match the selected local site",
        );
    }
    let outcome = match &message {
        ServerMessage::Test { .. } => certkite_deploy::check(target).map(|()| (false, None)),
        ServerMessage::Deploy {
            operation_id,
            generation,
            domain,
            fullchain_pem,
            private_key_pem,
            ..
        } => (|| {
            if download_only {
                certkite_deploy::TargetConfig::Files {
                    directory: certificate_root.join("downloads"),
                }
                .prepare()?;
                target.prepare()?;
            }
            certkite_deploy::deploy(
                target,
                &certkite_deploy::Deployment {
                    operation_id,
                    generation: *generation,
                    domain,
                    fullchain_pem,
                    private_key_pem,
                },
            )
            .map(|outcome| (outcome.changed, Some(outcome.generation)))
        })(),
        _ => unreachable!("executor receives operations only"),
    };
    match outcome {
        Ok((changed, generation)) => {
            result.status = ResultStatus::Success;
            result.code = ErrorCode::Ok;
            result.message = if download_only {
                "certificate downloaded; deployment skipped because target is not available"
            } else {
                "operation completed"
            }
            .into();
            result.changed = Some(changed);
            result.generation = generation;
        }
        Err(error) => {
            use certkite_deploy::Failure;
            let details = format!("{error:#}").replace(config.access_key(), "[redacted]");
            tracing::warn!(target = %result.target, error = %details, "local operation failed");
            let (code, explanation) = match certkite_deploy::classify(&error) {
                Failure::CertificateInvalid => (
                    ErrorCode::CertificateInvalid,
                    "certificate, key or domain validation failed",
                ),
                Failure::Conflict => (
                    ErrorCode::Conflict,
                    "operation identifier conflicts with existing content",
                ),
                Failure::StaleOperation => {
                    (ErrorCode::StaleOperation, "deployment generation is stale")
                }
                Failure::RecoveryFailed => (
                    ErrorCode::RecoveryFailed,
                    "publication recovery requires operator attention",
                ),
                Failure::LocalPublishFailed => (
                    ErrorCode::LocalPublishFailed,
                    "local publication failed; inspect server logs",
                ),
            };
            result.code = code;
            result.message = explanation.into();
        }
    }
    result
}

fn hello_message(
    identity: &Identity,
    targets: &BTreeMap<String, certkite_deploy::TargetConfig>,
) -> Result<ClientMessage> {
    Ok(ClientMessage::Hello {
        protocol_version: PROTOCOL_VERSION,
        client_id: identity.client_id.to_string(),
        client_version: VERSION.into(),
        build_id: build_id().into(),
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        hostname: hostname()?,
        targets: targets
            .iter()
            .map(|(id, target)| TargetSummary {
                id: id.clone(),
                kind: target.kind().into(),
                domains: target.domains().to_vec(),
            })
            .collect(),
    })
}

fn hostname() -> Result<String> {
    let mut bytes = [0u8; 256];
    // SAFETY: the pointer references a writable buffer of the supplied length.
    let code = unsafe { libc::gethostname(bytes.as_mut_ptr().cast(), bytes.len()) };
    ensure!(code == 0, "cannot read hostname");
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

fn notify_ready() -> Result<()> {
    let Some(address) = std::env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    let socket = std::os::unix::net::UnixDatagram::unbound()?;
    #[cfg(target_os = "linux")]
    {
        use std::os::{linux::net::SocketAddrExt, unix::ffi::OsStrExt};
        let bytes = address.as_bytes();
        if bytes.first() == Some(&b'@') {
            socket.connect_addr(&std::os::unix::net::SocketAddr::from_abstract_name(
                &bytes[1..],
            )?)?;
        } else {
            socket.connect(Path::new(&address))?;
        }
    }
    #[cfg(not(target_os = "linux"))]
    socket.connect(Path::new(&address))?;
    socket.send(b"READY=1\nSTATUS=Client initialized; connecting to CertKite")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{domain_matches, encode, execute, hello_message};
    use crate::{config::Config, identity::Identity, session_tests::certificate, state};
    use certkite_deploy::TargetConfig;
    use certkite_protocol::{ErrorCode, ResultStatus, ServerMessage};
    use std::{
        collections::BTreeMap,
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt},
    };

    #[test]
    fn unavailable_target_downloads_certificates_without_deploying_other_sites() {
        let (cert, key) = certificate();
        for target_id in ["nginx", "caddy"] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().canonicalize().unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let certificates = root.join("certificates");
            fs::create_dir(&certificates).unwrap();
            let config: Config = toml::from_str("accessKey='test-key'").unwrap();
            let config_file = root.join("nginx.conf");
            let source = "server { server_name example.com; }";
            fs::write(&config_file, source).unwrap();
            let legacy = certificates.join(target_id);
            fs::create_dir(&legacy).unwrap();
            fs::set_permissions(&legacy, fs::Permissions::from_mode(0o700)).unwrap();
            let fingerprint = "a".repeat(64);
            state::write_json(&legacy.join("state.json"), &serde_json::json!({
                "generation": 1,
                "operations": {"interrupted": {
                    "digest": fingerprint,
                    "outcome": {"changed": true, "generation": 1, "fingerprint": fingerprint},
                    "committed": false
                }},
                "pending": {"operation_id": "interrupted", "previous": null, "next": format!("versions/{fingerprint}")}
            })).unwrap();
            let metadata = fs::metadata(&config_file).unwrap();
            state::write_json(
                &legacy.join("config-backup.json"),
                &serde_json::json!({
                    "path": config_file,
                    "mode": metadata.mode() & 0o777,
                    "uid": metadata.uid(),
                    "gid": metadata.gid(),
                    "bytes": b"old service configuration".as_slice()
                }),
            )
            .unwrap();
            let legacy_mode = if target_id == "caddy" { 0o750 } else { 0o700 };
            fs::set_permissions(&legacy, fs::Permissions::from_mode(legacy_mode)).unwrap();
            let journal = fs::read(legacy.join("state.json")).unwrap();
            let backup = fs::read(legacy.join("config-backup.json")).unwrap();
            let mut targets = BTreeMap::new();
            if target_id == "caddy" {
                targets.insert(
                    "other-site".into(),
                    TargetConfig::NginxSite {
                        directory: certificates.join("other-site"),
                        nginx_binary: root.join("missing-nginx"),
                        systemd_unit: "nginx.service".into(),
                        config_file: config_file.clone(),
                        domains: vec!["example.com".into()],
                    },
                );
            }
            for (operation, generation, expected) in [
                ("op_1", 2, ErrorCode::Ok),
                ("op_1", 2, ErrorCode::Ok),
                ("op_older", 1, ErrorCode::StaleOperation),
                ("op_invalid", 3, ErrorCode::CertificateInvalid),
            ] {
                let result = execute(
                    ServerMessage::Deploy {
                        request_id: "req_1".into(),
                        operation_id: operation.into(),
                        target: target_id.into(),
                        generation,
                        domain: "example.com".into(),
                        fullchain_pem: cert.clone(),
                        private_key_pem: if operation == "op_invalid" {
                            "invalid key".into()
                        } else {
                            key.clone()
                        },
                    },
                    &config,
                    &targets,
                    &root,
                    &certificates,
                );
                assert_eq!(fs::read_to_string(&config_file).unwrap(), source);
                assert_eq!(fs::read(legacy.join("state.json")).unwrap(), journal);
                assert_eq!(fs::read(legacy.join("config-backup.json")).unwrap(), backup);
                assert_eq!(result.code, expected);
                assert_eq!(
                    result.status,
                    if expected == ErrorCode::Ok {
                        ResultStatus::Success
                    } else {
                        ResultStatus::Failed
                    }
                );
                if expected == ErrorCode::Ok {
                    assert!(result.message.contains("deployment skipped"));
                    assert_eq!(result.generation, Some(generation));
                }
            }
            let current = certificates
                .join("downloads")
                .join(target_id)
                .join("current");
            assert_eq!(
                fs::read_to_string(current.join("fullchain.pem")).unwrap(),
                cert
            );
            assert_eq!(
                fs::read_to_string(current.join("privkey.pem")).unwrap(),
                key
            );
            assert_eq!(
                fs::metadata(current.join("privkey.pem"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(fs::metadata(&legacy).unwrap().mode() & 0o777, legacy_mode);
            assert!(!legacy.join("current").exists());
            assert!(!certificates.join("other-site").exists());
        }
    }

    #[test]
    fn missing_target_checks_and_mismatched_site_domains_still_fail() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let certificates = root.join("certificates");
        let config: Config = toml::from_str("accessKey='test-key'").unwrap();
        let targets = BTreeMap::from([(
            "web".into(),
            TargetConfig::NginxSite {
                directory: certificates.join("web"),
                nginx_binary: root.join("missing-nginx"),
                systemd_unit: "nginx.service".into(),
                config_file: root.join("nginx.conf"),
                domains: vec!["other.example.com".into()],
            },
        )]);
        for message in [
            ServerMessage::Test {
                request_id: "req_1".into(),
                target: "missing".into(),
            },
            ServerMessage::Deploy {
                request_id: "req_2".into(),
                operation_id: "op_1".into(),
                target: "web".into(),
                generation: 1,
                domain: "example.com".into(),
                fullchain_pem: "cert".into(),
                private_key_pem: "key".into(),
            },
        ] {
            let result = execute(message, &config, &targets, &root, &certificates);
            assert_eq!(result.status, ResultStatus::Failed);
            assert_eq!(result.code, ErrorCode::TargetUnavailable);
        }
        assert!(!certificates.exists());
    }

    #[test]
    fn target_domain_matching_is_exact_or_one_label_wildcard() {
        assert!(domain_matches("example.com", "EXAMPLE.COM."));
        assert!(domain_matches("*.example.com", "api.example.com"));
        assert!(!domain_matches("*.example.com", "deep.api.example.com"));
        assert!(!domain_matches("example.com", "other.example.com"));
    }

    #[test]
    fn outbound_messages_obey_the_protocol_size_limit() {
        let identity = Identity {
            client_id: uuid::Uuid::new_v4(),
        };
        let domain = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        let mut targets = BTreeMap::new();
        for index in 0..64 {
            targets.insert(
                format!("nginx-{index:024}"),
                certkite_deploy::TargetConfig::NginxSite {
                    directory: "/fixture/certificates".into(),
                    nginx_binary: "/usr/sbin/nginx".into(),
                    systemd_unit: "nginx.service".into(),
                    config_file: "/etc/nginx/nginx.conf".into(),
                    domains: vec![domain.clone(); 128],
                },
            );
        }
        assert!(encode(&hello_message(&identity, &targets).unwrap()).is_err());
        targets.retain(|id, _| id.ends_with("000000"));
        assert!(encode(&hello_message(&identity, &targets).unwrap()).is_ok());
    }
}

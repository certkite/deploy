//! Foreground daemon with independent network and blocking deployment tasks.

use crate::{
    config::{self, Config, VERSION},
    core::{self, DeploymentContext},
    identity::Identity,
    state::{self, RuntimeStatus},
    transport,
};
use anyhow::{Context, Result, ensure};
use certkite_deploy::TargetConfig;
use certkite_protocol::{DeploymentCommand, ErrorCode, OperationResult, ResultStatus};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::watch,
    time::{Instant, timeout},
};

/// Build identity embedded by the release workflow.
pub fn build_id() -> &'static str {
    option_env!("CERTKITE_BUILD_ID").unwrap_or(VERSION)
}

/// Run until SIGINT or SIGTERM, draining an in-progress publication before exit.
pub async fn run(config_path: &Path) -> Result<()> {
    run_with_logs(config_path, None).await
}

/// Run with an optional independent log delivery worker.
pub async fn run_with_logs(
    config_path: &Path,
    logs: Option<tokio::sync::mpsc::Receiver<crate::logging::LogEntry>>,
) -> Result<()> {
    ensure!(
        cfg!(target_os = "linux"),
        "the daemon requires Linux; use doctor for local diagnostics"
    );
    let system = config::is_system_installation();
    let directory = config::state_directory()?;
    let certificate_root = if system {
        PathBuf::from(certkite_deploy::CERTIFICATE_ROOT)
    } else {
        config::user_certificate_root()?
    };
    let config = Arc::new(Config::load(config_path)?);
    state::private_dir(&directory)?;
    let _singleton = state::lock(&directory.join("runtime.lock"), true)
        .context("another client is already running")?;
    let now = state::now()?;
    let mut status = RuntimeStatus {
        pid: std::process::id(),
        version: VERSION.into(),
        build_id: build_id().into(),
        started_at: now,
        updated_at: now,
        ..Default::default()
    };
    save_status(&directory, &status).await?;
    let discovered = if system {
        crate::update::recover_pending()?;
        tokio::task::spawn_blocking(certkite_deploy::discover).await??
    } else {
        let root = certificate_root.clone();
        tokio::task::spawn_blocking(move || {
            fs::DirBuilder::new().recursive(true).mode(0o755).create(
                root.parent()
                    .context("missing certificate directory parent")?,
            )?;
            certkite_deploy::prepare_certificate_root(&root)
        })
        .await??;
        Vec::new()
    };
    let targets = Arc::new(
        discovered
            .into_iter()
            .map(|target| (target.id, target.config))
            .collect::<BTreeMap<_, _>>(),
    );
    let identity = Identity::load_or_create(&directory)?;
    let client_id = identity.client_id.to_string();
    let recovery_targets = targets.clone();
    let downloads = certificate_root.join("downloads");
    tokio::task::spawn_blocking(move || -> Result<()> {
        // The singleton protects startup recovery. An updater may hold deployment.lock
        // while waiting for this new process to become ready.
        for (name, target) in recovery_targets.iter() {
            certkite_deploy::recover(target)
                .with_context(|| format!("cannot recover target {name}"))?;
        }
        recover_downloads(&downloads)
    })
    .await??;
    status.ready = true;
    status.updated_at = state::now()?;
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
    let (stop_reporter, reporter_shutdown) = tokio::sync::oneshot::channel();
    let reporter = logs.map(|logs| {
        tokio::spawn(crate::logging::report(
            logs,
            identity.client_id.to_string(),
            config.access_key().to_owned(),
            reporter_shutdown,
        ))
    });
    tracing::info!(version = VERSION, targets = targets.len(), "client started");
    let deployment = DeploymentContext {
        config: config.clone(),
        targets,
        directory: directory.clone(),
        certificate_root,
    };
    let mut failures = 0u32;
    let outcome = async {
        loop {
            if *shutdown.borrow() {
                return Ok(());
            }
            let connection = tokio::select! {
                result = transport::connect_core(config.access_key(), &client_id) => result,
                _ = shutdown.changed() => return Ok(()),
            };
            match connection {
                Ok(socket) => {
                    let started = Instant::now();
                    let result = core::session(
                        socket,
                        &client_id,
                        deployment.clone(),
                        &mut status,
                        shutdown.clone(),
                    )
                    .await;
                    if let Err(error) = result {
                        tracing::warn!(error = %error, "connection ended");
                    }
                    if started.elapsed() > Duration::from_secs(60) {
                        failures = 0;
                    }
                }
                Err(error) => {
                    tracing::warn!(error = %error, "connection failed; check network and accessKey")
                }
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
    tracing::info!("client stopped");
    if outcome.is_err() {
        tracing::error!("client stopped after a runtime failure; inspect local service status");
    }
    if let Some(mut reporter) = reporter {
        if stop_reporter.send(()).is_err() {
            eprintln!("Core log worker already stopped");
        }
        match timeout(Duration::from_secs(5), &mut reporter).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => eprintln!("Core log worker failed: {error}"),
            Err(_) => {
                reporter.abort();
                if let Err(error) = reporter.await
                    && !error.is_cancelled()
                {
                    eprintln!("Core log worker failed: {error}");
                }
            }
        }
    }
    outcome
}

fn recover_downloads(downloads: &Path) -> Result<()> {
    if !downloads.try_exists()? {
        return Ok(());
    }
    certkite_deploy::prepare_certificate_root(downloads)?;
    for entry in fs::read_dir(downloads)? {
        let entry = entry?;
        if entry.file_type()?.is_dir()
            && entry
                .file_name()
                .to_str()
                .is_some_and(|name| certkite_protocol::valid_id(name, 64))
        {
            let directory = entry.path();
            certkite_deploy::recover_file_target(&directory)
                .with_context(|| format!("cannot recover download {}", directory.display()))?;
        }
    }
    Ok(())
}

async fn shutdown_signal() -> Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result?,
        _ = terminate.recv() => {},
    }
    Ok(())
}

pub(crate) async fn save_status(directory: &Path, status: &RuntimeStatus) -> Result<()> {
    let path = directory.join("startup.json");
    let status = status.clone();
    tokio::task::spawn_blocking(move || state::write_json(&path, &status)).await?
}

pub(crate) fn failed_result(
    message: &DeploymentCommand,
    code: ErrorCode,
    retryable: bool,
    explanation: &str,
) -> OperationResult {
    let (request_id, target, operation_id, generation) = match message {
        DeploymentCommand::Test { request_id, target } => {
            (request_id.clone(), target.clone(), None, None)
        }
        DeploymentCommand::Deploy {
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

pub(crate) fn domain_matches(site: &str, domain: &str) -> bool {
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

pub(crate) fn execute(
    message: DeploymentCommand,
    config: &Config,
    target: Option<&TargetConfig>,
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
    let download_only = target.is_none();
    let files;
    let target = match target {
        Some(target) => target,
        None if matches!(&message, DeploymentCommand::Deploy { .. }) => {
            if !certkite_protocol::valid_id(&result.target, 64) {
                return failed_result(
                    &message,
                    ErrorCode::InvalidRequest,
                    false,
                    "invalid target identifier",
                );
            }
            // Keep downloads away from service journals and configuration backups.
            let directory = certificate_root.join("downloads").join(&result.target);
            files = match config.download_group {
                Some(service_group) => TargetConfig::SharedFiles {
                    directory,
                    service_group,
                },
                None => TargetConfig::Files { directory },
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
    if let DeploymentCommand::Deploy { domain, .. } = &message
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
        DeploymentCommand::Test { .. } => certkite_deploy::check(target).map(|()| (false, None)),
        DeploymentCommand::Deploy {
            operation_id,
            generation,
            domain,
            fullchain_pem,
            private_key_pem,
            ..
        } => (|| {
            if download_only {
                certkite_deploy::prepare_certificate_root(&certificate_root.join("downloads"))?;
                target.prepare()?;
            }
            let request = certkite_deploy::Deployment {
                operation_id,
                generation: *generation,
                domain,
                fullchain_pem,
                private_key_pem,
            };
            let outcome = certkite_deploy::deploy(target, &request)?;
            Ok((outcome.changed, Some(outcome.generation)))
        })(),
    };
    match outcome {
        Ok((changed, generation)) => {
            result.status = ResultStatus::Success;
            result.code = ErrorCode::Ok;
            result.message = if download_only {
                "certificate saved to the download directory"
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
    match result.status {
        ResultStatus::Success => {
            tracing::info!(request_id = %result.request_id, target = %result.target, message = %result.message, "operation completed")
        }
        ResultStatus::Failed => {
            tracing::warn!(request_id = %result.request_id, target = %result.target, code = ?result.code, "operation failed")
        }
    }
    result
}

pub(crate) fn hostname() -> Result<String> {
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
    use super::{domain_matches, execute};
    use crate::{config::Config, session_tests::certificate, state};
    use certkite_deploy::TargetConfig;
    use certkite_protocol::{DeploymentCommand, ErrorCode, ResultStatus};
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt},
    };

    #[test]
    fn file_only_operations_leave_service_files_untouched() {
        let (cert, key) = certificate();
        for (target_id, shared) in [("nginx", false), ("caddy", false), ("shared", true)] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().canonicalize().unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let certificates = root.join("certificates");
            fs::create_dir(&certificates).unwrap();
            let mut config: Config = toml::from_str("accessKey='test-key'").unwrap();
            config.download_group = shared.then_some(fs::metadata(&root).unwrap().gid());
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
            for (operation, generation, expected) in [
                ("op_1", 2, ErrorCode::Ok),
                ("op_1", 2, ErrorCode::Ok),
                ("op_older", 1, ErrorCode::StaleOperation),
                ("op_invalid", 3, ErrorCode::CertificateInvalid),
            ] {
                let result = execute(
                    DeploymentCommand::Deploy {
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
                    None,
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
                    assert_eq!(
                        result.message,
                        "certificate saved to the download directory"
                    );
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
                if shared { 0o640 } else { 0o600 }
            );
            let downloads = certificates.join("downloads");
            assert_eq!(fs::metadata(&downloads).unwrap().mode() & 0o777, 0o711);
            assert_eq!(
                fs::metadata(downloads.join(target_id)).unwrap().mode() & 0o777,
                if shared { 0o750 } else { 0o700 }
            );
            assert_eq!(
                fs::metadata(current.join("privkey.pem")).unwrap().gid(),
                fs::metadata(&root).unwrap().gid()
            );
            assert_eq!(fs::metadata(&legacy).unwrap().mode() & 0o777, legacy_mode);
            assert!(!legacy.join("current").exists());
        }
    }

    #[test]
    fn missing_target_checks_and_mismatched_site_domains_still_fail() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let certificates = root.join("certificates");
        let config: Config = toml::from_str("accessKey='test-key'").unwrap();
        let target = TargetConfig::NginxSite {
            directory: certificates.join("web"),
            nginx_binary: root.join("missing-nginx"),
            systemd_unit: "nginx.service".into(),
            config_file: root.join("nginx.conf"),
            domains: vec!["other.example.com".into()],
        };
        for (message, target) in [
            (
                DeploymentCommand::Test {
                    request_id: "req_1".into(),
                    target: "missing".into(),
                },
                None,
            ),
            (
                DeploymentCommand::Deploy {
                    request_id: "req_2".into(),
                    operation_id: "op_1".into(),
                    target: "web".into(),
                    generation: 1,
                    domain: "example.com".into(),
                    fullchain_pem: "cert".into(),
                    private_key_pem: "key".into(),
                },
                Some(&target),
            ),
        ] {
            let result = execute(message, &config, target, &root, &certificates);
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
}

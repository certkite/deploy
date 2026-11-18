//! Durable certificate publication. Consumers use `current/fullchain.pem` and
//! `current/privkey.pem`; current is atomically switched to an immutable version.
//! Target access is private or restricted to the configured service group. Recovery runs before
//! serving requests, and is also performed by deploy while holding both locks.
mod certificate;
mod command;
mod discovery;
mod paths;
mod site;
use anyhow::{Context, Result, bail, ensure};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    os::unix::fs::symlink,
    path::{Path, PathBuf},
};

/// Stable error categories for protocol mapping; details remain in anyhow's chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Failure {
    #[error("certificate invalid")]
    CertificateInvalid,
    #[error("operation content conflict")]
    Conflict,
    #[error("stale operation")]
    StaleOperation,
    #[error("local publication failed")]
    LocalPublishFailed,
    #[error("deployment recovery failed")]
    RecoveryFailed,
}
pub fn classify(error: &anyhow::Error) -> Failure {
    error
        .downcast_ref::<Failure>()
        .copied()
        .unwrap_or(Failure::LocalPublishFailed)
}

/// Root for automatically discovered certificate targets.
pub const CERTIFICATE_ROOT: &str = "/var/lib/certkite-certificates";

#[derive(Debug, Clone)]
pub enum TargetConfig {
    Files {
        directory: PathBuf,
    },
    /// File publication readable by the locally authorized service group.
    SharedFiles {
        directory: PathBuf,
        service_group: u32,
    },
    Nginx {
        directory: PathBuf,
        nginx_binary: PathBuf,
        systemd_unit: String,
    },
    NginxSite {
        directory: PathBuf,
        nginx_binary: PathBuf,
        systemd_unit: String,
        config_file: PathBuf,
        domains: Vec<String>,
    },
    CaddySite {
        directory: PathBuf,
        caddy_binary: PathBuf,
        systemd_unit: String,
        config_file: PathBuf,
        domains: Vec<String>,
        service_group: u32,
    },
}

/// A local virtual host discovered from the active web-server configuration.
#[derive(Debug, Clone)]
pub struct DiscoveredTarget {
    pub id: String,
    pub kind: &'static str,
    pub domains: Vec<String>,
    pub config: TargetConfig,
}

/// Detect active supported web servers and their configured virtual hosts.
pub fn discover() -> Result<Vec<DiscoveredTarget>> {
    discovery::discover()
}

impl TargetConfig {
    pub fn directory(&self) -> &Path {
        match self {
            Self::Files { directory }
            | Self::SharedFiles { directory, .. }
            | Self::Nginx { directory, .. }
            | Self::NginxSite { directory, .. }
            | Self::CaddySite { directory, .. } => directory,
        }
    }
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Files { .. } | Self::SharedFiles { .. } => "files",
            Self::Nginx { .. } | Self::NginxSite { .. } => "nginx",
            Self::CaddySite { .. } => "caddy",
        }
    }
    pub fn domains(&self) -> &[String] {
        match self {
            Self::NginxSite { domains, .. } | Self::CaddySite { domains, .. } => domains,
            _ => &[],
        }
    }
    pub fn config_file(&self) -> Option<&Path> {
        match self {
            Self::NginxSite { config_file, .. } | Self::CaddySite { config_file, .. } => {
                Some(config_file)
            }
            _ => None,
        }
    }
    fn directory_mode(&self) -> u32 {
        if self.service_group().is_some() {
            0o750
        } else {
            0o700
        }
    }
    fn certificate_mode(&self) -> u32 {
        if self.service_group().is_some() {
            0o640
        } else {
            0o600
        }
    }
    fn service_group(&self) -> Option<u32> {
        match self {
            Self::CaddySite { service_group, .. } | Self::SharedFiles { service_group, .. } => {
                Some(*service_group)
            }
            _ => None,
        }
    }
    pub fn prepare(&self) -> Result<()> {
        ensure!(
            self.service_group() != Some(u32::MAX),
            "invalid certificate service group ID"
        );
        if matches!(self, Self::Files { .. } | Self::SharedFiles { .. }) {
            return prepare_file_target(self);
        }
        paths::directory_with(
            self.directory(),
            self.directory_mode(),
            self.service_group(),
        )
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.service_group() != Some(u32::MAX),
            "invalid certificate service group ID"
        );
        paths::root_with(
            self.directory(),
            self.directory_mode(),
            self.service_group(),
        )?;
        match self {
            Self::Nginx {
                nginx_binary,
                systemd_unit,
                ..
            }
            | Self::NginxSite {
                nginx_binary,
                systemd_unit,
                ..
            } => {
                command::binary(nginx_binary)?;
                validate_unit(systemd_unit)?;
            }
            Self::CaddySite {
                caddy_binary,
                systemd_unit,
                ..
            } => {
                command::binary(caddy_binary)?;
                validate_unit(systemd_unit)?;
            }
            Self::Files { .. } | Self::SharedFiles { .. } => {}
        }
        #[cfg(not(test))]
        if !matches!(self, Self::Files { .. } | Self::SharedFiles { .. }) {
            command::binary(Path::new("/usr/bin/systemctl"))?;
        }
        Ok(())
    }
}

/// Prepare a traversable certificate container without granting directory listing.
/// Existing private containers are upgraded after ownership and path validation.
pub fn prepare_certificate_root(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            paths::root_with(path, 0o700, None).or_else(|_| paths::root_with(path, 0o711, None))?;
            paths::set_access(path, 0o711, None)?;
            paths::sync(path)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            paths::directory_with(path, 0o711, None)
        }
        Err(error) => Err(error.into()),
    }
}

fn prepare_file_target(target: &TargetConfig) -> Result<()> {
    let root = target.directory();
    match fs::symlink_metadata(root) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => paths::directory(root)?,
        Err(error) => return Err(error.into()),
    }
    let validate_directory = |path: &Path| {
        paths::root_with(path, 0o700, None).or_else(|_| paths::root_with(path, 0o750, None))
    };
    validate_directory(root)?;
    let lock = paths::secure_file(&root.join(".lock"))?;
    lock.lock_exclusive()?;
    let mut directories = vec![root.to_owned()];
    let mut certificates = Vec::new();
    let versions = root.join("versions");
    match fs::symlink_metadata(&versions) {
        Ok(_) => {
            validate_directory(&versions)?;
            directories.push(versions.clone());
            for entry in fs::read_dir(&versions)? {
                let entry = entry?;
                let name = entry.file_name();
                let name = name.to_str().context("invalid version directory name")?;
                if !name.starts_with(".version-") {
                    version_path(&Path::new("versions").join(name))?;
                }
                let directory = entry.path();
                validate_directory(&directory)?;
                for name in ["fullchain.pem", "privkey.pem"] {
                    let path = directory.join(name);
                    paths::read_certificate(&path, 0o600, None)
                        .or_else(|_| paths::read_certificate(&path, 0o640, None))?;
                    if path.try_exists()? {
                        certificates.push(path);
                    }
                }
                directories.push(directory);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    // Reconcile every retained version so renewal and rollback keep the same readers.
    for path in certificates {
        paths::set_access(&path, target.certificate_mode(), target.service_group())?;
        paths::sync(&path)?;
    }
    for path in directories.into_iter().rev() {
        paths::set_access(&path, target.directory_mode(), target.service_group())?;
        paths::sync(&path)?;
    }
    target.validate()
}

fn validate_unit(systemd_unit: &str) -> Result<()> {
    ensure!(
        systemd_unit.ends_with(".service")
            && !systemd_unit.starts_with('-')
            && systemd_unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.@-".contains(&b))
            && systemd_unit.len() <= 255,
        "invalid systemd service unit"
    );
    Ok(())
}

fn target_root(target: &TargetConfig, path: &Path) -> Result<()> {
    paths::root_with(path, target.directory_mode(), target.service_group())
}

fn target_directory(target: &TargetConfig, path: &Path) -> Result<()> {
    paths::directory_with(path, target.directory_mode(), target.service_group())
}
pub struct Deployment<'a> {
    pub operation_id: &'a str,
    pub generation: u64,
    pub domain: &'a str,
    pub fullchain_pem: &'a str,
    pub private_key_pem: &'a str,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeploymentOutcome {
    pub changed: bool,
    pub generation: u64,
    pub fingerprint: String,
}
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    task_generation: Option<u64>,
    #[serde(
        rename = "generation",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    legacy_generation: Option<u64>,
    operations: BTreeMap<String, Operation>,
    pending: Option<Pending>,
    #[serde(default)]
    previous_version: Option<PathBuf>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Operation {
    digest: String,
    outcome: DeploymentOutcome,
    committed: bool,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    operation_id: String,
    previous: Option<PathBuf>,
    next: PathBuf,
}
struct Locks {
    _target: File,
    _nginx: Option<File>,
}
fn locks(target: &TargetConfig) -> Result<Locks> {
    target.validate()?;
    let file = paths::secure_file(&target.directory().join(".lock"))?;
    file.lock_exclusive()?;
    let nginx = if matches!(
        target,
        TargetConfig::Nginx { .. } | TargetConfig::NginxSite { .. }
    ) {
        // One global lock deliberately serializes all nginx instances, including
        // different target roots and different binary spellings of an instance.
        #[cfg(all(target_os = "linux", not(test)))]
        let dir = PathBuf::from("/run/certkite-client");
        #[cfg(any(not(target_os = "linux"), test))]
        let dir = std::env::temp_dir()
            .canonicalize()?
            .join(format!("certkite-deploy-{}", paths::uid()));
        paths::directory(&dir)?;
        let f = paths::secure_file(&dir.join("nginx.lock"))?;
        f.lock_exclusive()?;
        Some(f)
    } else {
        None
    };
    Ok(Locks {
        _target: file,
        _nginx: nginx,
    })
}
fn state(target: &TargetConfig) -> Result<State> {
    paths::read(&target.directory().join("state.json"))?
        .map(|b| serde_json::from_slice(&b).context("invalid deployment journal"))
        .unwrap_or_else(|| Ok(State::default()))
}
fn save(target: &TargetConfig, state: &State) -> Result<()> {
    paths::atomic(
        &target.directory().join("state.json"),
        &serde_json::to_vec(state)?,
    )
}
fn version_path(path: &Path) -> Result<()> {
    let s = path.to_str().context("non-UTF8 version")?;
    ensure!(
        s.len() == 73
            && s.starts_with("versions/")
            && s[9..]
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "invalid version link"
    );
    Ok(())
}
fn current(target: &TargetConfig) -> Result<Option<PathBuf>> {
    let path = target.directory().join("current");
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
        Ok(m) => {
            ensure!(
                m.file_type().is_symlink() && m.uid() == paths::uid(),
                "current must be runtime-owned symlink"
            );
            let link = fs::read_link(path)?;
            version_path(&link)?;
            target_root(target, &target.directory().join(&link))?;
            Ok(Some(link))
        }
    }
}
use std::os::unix::fs::MetadataExt;
fn switch(target: &TargetConfig, link: Option<&Path>) -> Result<()> {
    if let Some(link) = link {
        version_path(link)?;
        target_root(target, &target.directory().join(link))?;
        let temp = tempfile::Builder::new()
            .prefix(".switch-")
            .tempdir_in(target.directory())?;
        let name = temp.path().join("link");
        symlink(link, &name)?;
        fs::rename(name, target.directory().join("current"))?;
    } else {
        match fs::remove_file(target.directory().join("current")) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    paths::sync(target.directory())
}
fn recover_locked(target: &TargetConfig, state: &mut State) -> Result<()> {
    if let Some(pending) = &state.pending {
        version_path(&pending.next)?;
        ensure!(
            state.operations.contains_key(&pending.operation_id),
            "pending operation missing metadata"
        );
        if let Some(previous) = &pending.previous {
            version_path(previous)?;
        }
        switch(target, pending.previous.as_deref()).context("restore previous publication")?;
        command::restore_config(target).context("restore web-server configuration")?;
        // Test even an initial rollback: a broken service configuration remains journaled.
        command::test(target).context("validate rolled-back service configuration")?;
        command::reload(target).context("reload rolled-back service configuration")?;
        state.pending = None;
        save(target, state)?;
    } else {
        command::discard_config_backup(target)?;
    }
    Ok(())
}
pub fn recover(target: &TargetConfig) -> Result<()> {
    (|| {
        let _locks = locks(target)?;
        let mut state = state(target)?;
        recover_locked(target, &mut state)
    })()
    .context(Failure::RecoveryFailed)
}
pub fn check(target: &TargetConfig) -> Result<()> {
    let _locks = locks(target)?;
    // Actually prove the runtime user can create and sync a private file.
    let probe = tempfile::NamedTempFile::new_in(target.directory())?;
    probe.as_file().sync_all()?;
    let _ = state(target)?;
    let _ = current(target)?;
    command::test(target)
}
fn hash(parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    for part in parts {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    hex::encode(h.finalize())
}
impl State {
    fn migrate_core_receipts(&mut self) {
        if self.legacy_generation.take().is_none() {
            return;
        }
        // Earlier journals stored Core receipts under a prefix and tracked other
        // receipts in a separate generation sequence. Recover pending work first.
        const LEGACY_CORE_PREFIX: &str = "\u{1}core-v2:";
        for (id, operation) in std::mem::take(&mut self.operations) {
            if let Some(id) = id.strip_prefix(LEGACY_CORE_PREFIX) {
                let generation = self.task_generation.unwrap_or_default();
                self.task_generation = Some(generation.max(operation.outcome.generation));
                self.operations.insert(id.to_owned(), operation);
            }
        }
    }
}

pub fn deploy(target: &TargetConfig, request: &Deployment<'_>) -> Result<DeploymentOutcome> {
    ensure!(
        !request.operation_id.is_empty()
            && request.operation_id.len() <= 256
            && !request.operation_id.chars().any(char::is_control),
        "invalid operation ID"
    );
    ensure!(request.generation > 0, "generation must be positive");
    let fingerprint = hash(&[
        request.fullchain_pem.as_bytes(),
        request.private_key_pem.as_bytes(),
    ]);
    let digest = hash(&[
        request.domain.as_bytes(),
        fingerprint.as_bytes(),
        &request.generation.to_be_bytes(),
    ]);
    let _locks = locks(target)?;
    let mut state = state(target).context(Failure::RecoveryFailed)?;
    recover_locked(target, &mut state).context(Failure::RecoveryFailed)?;
    state.migrate_core_receipts();
    let last_generation = state.task_generation.unwrap_or_default();
    if let Some(op) = state.operations.get(request.operation_id) {
        ensure!(op.digest == digest, Failure::Conflict);
        if op.committed {
            let outcome = op.outcome.clone();
            prune_versions(target, state.previous_version.as_deref())?;
            return Ok(outcome);
        }
        ensure!(
            request.generation == last_generation,
            Failure::StaleOperation
        );
    } else {
        ensure!(
            request.generation > last_generation,
            Failure::StaleOperation
        );
    }
    let mut domains = vec![request.domain];
    domains.extend(
        target
            .domains()
            .iter()
            .map(String::as_str)
            .filter(|domain| *domain != request.domain),
    );
    certificate::validate_all(&domains, request.fullchain_pem, request.private_key_pem)
        .context(Failure::CertificateInvalid)?;
    let previous = current(target)?;
    let next = PathBuf::from(format!("versions/{fingerprint}"));
    let changed = previous.as_ref() != Some(&next);
    let outcome = DeploymentOutcome {
        changed,
        generation: request.generation,
        fingerprint,
    };
    publish_version(target, &next, request)?;
    state.task_generation = Some(request.generation);
    state.operations.insert(
        request.operation_id.to_owned(),
        Operation {
            digest,
            outcome: outcome.clone(),
            committed: false,
        },
    );
    // Retransmissions outside this bounded window are rejected by the durable
    // generation fence; retained operations return their original outcome.
    if state.operations.len() > 256 {
        let oldest = state
            .operations
            .iter()
            .min_by_key(|(_, op)| op.outcome.generation)
            .map(|(id, _)| id.clone())
            .context("missing oldest operation")?;
        state.operations.remove(&oldest);
    }
    state.pending = Some(Pending {
        operation_id: request.operation_id.to_owned(),
        previous: previous.clone(),
        next: next.clone(),
    });
    save(target, &state)?;
    let applied = (|| -> Result<()> {
        switch(target, Some(&next))?;
        let configured = command::configure(target)?;
        if changed || configured {
            command::test(target)?;
            command::reload(target)?;
        }
        Ok(())
    })();
    if let Err(error) = applied {
        return match recover_locked(target, &mut state) {
            Ok(()) => Err(error.context("deployment failed; publication rolled back")),
            Err(rollback) => Err(anyhow::anyhow!(
                "deployment failed: {error:#}; rollback failed (journal retained): {rollback:#}"
            )
            .context(Failure::RecoveryFailed)),
        };
    }
    state
        .operations
        .get_mut(request.operation_id)
        .unwrap()
        .committed = true;
    state.pending = None;
    if changed {
        state.previous_version = previous;
    }
    // If saving the commit fails, the durable pending journal intentionally makes
    // the next recovery roll back; no success is reported before this fsync.
    save(target, &state)?;
    command::discard_config_backup(target)?;
    prune_versions(target, state.previous_version.as_deref())?;
    Ok(outcome)
}

fn prune_versions(target: &TargetConfig, previous: Option<&Path>) -> Result<()> {
    let versions = target.directory().join("versions");
    match fs::symlink_metadata(&versions) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(_) => target_root(target, &versions)?,
    }
    let active = current(target)?;
    if let Some(previous) = previous {
        version_path(previous)?;
    }
    let mut removed = false;
    for entry in fs::read_dir(&versions)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name_text) = name.to_str() else {
            continue;
        };
        if name_text.starts_with(".version-") {
            target_root(target, &entry.path())?;
            fs::remove_dir_all(entry.path())?;
            removed = true;
            continue;
        }
        if name_text.len() != 64
            || !name_text
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            continue;
        }
        target_root(target, &entry.path())?;
        let relative = Path::new("versions").join(&name);
        if active.as_deref() != Some(relative.as_path()) && previous != Some(relative.as_path()) {
            fs::remove_dir_all(entry.path())?;
            removed = true;
        }
    }
    if removed {
        paths::sync(&versions)?;
    }
    Ok(())
}

fn publish_version(target: &TargetConfig, next: &Path, request: &Deployment<'_>) -> Result<()> {
    let versions = target.directory().join("versions");
    target_directory(target, &versions)?;
    let destination = target.directory().join(next);
    match fs::symlink_metadata(&destination) {
        Ok(_) => {
            target_root(target, &destination)?;
            ensure!(
                paths::read_certificate(
                    &destination.join("fullchain.pem"),
                    target.certificate_mode(),
                    target.service_group(),
                )?
                .as_deref()
                    == Some(request.fullchain_pem.as_bytes())
                    && paths::read_certificate(
                        &destination.join("privkey.pem"),
                        target.certificate_mode(),
                        target.service_group(),
                    )?
                    .as_deref()
                        == Some(request.private_key_pem.as_bytes()),
                "version content differs from hash"
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let temp = tempfile::Builder::new()
                .prefix(".version-")
                .tempdir_in(&versions)?;
            paths::set_access(temp.path(), target.directory_mode(), target.service_group())?;
            paths::atomic_certificate(
                &temp.path().join("fullchain.pem"),
                request.fullchain_pem.as_bytes(),
                target.certificate_mode(),
                target.service_group(),
            )?;
            paths::atomic_certificate(
                &temp.path().join("privkey.pem"),
                request.private_key_pem.as_bytes(),
                target.certificate_mode(),
                target.service_group(),
            )?;
            paths::sync(temp.path())?;
            fs::rename(temp.path(), &destination)?;
            paths::sync(&versions)?;
        }
        Err(e) => bail!(e),
    }
    Ok(())
}
#[cfg(test)]
mod tests;

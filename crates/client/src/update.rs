//! Signed releases for user installations and existing system services.
use crate::{config, state};
use anyhow::{Context, Result, bail, ensure};
use ed25519_dalek::{Signature, VerifyingKey};
use fs2::FileExt;
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const STATE: &str = config::SYSTEM_STATE;
const BINARY: &str = config::SYSTEM_BINARY;
const SERVICE: &str = "certkite.service";
const ORIGIN: &str = "https://certkite.com";
const MAX_BINARY: u64 = 256 * 1024 * 1024;
const MAX_ENVELOPE: usize = 64 * 1024;
const PENDING: &str = "update-pending";
const RETAINED_COMPLETED_JOBS: usize = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: String,
    pub platform: String,
    pub url: String,
    pub size: u64,
    pub sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    manifest: String,
    signature: String,
}
#[derive(Debug, Serialize)]
pub struct UpdateCheck {
    pub current_version: String,
    pub available: bool,
    pub manifest: Manifest,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateJob {
    pub id: String,
    pub path: PathBuf,
    pub status: String,
    pub error: Option<String>,
    manifest: Manifest,
    config: PathBuf,
    previous_version: String,
    phase: String,
}

fn platform() -> Result<String> {
    ensure!(
        std::env::consts::OS == "linux",
        "self-update requires Linux"
    );
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        a => bail!("unsupported update architecture: {a}"),
    };
    Ok(format!("{arch}-unknown-linux-gnu"))
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(180))
        .build()?)
}
fn release_url(to: Option<&str>) -> Result<String> {
    let suffix = match to {
        Some(v) => {
            let parsed = Version::parse(v).context("invalid requested semantic version")?;
            ensure!(
                parsed.to_string() == v,
                "requested version must be canonical"
            );
            v
        }
        None => "latest",
    };
    Ok(format!("{ORIGIN}/client/v1/releases/{suffix}"))
}
fn validate_manifest(
    m: &Manifest,
    current: &str,
    to: Option<&str>,
    expected_platform: &str,
) -> Result<()> {
    let version = Version::parse(&m.version).context("invalid release version")?;
    let current = Version::parse(current)?;
    ensure!(
        version >= current,
        "refusing downgrade from {current} to {version}"
    );
    ensure!(
        to.is_some() || version.pre.is_empty(),
        "latest must be a stable release"
    );
    if let Some(to) = to {
        ensure!(m.version == to, "release version does not match request");
    }
    ensure!(m.platform == expected_platform, "release platform mismatch");
    ensure!(m.size > 0 && m.size <= MAX_BINARY, "invalid artifact size");
    ensure!(
        hex::decode(&m.sha256)?.len() == 32,
        "invalid SHA-256 digest"
    );
    let u = reqwest::Url::parse(&m.url)?;
    ensure!(
        u.scheme() == "https"
            && u.host_str() == Some("certkite.com")
            && u.port_or_known_default() == Some(443)
            && u.username().is_empty()
            && u.password().is_none()
            && u.fragment().is_none(),
        "artifact must use https://certkite.com origin without credentials or fragment"
    );
    Ok(())
}
fn verify_envelope(bytes: &[u8], key: &[u8; 32]) -> Result<Manifest> {
    let envelope: Envelope =
        serde_json::from_slice(bytes).context("invalid signed release envelope")?;
    let signature =
        Signature::from_slice(&hex::decode(envelope.signature).context("invalid signature hex")?)?;
    VerifyingKey::from_bytes(key)?
        .verify_strict(envelope.manifest.as_bytes(), &signature)
        .context("release signature verification failed")?;
    serde_json::from_str(&envelope.manifest).context("invalid signed manifest")
}
fn public_key() -> Result<[u8; 32]> {
    let encoded = option_env!("CERTKITE_RELEASE_PUBLIC_KEY_HEX").context("updates disabled: rebuild with CERTKITE_RELEASE_PUBLIC_KEY_HEX set to your trusted 32-byte Ed25519 public key")?;
    hex::decode(encoded)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("CERTKITE_RELEASE_PUBLIC_KEY_HEX must encode 32 bytes"))
}
async fn bounded_response(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    ensure!(
        response.status().is_success(),
        "release HTTP error: {}",
        response.status()
    );
    if let Some(length) = response.content_length() {
        ensure!(length <= limit as u64, "HTTP response exceeds size limit");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            chunk.len() <= limit.saturating_sub(bytes.len()),
            "HTTP response exceeds size limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
pub async fn check(to: Option<&str>) -> Result<UpdateCheck> {
    let platform = platform()?;
    let key = public_key()?;
    let bytes = bounded_response(
        client()?
            .get(release_url(to)?)
            .header("X-Certkite-Platform", &platform)
            .send()
            .await?,
        MAX_ENVELOPE,
    )
    .await?;
    let manifest = verify_envelope(&bytes, &key)?;
    validate_manifest(&manifest, env!("CARGO_PKG_VERSION"), to, &platform)?;
    Ok(UpdateCheck {
        current_version: env!("CARGO_PKG_VERSION").into(),
        available: Version::parse(&manifest.version)? > Version::parse(env!("CARGO_PKG_VERSION"))?,
        manifest,
    })
}

/// Verify and atomically replace the binary installed in the user's local bin directory.
pub async fn install_user(to: Option<&str>) -> Result<UpdateCheck> {
    platform()?;
    let binary = config::user_binary()?;
    let parent = binary.parent().context("missing user binary directory")?;
    let uid = config::effective_uid();
    for ancestor in parent.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)
            .with_context(|| format!("inspect {}", ancestor.display()))?;
        ensure!(
            metadata.is_dir()
                && (metadata.uid() == 0 || metadata.uid() == uid)
                && (metadata.mode() & 0o022 == 0
                    || (ancestor != parent && metadata.mode() & 0o1000 != 0)),
            "untrusted installation directory: {}",
            ancestor.display()
        );
    }
    ensure!(
        fs::metadata(parent)?.uid() == uid,
        "user binary directory must belong to the running user"
    );
    let _lock = state::lock_file(&parent.join(".certkite-update.lock"), true)
        .context("cannot acquire the CertKite installation lock")?;
    // The procfs link identifies the executing inode even after an atomic replacement.
    let running = fs::metadata("/proc/self/exe")?;
    require_installed_binary(&binary, &running)?;
    let update = check(to).await?;
    if update.available {
        let bytes = download(&update.manifest).await?;
        let temporary = stage_bytes(&binary, &bytes, true)?;
        validate_executable(&temporary, &update.manifest.version)?;
        require_installed_binary(&binary, &running)?;
        temporary.persist(&binary).map_err(|error| error.error)?;
        sync_dir(parent)?;
    }
    Ok(update)
}

fn require_installed_binary(binary: &Path, running: &fs::Metadata) -> Result<()> {
    let installed = fs::symlink_metadata(binary)?;
    ensure!(
        installed.is_file()
            && installed.uid() == config::effective_uid()
            && installed.mode() & 0o022 == 0,
        "unsafe user binary ownership or permissions"
    );
    ensure!(
        (installed.dev(), installed.ino()) == (running.dev(), running.ino()),
        "run the currently installed executable at {} to update it",
        binary.display()
    );
    Ok(())
}

async fn download(manifest: &Manifest) -> Result<Vec<u8>> {
    let bytes = bounded_response(
        client()?.get(&manifest.url).send().await?,
        manifest.size as usize,
    )
    .await?;
    verify_artifact(&bytes, manifest)?;
    Ok(bytes)
}

#[cfg(unix)]
fn trusted(path: &Path, directory: bool) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    ensure!(path.is_absolute(), "trusted path must be absolute");
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)
            .with_context(|| format!("inspect {}", ancestor.display()))?;
        ensure!(
            !metadata.file_type().is_symlink()
                && metadata.uid() == 0
                && metadata.mode() & 0o022 == 0,
            "unsafe path ownership, permissions or symlink: {}",
            ancestor.display()
        );
    }
    let metadata = fs::metadata(path)?;
    ensure!(
        if directory {
            metadata.is_dir()
        } else {
            metadata.is_file()
        },
        "unexpected path type: {}",
        path.display()
    );
    Ok(())
}
#[cfg(not(unix))]
fn trusted(_: &Path, _: bool) -> Result<()> {
    bail!("updates require Unix")
}
fn root() -> Result<()> {
    platform()?;
    let out = command(
        Command::new("/usr/bin/id").arg("-u"),
        Duration::from_secs(5),
    )?;
    ensure!(
        String::from_utf8(out.stdout)?.trim() == "0",
        "update requires root"
    );
    Ok(())
}
fn state_dir() -> Result<PathBuf> {
    root()?;
    let path = PathBuf::from(STATE);
    if !path.exists() {
        fs::DirBuilder::new().mode(0o700).create(&path)?;
    }
    trusted(&path, true)?;
    ensure!(
        fs::metadata(&path)?.permissions().mode() & 0o077 == 0,
        "state directory must have mode 0700 or stricter"
    );
    Ok(path)
}
fn lock(path: &Path, blocking: bool) -> Result<File> {
    if path.exists() {
        trusted(path, false)?;
    }
    let f = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    trusted(path, false)?;
    ensure!(
        f.metadata()?.permissions().mode() & 0o077 == 0,
        "lock file must have mode 0600 or stricter"
    );
    if blocking {
        let deadline = Instant::now() + Duration::from_secs(360);
        loop {
            match f.try_lock_exclusive() {
                Ok(()) => break,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(100))
                }
                Err(e) => return Err(e).context("timed out or failed acquiring operation lock"),
            }
        }
    } else {
        f.try_lock_exclusive().context("another update is active")?;
    }
    Ok(f)
}
fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}
fn stage_bytes(path: &Path, bytes: &[u8], executable: bool) -> Result<tempfile::TempPath> {
    let parent = path.parent().context("missing parent")?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(if executable {
                0o755
            } else {
                0o600
            }))?;
    }
    temporary.as_file().sync_all()?;
    // Linux cannot execute a file while a writable descriptor to it is open.
    Ok(temporary.into_temp_path())
}

fn atomic_bytes(path: &Path, bytes: &[u8], executable: bool) -> Result<()> {
    stage_bytes(path, bytes, executable)?
        .persist(path)
        .map_err(|error| error.error)?;
    sync_dir(path.parent().context("missing parent")?)
}
fn save(job: &UpdateJob) -> Result<()> {
    atomic_bytes(&job.path, &serde_json::to_vec_pretty(job)?, false)
}
fn cleanup_completed_jobs(state: &Path, retain: usize) -> Result<()> {
    let mut completed = Vec::new();
    for entry in fs::read_dir(state)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let Some(id) = name.to_str().and_then(|name| name.strip_prefix("update-")) else {
            continue;
        };
        if uuid::Uuid::parse_str(id).is_err() {
            continue;
        }
        let job_path = entry.path().join("job.json");
        let metadata = match fs::symlink_metadata(&job_path) {
            Ok(metadata)
                if metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && metadata.len() <= MAX_ENVELOPE as u64 =>
            {
                metadata
            }
            _ => continue,
        };
        let job: UpdateJob = match serde_json::from_slice(&fs::read(&job_path)?) {
            Ok(job) => job,
            Err(_) => continue,
        };
        if job.path != job_path
            || job.id != id
            || !matches!(job.status.as_str(), "succeeded" | "failed" | "interrupted")
        {
            continue;
        }
        completed.push((metadata.modified().unwrap_or(UNIX_EPOCH), entry.path()));
    }
    completed.sort_by(|a, b| b.cmp(a));
    let remove = completed.len().saturating_sub(retain);
    for (_, path) in completed.into_iter().rev().take(remove) {
        fs::remove_dir_all(path)?;
    }
    if remove > 0 {
        sync_dir(state)?;
    }
    Ok(())
}
fn command(cmd: &mut Command, timeout: Duration) -> Result<Output> {
    // Commands have bounded output (systemctl properties, id); file-backed output avoids pipe deadlock.
    let stdout = tempfile::tempfile()?;
    let stderr = tempfile::tempfile()?;
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(stdout.try_clone()?)
        .stderr(stderr.try_clone()?)
        .spawn()
        .context("launch system command")?;
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() > timeout {
            child.kill()?;
            child.wait()?;
            bail!("system command timed out after {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    use std::io::{Seek, SeekFrom};
    let mut stdout = stdout;
    let mut stderr = stderr;
    stdout.seek(SeekFrom::Start(0))?;
    stderr.seek(SeekFrom::Start(0))?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    stdout.take(65536).read_to_end(&mut out)?;
    stderr.take(65536).read_to_end(&mut err)?;
    ensure!(
        status.success(),
        "system command failed ({status}): {}",
        String::from_utf8_lossy(&err)
    );
    Ok(Output {
        status,
        stdout: out,
        stderr: err,
    })
}
fn systemctl(action: &str) -> Result<()> {
    command(
        Command::new("/usr/bin/systemctl").args([action, SERVICE]),
        Duration::from_secs(360),
    )?;
    Ok(())
}

pub async fn launch(to: Option<&str>, config: &Path) -> Result<UpdateJob> {
    let state = state_dir()?;
    let _guard = lock(&state.join("update.lock"), false)?;
    ensure!(
        !state.join(PENDING).exists(),
        "unfinished update exists; inspect update-pending and recover before retrying"
    );
    cleanup_completed_jobs(&state, RETAINED_COMPLETED_JOBS)?;
    let config = fs::canonicalize(config)?;
    trusted(&config, false)?;
    trusted(Path::new(BINARY), false)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let current = fs::metadata(std::env::current_exe()?)?;
        let installed = fs::metadata(BINARY)?;
        ensure!(
            current.dev() == installed.dev() && current.ino() == installed.ino(),
            "launch updates using the installed /usr/local/bin/certkite executable"
        );
    }
    let checked = check(to).await?;
    ensure!(checked.available, "requested release is already installed");
    let id = uuid::Uuid::new_v4().to_string();
    let dir = state.join(format!("update-{id}"));
    fs::create_dir(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    let bytes = download(&checked.manifest).await?;
    atomic_bytes(&dir.join("candidate"), &bytes, true)?;
    atomic_bytes(&dir.join("worker"), &fs::read(BINARY)?, true)?;
    let mut job = UpdateJob {
        id,
        path: dir.join("job.json"),
        status: "queued".into(),
        error: None,
        manifest: checked.manifest,
        config,
        previous_version: env!("CARGO_PKG_VERSION").into(),
        phase: "staged".into(),
    };
    save(&job)?;
    atomic_bytes(
        &state.join(PENDING),
        job.path.to_str().context("non-UTF8 job path")?.as_bytes(),
        false,
    )?;
    let result = command(
        Command::new("/usr/bin/systemd-run")
            .args([
                "--quiet",
                "--collect",
                "--service-type=oneshot",
                "--no-block",
                "--property=TimeoutStartSec=2400",
                "--unit",
            ])
            .arg(format!("certkite-update-{}", job.id))
            .arg(dir.join("worker"))
            .arg("--config")
            .arg(&job.config)
            .args(["__update-worker", "--job"])
            .arg(&job.path),
        Duration::from_secs(20),
    );
    if let Err(error) = result {
        job.status = "failed".into();
        job.error = Some(format!(
            "launch worker failed: {error:#}; inspect transient unit before recovery"
        ));
        save(&job)?;
        return Err(error);
    }
    Ok(job)
}
fn verify_artifact(bytes: &[u8], manifest: &Manifest) -> Result<()> {
    ensure!(
        bytes.len() as u64 == manifest.size,
        "artifact size mismatch"
    );
    ensure!(
        hex::encode(Sha256::digest(bytes)).eq_ignore_ascii_case(&manifest.sha256),
        "artifact SHA-256 mismatch"
    );
    ensure!(
        bytes.starts_with(b"\x7fELF"),
        "artifact must be a raw ELF binary"
    );
    Ok(())
}
fn validate_executable(path: &Path, version: &str) -> Result<()> {
    let mut header = [0u8; 20];
    File::open(path)?.read_exact(&mut header)?;
    ensure!(
        &header[..4] == b"\x7fELF" && header[4] == 2 && header[5] == 1,
        "expected a 64-bit little-endian ELF executable"
    );
    let expected_machine = match std::env::consts::ARCH {
        "x86_64" => 62,
        "aarch64" => 183,
        _ => bail!("unsupported architecture"),
    };
    ensure!(
        u16::from_le_bytes([header[18], header[19]]) == expected_machine,
        "ELF machine does not match host"
    );
    let output = command(Command::new(path).arg("--version"), Duration::from_secs(10))?;
    let output = String::from_utf8(output.stdout)?;
    ensure!(
        output.split_whitespace().collect::<Vec<_>>() == ["certkite", version],
        "candidate --version does not match signed manifest"
    );
    Ok(())
}

fn load_job(path: &Path) -> Result<UpdateJob> {
    trusted(path, false)?;
    let dir = path.parent().context("missing job directory")?;
    let name = dir
        .file_name()
        .and_then(|s| s.to_str())
        .context("invalid job directory")?;
    ensure!(
        dir.parent() == Some(Path::new(STATE))
            && name.starts_with("update-")
            && path.file_name() == Some(std::ffi::OsStr::new("job.json")),
        "invalid update job path"
    );
    let id = uuid::Uuid::parse_str(&name[7..])?;
    let metadata = fs::metadata(path)?;
    ensure!(metadata.len() <= MAX_ENVELOPE as u64, "job file too large");
    let job: UpdateJob = serde_json::from_slice(&fs::read(path)?)?;
    ensure!(
        job.path == path && job.id == id.to_string(),
        "job identity mismatch"
    );
    validate_manifest(
        &job.manifest,
        &job.previous_version,
        Some(&job.manifest.version),
        &platform()?,
    )?;
    Ok(job)
}
fn pending_job(state: &Path) -> Result<PathBuf> {
    trusted(&state.join(PENDING), false)?;
    ensure!(
        fs::metadata(state.join(PENDING))?.len() < 4096,
        "pending marker too large"
    );
    Ok(PathBuf::from(String::from_utf8(fs::read(
        state.join(PENDING),
    )?)?))
}
fn clear_pending(state: &Path) -> Result<()> {
    fs::remove_file(state.join(PENDING))?;
    sync_dir(state)
}
fn replace(source: &Path, destination: &Path) -> Result<()> {
    trusted(source, false)?;
    atomic_bytes(destination, &fs::read(source)?, true)
}
fn verify_started(version: &str, since: u64) -> Result<()> {
    #[derive(Deserialize)]
    struct Startup {
        pid: u32,
        version: String,
        build_id: String,
        started_at: u64,
        ready: bool,
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut last = String::new();
    let mut stable: Option<(u32, Instant)> = None;
    while Instant::now() < deadline {
        let result = (|| -> Result<u32> {
            let out = command(
                Command::new("/usr/bin/systemctl").args([
                    "show",
                    SERVICE,
                    "--property=MainPID,ActiveState,SubState,Type",
                ]),
                Duration::from_secs(5),
            )?;
            let properties = String::from_utf8(out.stdout)?;
            let value = |key: &str| {
                properties
                    .lines()
                    .find_map(|l| l.strip_prefix(&format!("{key}=")))
                    .unwrap_or("")
            };
            ensure!(
                value("Type") == "notify"
                    && value("ActiveState") == "active"
                    && value("SubState") == "running",
                "service has not reached notify readiness"
            );
            let pid: u32 = value("MainPID").parse()?;
            ensure!(pid > 1, "invalid MainPID");
            trusted(&Path::new(STATE).join("startup.json"), false)?;
            let startup: Startup =
                serde_json::from_slice(&fs::read(Path::new(STATE).join("startup.json"))?)?;
            ensure!(
                startup.pid == pid
                    && startup.version == version
                    && !startup.build_id.is_empty()
                    && startup.started_at >= since
                    && startup.ready,
                "startup record does not match new process"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let running = fs::metadata(format!("/proc/{pid}/exe"))?;
                let installed = fs::metadata(BINARY)?;
                ensure!(
                    running.ino() == installed.ino() && running.dev() == installed.dev(),
                    "MainPID is not running installed binary"
                );
            }
            Ok(pid)
        })();
        match result {
            Ok(pid) => match stable {
                Some((previous, since))
                    if previous == pid && since.elapsed() >= Duration::from_secs(3) =>
                {
                    return Ok(());
                }
                Some((previous, _)) if previous == pid => {}
                _ => stable = Some((pid, Instant::now())),
            },
            Err(e) => {
                last = format!("{e:#}");
                stable = None;
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    bail!("service startup verification timed out: {last}")
}

trait ServiceControl {
    fn stop(&self) -> Result<()>;
    fn start_and_verify(&self, version: &str, since: u64) -> Result<()>;
}
struct Systemd;
impl ServiceControl for Systemd {
    fn stop(&self) -> Result<()> {
        systemctl("stop")
    }
    fn start_and_verify(&self, version: &str, since: u64) -> Result<()> {
        systemctl("reset-failed")?;
        systemctl("start")?;
        verify_started(version, since)
    }
}
// Sources are authenticated and path-checked by the caller. Both activation and
// rollback use this exact sequence; tests supply a service that never touches systemd.
fn activate(
    source: &Path,
    destination: &Path,
    version: &str,
    service: &impl ServiceControl,
) -> Result<()> {
    service.stop()?;
    atomic_bytes(destination, &fs::read(source)?, true)?;
    service.start_and_verify(version, now()?)
}

pub fn worker(path: &Path) -> Result<()> {
    let state = state_dir()?;
    let _update = lock(&state.join("update.lock"), true)?;
    ensure!(
        pending_job(&state)? == path,
        "worker does not match pending update"
    );
    let mut job = load_job(path)?;
    ensure!(
        job.phase == "staged",
        "job is not staged; boot recovery required"
    );
    let dir = path.parent().unwrap();
    let _deploy = match lock(&state.join("deployment.lock"), true) {
        Ok(guard) => guard,
        Err(error) => {
            job.status = "failed".into();
            job.phase = "rolled-back".into();
            job.error = Some(format!("could not drain deployment operations: {error:#}"));
            save(&job)?;
            clear_pending(&state)?;
            return Err(error);
        }
    };
    job.status = "running".into();
    save(&job)?;
    let result = (|| -> Result<()> {
        trusted(&dir.join("candidate"), false)?;
        verify_artifact(&fs::read(dir.join("candidate"))?, &job.manifest)?;
        validate_executable(&dir.join("candidate"), &job.manifest.version)?;
        // Backup is durable before the journal permits any replacement.
        replace(Path::new(BINARY), &dir.join("backup"))?;
        job.phase = "replacing".into();
        save(&job)?;
        activate(
            &dir.join("candidate"),
            Path::new(BINARY),
            &job.manifest.version,
            &Systemd,
        )?;
        job.phase = "committed".into();
        job.status = "succeeded".into();
        save(&job)?;
        Ok(())
    })();
    if let Err(error) = result {
        job.error = Some(format!("{error:#}"));
        if job.phase == "replacing" {
            // Keep the journal recoverable if any rollback step fails.
            let rollback = (|| -> Result<()> {
                trusted(&dir.join("backup"), false)?;
                activate(
                    &dir.join("backup"),
                    Path::new(BINARY),
                    &job.previous_version,
                    &Systemd,
                )
            })();
            if let Err(rollback) = rollback {
                job.status = "rollback-failed".into();
                job.error = Some(format!("{error:#}; rollback failed: {rollback:#}"));
                save(&job)?;
                bail!("{}", job.error.as_deref().unwrap());
            }
        }
        job.phase = "rolled-back".into();
        job.status = "failed".into();
        save(&job)?;
        clear_pending(&state)?;
        return Err(error);
    }
    if let Err(error) = clear_pending(&state) {
        job.status = "cleanup-failed".into();
        job.error = Some(format!(
            "new service started but update marker cleanup failed: {error:#}"
        ));
        save(&job)?;
        return Err(error);
    }
    Ok(())
}

/// Called during daemon startup. Never invokes systemctl against the starting service.
pub fn recover_pending() -> Result<()> {
    let state = state_dir()?;
    if !state.join(PENDING).exists() {
        return Ok(());
    }
    let guard = lock(&state.join("update.lock"), false);
    let _update = match guard {
        Ok(g) => g,
        Err(e) => {
            // Only lock contention means a live worker; other failures must surface.
            if e.chain().any(|cause| {
                cause
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::WouldBlock)
            }) {
                return Ok(());
            }
            return Err(e);
        }
    };
    let path = pending_job(&state)?;
    let mut job = load_job(&path)?;
    if job.phase == "replacing" {
        replace(&path.parent().unwrap().join("backup"), Path::new(BINARY))?;
        job.phase = "rolled-back".into();
        job.status = "interrupted".into();
        job.error = Some(
            "interrupted replacement restored; restart service to execute restored binary".into(),
        );
        save(&job)?;
        // Leave marker until the restored executable is actually running. The startup fails,
        // Restart=on-failure launches the restored executable without a recursive systemctl call.
        bail!("interrupted update restored previous binary; restart required");
    }
    if job.phase == "staged" {
        job.status = "interrupted".into();
        job.error = Some("worker interrupted before replacement".into());
        save(&job)?;
    }
    clear_pending(&state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn manifest() -> Manifest {
        Manifest {
            version: "2.0.0".into(),
            platform: "x86_64-unknown-linux-gnu".into(),
            url: "https://certkite.com/client/artifact".into(),
            size: 4,
            sha256: hex::encode(Sha256::digest(b"\x7fELF")),
        }
    }
    #[test]
    fn signature_exact_bytes() {
        let key = SigningKey::from_bytes(&[17; 32]);
        let raw = serde_json::to_string(&manifest()).unwrap();
        let signature = hex::encode(key.sign(raw.as_bytes()).to_bytes());
        let envelope = |raw: &str| {
            serde_json::to_vec(&serde_json::json!({"manifest":raw,"signature":signature})).unwrap()
        };
        assert!(verify_envelope(&envelope(&raw), &key.verifying_key().to_bytes()).is_ok());
        assert!(verify_envelope(&envelope(&(raw + " ")), &key.verifying_key().to_bytes()).is_err());
    }
    #[test]
    fn rejects_platform_downgrade_prerelease_and_origin() {
        let mut m = manifest();
        let p = m.platform.clone();
        assert!(validate_manifest(&m, "1.0.0", None, &p).is_ok());
        assert!(validate_manifest(&m, "3.0.0", None, &p).is_err());
        assert!(validate_manifest(&m, "1.0.0", None, "aarch64-unknown-linux-gnu").is_err());
        m.version = "2.0.0-rc.1".into();
        assert!(validate_manifest(&m, "1.0.0", None, &p).is_err());
        m = manifest();
        m.url = "https://evil.example/artifact".into();
        assert!(validate_manifest(&m, "1.0.0", None, &p).is_err());
    }
    #[test]
    fn verifies_digest_and_size() {
        let m = manifest();
        assert!(verify_artifact(b"\x7fELF", &m).is_ok());
        assert!(verify_artifact(b"evil", &m).is_err());
        assert!(verify_artifact(b"\x7fELFmore", &m).is_err());
    }
    #[test]
    fn refuses_to_update_from_an_executable_that_has_been_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("certkite");
        atomic_bytes(&binary, b"old", true).unwrap();
        let running = File::open(&binary).unwrap();
        require_installed_binary(&binary, &running.metadata().unwrap()).unwrap();
        atomic_bytes(&binary, b"new", true).unwrap();
        assert!(require_installed_binary(&binary, &running.metadata().unwrap()).is_err());
        assert_eq!(fs::read(binary).unwrap(), b"new");
    }

    #[test]
    fn staged_binary_can_be_executed_before_installing() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("certkite");
        let candidate = stage_bytes(&target, b"#!/bin/sh\nexit 0\n", true).unwrap();
        assert!(Command::new(&candidate).status().unwrap().success());
        assert!(!target.exists());
    }

    #[test]
    fn atomic_replacement_and_mock_rollback() {
        use std::cell::RefCell;
        struct MockService {
            events: RefCell<Vec<String>>,
            target: PathBuf,
        }
        impl ServiceControl for MockService {
            fn stop(&self) -> Result<()> {
                self.events.borrow_mut().push("stop".into());
                Ok(())
            }
            fn start_and_verify(&self, version: &str, _: u64) -> Result<()> {
                self.events.borrow_mut().push(format!("start:{version}"));
                if version == "2.0.0" {
                    ensure!(fs::read(&self.target)? == b"new", "wrong installed bytes");
                    bail!("mock startup failed");
                }
                ensure!(
                    fs::read(&self.target)? == b"old",
                    "rollback did not restore previous binary"
                );
                Ok(())
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("binary");
        let backup = dir.path().join("backup");
        let candidate = dir.path().join("candidate");
        atomic_bytes(&target, b"old", true).unwrap();
        atomic_bytes(&backup, b"old", true).unwrap();
        atomic_bytes(&candidate, b"new", true).unwrap();
        let old_reader = File::open(&target).unwrap();
        let service = MockService {
            events: RefCell::new(Vec::new()),
            target: target.clone(),
        };
        assert!(activate(&candidate, &target, "2.0.0", &service).is_err());
        activate(&backup, &target, "1.0.0", &service).unwrap();
        let mut original = String::new();
        (&old_reader).read_to_string(&mut original).unwrap();
        assert_eq!(original, "old");
        assert_eq!(fs::read(&target).unwrap(), b"old");
        assert_eq!(
            *service.events.borrow(),
            ["stop", "start:2.0.0", "stop", "start:1.0.0"]
        );
    }
    #[test]
    fn completed_update_jobs_are_bounded() {
        let state = tempfile::tempdir().unwrap();
        for value in 1..=3u128 {
            let id = uuid::Uuid::from_u128(value).to_string();
            let dir = state.path().join(format!("update-{id}"));
            fs::create_dir(&dir).unwrap();
            let job = UpdateJob {
                id,
                path: dir.join("job.json"),
                status: "succeeded".into(),
                error: None,
                manifest: manifest(),
                config: PathBuf::from("/etc/certkite-client/config.toml"),
                previous_version: "1.0.0".into(),
                phase: "committed".into(),
            };
            save(&job).unwrap();
        }
        let unrelated = state.path().join("update-not-a-job");
        fs::create_dir(&unrelated).unwrap();

        cleanup_completed_jobs(state.path(), 1).unwrap();

        let remaining = fs::read_dir(state.path())
            .unwrap()
            .filter(|entry| {
                let name = entry.as_ref().unwrap().file_name();
                let name = name.to_str().unwrap();
                name.starts_with("update-") && name != "update-not-a-job"
            })
            .count();
        assert_eq!(remaining, 1);
        assert!(unrelated.is_dir());
    }
    #[tokio::test]
    async fn does_not_follow_redirects() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut b = [0; 4096];
            let received = stream.read(&mut b).await.unwrap();
            assert!(
                received > 0,
                "client must send a request before redirecting"
            );
            stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/stolen\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
        });
        let response = client()
            .unwrap()
            .get(format!("http://{addr}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        assert!(bounded_response(response, 1024).await.is_err());
        task.await.unwrap();
    }
}

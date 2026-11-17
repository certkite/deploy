use anyhow::{Context, Result, bail, ensure};
use fs2::FileExt;
use serde_json::{Value, json};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const BINARY: &str = "/usr/local/bin/certkite";
const UNIT: &str = "/etc/systemd/system/certkite.service";
const STATE: &str = "/var/lib/certkite-client";
const NAME: &str = "certkite.service";
const DEFAULT_CONFIG: &str = r#"# Add the access key from CertKite. Active Nginx and Caddy sites are detected automatically.
accessKey = ""
"#;

fn run(program: &str, arguments: &[&str], timeout: Duration) -> Result<String> {
    let mut output = tempfile_file()?;
    let mut errors = tempfile_file()?;
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(output.try_clone()?)
        .stderr(errors.try_clone()?)
        .spawn()
        .with_context(|| format!("run {program}"))?;
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() > timeout {
            child.kill()?;
            child.wait()?;
            bail!("{program} timed out");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    output.seek(SeekFrom::Start(0))?;
    errors.seek(SeekFrom::Start(0))?;
    let mut stdout = String::new();
    let mut stderr = String::new();
    output.take(65536).read_to_string(&mut stdout)?;
    errors.take(65536).read_to_string(&mut stderr)?;
    ensure!(status.success(), "{program} failed ({status}): {stderr}");
    Ok(stdout)
}
// CLI has no tempfile dependency. Create a unique, immediately unlinked root-owned spool.
fn tempfile_file() -> Result<File> {
    let dir = Path::new(STATE);
    for counter in 0..100u32 {
        let p = dir.join(format!(".command-{}-{counter}", std::process::id()));
        let result = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&p);
        match result {
            Ok(file) => {
                fs::remove_file(p)?;
                return Ok(file);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    bail!("cannot allocate command output file")
}
fn supported() -> Result<()> {
    ensure!(
        std::env::consts::OS == "linux",
        "service management requires Linux with systemd"
    );
    Ok(())
}
fn root() -> Result<()> {
    supported()?;
    // Check root before creating privileged files or directories.
    let status = Command::new("/usr/bin/id").arg("-u").output()?;
    ensure!(
        status.status.success() && String::from_utf8(status.stdout)?.trim() == "0",
        "service management requires root"
    );
    Ok(())
}
fn write_config_template(path: &Path) -> Result<bool> {
    let mut file = match OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if let Err(error) = (|| -> Result<()> {
        file.write_all(DEFAULT_CONFIG.as_bytes())?;
        file.sync_all()?;
        Ok(())
    })() {
        drop(file);
        fs::remove_file(path).context("clean up incomplete default configuration")?;
        return Err(error);
    }
    File::open(path.parent().context("configuration path has no parent")?)?.sync_all()?;
    Ok(true)
}
pub fn create_default_config(path: &Path) -> Result<bool> {
    ensure!(
        path == Path::new(certkite_client::config::CONFIG_PATH),
        "automatic configuration creation only supports the default path"
    );
    match fs::symlink_metadata(path) {
        Ok(_) => return Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    root()?;
    let parent = path.parent().context("configuration path has no parent")?;
    if !parent.exists() {
        trusted(
            parent
                .parent()
                .context("configuration directory has no parent")?,
            true,
        )?;
        match fs::DirBuilder::new().mode(0o700).create(parent) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    trusted(parent, true)?;
    let created = write_config_template(path)?;
    trusted(path, false)?;
    Ok(created)
}
#[cfg(unix)]
fn trusted(path: &Path, directory: bool) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    ensure!(path.is_absolute(), "path must be absolute");
    for ancestor in path.ancestors() {
        let m = fs::symlink_metadata(ancestor)?;
        ensure!(
            !m.file_type().is_symlink() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "unsafe ownership, permissions or symlink: {}",
            ancestor.display()
        );
    }
    let m = fs::metadata(path)?;
    ensure!(
        if directory { m.is_dir() } else { m.is_file() },
        "unexpected path type: {}",
        path.display()
    );
    Ok(())
}
#[cfg(not(unix))]
fn trusted(_: &Path, _: bool) -> Result<()> {
    bail!("service management requires Unix")
}
fn prepare() -> Result<File> {
    root()?;
    if !Path::new(STATE).exists() {
        fs::DirBuilder::new().mode(0o700).create(STATE)?;
    }
    trusted(Path::new(STATE), true)?;
    ensure!(
        fs::metadata(STATE)?.permissions().mode() & 0o077 == 0,
        "state directory must have mode 0700 or stricter"
    );
    let path = Path::new(STATE).join("update.lock");
    if path.exists() {
        trusted(&path, false)?;
    }
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(&path)?;
    trusted(&path, false)?;
    ensure!(
        lock.metadata()?.permissions().mode() & 0o077 == 0,
        "lock file must have mode 0600 or stricter"
    );
    lock.try_lock_exclusive()
        .context("an update or service operation is active")?;
    ensure!(
        !Path::new(STATE).join("update-pending").exists(),
        "unfinished update exists; recover it before changing service installation"
    );
    Ok(lock)
}
fn quote(value: &str) -> Result<String> {
    ensure!(
        !value.chars().any(|c| c.is_control()),
        "control characters are not allowed in systemd paths"
    );
    Ok(format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
    ))
}
fn path_quote(path: &Path) -> Result<String> {
    quote(path.to_str().context("systemd paths must be UTF-8")?)
}
fn render(config: &Path, writable_paths: &[PathBuf]) -> Result<String> {
    ensure!(config.is_absolute(), "config path must be absolute");
    let config = path_quote(config)?.replace('$', "$$");
    let writable = writable_paths
        .iter()
        .map(|path| {
            ensure!(path.is_absolute(), "target path must be absolute");
            path_quote(path)
        })
        .collect::<Result<Vec<_>>>()?
        .join(" ");
    Ok(format!(
        "[Unit]\nDescription=CertKite certificate deployment client\nWants=network-online.target\nAfter=network-online.target\n\n[Service]\nType=notify\nNotifyAccess=main\nUser=root\nGroup=root\nExecStart={BINARY} --config {config} __daemon\nRestart=on-failure\nRestartSec=5s\nTimeoutStartSec=120s\nTimeoutStopSec=300s\nKillSignal=SIGTERM\nKillMode=mixed\nSendSIGKILL=no\nStateDirectory=certkite-client\nStateDirectoryMode=0700\nRuntimeDirectory=certkite-client\nRuntimeDirectoryMode=0700\nUMask=0077\nNoNewPrivileges=true\nPrivateTmp=true\nProtectHome=read-only\nProtectSystem=strict\nReadWritePaths=/var/lib/certkite-client /run/certkite-client {writable}\n\n[Install]\nWantedBy=multi-user.target\n"
    ))
}
fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().context("missing parent")?;
    trusted(parent, true)?;
    if path.exists() {
        trusted(path, false)?;
    }
    let staged = parent.join(format!(".certkite-install-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&staged)?;
    let result = (|| -> Result<()> {
        file.write_all(bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(mode))?;
        }
        file.sync_all()?;
        fs::rename(&staged, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() && staged.exists() {
        fs::remove_file(staged).context("clean up failed installation stage")?;
    }
    result
}
pub fn install(config: &Path) -> Result<()> {
    let _lock = prepare()?;
    let config = fs::canonicalize(config).context("resolve config file")?;
    trusted(&config, false)?;
    certkite_client::config::Config::load(&config)?;
    let discovered = certkite_deploy::discover()?;
    ensure!(
        !discovered.is_empty(),
        "no active Nginx or Caddy virtual hosts were detected"
    );
    let mut writable_paths = vec![PathBuf::from(certkite_deploy::CERTIFICATE_ROOT)];
    for target in &discovered {
        if let Some(parent) = target.config.config_file().and_then(Path::parent) {
            writable_paths.push(parent.to_owned());
        }
    }
    writable_paths.sort();
    writable_paths.dedup();
    for path in &writable_paths {
        trusted(path, true)?;
    }
    let unit = render(&config, &writable_paths)?;
    let executable = fs::canonicalize(std::env::current_exe()?)?;
    trusted(&executable, false)?;
    let installed = Path::new(BINARY);
    let installed_exists = match fs::symlink_metadata(installed) {
        Ok(_) => {
            trusted(installed, false)?;
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    // Replacing an installed service's binary belongs to the signed updater.
    if installed_exists && executable != installed {
        ensure!(
            fs::read(&executable)? == fs::read(installed)?,
            "different installed binary exists; use signed update or uninstall before reinstalling"
        );
    }
    if !installed_exists {
        atomic_write(installed, &fs::read(&executable)?, 0o755)?;
    }
    atomic_write(Path::new(UNIT), unit.as_bytes(), 0o644)?;
    run(
        "/usr/bin/systemctl",
        &["daemon-reload"],
        Duration::from_secs(30),
    )?;
    run(
        "/usr/bin/systemctl",
        &["enable", NAME],
        Duration::from_secs(30),
    )?;
    // Restart also starts an inactive unit and applies a newly rendered config.
    run(
        "/usr/bin/systemctl",
        &["restart", NAME],
        Duration::from_secs(360),
    )?;
    Ok(())
}
pub fn uninstall() -> Result<()> {
    let _lock = prepare()?;
    // Stop waits for the daemon to drain in-flight certificate publication.
    run(
        "/usr/bin/systemctl",
        &["disable", "--now", NAME],
        Duration::from_secs(360),
    )?;
    if Path::new(UNIT).exists() {
        trusted(Path::new(UNIT), false)?;
        fs::remove_file(UNIT)?;
        File::open("/etc/systemd/system")?.sync_all()?;
    }
    run(
        "/usr/bin/systemctl",
        &["daemon-reload"],
        Duration::from_secs(30),
    )?;
    // Preserve binary, credentials, journal and backups for explicit operator cleanup.
    Ok(())
}
pub fn state() -> Result<Value> {
    supported()?;
    trusted(Path::new(STATE), true)?;
    let output = run(
        "/usr/bin/systemctl",
        &[
            "show",
            NAME,
            "--property=LoadState,ActiveState,SubState,MainPID,UnitFileState,Type,Result",
        ],
        Duration::from_secs(15),
    )?;
    let mut properties = serde_json::Map::new();
    for line in output.lines() {
        if let Some((k, v)) = line.split_once('=') {
            properties.insert(k.into(), json!(v));
        }
    }
    Ok(
        json!({"service":NAME,"properties":properties,"update_pending":Path::new(STATE).join("update-pending").exists()}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unit_notifies_and_drains() {
        let unit = render(
            Path::new("/etc/certkite/client.toml"),
            &[PathBuf::from("/etc/nginx/certs")],
        )
        .unwrap();
        for value in [
            "Type=notify",
            "NotifyAccess=main",
            "SendSIGKILL=no",
            "KillSignal=SIGTERM",
            "ExecStart=/usr/local/bin/certkite --config \"/etc/certkite/client.toml\" __daemon",
            "ReadWritePaths=",
            "\"/etc/nginx/certs\"",
        ] {
            assert!(unit.contains(value));
        }
        assert!(!unit.contains("ReadWritePaths=/usr/local/bin"));
        assert!(!unit.contains(" /usr/local/bin "));
    }
    #[test]
    fn paths_cannot_inject_units_or_specifiers() {
        assert!(render(Path::new("/etc/bad\nExecStart=evil"), &[]).is_err());
        let unit = render(Path::new("/etc/a %n $HOME \"b.toml"), &[]).unwrap();
        assert!(unit.contains("%%n $$HOME \\\"b.toml"));
    }
    #[test]
    fn relative_paths_are_rejected() {
        assert!(render(Path::new("client.toml"), &[]).is_err());
        assert!(render(Path::new("/etc/client.toml"), &[PathBuf::from("relative")]).is_err());
    }
    #[test]
    fn config_template_is_private_and_never_overwrites() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        assert!(write_config_template(&path).unwrap());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(
            fs::read_to_string(&path)
                .unwrap()
                .contains("accessKey = \"\"")
        );
        fs::write(&path, "accessKey = \"configured\"\n").unwrap();
        assert!(!write_config_template(&path).unwrap());
        assert_eq!(
            fs::read_to_string(path).unwrap(),
            "accessKey = \"configured\"\n"
        );
    }
}

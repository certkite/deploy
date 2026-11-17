use crate::{TargetConfig, paths, site};
use anyhow::{Context, Result, bail, ensure};
use std::{
    fs,
    io::Write,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

pub(crate) fn binary(path: &Path) -> Result<()> {
    paths::absolute(path)?;
    let m = std::fs::metadata(path)?;
    ensure!(
        m.is_file()
            && m.permissions().mode() & 0o111 != 0
            && m.mode() & 0o022 == 0
            && (m.uid() == 0 || m.uid() == paths::uid()),
        "unsafe or non-executable binary: {}",
        path.display()
    );
    Ok(())
}
pub(crate) fn run(path: &Path, args: &[&str]) -> Result<()> {
    run_timeout(path, args, Duration::from_secs(30))
}

#[derive(Debug)]
pub(crate) struct Captured {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub(crate) fn capture(
    path: &Path,
    args: &[&str],
    timeout: Duration,
    limit: usize,
) -> Result<Captured> {
    binary(path)?;
    let stdout = tempfile::tempfile()?;
    let stderr = tempfile::tempfile()?;
    let mut command = Command::new(path);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(stdout.try_clone()?)
        .stderr(stderr.try_clone()?)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .process_group(0);
    let mut child = command
        .spawn()
        .with_context(|| format!("execute {}", path.display()))?;
    let start = Instant::now();
    let status = loop {
        if stdout.metadata()?.len() > limit as u64 || stderr.metadata()?.len() > limit as u64 {
            // SAFETY: child owns the process group created above.
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            child.wait()?;
            bail!("command output exceeds size limit");
        }
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() >= timeout {
            // SAFETY: a live child was placed in its own process group above.
            let killed = unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            let waited = child.wait();
            bail!(
                "{} exceeded deadline; kill result {killed}, reap {waited:?}",
                path.display()
            );
        }
        thread::sleep(Duration::from_millis(20));
    };
    use std::io::{Read, Seek, SeekFrom};
    let read = |mut file: std::fs::File| -> Result<Vec<u8>> {
        file.seek(SeekFrom::Start(0))?;
        let mut output = Vec::new();
        file.take(limit as u64 + 1).read_to_end(&mut output)?;
        ensure!(output.len() <= limit, "command output exceeds size limit");
        Ok(output)
    };
    Ok(Captured {
        status,
        stdout: read(stdout)?,
        stderr: read(stderr)?,
    })
}

fn run_timeout(path: &Path, args: &[&str], timeout: Duration) -> Result<()> {
    let captured = capture(path, args, timeout, 16 * 1024)?;
    ensure!(
        captured.status.success(),
        "{} {:?} failed ({}): {}",
        path.display(),
        args,
        captured.status,
        String::from_utf8_lossy(&captured.stderr)
    );
    Ok(())
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigBackup {
    path: PathBuf,
    mode: u32,
    uid: u32,
    gid: u32,
    bytes: Vec<u8>,
}

fn backup_path(target: &TargetConfig) -> PathBuf {
    target.directory().join("config-backup.json")
}

pub(crate) fn configure(target: &TargetConfig) -> Result<bool> {
    let (config_file, configured) = match target {
        TargetConfig::NginxSite {
            config_file,
            domains,
            ..
        } => {
            let source = fs::read_to_string(config_file)?;
            let configured = site::configure_nginx(
                &source,
                domains,
                &target.directory().join("current/fullchain.pem"),
                &target.directory().join("current/privkey.pem"),
            )?;
            (config_file, configured)
        }
        TargetConfig::CaddySite {
            config_file,
            domains,
            ..
        } => {
            let source = fs::read_to_string(config_file)?;
            let configured = site::configure_caddy(
                &source,
                domains,
                &target.directory().join("current/fullchain.pem"),
                &target.directory().join("current/privkey.pem"),
            )?;
            (config_file, configured)
        }
        _ => return Ok(false),
    };
    let previous = fs::read(config_file)?;
    if previous == configured.as_bytes() {
        return Ok(false);
    }
    let metadata = fs::metadata(config_file)?;
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && (metadata.uid() == 0 || metadata.uid() == paths::uid())
            && metadata.mode() & 0o022 == 0,
        "unsafe web-server configuration file"
    );
    ensure!(
        previous.len() <= 1024 * 1024,
        "web-server configuration file exceeds 1 MiB"
    );
    let backup = ConfigBackup {
        path: config_file.clone(),
        mode: metadata.mode() & 0o777,
        uid: metadata.uid(),
        gid: metadata.gid(),
        bytes: previous,
    };
    let backup_path = backup_path(target);
    ensure!(
        !backup_path.exists(),
        "unfinished web-server configuration backup exists"
    );
    paths::atomic(&backup_path, &serde_json::to_vec(&backup)?)?;
    atomic_config(
        config_file,
        configured.as_bytes(),
        backup.mode,
        backup.uid,
        backup.gid,
    )?;
    Ok(true)
}

pub(crate) fn restore_config(target: &TargetConfig) -> Result<()> {
    let path = backup_path(target);
    let Some(metadata) = paths::read(&path)? else {
        return Ok(());
    };
    let backup: ConfigBackup = serde_json::from_slice(&metadata)?;
    atomic_config(
        &backup.path,
        &backup.bytes,
        backup.mode,
        backup.uid,
        backup.gid,
    )?;
    discard_config_backup(target)
}

pub(crate) fn discard_config_backup(target: &TargetConfig) -> Result<()> {
    match fs::remove_file(backup_path(target)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    fs::File::open(target.directory())?.sync_all()?;
    Ok(())
}

fn atomic_config(path: &Path, bytes: &[u8], mode: u32, uid: u32, gid: u32) -> Result<()> {
    let parent = path.parent().context("configuration file has no parent")?;
    let mut staged = tempfile::NamedTempFile::new_in(parent)?;
    staged
        .as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    let c_path = std::ffi::CString::new(staged.path().as_os_str().as_bytes())?;
    // SAFETY: c_path is a live NUL-terminated path and uid/gid came from metadata.
    ensure!(
        unsafe { libc::chown(c_path.as_ptr(), uid, gid) } == 0,
        "cannot preserve web-server configuration ownership"
    );
    staged.write_all(bytes)?;
    staged.as_file().sync_all()?;
    staged.persist(path).map_err(|error| error.error)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

pub(crate) fn test(target: &TargetConfig) -> Result<()> {
    match target {
        TargetConfig::Nginx { nginx_binary, .. } | TargetConfig::NginxSite { nginx_binary, .. } => {
            run(nginx_binary, &["-t"])
        }
        TargetConfig::CaddySite {
            caddy_binary,
            config_file,
            ..
        } => run(
            caddy_binary,
            &[
                "validate",
                "--config",
                config_file
                    .to_str()
                    .context("Caddy config path is not UTF-8")?,
                "--adapter",
                "caddyfile",
            ],
        ),
        TargetConfig::Files { .. } => Ok(()),
    }
}

pub(crate) fn reload(target: &TargetConfig) -> Result<()> {
    let systemd_unit = match target {
        TargetConfig::Nginx { systemd_unit, .. }
        | TargetConfig::NginxSite { systemd_unit, .. }
        | TargetConfig::CaddySite { systemd_unit, .. } => systemd_unit,
        TargetConfig::Files { .. } => return Ok(()),
    };
    #[cfg(not(test))]
    let systemctl = std::path::PathBuf::from("/usr/bin/systemctl");
    #[cfg(test)]
    let systemctl = target.directory().join("test-systemctl");
    run(&systemctl, &["reload", "--", systemd_unit])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn failed_status_and_deadline_are_errors() {
        let root = tempfile::Builder::new()
            .tempdir_in(std::env::temp_dir().canonicalize().unwrap())
            .unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let binary = root.path().join("command");
        std::fs::write(&binary, "#!/bin/sh\necho rejected >&2\nexit 23\n").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let error = run(&binary, &[]).unwrap_err();
        assert!(error.to_string().contains("rejected"));
        std::fs::write(&binary, "#!/bin/sh\nsleep 20\n").unwrap();
        let start = Instant::now();
        assert!(
            run_timeout(&binary, &[], Duration::from_millis(80))
                .unwrap_err()
                .to_string()
                .contains("deadline")
        );
        assert!(start.elapsed() < Duration::from_secs(2));
        std::fs::write(&binary, "#!/bin/sh\nyes x | head -c 20000\n").unwrap();
        assert!(
            capture(&binary, &[], Duration::from_secs(1), 1024)
                .unwrap_err()
                .to_string()
                .contains("size limit")
        );
    }
}

//! Durable state and process coordination. No credentials are serialized here.

use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

/// Runtime health for status and update startup verification.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RuntimeStatus {
    pub pid: u32,
    pub version: String,
    pub build_id: String,
    pub started_at: u64,
    pub ready: bool,
    pub connected: bool,
    pub last_seen_at: Option<u64>,
    pub updated_at: u64,
    pub last_result: Option<certkite_protocol::OperationResult>,
}

/// Return Unix time in seconds, rejecting clocks before the epoch.
pub fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

/// Ensure a private directory without following a symlink at its final component.
pub fn private_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
    }
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "state directory must be a real directory"
    );
    ensure!(
        metadata.uid() == crate::config::effective_uid(),
        "state directory has unexpected owner"
    );
    ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "state directory must have mode 0700 or stricter"
    );
    Ok(())
}

/// Write a private JSON file with atomic rename and directory fsync.
pub fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path.parent().context("state file has no parent")?;
    private_dir(parent)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    serde_json::to_writer(&mut temp, value)?;
    temp.write_all(b"\n")?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|e| e.error)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

/// Read a bounded, owned state file without following a final symlink.
pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.uid() == crate::config::effective_uid(),
        "invalid state file ownership or type"
    );
    ensure!(meta.len() <= 2 * 1024 * 1024, "state file too large");
    Ok(serde_json::from_reader(file.take(2 * 1024 * 1024 + 1))?)
}

/// Hold an advisory exclusive lock. The lock is released when the file closes.
pub fn lock(path: &Path, nonblocking: bool) -> Result<File> {
    private_dir(path.parent().context("lock has no parent")?)?;
    lock_file(path, nonblocking)
}

/// Lock a file after its parent directory has been validated by the caller.
pub(crate) fn lock_file(path: &Path, nonblocking: bool) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.uid() == crate::config::effective_uid()
            && meta.nlink() == 1
            && meta.permissions().mode() & 0o077 == 0,
        "unsafe lock file"
    );
    if nonblocking {
        file.try_lock_exclusive()?;
    } else {
        file.lock_exclusive()?;
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_state_survives_a_new_read_and_locks_exclude_competitors() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("state.json");
        write_json(&path, &serde_json::json!({"generation":3})).unwrap();
        let loaded: serde_json::Value = read_json(&path).unwrap();
        assert_eq!(loaded["generation"], 3);
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let lock_path = temp.path().join("lock");
        let held = lock(&lock_path, true).unwrap();
        assert!(lock(&lock_path, true).is_err());
        drop(held);
        assert!(lock(&lock_path, true).is_ok());
    }

    #[test]
    fn refuses_symlink_state() {
        let temp = tempfile::tempdir().unwrap();
        let real = temp.path().join("real.json");
        fs::write(&real, "{}").unwrap();
        let alias = temp.path().join("alias.json");
        std::os::unix::fs::symlink(real, &alias).unwrap();
        assert!(read_json::<serde_json::Value>(&alias).is_err());
    }
}

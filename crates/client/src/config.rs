//! Configuration and local privilege boundaries.

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    env,
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

/// Configuration for existing system service installations.
pub const SYSTEM_CONFIG: &str = "/etc/certkite-client/config.toml";
/// Fixed service origin, also used by release requests.
pub const SERVER_ORIGIN: &str = "https://certkite.com";
/// Persistent data for existing system service installations.
pub const SYSTEM_STATE: &str = "/var/lib/certkite-client";
/// Executable used by existing system service installations.
pub const SYSTEM_BINARY: &str = "/usr/local/bin/certkite";
/// Running binary version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Private configuration. Debug and serialization are intentionally absent.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(rename = "accessKey")]
    access_key: String,
    /// Numeric local GID authorized to read download-only certificates.
    #[serde(default, rename = "downloadGroup")]
    pub download_group: Option<u32>,
}

/// Effective local user, used for ownership checks.
pub fn effective_uid() -> u32 {
    // SAFETY: geteuid takes no arguments and has no memory or lifetime requirements.
    unsafe { libc::geteuid() }
}

/// Whether this command is managing an existing system installation.
pub fn is_system_installation() -> bool {
    cfg!(target_os = "linux")
        && effective_uid() == 0
        && env::current_exe().is_ok_and(|path| path == Path::new(SYSTEM_BINARY))
}

fn absolute_env(name: &str) -> Option<PathBuf> {
    env::var_os(name).map(PathBuf::from).filter(|path| {
        path.is_absolute() && !path.components().any(|part| part == Component::ParentDir)
    })
}

fn home() -> Result<PathBuf> {
    absolute_env("HOME").context("set HOME to an absolute home directory")
}

fn user_base(name: &str, default: &str) -> Result<PathBuf> {
    match absolute_env(name) {
        Some(path) => Ok(path),
        None => Ok(home()?.join(default)),
    }
}

pub fn state_directory() -> Result<PathBuf> {
    if is_system_installation() {
        Ok(PathBuf::from(SYSTEM_STATE))
    } else {
        Ok(user_base("XDG_STATE_HOME", ".local/state")?.join("certkite"))
    }
}

pub fn default_config() -> Result<PathBuf> {
    if is_system_installation() {
        Ok(PathBuf::from(SYSTEM_CONFIG))
    } else {
        Ok(user_base("XDG_CONFIG_HOME", ".config")?.join("certkite/config.toml"))
    }
}

pub fn user_certificate_root() -> Result<PathBuf> {
    Ok(user_base("XDG_DATA_HOME", ".local/share")?.join("certkite/certificates"))
}

pub fn user_binary() -> Result<PathBuf> {
    Ok(home()?.join(".local/bin/certkite"))
}

impl Config {
    /// Read a private regular file and reject unknown options.
    pub fn load(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .with_context(|| format!("cannot open configuration {}", path.display()))?;
        let metadata = file.metadata()?;
        ensure!(metadata.is_file(), "configuration must be a regular file");
        ensure!(
            metadata.uid() == effective_uid(),
            "configuration must belong to the running user"
        );
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "configuration must have mode 0600 or stricter"
        );
        ensure!(metadata.len() <= 64 * 1024, "configuration exceeds 64 KiB");
        let mut source = String::new();
        file.take(64 * 1024 + 1)
            .read_to_string(&mut source)
            .context("cannot read configuration")?;
        let config: Self = toml::from_str(&source).map_err(|_| {
            anyhow::anyhow!(
                "invalid configuration; check TOML syntax and the supported accessKey/downloadGroup fields"
            )
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Access the credential only at the HTTP authentication boundary.
    pub fn access_key(&self) -> &str {
        &self.access_key
    }

    /// Validate the private authentication input. Deployment targets are discovered locally.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.download_group != Some(u32::MAX),
            "downloadGroup must be a valid numeric Unix group ID"
        );
        ensure!(
            !self.access_key.trim().is_empty()
                && self.access_key.len() <= 4096
                && self.access_key.bytes().all(|b| b.is_ascii_graphic()),
            "accessKey must be a nonempty printable ASCII value without spaces"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn configuration_rejects_manual_targets_and_does_not_echo_secret() {
        for body in [
            "accessKey = 'sensitive-value'\nserver = 'http://localhost'",
            "accessKey = 'sensitive-value'\n[targets.web]\ntype='files'\ndirectory='/srv/tls'",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("config.toml");
            fs::write(&path, body).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let error = Config::load(&path).err().unwrap().to_string();
            assert!(!error.contains("sensitive-value"));
            assert!(error.contains("invalid configuration"));
        }
    }

    #[test]
    fn download_group_requires_a_numeric_unix_gid() {
        let config: Config = toml::from_str("accessKey='key'\ndownloadGroup=1234").unwrap();
        config.validate().unwrap();
        assert_eq!(config.download_group, Some(1234));
        for value in ["-1", "4294967296", "\"readers\""] {
            assert!(
                toml::from_str::<Config>(&format!("accessKey='key'\ndownloadGroup={value}"))
                    .is_err()
            );
        }
        let config: Config = toml::from_str("accessKey='key'\ndownloadGroup=4294967295").unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn refuses_readable_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "accessKey='key'").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Config::load(&path).is_err());
    }
}

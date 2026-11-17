//! Configuration and local privilege boundaries.

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

/// Default configuration file. The service endpoint is intentionally not configurable.
pub const CONFIG_PATH: &str = "/etc/certkite-client/config.toml";
/// Fixed service origin, also used by release requests.
pub const SERVER_ORIGIN: &str = "https://certkite.com";
/// Persistent client data, independent of deployed certificate directories.
pub const STATE_DIR: &str = "/var/lib/certkite-client";
/// Ephemeral locks used by the installed service.
pub const RUN_DIR: &str = "/run/certkite-client";
/// Running binary version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Private configuration. Debug and serialization are intentionally absent.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(rename = "accessKey")]
    access_key: String,
}

/// Effective local user, used for ownership checks.
pub fn effective_uid() -> u32 {
    // SAFETY: geteuid takes no arguments and has no memory or lifetime requirements.
    unsafe { libc::geteuid() }
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
                "invalid configuration; check TOML syntax and the supported accessKey field"
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
    fn refuses_readable_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "accessKey='key'").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Config::load(&path).is_err());
    }
}

//! Stable public identity, independent of hostname and network addresses.

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{io::ErrorKind, path::Path};
use uuid::Uuid;

/// Public client identifier. It grants no authority without accessKey.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Identity {
    pub client_id: Uuid,
}

impl Identity {
    /// Load or create identity under a process-independent lock.
    pub fn load_or_create(directory: &Path) -> Result<Self> {
        crate::state::private_dir(directory)?;
        let _guard = crate::state::lock(&directory.join("identity.lock"), false)?;
        let path = directory.join("identity.json");
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                let identity: Self = crate::state::read_json(&path)?;
                ensure!(!identity.client_id.is_nil(), "invalid persisted identity");
                Ok(identity)
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                let identity = Self {
                    client_id: Uuid::new_v4(),
                };
                crate::state::write_json(&path, &identity)?;
                Ok(identity)
            }
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_is_persistent_and_corruption_is_not_silently_replaced() {
        let dir = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let first = Identity::load_or_create(dir.path()).unwrap();
        assert_eq!(
            Identity::load_or_create(dir.path()).unwrap().client_id,
            first.client_id
        );
        std::fs::write(dir.path().join("identity.json"), "broken").unwrap();
        assert!(Identity::load_or_create(dir.path()).is_err());
    }
}

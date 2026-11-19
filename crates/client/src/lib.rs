//! CertKite client runtime. The server origin is fixed and Core remains independent.

pub mod config;
mod core;
pub mod daemon;
pub mod identity;
pub mod logging;
pub mod state;
pub mod transport;
pub mod update;

#[cfg(test)]
mod session_tests;

use anyhow::{Context, Result};
use serde::Serialize;
use std::{collections::BTreeMap, path::Path};

/// Local diagnostic outcome; timestamps distinguish snapshots from live state.
#[derive(Debug, Serialize)]
pub struct Status {
    pub installed_version: String,
    pub client_id: Option<String>,
    pub runtime: Option<state::RuntimeStatus>,
    pub latest_update: Option<serde_json::Value>,
}

/// Read persisted status without creating identity or contacting the platform.
pub fn status() -> Result<Status> {
    let root = config::state_directory()?;
    let id_path = root.join("identity.json");
    let client_id = if id_path.try_exists()? {
        Some(
            state::read_json::<identity::Identity>(&id_path)?
                .client_id
                .to_string(),
        )
    } else {
        None
    };
    let runtime_path = root.join("startup.json");
    let runtime = if runtime_path.try_exists()? {
        Some(state::read_json(&runtime_path)?)
    } else {
        None
    };
    let update_path = root.join("update-pending");
    let latest_update = if update_path.try_exists()? {
        Some(serde_json::json!({"pending":true}))
    } else {
        None
    };
    Ok(Status {
        installed_version: config::VERSION.into(),
        client_id,
        runtime,
        latest_update,
    })
}

/// One named diagnostic check.
#[derive(Debug, Serialize)]
pub struct Check {
    pub ok: bool,
    pub message: String,
}

/// Complete local and remote diagnostics.
#[derive(Debug, Serialize)]
pub struct DoctorReport {
    pub ok: bool,
    pub checks: BTreeMap<String, Check>,
}

/// Diagnose configuration, discovered web-server targets and authentication.
pub async fn doctor(path: &Path) -> Result<DoctorReport> {
    let config = config::Config::load(path)?;
    let mut checks = BTreeMap::new();
    checks.insert(
        "configuration".into(),
        Check {
            ok: true,
            message: "configuration and private file permissions are valid".into(),
        },
    );
    checks.insert(
        "platform".into(),
        Check {
            ok: cfg!(target_os = "linux"),
            message: "the CertKite daemon requires Linux".into(),
        },
    );
    let system = config::is_system_installation();
    let targets = if system {
        tokio::task::spawn_blocking(certkite_deploy::discover)
            .await
            .context("service discovery task failed")??
    } else {
        Vec::new()
    };
    if cfg!(target_os = "linux") && targets.is_empty() {
        checks.insert(
            "discovery".into(),
            Check {
                ok: true,
                message: if system {
                    "no active Nginx or Caddy virtual hosts detected; certificates will be downloaded"
                        .into()
                } else {
                    format!("certificate downloads: {}", config::user_certificate_root()?.display())
                },
            },
        );
    }
    for discovered in targets {
        let id = discovered.id;
        let target = discovered.config;
        let result = tokio::task::spawn_blocking(move || certkite_deploy::check(&target))
            .await
            .context("target diagnostic task failed")?;
        checks.insert(
            format!("target:{id}"),
            match result {
                Ok(()) => Check {
                    ok: true,
                    message: "detected target is usable".into(),
                },
                Err(error) => Check {
                    ok: false,
                    message: format!("{error:#}").replace(config.access_key(), "[redacted]"),
                },
            },
        );
    }
    let result = transport::check_identity(config.access_key()).await;
    checks.insert(
        "authentication".into(),
        match result {
            Ok(()) => Check {
                ok: true,
                message: "accessKey accepted".into(),
            },
            Err(error) => Check {
                ok: false,
                message: format!("{error:#}").replace(config.access_key(), "[redacted]"),
            },
        },
    );
    Ok(DoctorReport {
        ok: checks.values().all(|check| check.ok),
        checks,
    })
}

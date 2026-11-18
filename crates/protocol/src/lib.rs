//! Local deployment commands, validation limits and operation results.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Maximum size of a WebSocket message, including certificate material.
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
/// Maximum size of either PEM field.
pub const MAX_PEM_BYTES: usize = 256 * 1024;

/// A local command translated from a Core deployment request.
/// Secret-bearing commands do not implement Debug.
pub enum DeploymentCommand {
    Test {
        request_id: String,
        target: String,
    },
    Deploy {
        request_id: String,
        operation_id: String,
        target: String,
        generation: u64,
        domain: String,
        fullchain_pem: String,
        private_key_pem: String,
    },
}

/// Final result for a test or deployment operation.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct OperationResult {
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    pub target: String,
    pub status: ResultStatus,
    pub code: ErrorCode,
    pub retryable: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation: Option<u64>,
}

/// Stable terminal statuses.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResultStatus {
    Success,
    Failed,
}

/// Machine-readable failure classification; clients never parse message text.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Ok,
    InvalidRequest,
    TargetUnavailable,
    CertificateInvalid,
    Conflict,
    StaleOperation,
    Busy,
    LocalPublishFailed,
    RecoveryFailed,
    Unsupported,
}

/// Invalid deployment input, without including the original secret-bearing input.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("invalid deployment command: {0}")]
pub struct ValidationError(pub &'static str);

/// Validate an opaque local target or operation identifier.
pub fn valid_id(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}

impl DeploymentCommand {
    /// Apply bounds before dispatch or allocation of deployment work.
    pub fn validate(&self) -> Result<(), ValidationError> {
        let validate_target = |request: &str, target: &str| {
            if !valid_id(request, 128) || !valid_id(target, 64) {
                return Err(ValidationError("invalid request or target identifier"));
            }
            Ok(())
        };
        match self {
            Self::Test { request_id, target } => validate_target(request_id, target)?,
            Self::Deploy {
                request_id,
                operation_id,
                target,
                generation,
                domain,
                fullchain_pem,
                private_key_pem,
            } => {
                validate_target(request_id, target)?;
                if !valid_id(operation_id, 128) || *generation == 0 {
                    return Err(ValidationError(
                        "invalid operation identifier or generation",
                    ));
                }
                if domain.is_empty()
                    || domain.len() > 253
                    || !domain.is_ascii()
                    || domain
                        .bytes()
                        .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
                {
                    return Err(ValidationError("invalid domain"));
                }
                if fullchain_pem.is_empty()
                    || private_key_pem.is_empty()
                    || fullchain_pem.len() > MAX_PEM_BYTES
                    || private_key_pem.len() > MAX_PEM_BYTES
                {
                    return Err(ValidationError("invalid PEM length"));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_paths_oversized_material_and_zero_generations() {
        for (target, generation, key, valid) in [
            ("web", 1, "key".into(), true),
            ("../web", 1, "key".into(), false),
            ("web", 0, "key".into(), false),
            ("web", 1, "x".repeat(MAX_PEM_BYTES + 1), false),
        ] {
            let command = DeploymentCommand::Deploy {
                request_id: "req".into(),
                operation_id: "task-1".into(),
                target: target.into(),
                generation,
                domain: "example.com".into(),
                fullchain_pem: "cert".into(),
                private_key_pem: key,
            };
            assert_eq!(command.validate().is_ok(), valid);
        }
    }
}

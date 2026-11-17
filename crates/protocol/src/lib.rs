//! Public JSON wire contract for CertKite clients. No Core source is required.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// First supported protocol major version.
pub const PROTOCOL_VERSION: u32 = 1;
/// Maximum size of a WebSocket message, including certificate material.
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
/// Maximum size of either PEM field.
pub const MAX_PEM_BYTES: usize = 256 * 1024;

/// A locally configured deployment capability; paths and secrets stay local.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct TargetSummary {
    pub id: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<String>,
}

/// Messages sent by the client. Deliberately does not implement Debug.
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    Hello {
        protocol_version: u32,
        client_id: String,
        client_version: String,
        build_id: String,
        os: String,
        arch: String,
        hostname: String,
        targets: Vec<TargetSummary>,
    },
    Heartbeat {
        client_id: String,
        timestamp: u64,
    },
    Result {
        client_id: String,
        #[serde(flatten)]
        result: OperationResult,
    },
}

/// Messages accepted from Core. Secret-bearing payloads do not implement Debug.
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    Welcome {
        protocol_version: u32,
        heartbeat_seconds: u64,
    },
    Heartbeat {},
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
    Error {
        code: String,
        message: String,
    },
    #[serde(other)]
    Unknown,
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

/// Invalid wire input, without including the original secret-bearing input.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("invalid protocol message: {0}")]
pub struct ValidationError(pub &'static str);

/// Validate an opaque local target or operation identifier.
pub fn valid_id(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}

impl ServerMessage {
    /// Apply bounds before dispatch or allocation of deployment work.
    pub fn validate(&self) -> Result<(), ValidationError> {
        let validate_target = |request: &str, target: &str| {
            if !valid_id(request, 128) || !valid_id(target, 64) {
                return Err(ValidationError("invalid request or target identifier"));
            }
            Ok(())
        };
        match self {
            Self::Welcome {
                protocol_version,
                heartbeat_seconds,
            } => {
                if *protocol_version != PROTOCOL_VERSION || !(5..=120).contains(heartbeat_seconds) {
                    return Err(ValidationError("unsupported version or heartbeat interval"));
                }
            }
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
            Self::Error { code, message } => {
                if !valid_id(code, 64) || message.len() > 1024 {
                    return Err(ValidationError("invalid error response"));
                }
            }
            Self::Unknown => return Err(ValidationError("unsupported message type")),
            Self::Heartbeat {} => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_payload_round_trips_without_protocol_drift() {
        let json = r#"{"type":"deploy","request_id":"req_1","operation_id":"op_1","target":"web","generation":2,"domain":"example.com","fullchain_pem":"certificate","private_key_pem":"secret","future_field":true}"#;
        let message: ServerMessage = serde_json::from_str(json).unwrap();
        message.validate().unwrap();
        let encoded = serde_json::to_value(message).unwrap();
        assert_eq!(encoded["type"], "deploy");
        assert_eq!(encoded["generation"], 2);
        assert_eq!(encoded["private_key_pem"], "secret");
    }

    #[test]
    fn rejects_paths_oversized_material_and_zero_generations() {
        let mut value = serde_json::json!({"type":"deploy","request_id":"req","operation_id":"op","target":"../web","generation":1,"domain":"example.com","fullchain_pem":"cert","private_key_pem":"key"});
        assert!(
            serde_json::from_value::<ServerMessage>(value.clone())
                .unwrap()
                .validate()
                .is_err()
        );
        value["target"] = "web".into();
        value["generation"] = 0.into();
        assert!(
            serde_json::from_value::<ServerMessage>(value.clone())
                .unwrap()
                .validate()
                .is_err()
        );
        value["generation"] = 1.into();
        value["private_key_pem"] = "x".repeat(MAX_PEM_BYTES + 1).into();
        assert!(
            serde_json::from_value::<ServerMessage>(value)
                .unwrap()
                .validate()
                .is_err()
        );
    }

    #[test]
    fn unknown_messages_are_explicitly_unsupported() {
        let message: ServerMessage =
            serde_json::from_str(r#"{"type":"execute_shell","command":"anything"}"#).unwrap();
        assert_eq!(
            message.validate(),
            Err(ValidationError("unsupported message type"))
        );
    }
}

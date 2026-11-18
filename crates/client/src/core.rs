//! Core deployment WebSocket registration and local certificate operations.

use crate::{
    config::{Config, VERSION},
    daemon::{self, domain_matches, failed_result, hostname, save_status},
    state::{self, RuntimeStatus},
    transport::{self, Socket},
};
use anyhow::{Context, Result, bail, ensure};
use certkite_deploy::TargetConfig;
use certkite_protocol::{DeploymentCommand, ErrorCode, OperationResult, ResultStatus, valid_id};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::watch,
    task::JoinSet,
    time::{Instant, interval_at, sleep, timeout},
};
use tokio_tungstenite::tungstenite::Message;

const PROTOCOL_VERSION: u32 = 2;
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const SERVER_IDLE_TIMEOUT: Duration = Duration::from_secs(180);
// Numeric protobuf enum values sent by Core's deployment transport.
const LOCAL_PROVIDER: u32 = 1;
const NGINX: u32 = 1;
const SAVE_FILES: u32 = 11;
const CADDY: u32 = 26;

#[derive(Clone)]
pub(crate) struct DeploymentContext {
    pub config: Arc<Config>,
    pub targets: Arc<BTreeMap<String, TargetConfig>>,
    pub directory: PathBuf,
    pub certificate_root: PathBuf,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Registration {
    protocol_version: u32,
    client_version: &'static str,
    os: &'static str,
    arch: &'static str,
    hostname: String,
    ip: IpAddr,
    features: [&'static str; 1],
    capabilities: Vec<Capability>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Envelope<T> {
    client_id: String,
    #[serde(flatten)]
    payload: T,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
enum RegistrationPayload<'a> {
    Register(&'a Registration),
    Heartbeat { registration: &'a Registration },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationAck {
    client_id: String,
    register: RegistrationVersion,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationVersion {
    protocol_version: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Command {
    client_id: String,
    #[serde(default)]
    request_id: String,
    #[serde(default)]
    discover_request: Option<Selection>,
    #[serde(default)]
    test_request: Option<Selection>,
    #[serde(default)]
    execute_request: Option<ExecuteRequest>,
}

#[derive(Deserialize)]
struct Selection {
    selector: Selector,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Selector {
    provider: u32,
    deployment_type: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    target_ref: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExecuteRequest {
    selector: Selector,
    #[serde(default)]
    domain: String,
    #[serde(default)]
    cert: String,
    #[serde(default)]
    key: String,
    // ProtoJSON serializes uint64 as a decimal string.
    #[serde(default)]
    generation: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Capability {
    provider: u32,
    deployment_type: u32,
    target_mode: u32,
    supports_test: bool,
    supports_manual_execute: bool,
    resource_status: u32,
}

impl Selector {
    fn local(deployment_type: u32) -> Self {
        Self {
            provider: LOCAL_PROVIDER,
            deployment_type,
            target_ref: String::new(),
        }
    }

    fn supported(&self) -> bool {
        self.provider == LOCAL_PROVIDER
            && matches!(self.deployment_type, NGINX | CADDY | SAVE_FILES)
    }

    fn matches_target(&self, id: &str, target: &TargetConfig) -> bool {
        let kind = match self.deployment_type {
            NGINX => "nginx",
            CADDY => "caddy",
            _ => return false,
        };
        target.kind() == kind && (self.target_ref.is_empty() || self.target_ref == id)
    }
}

impl DeploymentContext {
    fn capability(&self, selector: Selector) -> Capability {
        let available = selector.supported()
            && (selector.deployment_type == SAVE_FILES
                || self
                    .targets
                    .iter()
                    .any(|(id, target)| selector.matches_target(id, target)));
        Capability {
            provider: selector.provider,
            deployment_type: selector.deployment_type,
            target_mode: 1, // Core's local capabilities use domain selection instead of targetRef.
            supports_test: available,
            supports_manual_execute: available,
            resource_status: if available { 0 } else { 3 }, // UNKNOWN (no resources needed) / NOT_CONFIGURED.
        }
    }
}

enum Operation {
    Test(Selection),
    Deploy(ExecuteRequest),
}

impl Operation {
    fn selector(&self) -> &Selector {
        match self {
            Self::Test(request) => &request.selector,
            Self::Deploy(request) => &request.selector,
        }
    }

    fn response(&self, client_id: String, result: &OperationResult) -> Envelope<Value> {
        let (status, failure_kind) = match result.code {
            ErrorCode::Ok => (1, 0),          // SUCCESS
            ErrorCode::Unsupported => (3, 0), // NOT_SUPPORTED
            ErrorCode::Busy => (2, 3),
            ErrorCode::TargetUnavailable => (2, 4),
            ErrorCode::LocalPublishFailed | ErrorCode::RecoveryFailed => (2, 7),
            _ => (2, 0),
        };
        let body = json!({
            "requestId": result.request_id,
            "selector": self.selector(),
            "result": { "status": status, "failureKind": failure_kind, "message": result.message, "retryable": result.retryable },
        });
        let response = match self {
            Self::Test(_) => json!({"testResponse": body}),
            Self::Deploy(_) => json!({"executeResponse": body}),
        };
        let mut payload = response;
        payload["requestId"] = json!(result.request_id);
        Envelope { client_id, payload }
    }
}

pub(crate) async fn session(
    mut socket: Socket,
    client_id: &str,
    deployment: DeploymentContext,
    status: &mut RuntimeStatus,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let registration = Registration {
        protocol_version: PROTOCOL_VERSION,
        client_version: VERSION,
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        hostname: hostname()?,
        ip: socket
            .get_ref()
            .get_ref()
            .local_addr()
            .context("cannot read local address of the Core connection")?
            .ip()
            .to_canonical(),
        features: ["deployment-generation"],
        capabilities: [NGINX, CADDY, SAVE_FILES]
            .into_iter()
            .map(|kind| deployment.capability(Selector::local(kind)))
            .filter(|capability| capability.supports_manual_execute)
            .collect(),
    };
    let register = Envelope {
        client_id: client_id.into(),
        payload: RegistrationPayload::Register(&registration),
    };
    tokio::select! {
        result = timeout(Duration::from_secs(15), async {
            transport::send(&mut socket, &register).await?;
            receive_registration(&mut socket, client_id).await
        }) => result.context("Core registration timed out")??,
        _ = shutdown.changed() => return Ok(()),
    }

    tracing::info!("registered with Core deployment service");
    status.connected = true;
    record_activity(&deployment.directory, status).await?;

    let heartbeat = Envelope {
        client_id: client_id.into(),
        payload: RegistrationPayload::Heartbeat {
            registration: &registration,
        },
    };
    let mut timer = interval_at(Instant::now() + HEARTBEAT_INTERVAL, HEARTBEAT_INTERVAL);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let idle_timeout = sleep(SERVER_IDLE_TIMEOUT);
    tokio::pin!(idle_timeout);
    let mut work = JoinSet::<(Envelope<Value>, OperationResult)>::new();
    let outcome: Result<()> = async {
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = &mut idle_timeout => bail!("Core deployment WebSocket became idle"),
                _ = timer.tick() => transport::send(&mut socket, &heartbeat).await?,
                result = work.join_next(), if !work.is_empty() => {
                    let (response, result) = result.context("deployment task disappeared")??;
                    status.last_result = Some(result);
                    record_activity(&deployment.directory, status).await?;
                    transport::send(&mut socket, &response).await?;
                }
                frame = socket.next() => {
                    match frame.context("Core deployment WebSocket closed")?
                        .map_err(|_| anyhow::anyhow!("Core deployment WebSocket read failed"))? {
                        Message::Ping(_) => flush_control(&mut socket).await?,
                        Message::Pong(_) => {},
                        Message::Close(_) => break,
                        Message::Text(text) => {
                            let command: Command = serde_json::from_str(&text)
                                .map_err(|_| anyhow::anyhow!("invalid Core deployment message"))?;
                            ensure!(command.client_id == client_id, "Core deployment client ID mismatch");
                            let operation = match (command.discover_request, command.test_request, command.execute_request) {
                                (Some(request), None, None) => {
                                    ensure!(valid_id(&command.request_id, 128), "invalid Core discovery request ID");
                                    let response = Envelope { client_id: command.client_id, payload: json!({
                                        "requestId": command.request_id,
                                        "discoverResponse": { "capability": deployment.capability(request.selector) },
                                    }) };
                                    transport::send(&mut socket, &response).await?;
                                    None
                                }
                                (None, Some(request), None) => Some(Operation::Test(request)),
                                (None, None, Some(request)) => Some(Operation::Deploy(request)),
                                (None, None, None) => {
                                    tracing::debug!("received unsupported Core deployment message");
                                    None
                                }
                                _ => bail!("Core deployment message has multiple operations"),
                            };
                            if let Some(operation) = operation {
                                let request_id = command.request_id;
                                ensure!(valid_id(&request_id, 128), "invalid Core deployment request ID");
                                if work.is_empty() {
                                    let deployment = deployment.clone();
                                    let client_id = client_id.to_owned();
                                    work.spawn_blocking(move || {
                                        let result = execute(&deployment, &request_id, &operation);
                                        (operation.response(client_id, &result), result)
                                    });
                                } else {
                                    let result = operation_error(&request_id, ErrorCode::Busy, true, "another operation is running");
                                    transport::send(&mut socket, &operation.response(client_id.into(), &result)).await?;
                                }
                            }
                        }
                        _ => bail!("unsupported Core deployment WebSocket frame"),
                    }
                    idle_timeout.as_mut().reset(Instant::now() + SERVER_IDLE_TIMEOUT);
                    record_activity(&deployment.directory, status).await?;
                }
            }
        }
        Ok(())
    }.await;
    // Blocking publication must finish even if the WebSocket drops or the service stops.
    while let Some(result) = work.join_next().await {
        let (_, result) = result.context("deployment task failed during disconnect")?;
        status.last_result = Some(result);
        record_activity(&deployment.directory, status).await?;
    }
    outcome
}

fn operation_error(
    request_id: &str,
    code: ErrorCode,
    retryable: bool,
    message: &str,
) -> OperationResult {
    OperationResult {
        request_id: request_id.into(),
        operation_id: None,
        target: String::new(),
        status: ResultStatus::Failed,
        code,
        retryable,
        message: message.into(),
        changed: None,
        generation: None,
    }
}

fn execute(
    context: &DeploymentContext,
    request_id: &str,
    operation: &Operation,
) -> OperationResult {
    let selector = operation.selector();
    let fail = |code, message| operation_error(request_id, code, false, message);
    if !selector.supported()
        || (selector.deployment_type == SAVE_FILES && !selector.target_ref.is_empty())
    {
        return fail(ErrorCode::Unsupported, "unsupported deployment selector");
    }
    let targets = context
        .targets
        .iter()
        .filter(|(id, target)| selector.matches_target(id, target));
    let execute = |message, target| {
        daemon::execute(
            message,
            &context.config,
            target,
            &context.directory,
            &context.certificate_root,
        )
    };
    match operation {
        Operation::Test(_) if selector.deployment_type == SAVE_FILES => {
            let result = certkite_deploy::prepare_certificate_root(
                &context.certificate_root.join("downloads"),
            );
            if result.is_err() {
                return fail(
                    ErrorCode::LocalPublishFailed,
                    "cannot prepare the certificate download directory",
                );
            }
            OperationResult {
                status: ResultStatus::Success,
                ..fail(ErrorCode::Ok, "certificate download directory is ready")
            }
        }
        Operation::Test(_) => {
            let mut result = fail(
                ErrorCode::TargetUnavailable,
                "no local site matches the selected web server",
            );
            for (id, target) in targets {
                result = execute(
                    DeploymentCommand::Test {
                        request_id: request_id.into(),
                        target: id.clone(),
                    },
                    Some(target),
                );
                if result.status == ResultStatus::Failed {
                    break;
                }
            }
            result
        }
        Operation::Deploy(request) => {
            let Ok(generation) = request.generation.parse::<u64>() else {
                return fail(
                    ErrorCode::Unsupported,
                    "Core deployment generation is required",
                );
            };
            let (target_id, target) = if selector.deployment_type == SAVE_FILES {
                let domain = request.domain.trim_end_matches('.').to_ascii_lowercase();
                let digest = Sha256::digest(domain.as_bytes());
                let id = hex::encode(&digest[..20]);
                // Keep serving the stable certificate paths created by earlier clients.
                let existing_id = format!("v2-{id}");
                let existing = context
                    .certificate_root
                    .join("downloads")
                    .join(&existing_id);
                match existing.try_exists() {
                    Ok(true) => (existing_id, None),
                    Ok(false) => (id, None),
                    Err(_) => {
                        return fail(
                            ErrorCode::LocalPublishFailed,
                            "cannot inspect the certificate download directory",
                        );
                    }
                }
            } else {
                let mut matches = targets.filter(|(_, target)| {
                    target
                        .domains()
                        .iter()
                        .any(|domain| domain_matches(domain, &request.domain))
                });
                let Some((id, target)) = matches.next() else {
                    return fail(
                        ErrorCode::TargetUnavailable,
                        "no local site matches the certificate domain",
                    );
                };
                if matches.next().is_some() {
                    return fail(
                        ErrorCode::TargetUnavailable,
                        "multiple local sites match the certificate domain",
                    );
                }
                (id.clone(), Some(target))
            };
            let message = DeploymentCommand::Deploy {
                request_id: request_id.into(),
                operation_id: format!("task-{generation}"),
                target: target_id,
                generation,
                domain: request.domain.clone(),
                fullchain_pem: request.cert.clone(),
                private_key_pem: request.key.clone(),
            };
            if message.validate().is_err() {
                return failed_result(
                    &message,
                    ErrorCode::InvalidRequest,
                    false,
                    "invalid certificate deployment request",
                );
            }
            execute(message, target)
        }
    }
}

async fn receive_registration(socket: &mut Socket, client_id: &str) -> Result<()> {
    while let Some(frame) = socket.next().await {
        match frame.map_err(|_| anyhow::anyhow!("Core registration connection failed"))? {
            Message::Text(text) => {
                let ack: RegistrationAck = serde_json::from_str(&text)
                    .map_err(|_| anyhow::anyhow!("invalid Core registration acknowledgement"))?;
                ensure!(
                    ack.client_id == client_id && ack.register.protocol_version == PROTOCOL_VERSION,
                    "Core registration acknowledgement has the wrong client or protocol version"
                );
                return Ok(());
            }
            Message::Ping(_) => flush_control(socket).await?,
            Message::Pong(_) => {}
            _ => break,
        }
    }
    bail!("Core closed the WebSocket before acknowledging registration")
}

async fn flush_control(socket: &mut Socket) -> Result<()> {
    // Tungstenite queues a WebSocket Pong when reading a Ping.
    timeout(Duration::from_secs(10), socket.flush())
        .await
        .context("WebSocket control write timed out")?
        .map_err(|_| anyhow::anyhow!("WebSocket closed while writing a control frame"))
}

async fn record_activity(directory: &Path, status: &mut RuntimeStatus) -> Result<()> {
    let now = state::now()?;
    status.last_seen_at = Some(now);
    status.updated_at = now;
    save_status(directory, status).await
}

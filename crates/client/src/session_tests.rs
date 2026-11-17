use super::*;
use crate::daemon::{build_id, session};
use certkite_protocol::{ClientMessage, ServerMessage};
use futures_util::{SinkExt, StreamExt};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    pkey::PKey,
    rsa::Rsa,
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, SubjectAlternativeName},
    },
};
use std::{collections::BTreeMap, os::unix::fs::PermissionsExt, sync::Arc};
use tokio_tungstenite::tungstenite::Message;

pub(crate) fn certificate() -> (String, String) {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "example.com").unwrap();
    let name = name.build();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(7).unwrap())
        .unwrap();
    cert.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    let san = SubjectAlternativeName::new()
        .dns("example.com")
        .build(&cert.x509v3_context(None, None))
        .unwrap();
    cert.append_extension(san).unwrap();
    cert.sign(&key, MessageDigest::sha256()).unwrap();
    (
        String::from_utf8(cert.build().to_pem().unwrap()).unwrap(),
        String::from_utf8(key.private_key_to_pem_pkcs8().unwrap()).unwrap(),
    )
}

#[tokio::test]
async fn mock_core_deploys_retries_and_rejects_an_older_generation() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let target = root.join("target");
    std::fs::create_dir(&target).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
    let configuration: config::Config = toml::from_str("accessKey='test-key'\n").unwrap();
    configuration.validate().unwrap();
    let config = Arc::new(configuration);
    let targets = Arc::new(BTreeMap::from([(
        "web".into(),
        certkite_deploy::TargetConfig::Files {
            directory: target.clone(),
        },
    )]));
    let identity = identity::Identity::load_or_create(&root).unwrap();
    let (cert, key) = certificate();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        let hello = socket.next().await.unwrap().unwrap();
        let hello: ClientMessage = serde_json::from_str(hello.to_text().unwrap()).unwrap();
        assert!(
            matches!(hello, ClientMessage::Hello { protocol_version: 1, targets, .. } if targets[0].id == "web" && targets[0].domains.is_empty())
        );
        let welcome = ServerMessage::Welcome {
            protocol_version: 1,
            heartbeat_seconds: 5,
        };
        socket
            .send(Message::Text(
                serde_json::to_string(&welcome).unwrap().into(),
            ))
            .await
            .unwrap();
        for (request, operation, generation, success) in [
            ("req_1", "op_1", 2, true),
            ("req_2", "op_1", 2, true),
            ("req_3", "op_older", 1, false),
        ] {
            let deploy = ServerMessage::Deploy {
                request_id: request.into(),
                operation_id: operation.into(),
                target: "web".into(),
                generation,
                domain: "example.com".into(),
                fullchain_pem: cert.clone(),
                private_key_pem: key.clone(),
            };
            socket
                .send(Message::Text(
                    serde_json::to_string(&deploy).unwrap().into(),
                ))
                .await
                .unwrap();
            loop {
                let frame = socket.next().await.unwrap().unwrap();
                let message: ClientMessage =
                    serde_json::from_str(frame.to_text().unwrap()).unwrap();
                match message {
                    ClientMessage::Heartbeat { .. } => {
                        socket
                            .send(Message::Text(r#"{"type":"heartbeat"}"#.into()))
                            .await
                            .unwrap();
                    }
                    ClientMessage::Result { result, .. } => {
                        assert_eq!(result.request_id, request);
                        assert_eq!(
                            result.status == certkite_protocol::ResultStatus::Success,
                            success
                        );
                        if !success {
                            assert_eq!(result.code, certkite_protocol::ErrorCode::StaleOperation);
                        }
                        break;
                    }
                    _ => panic!("unexpected hello"),
                }
            }
        }
        socket.close(None).await.unwrap();
    });
    let socket = transport::connect(&format!("ws://{address}/client/v1/connect"), "test-key")
        .await
        .unwrap();
    let mut runtime = state::RuntimeStatus {
        pid: std::process::id(),
        version: config::VERSION.into(),
        build_id: build_id().into(),
        ready: true,
        ..Default::default()
    };
    let (_sender, shutdown) = tokio::sync::watch::channel(false);
    tokio::time::timeout(
        std::time::Duration::from_secs(20),
        session(
            socket,
            config,
            targets,
            &identity,
            &root,
            &mut runtime,
            shutdown,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    server.await.unwrap();
    assert!(target.join("current/fullchain.pem").is_file());
    assert!(target.join("current/privkey.pem").is_file());
    let persisted: state::RuntimeStatus = state::read_json(&root.join("startup.json")).unwrap();
    assert_eq!(persisted.last_result.unwrap().request_id, "req_3");
}

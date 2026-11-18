use super::*;
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
async fn core_connects_with_bearer_and_publishes_certificate() {
    for existing_download in [false, true] {
        run_file_deployment_session(existing_download).await;
    }
}

// The callback signature is fixed by tungstenite.
#[allow(clippy::result_large_err)]
async fn run_file_deployment_session(existing_download: bool) {
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let domain_id = "a379a6f6eeafb9a55e378c118034e2751e682fab";
    let expected_target = if existing_download {
        let id = format!("v2-{domain_id}");
        let downloads = root.join("downloads");
        certkite_deploy::prepare_certificate_root(&downloads).unwrap();
        certkite_deploy::TargetConfig::Files {
            directory: downloads.join(&id),
        }
        .prepare()
        .unwrap();
        id
    } else {
        domain_id.to_owned()
    };
    let identity = identity::Identity::load_or_create(&root).unwrap();
    let client_id = identity.client_id.to_string();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_client_id = client_id.clone();
    let (cert, key) = certificate();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket =
            tokio_tungstenite::accept_hdr_async(stream, |request: &Request, response: Response| {
                assert_eq!(request.uri().path(), "/deploy/v2/ws");
                assert_eq!(
                    request.uri().query().unwrap(),
                    format!("clientId={server_client_id}")
                );
                assert_eq!(request.headers()["authorization"], "Bearer test&key=+");
                Ok(response)
            })
            .await
            .unwrap();
        let frame = socket.next().await.unwrap().unwrap();
        let register: serde_json::Value = serde_json::from_str(frame.to_text().unwrap()).unwrap();
        assert_eq!(register["clientId"], server_client_id);
        assert_eq!(register["register"]["protocolVersion"], 2);
        assert_eq!(register["register"]["clientVersion"], config::VERSION);
        assert_eq!(register["register"]["ip"], address.ip().to_string());
        assert!(register.get("accessKey").is_none());
        assert_eq!(register["register"]["features"][0], "deployment-generation");
        assert_eq!(
            register["register"]["capabilities"][0]["deploymentType"],
            11
        );
        socket
            .send(Message::Text(
                serde_json::json!({
                    "clientId": server_client_id,
                    "register": {"protocolVersion": 2, "clientVersion": config::VERSION}
                })
                .to_string()
                .into(),
            ))
            .await
            .unwrap();
        socket
            .send(Message::Ping(vec![1, 2, 3].into()))
            .await
            .unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap(),
            Message::Pong(vec![1, 2, 3].into())
        );
        let selector = serde_json::json!({"provider": 1, "deploymentType": 11});
        let mut requests = vec![
            (
                "discoverRequest",
                "discoverResponse",
                "discover-1",
                serde_json::json!({"selector": selector, "includeResources": true}),
                None,
            ),
            (
                "testRequest",
                "testResponse",
                "test-1",
                serde_json::json!({"selector": selector}),
                Some(1),
            ),
            (
                "testRequest",
                "testResponse",
                "test-unsupported",
                serde_json::json!({"selector": {"provider": 2, "deploymentType": 3}}),
                Some(3),
            ),
        ];
        for (request_id, generation, expected_status) in [
            ("deploy-1", "12", 1),
            ("deploy-retry", "12", 1),
            ("deploy-old", "11", 2),
        ] {
            requests.push(("executeRequest", "executeResponse", request_id, serde_json::json!({
                "selector": selector, "domain": "example.com", "cert": cert, "key": key, "generation": generation,
            }), Some(expected_status)));
        }
        for (command, reply, request_id, body, status) in requests {
            let mut message =
                serde_json::json!({"clientId": server_client_id, "requestId": request_id});
            message[command] = body;
            socket
                .send(Message::Text(message.to_string().into()))
                .await
                .unwrap();
            let frame = socket.next().await.unwrap().unwrap();
            let response: serde_json::Value =
                serde_json::from_str(frame.to_text().unwrap()).unwrap();
            assert_eq!(response["clientId"], server_client_id);
            assert_eq!(response["requestId"], request_id);
            if let Some(status) = status {
                assert_eq!(response[reply]["requestId"], request_id);
                assert_eq!(response[reply]["result"]["status"], status);
            } else {
                assert_eq!(response[reply]["capability"]["deploymentType"], 11);
                assert_eq!(response[reply]["capability"]["supportsManualExecute"], true);
            }
        }
        socket.close(None).await.unwrap();
    });
    let socket = transport::connect(
        &format!("ws://{address}/deploy/v2/ws"),
        "test&key=+",
        &client_id,
    )
    .await
    .unwrap();
    let mut runtime = state::RuntimeStatus::default();
    let (_sender, shutdown) = tokio::sync::watch::channel(false);
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        core::session(
            socket,
            &client_id,
            core::DeploymentContext {
                config: Arc::new(toml::from_str("accessKey='test-key'\n").unwrap()),
                targets: Arc::new(BTreeMap::new()),
                directory: root.clone(),
                certificate_root: root.clone(),
            },
            &mut runtime,
            shutdown,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    server.await.unwrap();
    let persisted: state::RuntimeStatus = state::read_json(&root.join("startup.json")).unwrap();
    assert!(persisted.connected);
    assert!(persisted.last_seen_at.is_some());
    let last = persisted.last_result.unwrap();
    assert_eq!(last.request_id, "deploy-old");
    assert_eq!(last.code, certkite_protocol::ErrorCode::StaleOperation);
    assert_eq!(last.target, expected_target);
    let download = root.join("downloads").join(last.target);
    assert!(download.join("current/fullchain.pem").is_file());
    assert!(download.join("current/privkey.pem").is_file());
}

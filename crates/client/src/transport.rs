//! Bounded HTTP and authenticated WebSocket transport.

use anyhow::{Context, Result, ensure};
use certkite_protocol::{MAX_MESSAGE_BYTES, ServerMessage};
use futures_util::{SinkExt, StreamExt};
use reqwest::{Url, redirect::Policy};
use serde::{Deserialize, Serialize};
use tokio::{
    net::TcpStream,
    time::{Duration, timeout},
};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream,
    tungstenite::{
        Error, Message,
        client::IntoClientRequest,
        handshake::client::{Request, Response},
        http::{HeaderValue, StatusCode, header::AUTHORIZATION},
        protocol::WebSocketConfig,
    },
};

const AUTHENTICATION_URL: &str = "https://certkite.com/openapi/v1/cert?size=1";
pub const IDENTITY_URL: &str = "https://certkite.com/client/v1/identity";
const DEPLOY_V2_URL: &str = "wss://certkite.com/deploy/v2/ws";
pub const CONNECT_URL: &str = "wss://certkite.com/client/v1/connect";
const USER_AGENT: &str = concat!("certkite-client/", env!("CARGO_PKG_VERSION"));

pub(crate) type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// HTTP client with bounded time and no cross-origin credential redirects.
pub fn http_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .https_only(true)
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .user_agent(USER_AGENT)
        .build()?)
}

/// Check accessKey without opening a deployment session.
pub async fn check_identity(access_key: &str) -> Result<()> {
    check_identity_at(
        &http_client()?,
        AUTHENTICATION_URL,
        IDENTITY_URL,
        access_key,
    )
    .await
}

async fn check_identity_at(
    client: &reqwest::Client,
    openapi_url: &str,
    identity_url: &str,
    access_key: &str,
) -> Result<()> {
    let response = client
        .get(openapi_url)
        .bearer_auth(access_key)
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("Core OpenAPI is unreachable"))?;
    if matches!(
        response.status(),
        StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
    ) {
        let response = client
            .get(identity_url)
            .bearer_auth(access_key)
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("Core identity endpoint is unreachable"))?;
        read_identity_body(response, "Core identity endpoint").await?;
        return Ok(());
    }
    let bytes = read_identity_body(response, "Core OpenAPI").await?;
    #[derive(Deserialize)]
    struct Response {
        code: i32,
    }
    let response: Response = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid Core OpenAPI response"))?;
    ensure!(
        response.code == 0,
        "Core OpenAPI returned code {}",
        response.code
    );
    Ok(())
}

async fn read_identity_body(response: reqwest::Response, endpoint: &str) -> Result<Vec<u8>> {
    ensure!(
        response.status().is_success(),
        "{endpoint} returned HTTP {}",
        response.status().as_u16()
    );
    let mut bytes = Vec::new();
    let mut body = response.bytes_stream();
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|_| anyhow::anyhow!("cannot read {endpoint} response"))?;
        ensure!(
            bytes.len() + chunk.len() <= 16 * 1024,
            "{endpoint} response exceeds limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

pub(crate) enum Connection {
    DeployV2(Socket),
    ClientV1(Socket),
}

pub(crate) async fn connect_core(access_key: &str, client_id: &str) -> Result<Connection> {
    match connect_deploy_v2(DEPLOY_V2_URL, access_key, client_id).await? {
        Some(socket) => Ok(Connection::DeployV2(socket)),
        None => Ok(Connection::ClientV1(
            connect(CONNECT_URL, access_key)
                .await
                .context("Core deployment v2 was unavailable or rejected Bearer authentication")?,
        )),
    }
}

pub(crate) async fn connect_deploy_v2(
    url: &str,
    access_key: &str,
    client_id: &str,
) -> Result<Option<Socket>> {
    let mut url = Url::parse(url).context("invalid deployment endpoint")?;
    url.query_pairs_mut().append_pair("clientId", client_id);
    let request = authenticated_request(url.as_str(), access_key)?;
    match upgrade(request).await? {
        Ok((socket, _)) => Ok(Some(socket)),
        // Older Core releases only recognize credentials in the query string and return 401.
        Err(Error::Http(response))
            if matches!(
                response.status(),
                StatusCode::NOT_FOUND | StatusCode::UNAUTHORIZED
            ) =>
        {
            Ok(None)
        }
        Err(Error::Http(response)) => anyhow::bail!(
            "Core deployment handshake returned HTTP {}",
            response.status().as_u16()
        ),
        Err(_) => anyhow::bail!("Core deployment WebSocket connection failed"),
    }
}

pub(crate) async fn connect(url: &str, access_key: &str) -> Result<Socket> {
    let request = authenticated_request(url, access_key)?;
    let (socket, _) = upgrade(request).await?.map_err(|_| {
        anyhow::anyhow!("WebSocket connection failed; verify network and accessKey")
    })?;
    Ok(socket)
}

fn authenticated_request(url: &str, access_key: &str) -> Result<Request> {
    let mut request = url
        .into_client_request()
        .map_err(|_| anyhow::anyhow!("invalid deployment handshake"))?;
    let mut credential = HeaderValue::from_str(&format!("Bearer {access_key}"))
        .map_err(|_| anyhow::anyhow!("invalid accessKey header"))?;
    credential.set_sensitive(true);
    request.headers_mut().insert(AUTHORIZATION, credential);
    Ok(request)
}

async fn upgrade(mut request: Request) -> Result<std::result::Result<(Socket, Response), Error>> {
    request
        .headers_mut()
        .insert("User-Agent", HeaderValue::from_static(USER_AGENT));
    let mut limits = WebSocketConfig::default();
    limits.max_message_size = Some(MAX_MESSAGE_BYTES);
    limits.max_frame_size = Some(MAX_MESSAGE_BYTES);
    timeout(
        Duration::from_secs(15),
        tokio_tungstenite::connect_async_with_config(request, Some(limits), false),
    )
    .await
    .context("connection timed out")
}

pub(crate) fn encode(message: &impl Serialize) -> Result<String> {
    let encoded = serde_json::to_string(message)?;
    ensure!(
        encoded.len() <= MAX_MESSAGE_BYTES,
        "outbound protocol message exceeds {MAX_MESSAGE_BYTES} bytes"
    );
    Ok(encoded)
}

pub(crate) async fn send(socket: &mut Socket, message: &impl Serialize) -> Result<()> {
    let encoded = encode(message)?;
    timeout(
        Duration::from_secs(10),
        socket.send(Message::Text(encoded.into())),
    )
    .await
    .context("server write timed out")?
    .map_err(|_| anyhow::anyhow!("server connection closed while writing"))
}

pub(crate) fn decode(text: &str) -> Result<ServerMessage> {
    ensure!(text.len() <= MAX_MESSAGE_BYTES, "message exceeds limit");
    let message: ServerMessage =
        serde_json::from_str(text).map_err(|_| anyhow::anyhow!("malformed server message"))?;
    message.validate()?;
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::{
        Message,
        handshake::server::{ErrorResponse, Request, Response},
    };

    // tungstenite requires this exact by-value HTTP error response in its callback.
    #[allow(clippy::result_large_err)]
    #[tokio::test]
    async fn handshake_uses_header_and_accepts_public_json_contract() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_hdr_async(
                tcp,
                |request: &Request, response: Response| {
                    assert_eq!(request.headers()[AUTHORIZATION], "Bearer test-access-key");
                    assert!(request.uri().query().is_none());
                    Ok(response)
                },
            )
            .await
            .unwrap();
            socket
                .send(Message::Text(
                    r#"{"type":"welcome","protocol_version":1,"heartbeat_seconds":30}"#.into(),
                ))
                .await
                .unwrap();
        });
        let mut client = connect(&format!("ws://{addr}/client/v1/connect"), "test-access-key")
            .await
            .unwrap();
        let message = client.next().await.unwrap().unwrap();
        assert!(matches!(
            decode(message.to_text().unwrap()).unwrap(),
            ServerMessage::Welcome {
                protocol_version: 1,
                ..
            }
        ));
        server.await.unwrap();
    }

    #[allow(clippy::result_large_err)]
    #[tokio::test]
    async fn v2_handshake_allows_fallback_for_older_core() {
        for status in [StatusCode::NOT_FOUND, StatusCode::UNAUTHORIZED] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let error = tokio_tungstenite::accept_hdr_async(
                    stream,
                    |request: &Request, _: Response| {
                        assert_eq!(request.uri().query(), Some("clientId=test-client"));
                        assert_eq!(request.headers()[AUTHORIZATION], "Bearer test-key");
                        let mut response = ErrorResponse::new(None);
                        *response.status_mut() = status;
                        Err(response)
                    },
                )
                .await;
                assert!(error.is_err());
            });
            let v2 = connect_deploy_v2(
                &format!("ws://{addr}/deploy/v2/ws"),
                "test-key",
                "test-client",
            )
            .await
            .unwrap();
            assert!(v2.is_none());
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn doctor_falls_back_when_openapi_route_is_missing() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            for (path, status) in [
                ("/openapi/v1/cert?size=1", "404 Not Found"),
                ("/client/v1/identity", "200 OK"),
            ] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(stream.read_u8().await.unwrap());
                }
                let request = String::from_utf8(request).unwrap();
                assert!(request.starts_with(&format!("GET {path} HTTP/1.1\r\n")));
                assert!(request.contains("authorization: Bearer test-key\r\n"));
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            }
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        check_identity_at(
            &client,
            &format!("{base}/openapi/v1/cert?size=1"),
            &format!("{base}/client/v1/identity"),
            "test-key",
        )
        .await
        .unwrap();
        server.await.unwrap();
    }

    #[test]
    fn malformed_input_errors_do_not_include_private_material() {
        let error = decode(r#"{"type":"deploy","generation":"private-key-material"}"#)
            .err()
            .unwrap();
        assert!(!error.to_string().contains("private-key-material"));
    }
}

//! Bounded HTTP and authenticated WebSocket transport.

use anyhow::{Context, Result, ensure};
use certkite_protocol::MAX_MESSAGE_BYTES;
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
        http::{HeaderValue, header::AUTHORIZATION},
        protocol::WebSocketConfig,
    },
};

const AUTHENTICATION_URL: &str = "https://certkite.com/openapi/v1/cert?size=1";
const DEPLOYMENT_URL: &str = "wss://certkite.com/deploy/v2/ws";
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
    check_identity_at(&http_client()?, AUTHENTICATION_URL, access_key).await
}

async fn check_identity_at(client: &reqwest::Client, url: &str, access_key: &str) -> Result<()> {
    let response = client
        .get(url)
        .bearer_auth(access_key)
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("Core OpenAPI is unreachable"))?;
    let bytes = read_identity_body(response).await?;
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

async fn read_identity_body(response: reqwest::Response) -> Result<Vec<u8>> {
    ensure!(
        response.status().is_success(),
        "Core OpenAPI returned HTTP {}",
        response.status().as_u16()
    );
    let mut bytes = Vec::new();
    let mut body = response.bytes_stream();
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|_| anyhow::anyhow!("cannot read Core OpenAPI response"))?;
        ensure!(
            bytes.len() + chunk.len() <= 16 * 1024,
            "Core OpenAPI response exceeds limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

pub(crate) async fn connect_core(access_key: &str, client_id: &str) -> Result<Socket> {
    connect(DEPLOYMENT_URL, access_key, client_id).await
}

pub(crate) async fn connect(url: &str, access_key: &str, client_id: &str) -> Result<Socket> {
    let mut url = Url::parse(url).context("invalid deployment endpoint")?;
    url.query_pairs_mut().append_pair("clientId", client_id);
    let request = authenticated_request(url.as_str(), access_key)?;
    match upgrade(request).await? {
        Ok((socket, _)) => Ok(socket),
        Err(Error::Http(response)) => anyhow::bail!(
            "Core deployment handshake returned HTTP {}",
            response.status().as_u16()
        ),
        Err(_) => anyhow::bail!("Core deployment WebSocket connection failed"),
    }
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

fn encode(message: &impl Serialize) -> Result<String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_tungstenite::tungstenite::{
        handshake::server::{ErrorResponse, Request, Response},
        http::StatusCode,
    };

    // tungstenite requires this exact by-value HTTP error response in its callback.
    #[allow(clippy::result_large_err)]
    #[tokio::test]
    async fn deployment_handshake_reports_rejected_http_status() {
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
            let error = connect(
                &format!("ws://{addr}/deploy/v2/ws"),
                "test-key",
                "test-client",
            )
            .await
            .unwrap_err();
            assert_eq!(
                error.to_string(),
                format!(
                    "Core deployment handshake returned HTTP {}",
                    status.as_u16()
                )
            );
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn doctor_uses_core_openapi_for_authentication() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://{}/openapi/v1/cert?size=1",
            listener.local_addr().unwrap()
        );
        let server = tokio::spawn(async move {
            for (status, body) in [("200 OK", r#"{"code":0}"#), ("404 Not Found", "")] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(stream.read_u8().await.unwrap());
                }
                let request = String::from_utf8(request).unwrap();
                assert!(request.starts_with("GET /openapi/v1/cert?size=1 HTTP/1.1\r\n"));
                assert!(request.contains("authorization: Bearer test-key\r\n"));
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
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
        check_identity_at(&client, &url, "test-key").await.unwrap();
        let error = check_identity_at(&client, &url, "test-key")
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "Core OpenAPI returned HTTP 404");
        server.await.unwrap();
    }

    #[test]
    fn outbound_messages_obey_the_protocol_size_limit() {
        assert!(encode(&"a".repeat(MAX_MESSAGE_BYTES - 2)).is_ok());
        assert!(encode(&"a".repeat(MAX_MESSAGE_BYTES - 1)).is_err());
    }
}

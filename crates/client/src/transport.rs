//! Bounded HTTP and authenticated WebSocket transport.

use anyhow::{Context, Result, ensure};
use certkite_protocol::{MAX_MESSAGE_BYTES, ServerMessage};
use futures_util::StreamExt;
use reqwest::redirect::Policy;
use tokio::{
    net::TcpStream,
    time::{Duration, timeout},
};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream,
    tungstenite::{
        client::IntoClientRequest,
        http::{HeaderValue, header::AUTHORIZATION},
        protocol::WebSocketConfig,
    },
};

/// TLS-only identity endpoint used by diagnostics.
pub const IDENTITY_URL: &str = "https://certkite.com/client/v1/identity";
/// Fixed WebSocket endpoint; no configuration or environment override exists.
pub const CONNECT_URL: &str = "wss://certkite.com/client/v1/connect";

pub(crate) type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// HTTP client with bounded time and no cross-origin credential redirects.
pub fn http_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .https_only(true)
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("certkite-client/", env!("CARGO_PKG_VERSION")))
        .build()?)
}

/// Check authentication without creating or registering a node.
pub async fn check_identity(access_key: &str) -> Result<()> {
    let response = http_client()?
        .get(IDENTITY_URL)
        .bearer_auth(access_key)
        .send()
        .await
        .context("identity endpoint is unreachable")?;
    ensure!(
        response.status().is_success(),
        "identity endpoint returned HTTP {}",
        response.status().as_u16()
    );
    let mut received = 0usize;
    let mut body = response.bytes_stream();
    while let Some(chunk) = body.next().await {
        received += chunk.context("cannot read identity response")?.len();
        ensure!(received <= 16 * 1024, "identity response exceeds limit");
    }
    Ok(())
}

pub(crate) async fn connect(url: &str, access_key: &str) -> Result<Socket> {
    let mut request = url
        .into_client_request()
        .context("invalid compiled connection endpoint")?;
    let mut credential = HeaderValue::from_str(&format!("Bearer {access_key}"))
        .map_err(|_| anyhow::anyhow!("invalid accessKey header"))?;
    credential.set_sensitive(true);
    request.headers_mut().insert(AUTHORIZATION, credential);
    request.headers_mut().insert(
        "User-Agent",
        HeaderValue::from_static(concat!("certkite-client/", env!("CARGO_PKG_VERSION"))),
    );
    let mut limits = WebSocketConfig::default();
    limits.max_message_size = Some(MAX_MESSAGE_BYTES);
    limits.max_frame_size = Some(MAX_MESSAGE_BYTES);
    let (socket, _) = timeout(
        Duration::from_secs(15),
        tokio_tungstenite::connect_async_with_config(request, Some(limits), false),
    )
    .await
    .context("connection timed out")?
    .map_err(|_| anyhow::anyhow!("WebSocket connection failed; verify network and accessKey"))?;
    Ok(socket)
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
        handshake::server::{Request, Response},
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

    #[test]
    fn malformed_input_errors_do_not_include_private_material() {
        let error = decode(r#"{"type":"deploy","generation":"private-key-material"}"#)
            .err()
            .unwrap();
        assert!(!error.to_string().contains("private-key-material"));
    }
}

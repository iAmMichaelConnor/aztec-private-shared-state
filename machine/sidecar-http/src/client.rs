//! A small JSON client of the node API over mutual TLS: one connection per
//! call, HTTP/1.1. The tests drive the nodes with it, and it is the shape of
//! the orchestrator's node leg. Its one HTTP exchange ([`exchange`]) is also
//! the chain reader's JSON-RPC transport (sidecar-tip's `rpc`), over plain
//! TCP or TLS. Every answer body is read under a size cap the caller gives:
//! a peer that streams more fails the call instead of filling memory.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use eyre::Context;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::Method;
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use serde::Serialize;
use serde::de::DeserializeOwned;
use sidecar_core::Refusal;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// A client of one node's API.
#[derive(Clone)]
pub struct ApiClient {
    /// `host:port`, resolved at each connect.
    addr: String,
    server_name: ServerName<'static>,
    tls: TlsConnector,
    /// The bound on one whole call, when set.
    timeout: Option<Duration>,
    /// The largest answer body a call reads ([`DEFAULT_MAX_ANSWER_BYTES`]
    /// unless set).
    max_answer: usize,
}

// Operator knob: DESIGN.md, "Configuration reference" (answer size caps; no
// knob). The default cap of an [`ApiClient`] call: twice the node listener's
// 32 MiB body limit, the largest answer class (a registry row carries a
// circuit a node accepted in a body). Callers that know their route class
// lower it ([`ApiClient::with_max_answer`]).
/// The largest answer body an [`ApiClient`] reads by default.
pub const DEFAULT_MAX_ANSWER_BYTES: usize = 64 * 1024 * 1024;

/// An answer: the HTTP status and the body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Answer {
    /// The body as `T` when the status is 200, else the refusal it carries.
    pub fn json<T: DeserializeOwned>(&self) -> eyre::Result<Result<T, Refusal>> {
        let text = std::str::from_utf8(&self.body).context("the answer is not UTF-8")?;
        if self.status == 200 {
            Ok(Ok(serde_json::from_str(text)
                .with_context(|| format!("parsing the answer `{text}`"))?))
        } else {
            let refusal: Refusal = serde_json::from_str(text)
                .with_context(|| format!("parsing the {} answer `{text}`", self.status))?;
            // A listener's transport refusals (413 for a body over its
            // limit, 408 for one that did not arrive in time) carry the
            // class `bad_request` under their own HTTP status, and a full
            // waiting room (503, `crate::respond::busy`) the class
            // `mpc_failure`.
            let transport = match self.status {
                408 | 413 => refusal.class == sidecar_core::ErrorClass::BadRequest,
                503 => refusal.class == sidecar_core::ErrorClass::MpcFailure,
                _ => false,
            };
            eyre::ensure!(
                refusal.status() == self.status || transport,
                "a {} answer carries the class {}",
                self.status,
                refusal.class
            );
            Ok(Err(refusal))
        }
    }
}

impl ApiClient {
    /// A client of the node at `addr`, whose certificate must name
    /// `server_name`, over `tls` ([`crate::tls::client_config`]).
    pub fn new(addr: SocketAddr, server_name: &str, tls: Arc<ClientConfig>) -> eyre::Result<Self> {
        Self::to_host(addr.to_string(), server_name, tls)
    }

    /// A client of the node at `host_port`, resolved at every connect (each
    /// address the name resolves to tried in turn), so a node whose address
    /// changes is reached without a restart.
    pub fn to_host(
        host_port: String,
        server_name: &str,
        tls: Arc<ClientConfig>,
    ) -> eyre::Result<Self> {
        Ok(ApiClient {
            addr: host_port,
            server_name: ServerName::try_from(server_name.to_string())
                .with_context(|| format!("server name `{server_name}`"))?,
            tls: TlsConnector::from(tls),
            timeout: None,
            max_answer: DEFAULT_MAX_ANSWER_BYTES,
        })
    }

    /// The same client with every call bounded by `timeout`, from the
    /// connect to the last byte of the answer.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// The same client reading at most `bytes` of each answer body.
    pub fn with_max_answer(mut self, bytes: usize) -> Self {
        self.max_answer = bytes;
        self
    }

    /// One call. Fails when the connection, the TLS handshake (a refused
    /// client certificate, for instance) or HTTP fails, when the answer body
    /// is larger than the client's cap, or when the call takes longer than
    /// the client's timeout.
    pub async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> eyre::Result<Answer> {
        match self.timeout {
            None => self.call_once(method, path, body).await,
            Some(limit) => tokio::time::timeout(limit, self.call_once(method, path, body))
                .await
                .unwrap_or_else(|_| {
                    Err(eyre::eyre!(
                        "{} {path}: no answer within {limit:?}",
                        self.addr
                    ))
                }),
        }
    }

    async fn call_once(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> eyre::Result<Answer> {
        let tcp = TcpStream::connect(self.addr.as_str())
            .await
            .with_context(|| format!("connecting to {}", self.addr))?;
        let tls = self
            .tls
            .connect(self.server_name.clone(), tcp)
            .await
            .context("the TLS handshake failed")?;
        exchange(tls, method, path, &self.addr, body, self.max_answer).await
    }

    pub async fn get(&self, path: &str) -> eyre::Result<Answer> {
        self.call(Method::GET, path, None).await
    }

    pub async fn post<T: Serialize + ?Sized>(&self, path: &str, body: &T) -> eyre::Result<Answer> {
        self.call(Method::POST, path, Some(serde_json::to_vec(body)?))
            .await
    }

    /// POST a body that is already JSON text.
    pub async fn post_raw(&self, path: &str, body: impl Into<Vec<u8>>) -> eyre::Result<Answer> {
        self.call(Method::POST, path, Some(body.into())).await
    }
}

/// One HTTP/1.1 request on `stream`, a fresh connection (plain TCP or TLS):
/// `method path` with `Host: host` and, with a body, as JSON; the answer's
/// status and whole body, read up to `max_answer` bytes. The connection
/// closes after the answer. Fails when the HTTP handshake, the request or
/// reading the answer fails, or when the answer body (declared or sent) is
/// larger than `max_answer`.
pub async fn exchange<S>(
    stream: S,
    method: Method,
    path: &str,
    host: &str,
    body: Option<Vec<u8>>,
    max_answer: usize,
) -> eyre::Result<Answer>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .context("the HTTP handshake failed")?;
    let conn = tokio::spawn(conn);
    let mut builder = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header(hyper::header::HOST, host);
    if body.is_some() {
        builder = builder.header(hyper::header::CONTENT_TYPE, "application/json");
    }
    let request = builder.body(Full::new(Bytes::from(body.unwrap_or_default())))?;
    let response = match sender.send_request(request).await {
        Ok(response) => response,
        // The connection ended before it took the request: its own error (a
        // TLS alert the server sent, for one) is the cause, not the
        // cancellation.
        Err(e) if e.is_canceled() => {
            return Err(match conn.await {
                Ok(Err(cause)) => eyre::Error::new(cause),
                _ => eyre::Error::new(e),
            }
            .wrap_err("the request failed"));
        }
        Err(e) => return Err(eyre::Error::new(e).wrap_err("the request failed")),
    };
    let status = response.status().as_u16();
    let too_large = || eyre::eyre!("the answer is larger than the {max_answer}-byte cap");
    let declared = response
        .headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > max_answer as u64) {
        conn.abort();
        return Err(too_large());
    }
    let body = match Limited::new(response.into_body(), max_answer)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes().to_vec(),
        Err(e) => {
            conn.abort();
            if e.downcast_ref::<LengthLimitError>().is_some() {
                return Err(too_large());
            }
            return Err(eyre::eyre!("reading the answer: {e}"));
        }
    };
    drop(sender);
    let _ = conn.await;
    Ok(Answer { status, body })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A server that answers one request on a fresh connection with
    /// `head` and then `body`, written in pieces.
    async fn answer_once(head: &'static str, body: Vec<u8>) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _ = tcp.read(&mut request).await;
            let _ = tcp.write_all(head.as_bytes()).await;
            for piece in body.chunks(4096) {
                if tcp.write_all(piece).await.is_err() {
                    return;
                }
            }
        });
        addr
    }

    async fn get(addr: std::net::SocketAddr, cap: usize) -> eyre::Result<Answer> {
        let tcp = TcpStream::connect(addr).await.unwrap();
        exchange(tcp, Method::GET, "/", "localhost", None, cap).await
    }

    /// An answer body over the caller's cap fails the call, whether its
    /// length is declared or it is streamed without one; one within the cap
    /// is read whole.
    #[tokio::test]
    async fn an_answer_over_the_cap_is_refused() {
        let declared = answer_once(
            "HTTP/1.1 200 OK\r\ncontent-length: 100000\r\n\r\n",
            vec![b'x'; 100_000],
        )
        .await;
        let err = get(declared, 1000).await.unwrap_err();
        assert!(
            format!("{err:#}").contains("larger than the 1000-byte cap"),
            "{err:#}"
        );

        // Close-delimited: no length, the body runs until the server closes.
        let streamed = answer_once(
            "HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n",
            vec![b'y'; 100_000],
        )
        .await;
        let err = get(streamed, 1000).await.unwrap_err();
        assert!(
            format!("{err:#}").contains("larger than the 1000-byte cap"),
            "{err:#}"
        );

        let small = answer_once(
            "HTTP/1.1 200 OK\r\ncontent-length: 3\r\n\r\n",
            b"abc".to_vec(),
        )
        .await;
        let answer = get(small, 1000).await.unwrap();
        assert_eq!((answer.status, answer.body.as_slice()), (200, &b"abc"[..]));
    }
}

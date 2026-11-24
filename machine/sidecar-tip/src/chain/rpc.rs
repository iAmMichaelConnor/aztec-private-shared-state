//! The JSON-RPC call to one Aztec node ([`Transport`]: `method`, with its
//! `node_` prefix, and its positional `params`, answering the response's
//! `result`) and its client over HTTP(S), [`HttpTransport`]: `POST <url>`
//! with `{"jsonrpc": "2.0", "id", "method": "node_<name>", "params": [...]}`,
//! one connection per call, HTTP/1.1 through sidecar-http's client exchange
//! (the one the node API client makes), plain for `http://` and through
//! tokio-rustls for `https://`. Tests answer from recorded bodies or from an
//! in-memory node ([`crate::testing`]).

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use hyper::{Method, Uri};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use serde_json::{Value, json};
use sidecar_core::Fr;
use sidecar_core::field::fr_from_hex;
use sidecar_http::client::{Answer, exchange};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::ReadError;

/// Why a call to the node gave no result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RpcError {
    /// No answer: connect, TLS, HTTP or the timeout failed.
    Transport(String),
    /// The node answered with a JSON-RPC error object.
    Node { code: i64, message: String },
    /// The answer is not a JSON-RPC response.
    Malformed(String),
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::Transport(e) => write!(f, "no answer from the Aztec node: {e}"),
            RpcError::Node { code, message } => {
                write!(f, "the Aztec node refused ({code}): {message}")
            }
            RpcError::Malformed(e) => write!(f, "the Aztec node's answer is not JSON-RPC: {e}"),
        }
    }
}

impl std::error::Error for RpcError {}

/// One JSON-RPC call: `method` and its positional `params`, answering the
/// response's `result`.
pub trait Transport: Send + Sync {
    fn call(
        &self,
        method: &str,
        params: Value,
    ) -> impl Future<Output = Result<Value, RpcError>> + Send;
}

/// A shared transport: a reader and a test that writes the chain hold the
/// same one.
impl<T: Transport + ?Sized> Transport for Arc<T> {
    fn call(
        &self,
        method: &str,
        params: Value,
    ) -> impl Future<Output = Result<Value, RpcError>> + Send {
        (**self).call(method, params)
    }
}

/// The `result` of a JSON-RPC response body, or its `error`.
pub fn response_result(body: Value) -> Result<Value, RpcError> {
    let Value::Object(mut map) = body else {
        return Err(RpcError::Malformed(format!("{body} is not an object")));
    };
    if let Some(error) = map.remove("error") {
        let code = error.get("code").and_then(Value::as_i64).unwrap_or(0);
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| error.to_string());
        return Err(RpcError::Node { code, message });
    }
    map.remove("result")
        .ok_or_else(|| RpcError::Malformed("neither result nor error".into()))
}

pub(crate) async fn call<T: Transport + ?Sized>(
    node: &T,
    method: &'static str,
    params: Value,
) -> Result<Value, ReadError> {
    node.call(method, params)
        .await
        .map_err(|error| ReadError::Rpc { method, error })
}

pub(crate) fn field(method: &'static str, value: &Value) -> Result<Fr, ReadError> {
    let text = value
        .as_str()
        .ok_or_else(|| malformed(method, format!("{value} is not a field")))?;
    fr_from_hex(text).map_err(|e| malformed(method, format!("{text}: {e}")))
}

pub(crate) fn number(method: &'static str, value: &Value, key: &str) -> Result<u64, ReadError> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| malformed(method, format!("no {key} in {value}")))
}

pub(crate) fn malformed(method: &'static str, detail: impl Into<String>) -> ReadError {
    ReadError::Malformed {
        method,
        detail: detail.into(),
    }
}

// Operator knob: DESIGN.md, "Configuration reference" (Aztec node RPC
// timeout). Every call, from the connect to the last byte of the answer, is
// bounded by 10 s; `HttpTransport::with_timeout` changes it.
pub const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(10);

// Operator knob: DESIGN.md, "Configuration reference" (Aztec node answer
// cap; no knob). The largest answer the reader takes is a tag query's: up to
// 100 tags of 20 logs each, a few MiB; 16 MiB leaves room and keeps a hostile
// or on-path node from filling memory.
/// The largest JSON-RPC answer body the reader reads.
pub const DEFAULT_RPC_MAX_ANSWER: usize = 16 * 1024 * 1024;

/// `url` as a log or an error shows an Aztec node URL: its scheme, host and
/// port only, without a user, password, path, query or fragment, any of
/// which may carry an API key.
pub fn url_origin(url: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((scheme, rest)) => (Some(scheme), rest),
        None => (None, url),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    match scheme {
        Some(scheme) => format!("{scheme}://{host}"),
        None => host.to_string(),
    }
}

/// A [`Transport`] over HTTP(S) to one node URL.
#[derive(Clone)]
pub struct HttpTransport {
    uri: Uri,
    /// The URL as errors show it ([`url_origin`]).
    origin: String,
    host: String,
    port: u16,
    tls: Option<TlsConnector>,
    timeout: Duration,
    next_id: Arc<AtomicU64>,
}

impl HttpTransport {
    /// A client of the node at `url` (`http://host:port[/path]`). An
    /// `https://` URL needs [`HttpTransport::with_tls`].
    pub fn new(url: &str) -> Result<Self, RpcError> {
        let origin = url_origin(url);
        let uri: Uri = url
            .parse()
            .map_err(|e| RpcError::Transport(format!("node URL `{origin}`: {e}")))?;
        let secure = match uri.scheme_str() {
            Some("http") => false,
            Some("https") => true,
            _ => {
                return Err(RpcError::Transport(format!(
                    "node URL `{origin}`: not http or https"
                )));
            }
        };
        let host = uri
            .host()
            .ok_or_else(|| RpcError::Transport(format!("node URL `{origin}` has no host")))?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let port = uri.port_u16().unwrap_or(if secure { 443 } else { 80 });
        Ok(HttpTransport {
            uri,
            origin,
            host,
            port,
            tls: None,
            timeout: DEFAULT_RPC_TIMEOUT,
            next_id: Arc::new(AtomicU64::new(1)),
        })
    }

    /// The same client over TLS with `config` (its roots decide which node
    /// certificates are accepted; the node's host name is checked).
    pub fn with_tls(mut self, config: Arc<ClientConfig>) -> Self {
        self.tls = Some(TlsConnector::from(config));
        self
    }

    /// The same client with every call bounded by `timeout`.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    async fn post(&self, body: Vec<u8>) -> Result<Value, RpcError> {
        let tcp = TcpStream::connect((self.host.as_str(), self.port))
            .await
            .map_err(|e| RpcError::Transport(format!("connecting to {}: {e}", self.origin)))?;
        match (self.uri.scheme_str(), &self.tls) {
            (Some("https"), Some(tls)) => {
                let name = ServerName::try_from(self.host.clone()).map_err(|e| {
                    RpcError::Transport(format!("server name `{}`: {e}", self.host))
                })?;
                let stream = tls.connect(name, tcp).await.map_err(|e| {
                    RpcError::Transport(format!("TLS handshake with {}: {e}", self.origin))
                })?;
                self.exchange(stream, body).await
            }
            (Some("https"), None) => Err(RpcError::Transport(format!(
                "{} is https and the reader has no TLS configuration",
                self.origin
            ))),
            _ => self.exchange(tcp, body).await,
        }
    }

    /// The one HTTP exchange, and the answer's body as JSON.
    async fn exchange<S>(&self, stream: S, body: Vec<u8>) -> Result<Value, RpcError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let path = self.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let authority = self
            .uri
            .authority()
            .map(|a| a.as_str().to_string())
            .unwrap_or_else(|| self.host.clone());
        let Answer { status, body } = exchange(
            stream,
            Method::POST,
            path,
            &authority,
            Some(body),
            DEFAULT_RPC_MAX_ANSWER,
        )
        .await
        .map_err(|e| RpcError::Transport(format!("{}: {e:#}", self.origin)))?;
        // The node answers JSON-RPC errors with a JSON body under an HTTP
        // error status too; read the body whenever it parses.
        match serde_json::from_slice::<Value>(&body) {
            Ok(value) => Ok(value),
            Err(e) => Err(RpcError::Transport(format!(
                "HTTP {status}: {e}: {}",
                String::from_utf8_lossy(&body[..body.len().min(200)])
            ))),
        }
    }
}

impl Transport for HttpTransport {
    async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }))
        .map_err(|e| RpcError::Malformed(e.to_string()))?;
        let answer = tokio::time::timeout(self.timeout, self.post(body))
            .await
            .map_err(|_| {
                RpcError::Transport(format!("{method}: no answer within {:?}", self.timeout))
            })??;
        response_result(answer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_parse() {
        let t = HttpTransport::new("http://127.0.0.1:10280").unwrap();
        assert_eq!((t.host.as_str(), t.port), ("127.0.0.1", 10280));
        let t = HttpTransport::new("https://node.example/rpc").unwrap();
        assert_eq!((t.host.as_str(), t.port), ("node.example", 443));
        assert!(HttpTransport::new("ftp://x").is_err());
        assert!(HttpTransport::new("not a url").is_err());
    }

    #[test]
    fn a_shown_aztec_node_url_carries_no_credentials() {
        for (url, shown) in [
            ("http://127.0.0.1:8080", "http://127.0.0.1:8080"),
            (
                "https://user:secret@node.example:443/v1/key123?apikey=k#f",
                "https://node.example:443",
            ),
            ("https://node.example?token=t", "https://node.example"),
            ("node.example:8080/key123", "node.example:8080"),
        ] {
            assert_eq!(url_origin(url), shown);
        }
        let err = HttpTransport::new("ftp://user:secret@x/key123")
            .err()
            .unwrap()
            .to_string();
        assert!(!err.contains("secret") && !err.contains("key123"), "{err}");
    }

    #[tokio::test]
    async fn a_closed_port_is_a_transport_error() {
        // nothing listens on port 9 of localhost: the connect fails first
        let t = HttpTransport::new("http://127.0.0.1:9")
            .unwrap()
            .with_timeout(Duration::from_secs(2));
        assert!(matches!(
            t.call("node_getBlockNumber", json!([])).await,
            Err(RpcError::Transport(_))
        ));
    }

    #[test]
    fn responses_split_into_result_and_error() {
        assert_eq!(
            response_result(json!({"jsonrpc": "2.0", "id": 1, "result": 4})),
            Ok(json!(4))
        );
        assert_eq!(
            response_result(json!({"error": {"code": -32702, "message": "Block not found"}})),
            Err(RpcError::Node {
                code: -32702,
                message: "Block not found".into()
            })
        );
        assert!(matches!(
            response_result(json!([])),
            Err(RpcError::Malformed(_))
        ));
    }
}

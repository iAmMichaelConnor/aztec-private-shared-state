//! The listener both binaries serve their API on: TLS connections accepted
//! under a handshake budget and, once their handshake is done, a connection
//! cap, each served by hyper with a header-read bound,
//! every request body read whole under a size and time limit before a route
//! runs, and every write of an answer bounded by [`WRITE_STALL_TIMEOUT`], so
//! a client that stops reading does not hold its connection slot. The node's
//! mutual-TLS listener and the orchestrator's public listener differ only in
//! the values they pass.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Router;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use http_body_util::{BodyExt, LengthLimitError, Limited};
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use sidecar_core::Refusal;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::Sleep;
use tokio_rustls::TlsAcceptor;

// Operator knob: DESIGN.md, "Configuration reference" (listener transport
// bounds). A connection that has not finished its TLS handshake in 10 s is closed.
/// How long a client has to complete its TLS handshake.
pub const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

// Operator knob: DESIGN.md, "Configuration reference" (listener transport
// bounds; no knob). An answer the client does not take for 30 s (a write or
// flush that makes no progress that long) ends the connection: a client
// that stops reading would otherwise hold its slot under the connection cap
// for as long as it keeps the TCP connection open.
/// How long one write of an answer may wait for the client to read.
const WRITE_STALL_TIMEOUT: Duration = Duration::from_secs(30);

// Operator knob: DESIGN.md, "Configuration reference" (listener transport
// bounds). One loop for the node's mutual-TLS listener and the orchestrator's
// public one, each with its own values; hyper applies `header_read` only with a
// timer, so [`serve`] gives it hyper-util's tokio timer. A connection counts
// against `max_connections` only once its TLS handshake is done, so at the
// node only a holder of a client certificate the CA signed takes one; until
// then it counts against `max_handshakes`, which anyone who reaches the port
// can fill with silent connections, each for `tls_handshake`.
/// How long a connection may take over its handshake and each request head,
/// how many connections a listener serves at once, and how many it takes
/// through their handshake (or waits on a free connection slot for) at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListenerLimits {
    pub tls_handshake: Duration,
    pub header_read: Duration,
    pub max_connections: usize,
    pub max_handshakes: usize,
}

/// The largest body a router accepts and how long the body may take to
/// arrive once the head is read; enforced by [`read_body`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BodyLimits {
    pub max_bytes: usize,
    pub read_timeout: Duration,
}

/// `router` with every request body read under `limits` before a route runs
/// ([`read_body`]). The routes' own extractor limit is off: the body they see
/// is already whole and within the limit.
pub fn limit_bodies<S: Clone + Send + Sync + 'static>(
    router: Router<S>,
    limits: BodyLimits,
) -> Router<S> {
    router
        .layer(middleware::from_fn_with_state(limits, read_body))
        .layer(DefaultBodyLimit::disable())
}

/// A transport refusal: `status` (413, 408) with the one error shape and the
/// class `bad_request`.
fn transport_refusal(status: StatusCode, message: String) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        Refusal::bad_request(message).to_json(),
    )
        .into_response()
}

/// Read the whole body under `limits`, then run the route on it: 413 for a
/// body over `max_bytes` (declared or sent), 408 for one not in within
/// `read_timeout`, 400 for a body the connection fails to deliver.
pub async fn read_body(
    State(limits): State<BodyLimits>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let too_large = || {
        transport_refusal(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "body: larger than this listener's limit of {} bytes",
                limits.max_bytes
            ),
        )
    };
    let (parts, body) = request.into_parts();
    let declared = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > limits.max_bytes as u64) {
        return too_large();
    }
    let read = Limited::new(body, limits.max_bytes).collect();
    let bytes = match tokio::time::timeout(limits.read_timeout, read).await {
        Ok(Ok(collected)) => collected.to_bytes(),
        Ok(Err(e)) if e.downcast_ref::<LengthLimitError>().is_some() => return too_large(),
        Ok(Err(e)) => {
            return transport_refusal(StatusCode::BAD_REQUEST, format!("body: {e}"));
        }
        Err(_) => {
            return transport_refusal(
                StatusCode::REQUEST_TIMEOUT,
                format!(
                    "body: not received within {} s of the request head",
                    limits.read_timeout.as_secs()
                ),
            );
        }
    };
    next.run(axum::extract::Request::from_parts(
        parts,
        axum::body::Body::from(bytes),
    ))
    .await
}

/// Accept TLS connections on `listener` and serve `router` on each under
/// `limits`, until the task is aborted. A client whose handshake fails (no
/// certificate, one under another CA, a timeout) is logged and dropped.
pub async fn serve(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    router: Router,
    limits: ListenerLimits,
) {
    let slots = Arc::new(Semaphore::new(limits.max_connections));
    let handshakes = Arc::new(Semaphore::new(limits.max_handshakes));
    loop {
        // A free handshake first: past the budget, new clients wait in the
        // backlog.
        let handshake = handshakes
            .clone()
            .acquire_owned()
            .await
            .expect("the semaphore is never closed");
        let (tcp, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!(error = %e, "API listener: accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let router = router.clone();
        let slots = slots.clone();
        tokio::spawn(async move {
            serve_connection(tcp, peer, acceptor, router, limits, handshake, slots).await;
        });
    }
}

/// Serve one accepted connection: its handshake under the `handshake`
/// permit, then, holding that permit until a connection slot is free, the
/// connection under the slot.
async fn serve_connection(
    tcp: tokio::net::TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    router: Router,
    limits: ListenerLimits,
    handshake: tokio::sync::OwnedSemaphorePermit,
    slots: Arc<Semaphore>,
) {
    let tls = match tokio::time::timeout(limits.tls_handshake, acceptor.accept(tcp)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => {
            tracing::info!(%peer, error = %e, "API: TLS handshake refused");
            return;
        }
        Err(_) => {
            tracing::info!(%peer, "API: TLS handshake timed out");
            return;
        }
    };
    let _slot = slots
        .acquire_owned()
        .await
        .expect("the semaphore is never closed");
    drop(handshake);
    let service = TowerToHyperService::new(router);
    let io = WriteDeadline::new(tls, WRITE_STALL_TIMEOUT);
    if let Err(e) = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_read)
        .serve_connection(TokioIo::new(io), service)
        .await
    {
        tracing::debug!(%peer, error = %e, "API: connection ended with an error");
    }
}

/// A stream whose writes fail (`TimedOut`) once one has made no progress for
/// `stall`: a peer that stops reading ends its connection instead of holding
/// it open. Reads pass through.
struct WriteDeadline<S> {
    inner: S,
    stall: Duration,
    /// Running while a write, flush or shutdown is pending.
    timer: Option<Pin<Box<Sleep>>>,
}

impl<S> WriteDeadline<S> {
    fn new(inner: S, stall: Duration) -> Self {
        WriteDeadline {
            inner,
            stall,
            timer: None,
        }
    }

    /// `polled`, the inner stream's answer to a write-side poll: ready
    /// clears the timer; pending starts it and fails once it runs out.
    fn bound<T>(
        &mut self,
        cx: &mut Context<'_>,
        polled: Poll<std::io::Result<T>>,
    ) -> Poll<std::io::Result<T>> {
        if polled.is_ready() {
            self.timer = None;
            return polled;
        }
        let stall = self.stall;
        let timer = self
            .timer
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(stall)));
        match timer.as_mut().poll(cx) {
            Poll::Ready(()) => {
                self.timer = None;
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("the peer took no data for {} s", stall.as_secs()),
                )))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for WriteDeadline<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WriteDeadline<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, buf);
        self.bound(cx, polled)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let polled = Pin::new(&mut self.inner).poll_flush(cx);
        self.bound(cx, polled)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let polled = Pin::new(&mut self.inner).poll_shutdown(cx);
        self.bound(cx, polled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    // A peer that never reads: the write fails once it has made no progress
    // for the stall bound; while the peer reads, writes go through.
    #[tokio::test]
    async fn a_write_the_peer_never_takes_times_out() {
        let (ours, _theirs) = tokio::io::duplex(64);
        let mut io = WriteDeadline::new(ours, Duration::from_millis(100));
        let started = tokio::time::Instant::now();
        let err = io.write_all(&[0u8; 4096]).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() >= Duration::from_millis(100));

        let (ours, mut reader) = tokio::io::duplex(64);
        let mut io = WriteDeadline::new(ours, Duration::from_millis(100));
        let drain = tokio::spawn(async move {
            let mut sink = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut sink)
                .await
                .unwrap();
            sink.len()
        });
        io.write_all(&[1u8; 4096]).await.unwrap();
        io.shutdown().await.unwrap();
        assert_eq!(drain.await.unwrap(), 4096);
    }
}

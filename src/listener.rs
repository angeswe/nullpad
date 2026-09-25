//! TCP listener that puts a write timeout on every accepted connection.
//!
//! A paste body is streamed from disk while the client reads it. A client
//! that stops reading would otherwise hold the connection, the open file and
//! its blob read slot for as long as it likes. With a write timeout, a socket
//! write that stays blocked for longer than the limit fails with
//! `io::ErrorKind::TimedOut`, hyper drops the connection, and the response
//! body (and the slot it holds) is released.
//!
//! Only writes are timed. Reads have no timeout here, so idle keep-alive
//! connections are not affected.
//!
//! `ConnectInfo<SocketAddr>`: axum implements `Connected` for `SocketAddr`
//! only for its own listener types, and the orphan rule stops this crate from
//! adding an impl for `WriteTimeoutListener`. Callers therefore wrap the
//! listener with a no-op `ListenerExt::tap_io(|_| {})`; axum's `TapIo` impl
//! provides the `SocketAddr` connect info for any listener.

use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio_io_timeout::TimeoutStream;

/// A [`TcpListener`] whose accepted streams time out blocked writes.
#[derive(Debug)]
pub struct WriteTimeoutListener {
    inner: TcpListener,
    write_timeout: Duration,
}

impl WriteTimeoutListener {
    pub fn new(inner: TcpListener, write_timeout: Duration) -> Self {
        Self {
            inner,
            write_timeout,
        }
    }
}

impl axum::serve::Listener for WriteTimeoutListener {
    // TimeoutStream is !Unpin; axum needs an Unpin stream.
    type Io = Pin<Box<TimeoutStream<TcpStream>>>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        // The TcpListener impl retries and logs accept errors.
        let (stream, addr) = axum::serve::Listener::accept(&mut self.inner).await;
        let mut stream = TimeoutStream::new(stream);
        stream.set_write_timeout(Some(self.write_timeout));
        (Box::pin(stream), addr)
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn stalled_write_times_out() {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let mut listener = WriteTimeoutListener::new(tcp, Duration::from_millis(200));

        // The peer connects and never reads.
        let _peer = TcpStream::connect(addr).await.unwrap();
        let (mut io, _remote) = axum::serve::Listener::accept(&mut listener).await;

        let chunk = vec![0u8; 64 * 1024];
        let err = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Err(e) = io.write_all(&chunk).await {
                    return e;
                }
            }
        })
        .await
        .expect("a stalled write did not fail within 5 s");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }
}

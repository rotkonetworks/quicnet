// authenticated stream abstraction over quinn
use crate::PeerId;
use anyhow::Result;
use quinn::{Connection, RecvStream, SendStream};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct AuthenticatedStream {
    conn: Connection,
    send: SendStream,
    recv: RecvStream,
    peer_id: PeerId,
}

impl AuthenticatedStream {
    pub async fn client(conn: Connection, peer_id: PeerId) -> Result<Self> {
        let (send, recv) = conn.open_bi().await?;
        Ok(Self {
            conn,
            send,
            recv,
            peer_id,
        })
    }

    pub async fn server(conn: Connection, peer_id: PeerId) -> Result<Self> {
        let (send, recv) = conn.accept_bi().await?;
        Ok(Self {
            conn,
            send,
            recv,
            peer_id,
        })
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    pub fn remote_address(&self) -> std::net::SocketAddr {
        self.conn.remote_address()
    }

    pub fn split(self) -> (SendStream, RecvStream) {
        (self.send, self.recv)
    }
}

impl AsyncRead for AuthenticatedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for AuthenticatedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.send).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.send).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.send).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

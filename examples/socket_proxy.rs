// socket_proxy.rs - proxy Unix sockets over quicnet
//
// Use case: remote bspwm control with local-feeling latency
//
// Server (on remote, e.g. bkk12):
//   cargo run --example socket_proxy -- server /tmp/bspwm_:0_0_0-socket
//
// Client (on local):
//   cargo run --example socket_proxy -- client <peer_id>@<host> /tmp/bspwm_remote
//
// Then locally:
//   BSPWM_SOCKET=/tmp/bspwm_remote bspc query -N

use anyhow::{Context, Result};
use quicnet::{Identity, Peer, PeerId};
use std::path::PathBuf;
use tokio::io;
use tokio::net::{UnixListener, UnixStream};

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install crypto provider");

    let args: Vec<_> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("server") => {
            let socket = args.get(2).ok_or_else(|| anyhow::anyhow!("need socket path"))?;
            run_server(socket.into()).await
        }
        Some("client") => {
            let target = args.get(2).ok_or_else(|| anyhow::anyhow!("need peer@host"))?;
            let local_socket = args.get(3).ok_or_else(|| anyhow::anyhow!("need local socket path"))?;
            run_client(target, local_socket.into()).await
        }
        _ => {
            eprintln!("Usage:");
            eprintln!("  {} server <remote_socket>", args[0]);
            eprintln!("  {} client <peer_id>@<host:port> <local_socket>", args[0]);
            eprintln!();
            eprintln!("Example (bspwm):");
            eprintln!("  Server: {} server /tmp/bspwm_:0_0_0-socket", args[0]);
            eprintln!("  Client: {} client abc123@192.168.1.100:4433 /tmp/bspwm_remote", args[0]);
            eprintln!();
            eprintln!("Then: BSPWM_SOCKET=/tmp/bspwm_remote bspc query -N");
            std::process::exit(1);
        }
    }
}

async fn run_server(socket_path: PathBuf) -> Result<()> {
    // Verify target socket exists
    if !socket_path.exists() {
        anyhow::bail!("target socket doesn't exist: {}", socket_path.display());
    }

    let identity = Identity::load_or_generate()?;
    let peer = Peer::new("[::]:4433".parse()?, identity)?;

    eprintln!("socket proxy server on {}", peer.local_addr()?);
    eprintln!("peer id: {}", peer.identity().peer_id());
    eprintln!("proxying to: {}", socket_path.display());

    while let Some(incoming) = peer.accept().await {
        let socket_path = socket_path.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_proxy_session(incoming, socket_path).await {
                eprintln!("proxy session error: {e}");
            }
        });
    }
    Ok(())
}

async fn handle_proxy_session(
    incoming: quicnet::IncomingConnection,
    socket_path: PathBuf,
) -> Result<()> {
    let (conn, peer_id) = incoming.accept().await?;
    eprintln!("[{}] connected", peer_id.short());

    // Accept streams from this connection
    loop {
        let stream = match conn.accept_bi().await {
            Ok((send, recv)) => (send, recv),
            Err(_) => break, // Connection closed
        };

        let socket_path = socket_path.clone();
        let peer_short = peer_id.short().to_string();

        tokio::spawn(async move {
            if let Err(e) = proxy_stream(stream, socket_path, &peer_short).await {
                eprintln!("[{}] stream error: {e}", peer_short);
            }
        });
    }

    eprintln!("[{}] disconnected", peer_id.short());
    Ok(())
}

async fn proxy_stream(
    (mut quic_send, mut quic_recv): (quinn::SendStream, quinn::RecvStream),
    socket_path: PathBuf,
    _peer: &str,
) -> Result<()> {
    // Connect to local Unix socket
    let unix = UnixStream::connect(&socket_path)
        .await
        .context("failed to connect to local socket")?;

    let (mut unix_read, mut unix_write) = unix.into_split();

    // Bidirectional copy
    tokio::select! {
        r = io::copy(&mut quic_recv, &mut unix_write) => {
            r.context("quic->unix copy failed")?;
        }
        r = io::copy(&mut unix_read, &mut quic_send) => {
            r.context("unix->quic copy failed")?;
        }
    }

    Ok(())
}

async fn run_client(target: &str, local_socket: PathBuf) -> Result<()> {
    // Parse peer_id@host:port
    let (peer_id_str, addr) = target
        .split_once('@')
        .ok_or_else(|| anyhow::anyhow!("target must be peer_id@host:port"))?;

    let peer_id: PeerId = peer_id_str.parse()
        .context("invalid peer id")?;

    let identity = Identity::load_or_generate()?;
    let peer = Peer::new("[::]:0".parse()?, identity)?;

    eprintln!("connecting to {} @ {}", peer_id.short(), addr);

    // Connect to remote
    let (conn, remote_peer_id) = peer.dial(addr.parse()?, Some(&peer_id)).await?;
    eprintln!("connected to {}", remote_peer_id.short());

    // Remove old socket if exists
    let _ = std::fs::remove_file(&local_socket);

    // Create local Unix socket listener
    let listener = UnixListener::bind(&local_socket)
        .context("failed to create local socket")?;

    eprintln!("local socket: {}", local_socket.display());
    eprintln!("ready - use: BSPWM_SOCKET={} bspc ...", local_socket.display());

    loop {
        let (unix_stream, _) = listener.accept().await?;

        // Open new QUIC stream for this connection
        let (quic_send, quic_recv) = conn.open_bi().await
            .context("failed to open QUIC stream")?;

        tokio::spawn(async move {
            if let Err(e) = proxy_client_stream(unix_stream, quic_send, quic_recv).await {
                eprintln!("client proxy error: {e}");
            }
        });
    }
}

async fn proxy_client_stream(
    unix: UnixStream,
    mut quic_send: quinn::SendStream,
    mut quic_recv: quinn::RecvStream,
) -> Result<()> {
    let (mut unix_read, mut unix_write) = unix.into_split();

    tokio::select! {
        r = io::copy(&mut unix_read, &mut quic_send) => {
            r.context("unix->quic copy failed")?;
        }
        r = io::copy(&mut quic_recv, &mut unix_write) => {
            r.context("quic->unix copy failed")?;
        }
    }

    Ok(())
}

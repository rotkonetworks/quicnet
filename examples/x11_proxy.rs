// x11_proxy.rs - X11 display proxy over quicnet
//
// Lowest latency remote desktop: X11 protocol over QUIC
// No video encoding - your local GPU renders everything
//
// Two modes:
//   Normal: Local machine has public IP, remote dials in
//   Reverse: Remote has public IP, local dials out (for NAT)
//
// Normal mode (local has public IP):
//   [remote: bspwm] → DISPLAY=:99 → x11_proxy client
//        → quicnet → x11_proxy server → [local Xorg :1]
//
// Reverse mode (remote has public IP, local behind NAT):
//   [remote: bspwm] → DISPLAY=:99 → x11_proxy rserver
//        ← quicnet ← x11_proxy rclient → [local Xorg :1]
//
// Setup (reverse mode for NAT):
//   1. Remote (bkk07): Run reverse server (creates fake X display, listens)
//      x11_proxy rserver
//
//   2. Local: Run reverse client (dials out, forwards to your X)
//      x11_proxy rclient <peer>@<remote_ip>:5000 :1
//
//   3. Remote: Start bspwm
//      DISPLAY=:99 bspwm

use anyhow::{Context, Result};
use quicnet::{Identity, Peer, PeerId};
use std::sync::Arc;
use tokio::io;
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};

const X11_UNIX_DIR: &str = "/tmp/.X11-unix";
const X11_TCP_BASE: u16 = 6000;
const PROXY_DISPLAY: u32 = 99; // Remote side gets :99

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install crypto provider");

    let args: Vec<_> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("server") => {
            let display = args.get(2).map(|s| s.as_str()).unwrap_or(":0");
            run_server(display).await
        }
        Some("client") => {
            let target = args.get(2).ok_or_else(|| anyhow::anyhow!("need peer@host"))?;
            run_client(target).await
        }
        Some("rserver") => {
            let bind_addr = args.get(2).map(|s| s.as_str()).unwrap_or("0.0.0.0:5000");
            run_reverse_server(bind_addr).await
        }
        Some("rclient") => {
            let target = args.get(2).ok_or_else(|| anyhow::anyhow!("need peer@host"))?;
            let display = args.get(3).map(|s| s.as_str()).unwrap_or(":0");
            run_reverse_client(target, display).await
        }
        _ => {
            eprintln!("X11 over quicnet - lowest latency remote display");
            eprintln!();
            eprintln!("Normal mode (you have public IP):");
            eprintln!("  {} server [:display]     Local: listen, forward to X", args[0]);
            eprintln!("  {} client <peer>@<host>  Remote: dial, create DISPLAY=:99", args[0]);
            eprintln!();
            eprintln!("Reverse mode (you're behind NAT, remote has public IP):");
            eprintln!("  {} rserver [bind_addr]   Remote: listen, create DISPLAY=:99", args[0]);
            eprintln!("                           bind_addr: ip:port to bind (default 0.0.0.0:5000)");
            eprintln!("                           Use specific public IP for proper source routing");
            eprintln!("  {} rclient <peer>@<host> [:display]  Local: dial out, forward to X", args[0]);
            eprintln!();
            eprintln!("Example (reverse mode):");
            eprintln!("  Remote: {} rserver", args[0]);
            eprintln!("  Remote: DISPLAY=:99 bspwm");
            eprintln!("  Local:  {} rclient abc123@160.22.181.7:5000 :1", args[0]);
            std::process::exit(1);
        }
    }
}

// Server runs on local machine (with the monitor)
// Accepts quicnet connections and forwards X11 to local display
async fn run_server(display: &str) -> Result<()> {
    let display_num: u32 = display.trim_start_matches(':').parse()
        .context("invalid display number")?;

    // Connect to local X server (prefer Unix socket)
    let x11_socket = format!("{}/X{}", X11_UNIX_DIR, display_num);
    let x11_tcp = format!("127.0.0.1:{}", X11_TCP_BASE + display_num as u16);

    let use_unix = std::path::Path::new(&x11_socket).exists();
    eprintln!("X11 target: {} ({})",
        if use_unix { &x11_socket } else { &x11_tcp },
        if use_unix { "unix" } else { "tcp" });

    let identity = Identity::load_or_generate()?;
    let peer = Peer::new("0.0.0.0:5000".parse()?, identity)?;

    eprintln!("x11 proxy server on {}", peer.local_addr()?);
    eprintln!("peer id: {}", peer.identity().peer_id());
    eprintln!("waiting for remote bspwm to connect...");

    while let Some(incoming) = peer.accept().await {
        let x11_socket = x11_socket.clone();
        let x11_tcp = x11_tcp.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_x11_session(incoming, &x11_socket, &x11_tcp, use_unix).await {
                eprintln!("x11 session error: {e}");
            }
        });
    }
    Ok(())
}

async fn handle_x11_session(
    incoming: quicnet::IncomingConnection,
    x11_socket: &str,
    x11_tcp: &str,
    use_unix: bool,
) -> Result<()> {
    let (conn, peer_id) = incoming.accept().await?;
    eprintln!("[{}] connected - X11 session starting", peer_id.short());

    // Each QUIC stream = one X11 connection
    loop {
        let (quic_send, quic_recv) = match conn.accept_bi().await {
            Ok(s) => s,
            Err(_) => break,
        };

        let x11_socket = x11_socket.to_string();
        let x11_tcp = x11_tcp.to_string();

        tokio::spawn(async move {
            let result = if use_unix {
                proxy_to_unix(quic_send, quic_recv, &x11_socket).await
            } else {
                proxy_to_tcp(quic_send, quic_recv, &x11_tcp).await
            };
            if let Err(e) = result {
                eprintln!("x11 stream error: {e}");
            }
        });
    }

    eprintln!("[{}] disconnected", peer_id.short());
    Ok(())
}

async fn proxy_to_unix(
    mut quic_send: quinn::SendStream,
    mut quic_recv: quinn::RecvStream,
    socket_path: &str,
) -> Result<()> {
    let unix = UnixStream::connect(socket_path).await?;
    let (mut unix_read, mut unix_write) = unix.into_split();

    tokio::select! {
        r = io::copy(&mut quic_recv, &mut unix_write) => { r?; }
        r = io::copy(&mut unix_read, &mut quic_send) => { r?; }
    }
    Ok(())
}

async fn proxy_to_tcp(
    mut quic_send: quinn::SendStream,
    mut quic_recv: quinn::RecvStream,
    addr: &str,
) -> Result<()> {
    let tcp = TcpStream::connect(addr).await?;
    let (mut tcp_read, mut tcp_write) = tcp.into_split();

    tokio::select! {
        r = io::copy(&mut quic_recv, &mut tcp_write) => { r?; }
        r = io::copy(&mut tcp_read, &mut quic_send) => { r?; }
    }
    Ok(())
}

// Client runs on remote machine (bkk12)
// Creates a fake X display that tunnels to local machine
async fn run_client(target: &str) -> Result<()> {
    let (peer_id_str, addr) = target
        .split_once('@')
        .ok_or_else(|| anyhow::anyhow!("target must be peer_id@host:port"))?;

    let peer_id: PeerId = peer_id_str.parse()
        .context("invalid peer id")?;

    let identity = Identity::load_or_generate()?;
    let peer = Peer::new("[::]:0".parse()?, identity)?;

    eprintln!("connecting to {} @ {}", peer_id.short(), addr);

    let (conn, remote_peer_id) = peer.dial(addr.parse()?, Some(&peer_id)).await?;
    let conn = Arc::new(conn);
    eprintln!("connected to {}", remote_peer_id.short());

    // Create X11 Unix socket (apps connect here)
    let x11_socket = format!("{}/X{}", X11_UNIX_DIR, PROXY_DISPLAY);
    let _ = std::fs::remove_file(&x11_socket);

    // Ensure directory exists
    std::fs::create_dir_all(X11_UNIX_DIR).ok();

    let unix_listener = UnixListener::bind(&x11_socket)
        .context("failed to create X11 socket - need write access to /tmp/.X11-unix")?;

    // Also listen on TCP for compatibility
    let tcp_port = X11_TCP_BASE + PROXY_DISPLAY as u16;
    let tcp_listener = TcpListener::bind(format!("127.0.0.1:{}", tcp_port)).await
        .context("failed to bind X11 TCP port")?;

    eprintln!("X11 proxy ready:");
    eprintln!("  Unix: {}", x11_socket);
    eprintln!("  TCP:  localhost:{}", tcp_port);
    eprintln!();
    eprintln!("Start bspwm with: DISPLAY=:{} bspwm", PROXY_DISPLAY);

    // Accept connections on both Unix and TCP
    loop {
        tokio::select! {
            Ok((stream, _)) = unix_listener.accept() => {
                let conn = Arc::clone(&conn);
                tokio::spawn(async move {
                    if let Err(e) = handle_x11_client_unix(stream, conn).await {
                        eprintln!("x11 client error: {e}");
                    }
                });
            }
            Ok((stream, _)) = tcp_listener.accept() => {
                let conn = Arc::clone(&conn);
                tokio::spawn(async move {
                    if let Err(e) = handle_x11_client_tcp(stream, conn).await {
                        eprintln!("x11 client error: {e}");
                    }
                });
            }
        }
    }
}

async fn handle_x11_client_unix(
    unix: UnixStream,
    conn: Arc<quinn::Connection>,
) -> Result<()> {
    let (quic_send, quic_recv) = conn.open_bi().await?;
    let (mut unix_read, mut unix_write) = unix.into_split();
    let (mut quic_send, mut quic_recv) = (quic_send, quic_recv);

    tokio::select! {
        r = io::copy(&mut unix_read, &mut quic_send) => { r?; }
        r = io::copy(&mut quic_recv, &mut unix_write) => { r?; }
    }
    Ok(())
}

async fn handle_x11_client_tcp(
    tcp: TcpStream,
    conn: Arc<quinn::Connection>,
) -> Result<()> {
    let (quic_send, quic_recv) = conn.open_bi().await?;
    let (mut tcp_read, mut tcp_write) = tcp.into_split();
    let (mut quic_send, mut quic_recv) = (quic_send, quic_recv);

    tokio::select! {
        r = io::copy(&mut tcp_read, &mut quic_send) => { r?; }
        r = io::copy(&mut quic_recv, &mut tcp_write) => { r?; }
    }
    Ok(())
}

// Reverse server: runs on remote (where bspwm runs)
// Creates fake X display, listens for quicnet connections from local machine
async fn run_reverse_server(bind_addr: &str) -> Result<()> {
    // Create X11 Unix socket (apps connect here)
    let x11_socket = format!("{}/X{}", X11_UNIX_DIR, PROXY_DISPLAY);
    let _ = std::fs::remove_file(&x11_socket);
    std::fs::create_dir_all(X11_UNIX_DIR).ok();

    let unix_listener = UnixListener::bind(&x11_socket)
        .context("failed to create X11 socket")?;

    let tcp_port = X11_TCP_BASE + PROXY_DISPLAY as u16;
    let tcp_listener = TcpListener::bind(format!("127.0.0.1:{}", tcp_port)).await
        .context("failed to bind X11 TCP port")?;

    let identity = Identity::load_or_generate()?;
    let peer = Peer::new(bind_addr.parse()?, identity)?;

    eprintln!("x11 reverse server on {}", peer.local_addr()?);
    eprintln!("peer id: {}", peer.identity().peer_id());
    eprintln!();
    eprintln!("X11 proxy ready:");
    eprintln!("  Unix: {}", x11_socket);
    eprintln!("  TCP:  localhost:{}", tcp_port);
    eprintln!();
    eprintln!("Start bspwm with: DISPLAY=:{} bspwm", PROXY_DISPLAY);

    // Keep accepting connections in a loop
    loop {
        eprintln!("Waiting for local machine to connect...");

        // Wait for rclient to connect
        let incoming = match peer.accept().await {
            Some(i) => i,
            None => {
                eprintln!("accept failed, retrying...");
                continue;
            }
        };
        let (conn, peer_id) = match incoming.accept().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("connection accept error: {e}, retrying...");
                continue;
            }
        };
        let conn = Arc::new(conn);
        eprintln!("[{}] connected - ready for X11", peer_id.short());

        // Forward X11 connections to the rclient until it disconnects
        loop {
            tokio::select! {
                result = unix_listener.accept() => {
                    match result {
                        Ok((stream, _)) => {
                            let conn = Arc::clone(&conn);
                            tokio::spawn(async move {
                                if let Err(e) = handle_x11_client_unix(stream, conn).await {
                                    eprintln!("x11 error: {e}");
                                }
                            });
                        }
                        Err(e) => eprintln!("unix accept error: {e}"),
                    }
                }
                result = tcp_listener.accept() => {
                    match result {
                        Ok((stream, _)) => {
                            let conn = Arc::clone(&conn);
                            tokio::spawn(async move {
                                if let Err(e) = handle_x11_client_tcp(stream, conn).await {
                                    eprintln!("x11 error: {e}");
                                }
                            });
                        }
                        Err(e) => eprintln!("tcp accept error: {e}"),
                    }
                }
            }

            // Check if connection is still alive
            if conn.close_reason().is_some() {
                eprintln!("[{}] disconnected", peer_id.short());
                break;
            }
        }
    }
}

// Reverse client: runs on local machine (behind NAT, has the monitor)
// Dials out to remote rserver, forwards X11 to local display
async fn run_reverse_client(target: &str, display: &str) -> Result<()> {
    let display_num: u32 = display.trim_start_matches(':').parse()
        .context("invalid display number")?;

    let x11_socket = format!("{}/X{}", X11_UNIX_DIR, display_num);
    let x11_tcp = format!("127.0.0.1:{}", X11_TCP_BASE + display_num as u16);

    let use_unix = std::path::Path::new(&x11_socket).exists();
    eprintln!("X11 target: {} ({})",
        if use_unix { &x11_socket } else { &x11_tcp },
        if use_unix { "unix" } else { "tcp" });

    let (peer_id_str, addr) = target
        .split_once('@')
        .ok_or_else(|| anyhow::anyhow!("target must be peer_id@host:port"))?;

    let peer_id: PeerId = peer_id_str.parse()
        .context("invalid peer id")?;

    let identity = Identity::load_or_generate()?;
    let peer = Peer::new("[::]:0".parse()?, identity)?;

    eprintln!("connecting to {} @ {}", peer_id.short(), addr);

    let (conn, remote_peer_id) = peer.dial(addr.parse()?, Some(&peer_id)).await?;
    eprintln!("connected to {} - forwarding X11 to :{}", remote_peer_id.short(), display_num);

    // Accept streams from rserver and forward to local X
    loop {
        let (quic_send, quic_recv) = match conn.accept_bi().await {
            Ok(s) => s,
            Err(_) => break,
        };

        let x11_socket = x11_socket.clone();
        let x11_tcp = x11_tcp.clone();

        tokio::spawn(async move {
            let result = if use_unix {
                proxy_to_unix(quic_send, quic_recv, &x11_socket).await
            } else {
                proxy_to_tcp(quic_send, quic_recv, &x11_tcp).await
            };
            if let Err(e) = result {
                eprintln!("x11 stream error: {e}");
            }
        });
    }

    eprintln!("connection closed");
    Ok(())
}

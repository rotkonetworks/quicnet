// minimal p2p quic with identity-bound TLS and application auth
use anyhow::Result;
use clap::Parser;
use quicnet::{Client, Identity, PeerId, Server, manage};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Parser)]
#[command(name = "quicnet")]
#[command(version)]
#[command(about = "authenticated pipes over quic", long_about = None)]
#[command(override_usage = "quicnet [OPTIONS] <TARGET>\n       quicnet -l [OPTIONS]")]
struct Args {
    /// target: host[:port] or peer_id@host[:port]
    target: Option<String>,

    /// listen for connections
    #[arg(short = 'l', long)]
    listen: bool,

    /// port number
    #[arg(short = 'p', long, default_value = "4433")]
    port: u16,

    /// identity file (default: ~/.ssh/id_quicnet)
    #[arg(short = 'i', long)]
    identity: Option<PathBuf>,

    /// bind address (default: [::])
    #[arg(short = 'b', long, default_value = "::")]
    bind: String,

    /// echo mode (reflect data back)
    #[arg(long)]
    echo: bool,

    /// verbose output
    #[arg(short = 'v', long)]
    verbose: bool,

    /// suppress info messages
    #[arg(short = 'q', long)]
    quiet: bool,

    /// manage peer authorizations
    #[arg(long)]
    authorize: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install crypto provider");

    let args = Args::parse();

    if args.listen {
        run_server(args).await
    }    else if args.authorize {
        return manage::authorize_pending();
    } else if let Some(target) = args.target.clone() {
        run_client(args, &target).await
    } else {
        eprintln!("error: must specify either -l or a target");
        eprintln!();
        eprintln!("Usage: quicnet [OPTIONS] <TARGET>");
        eprintln!("       quicnet -l [OPTIONS]");
        eprintln!();
        eprintln!("Try 'quicnet --help' for more information.");
        std::process::exit(1);
    }
}

async fn run_server(args: Args) -> Result<()> {
    let addr = parse_bind_address(&args.bind, args.port)?;
    let identity = load_identity(&args)?;
    let server = Server::bind(addr, identity)?;
    
    if !args.quiet {
        eprintln!("peer id: {}", server.identity().peer_id());
        eprintln!("listening on {}", server.local_addr()?);
    }

    while let Some(incoming) = server.accept().await {
        let echo = args.echo;
        let verbose = args.verbose;
        let quiet = args.quiet;
        
        tokio::spawn(async move {
            if let Err(e) = handle_connection(incoming, echo, verbose, quiet).await {
                if verbose {
                    eprintln!("connection error: {}", e);
                }
            }
        });
    }
    Ok(())
}

async fn run_client(args: Args, target: &str) -> Result<()> {
    let (peer_hint, host) = parse_target(target);
    let addr = resolve_address(host, args.port)?;
    let identity = load_identity(&args)?;
    
    if !args.quiet {
        eprintln!("peer id: {}", identity.peer_id());
        eprintln!("connecting to {}", addr);
    }

    let bind_addr = parse_bind_address(&args.bind, 0)?;
    let client = Client::new(bind_addr, identity)?;
    let expected_peer = peer_hint.and_then(|h| PeerId::from_str(h).ok());
    
    let (conn, peer_id) = client.connect(addr, expected_peer.as_ref()).await?;
    
    if !args.quiet {
        eprintln!("connected to {} ({})", peer_id, conn.remote_address());
    }

    pipe_bidirectional(conn, true).await
}

async fn handle_connection(
    incoming: quicnet::server::AuthenticatedIncoming,
    echo: bool,
    verbose: bool,
    quiet: bool,
) -> Result<()> {
    let remote = incoming.remote_address();
    let (conn, peer_id) = incoming.accept().await?;

    if !quiet {
        eprintln!("[{}] connected from {}", peer_id, remote);
    }

    let result = if echo {
        handle_echo(conn, peer_id, verbose).await
    } else {
        pipe_bidirectional(conn, false).await
    };

    if !quiet {
        eprintln!("[{}] disconnected", peer_id);
    }

    result
}

async fn handle_echo(
    conn: quinn::Connection,
    peer_id: PeerId,
    verbose: bool,
) -> Result<()> {
    let (mut send, mut recv) = conn.accept_bi().await?;
    let mut buf = [0u8; 8192];

    loop {
        match recv.read(&mut buf).await {
            Ok(Some(n)) => {
                if verbose {
                    eprintln!("[{}] {} bytes", peer_id, n);
                }
                send.write_all(&buf[..n]).await?;
                send.flush().await?;
            }
            Ok(None) => break,
            Err(e) => {
                if verbose {
                    eprintln!("read error: {}", e);
                }
                break;
            }
        }
    }

    send.finish()?;
    conn.close(0u32.into(), b"");
    Ok(())
}

async fn pipe_bidirectional(conn: quinn::Connection, initiator: bool) -> Result<()> {
    let (mut send, mut recv) = if initiator {
        conn.open_bi().await?
    } else {
        conn.accept_bi().await?
    };

    let recv_task = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        let mut buf = [0u8; 64 * 1024];
        loop {
            match recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    if stdout.write_all(&buf[..n]).await.is_err() { break; }
                    if stdout.flush().await.is_err() { break; }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
    });

    let mut stdin = tokio::io::stdin();
    let mut buf = [0u8; 64 * 1024];
    loop {
        match stdin.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                if send.write_all(&buf[..n]).await.is_err() { break; }
                if send.flush().await.is_err() { break; }
            }
            Err(_) => break,
        }
    }

    send.finish()?;
    let _ = recv_task.await;
    conn.close(0u32.into(), b"");
    Ok(())
}

fn parse_target(target: &str) -> (Option<&str>, &str) {
    if let Some((prefix, suffix)) = target.split_once('@') {
        (Some(prefix), suffix)
    } else {
        (None, target)
    }
}

fn parse_bind_address(bind: &str, port: u16) -> Result<SocketAddr> {
    match bind {
        "::" | "::0" => Ok(format!("[::]:{}", port).parse()?),
        "0.0.0.0" | "0" => Ok(format!("0.0.0.0:{}", port).parse()?),
        s if s.starts_with('[') && s.ends_with(']') => {
            // [ipv6] format
            Ok(format!("{}:{}", s, port).parse()?)
        }
        s if s.contains(':') && !s.contains('.') => {
            // bare ipv6
            Ok(format!("[{}]:{}", s, port).parse()?)
        }
        s if s.parse::<std::net::Ipv4Addr>().is_ok() => {
            // ipv4
            Ok(format!("{}:{}", s, port).parse()?)
        }
        _ => {
            // try as hostname
            format!("{}:{}", bind, port).to_socket_addrs()?
                .next()
                .ok_or_else(|| anyhow::anyhow!("cannot resolve: {}", bind))
        }
    }
}

fn resolve_address(host: &str, default_port: u16) -> Result<SocketAddr> {
    // handle [ipv6]:port
    if host.starts_with('[') {
        if let Some(end) = host.find(']') {
            let ipv6 = &host[1..end];
            let port = if host.len() > end + 1 && host.chars().nth(end + 1) == Some(':') {
                host[end + 2..].parse()?
            } else {
                default_port
            };
            return format!("[{}]:{}", ipv6, port).parse()
                .map_err(|_| anyhow::anyhow!("invalid address"));
        }
    }

    // try as-is first
    if let Ok(addr) = host.parse::<SocketAddr>() {
        return Ok(addr);
    }

    // try host:port
    if let Some((h, p)) = host.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return format!("{}:{}", h, port).to_socket_addrs()?
                .next()
                .ok_or_else(|| anyhow::anyhow!("cannot resolve: {}", h));
        }
    }

    // add default port
    format!("{}:{}", host, default_port).to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("cannot resolve: {}", host))
}

fn load_identity(args: &Args) -> Result<Identity> {
    if let Some(path) = &args.identity {
        return load_identity_file(path);
    }
    
    // try default ssh key
    if let Ok(identity) = Identity::from_ssh_key(None) {
        return Ok(identity);
    }
    
    // generate or load ~/.ssh/id_quicnet
    Identity::load_or_generate()
}

fn load_identity_file(path: &std::path::Path) -> Result<Identity> {
    // try openssh format first
    if let Ok(identity) = Identity::from_ssh_key(Some(path)) {
        return Ok(identity);
    }
    // fall back to raw 32 bytes
    Identity::from_file(path)
}

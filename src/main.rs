// minimal p2p quic with identity-bound TLS and application auth
use anyhow::Result;
use clap::Parser;
use quicnet::known_hosts::{KnownHosts, Trust};
use quicnet::{Identity, Peer, PeerId, manage};
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

    /// identity file (default: ~/.quicnet/identity)
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
        run_listener(args).await
    } else if args.authorize {
        return manage::authorize_pending();
    } else if let Some(target) = args.target.clone() {
        run_dialer(args, &target).await
    } else {
        eprintln!("error: must specify either -l or a target\n");
        eprintln!("Usage: quicnet [OPTIONS] <TARGET>");
        eprintln!("       quicnet -l [OPTIONS]");
        eprintln!("\nTry 'quicnet --help' for more information.");
        std::process::exit(1);
    }
}

async fn run_listener(args: Args) -> Result<()> {
    let addr = parse_bind_address(&args.bind, args.port)?;
    let identity = load_identity(&args)?;
    let peer = Peer::new(addr, identity)?;

    if !args.quiet {
        eprintln!("peer id: {}", peer.identity().peer_id());
        eprintln!("listening on {}", peer.local_addr()?);
    }

    while let Some(incoming) = peer.accept().await {
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

async fn run_dialer(args: Args, target: &str) -> Result<()> {
    let (peer_hint, host) = parse_target(target);
    let addr = resolve_address(host, args.port)?;
    let used_port = addr.port();
    let identity = load_identity(&args)?;

    if !args.quiet {
        eprintln!("peer id: {}", identity.peer_id());
        eprintln!("connecting to {}", addr);
    }

    let bind_addr = parse_bind_address(&args.bind, 0)?;
    let peer = Peer::new(bind_addr, identity)?;
    let expected_peer = peer_hint.and_then(|h| PeerId::from_str(h).ok());

    let (conn, peer_id) = peer.dial(addr, expected_peer.as_ref()).await?;

    // TOFU when no explicit peer pinning
    if expected_peer.is_none() {
        let mut known_hosts = KnownHosts::load()?;
        let host_str = host.to_string();
        match known_hosts.check(&host_str, used_port, &peer_id) {
            Trust::Known => {}
            Trust::Unknown => {
                if !args.quiet {
                    eprintln!("new peer: {} ({})", peer_id.short(), addr);
                    eprintln!("to pin: {}@{}", peer_id, host);
                }
                known_hosts.add(&host_str, used_port, peer_id)?;
            }
            Trust::Different(previous) => {
                eprintln!("\nwarning: {} has different identity", host);
                eprintln!("  current: {}", peer_id.short());
                eprintln!("  previous: {}", previous.short());
                eprintln!("\noptions:\n  [1] continue (accept new key)\n  [2] abort\n");
                eprintln!("tip: use {}@{} to pin identity", peer_id, host);
                eprint!("choice [1]: ");

                use std::io::{self, BufRead};
                let stdin = io::stdin();
                let mut line = String::new();
                stdin.lock().read_line(&mut line)?;

                match line.trim() {
                    "" | "1" => {
                        known_hosts.add(&host_str, used_port, peer_id)?;
                        if !args.quiet {
                            eprintln!("accepted new identity");
                        }
                    }
                    _ => {
                        conn.close(0u32.into(), b"user rejected");
                        anyhow::bail!("connection aborted by user");
                    }
                }
            }
        }
    }

    if !args.quiet {
        eprintln!("connected to {} ({})", peer_id, conn.remote_address());
    }

    pipe_bidirectional(conn, true).await
}

async fn handle_connection(
    incoming: quicnet::IncomingConnection,
    echo: bool,
    verbose: bool,
    quiet: bool,
) -> Result<()> {
    let remote = incoming.remote_address();
    let (conn, peer_id) = incoming.accept().await?;

    // check authorization (default policy file)
    use quicnet::authorized_peers::AuthorizedPeers;
    use quicnet::pending_peers::PendingPeers;
    let authorized = AuthorizedPeers::load()?;
    if !authorized.is_authorized(&peer_id) {
        let pending = PendingPeers::new()?;
        pending.log(&peer_id, &remote.to_string())?;

        if !quiet {
            eprintln!("[{}] unauthorized (logged for review)", peer_id.short());
            eprintln!("  run: quicnet --authorize");
        }

        conn.close(0u32.into(), b"unauthorized");
        return Ok(());
    }

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

async fn handle_echo(conn: quinn::Connection, peer_id: PeerId, verbose: bool) -> Result<()> {
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
                    if stdout.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    if stdout.flush().await.is_err() {
                        break;
                    }
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
                if send.write_all(&buf[..n]).await.is_err() {
                    break;
                }
                if send.flush().await.is_err() {
                    break;
                }
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
        s if s.starts_with('[') && s.ends_with(']') => Ok(format!("{}:{}", s, port).parse()?),
        s if s.contains(':') && !s.contains('.') => Ok(format!("[{}]:{}", s, port).parse()?),
        s if s.parse::<std::net::Ipv4Addr>().is_ok() => Ok(format!("{}:{}", s, port).parse()?),
        _ => format!("{}:{}", bind, port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow::anyhow!("cannot resolve: {}", bind)),
    }
}

fn resolve_address(host: &str, default_port: u16) -> Result<SocketAddr> {
    if host.starts_with('[') {
        if let Some(end) = host.find(']') {
            let ipv6 = &host[1..end];
            let port = if host.len() > end + 1 && host.chars().nth(end + 1) == Some(':') {
                host[end + 2..].parse()?
            } else {
                default_port
            };
            return format!("[{}]:{}", ipv6, port)
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid address"));
        }
    }

    if let Ok(addr) = host.parse::<SocketAddr>() {
        return Ok(addr);
    }

    if let Some((h, p)) = host.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return format!("{}:{}", h, port)
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| anyhow::anyhow!("cannot resolve: {}", h));
        }
    }

    format!("{}:{}", host, default_port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("cannot resolve: {}", host))
}

fn load_identity(args: &Args) -> Result<Identity> {
    if let Some(path) = &args.identity {
        return load_identity_file(path);
    }
    if let Ok(identity) = Identity::from_ssh_key(None) {
        return Ok(identity);
    }
    Identity::load_or_generate()
}

fn load_identity_file(path: &std::path::Path) -> Result<Identity> {
    if let Ok(identity) = Identity::from_ssh_key(Some(path)) {
        return Ok(identity);
    }
    Identity::from_file(path)
}

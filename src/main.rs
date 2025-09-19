// minimal p2p quic with identity-bound TLS and application auth
use anyhow::Result;
use clap::Parser;
use quicnet::{Client, Identity, PeerId, Server};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Parser)]
#[command(name = "quicnet")]
#[command(version)]
#[command(about = "authenticated pipes over quic", long_about = None)]
#[command(override_usage = "quicnet [OPTIONS] [TARGET]\n       quicnet -l [OPTIONS]")]
struct Args {
    /// target: host[:port] or peer_id@host[:port]
    target: Option<String>,

    /// listen for connections
    #[arg(short = 'l', long)]
    listen: bool,

    /// port number
    #[arg(short = 'p', long, value_name = "PORT")]
    port: Option<u16>,

    /// identity file (default: ~/.ssh/id_quicnet)
    #[arg(short = 'i', long, value_name = "FILE")]
    identity: Option<PathBuf>,

    /// bind address (default: [::])
    #[arg(short = 'b', long, value_name = "ADDR")]
    bind: Option<String>,

    /// relay via coordinator (EXPERIMENTAL; not wired yet)
    #[arg(long, value_name = "HOST")]
    via: Option<String>,

    /// echo mode (reflect data back)
    #[arg(long)]
    echo: bool,

    /// verbose output
    #[arg(short = 'v', long)]
    verbose: bool,

    /// suppress info messages
    #[arg(short = 'q', long)]
    quiet: bool,

    #[cfg(feature = "coordinator")]
    /// run as coordinator (EXPERIMENTAL)
    #[arg(long)]
    coordinator: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider().install_default()
        .expect("failed to install crypto provider");

    let args = Args::parse();

    // validate args
    if !args.listen && args.target.is_none() {
        #[cfg(feature = "coordinator")]
        if !args.coordinator {
            print_usage_and_exit();
        }
        #[cfg(not(feature = "coordinator"))]
        print_usage_and_exit();
    }

    if args.listen && args.target.is_some() {
        eprintln!("error: cannot specify both -l and target");
        std::process::exit(1);
    }

    #[cfg(feature = "coordinator")]
    if args.coordinator {
        return run_coordinator(args).await;
    }

    if args.listen {
        run_server(args).await
    } else {
        run_client(args).await
    }
}

fn print_usage_and_exit() -> ! {
    eprintln!("usage: quicnet [OPTIONS] [TARGET]");
    eprintln!("       quicnet -l [OPTIONS]\n");
    eprintln!("examples:");
    eprintln!("  quicnet -l                    # listen on default port");
    eprintln!("  quicnet localhost             # connect to localhost");
    eprintln!("  quicnet -l -p 5000            # listen on port 5000");
    eprintln!("  quicnet host:5000             # connect to host:5000");
    eprintln!("  quicnet peer_id@host          # verify peer identity");
    eprintln!("\nrun 'quicnet --help' for all options");
    std::process::exit(1);
}

async fn run_server(args: Args) -> Result<()> {
    let port = args.port.unwrap_or(quicnet::DEFAULT_PORT);
    let bind = args.bind.as_deref().unwrap_or("::");

    let addr: SocketAddr = if bind == "::" {
        format!("[::]:{}", port).parse()
    } else {
        format!("{}:{}", bind, port).parse()
    }.map_err(|_| anyhow::anyhow!("invalid bind address: {}:{}", bind, port))?;

    let identity = load_identity(&args)?;
    let peer_id = identity.peer_id().to_string();

    let server = Server::bind(addr, identity)?;
    let actual_addr = server.local_addr()?;

    if !args.quiet {
        eprintln!("peer id: {}", peer_id);
        eprintln!("listening on {}", actual_addr);
        if actual_addr.ip().is_loopback() {
            eprintln!("connect: quicnet localhost:{}", actual_addr.port());
        }
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

async fn run_client(args: Args) -> Result<()> {
    let target = args.target.clone().unwrap();

    // parse target
    let (peer_hint, host_part) = if let Some((prefix, suffix)) = target.split_once('@') {
        (Some(prefix), suffix)
    } else {
        (None, target.as_str())
    };

    // parse host:port
    let default_port = args.port.unwrap_or(quicnet::DEFAULT_PORT);
    let addr = parse_address(host_part, default_port)?;

    // load identity
    let identity = if let Some(hint) = peer_hint {
        load_identity_with_hint(&args, hint)?
    } else {
        load_identity(&args)?
    };

    if !args.quiet {
        eprintln!("peer id: {}", identity.peer_id().to_string());
    }

    // bind address
    let bind = args.bind.as_deref().unwrap_or("[::]:0");
    let bind_addr: SocketAddr = bind.parse()
        .map_err(|_| anyhow::anyhow!("invalid bind address: {}", bind))?;

    let client = Client::new(bind_addr, identity)?;

    if args.via.is_some() {
        eprintln!("--via is experimental and not wired yet; making direct connection");
    }

    // direct connection
    let expected_peer = peer_hint.and_then(|h| PeerId::from_str(h).ok());

    if !args.quiet {
        eprintln!("connecting to {}", addr);
    }

    let (conn, peer_id) = client.connect(addr, expected_peer.as_ref()).await
        .map_err(|e| anyhow::anyhow!("connection failed: {}", e))?;

    if !args.quiet {
        eprintln!("connected to {} ({})", peer_id, conn.remote_address());
    }

    // client is the initiator
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
        // server is responder (accepts the BI stream)
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
    // accept a bi stream
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
    // one bi-stream per connection: client opens, server accepts
    let (mut send, mut recv) = if initiator {
        conn.open_bi().await?
    } else {
        conn.accept_bi().await?
    };

    // recv -> stdout
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

    // stdin -> send
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

fn parse_address(s: &str, default_port: u16) -> Result<SocketAddr> {
    // handle [ipv6]:port
    if s.starts_with('[') {
        if let Some(end) = s.find(']') {
            let host = &s[1..end];
            let port = if s.len() > end + 1 && s.chars().nth(end + 1) == Some(':') {
                s[end + 2..].parse()
                    .map_err(|_| anyhow::anyhow!("invalid port: {}", &s[end + 2..]))?
            } else {
                default_port
            };
            let addr_str = format!("[{}]:{}", host, port);
            return addr_str.parse()
                .map_err(|_| anyhow::anyhow!("invalid address: {}", addr_str));
        }
    }

    // try as-is first (for ipv6 without port)
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }

    // try host:port
    if let Some((host, port_str)) = s.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            let addr_str = format!("{}:{}", host, port);
            return addr_str.to_socket_addrs()?
                .next()
                .ok_or_else(|| anyhow::anyhow!("cannot resolve: {}", host));
        }
    }

    // add default port
    let addr_str = format!("{}:{}", s, default_port);
    addr_str.to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("cannot resolve: {}", s))
}

fn load_identity(args: &Args) -> Result<Identity> {
    if let Some(path) = &args.identity {
        return Identity::from_file(path)
            .map_err(|e| anyhow::anyhow!("cannot load identity {}: {}", path.display(), e));
    }
    if let Ok(identity) = Identity::from_ssh_key(None) {
        return Ok(identity);
    }
    Identity::load_or_generate()
}

fn load_identity_with_hint(args: &Args, hint: &str) -> Result<Identity> {
    if let Some(path) = &args.identity {
        return Identity::from_file(path)
            .map_err(|e| anyhow::anyhow!("cannot load identity {}: {}", path.display(), e));
    }

    // try hint as path variations
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("no home directory"))?;
    let paths = vec![
        home.join(".ssh").join(format!("id_ed25519_{}", hint)),
        home.join(".ssh").join(format!("id_{}", hint)),
        home.join(".ssh").join(hint),
    ];

    for path in paths {
        if path.exists() {
            if let Ok(identity) = Identity::from_ssh_key(Some(&path)) {
                return Ok(identity);
            }
            if let Ok(identity) = Identity::from_file(&path) {
                return Ok(identity);
            }
        }
    }

    load_identity(args)
}

#[cfg(feature = "coordinator")]
async fn run_coordinator(args: Args) -> Result<()> {
    use quicnet::coordinator::Coordinator;

    let port = args.port.unwrap_or(quicnet::DEFAULT_PORT);
    let bind = args.bind.as_deref().unwrap_or("::");

    let addr: SocketAddr = if bind == "::" {
        format!("[::]:{}", port).parse()
    } else {
        format!("{}:{}", bind, port).parse()
    }.map_err(|_| anyhow::anyhow!("invalid bind address: {}:{}", bind, port))?;

    let identity = load_identity(&args)?;

    if !args.quiet {
        eprintln!("coordinator id: {}", identity.peer_id().to_string());
        eprintln!("listening on {}", addr);
        eprintln!("(experimental; --via not wired yet)");
    }

    let coordinator = Coordinator::new(addr, identity).await?;
    coordinator.run().await
}

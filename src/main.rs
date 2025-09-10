// minimal p2p quic with proper authentication
use anyhow::Result;
use clap::Parser;
use quicnet::{Client, Identity, PeerId, Server};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::io::Write;
use tokio::io::{stdin, AsyncBufReadExt, AsyncWriteExt, BufReader};

#[derive(Parser)]
#[command(name = "quicnet")]
#[command(version)]
#[command(about = "peer-to-peer network protocol over quic")]
struct Args {
    /// target: [user@]host[:port] or peer_id@host[:port]
    target: Option<String>,

    /// port (overrides port in target)
    port: Option<u16>,

    /// listen mode
    #[arg(short = 'l', long)]
    listen: bool,

    /// identity file
    #[arg(short = 'i', long)]
    identity: Option<PathBuf>,

    /// bind address
    #[arg(short = 'b', long)]
    bind: Option<String>,

    /// listen port
    #[arg(short = 'p', long)]
    port_flag: Option<u16>,

    /// relay through coordinator
    #[arg(long = "via")]
    via: Option<String>,

    /// verbose output
    #[arg(short = 'v', action = clap::ArgAction::Count)]
    verbose: u8,

    /// quiet mode
    #[arg(short = 'q', long)]
    quiet: bool,

    #[cfg(feature = "coordinator")]
    #[arg(long)]
    coordinator: bool,
}

#[derive(Debug)]
struct Target {
    identity_hint: Option<String>,
    host: String,
    port: u16,
}

impl Target {
    fn parse(s: &str, default_port: u16) -> Result<Self> {
        let (identity_hint, host_part) = if let Some((prefix, suffix)) = s.split_once('@') {
            (Some(prefix.to_string()), suffix)
        } else {
            (None, s)
        };

        let (host, port) = Self::parse_host_port(host_part, default_port)?;
        Ok(Target { identity_hint, host, port })
    }

    fn parse_host_port(s: &str, default_port: u16) -> Result<(String, u16)> {
        // handle [ipv6]:port
        if s.starts_with('[') {
            if let Some(end) = s.find(']') {
                let host = s[1..end].to_string();
                let port = if s.len() > end + 1 && s.chars().nth(end + 1) == Some(':') {
                    s[end + 2..].parse()?
                } else {
                    default_port
                };
                return Ok((host, port));
            }
        }

        // bare ipv6
        if s.contains("::") && !s.starts_with('[') {
            return Ok((s.to_string(), default_port));
        }

        // try host:port
        if let Some((host, port_str)) = s.rsplit_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                return Ok((host.to_string(), port));
            }
        }

        Ok((s.to_string(), default_port))
    }

    fn to_socket_addr(&self) -> Result<SocketAddr> {
        let addr_str = if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        };

        addr_str.to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow::anyhow!("failed to resolve {}", addr_str))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider().install_default()
        .expect("failed to install crypto provider");

    let args = Args::parse();

    #[cfg(feature = "coordinator")]
    if args.coordinator {
        return run_coordinator(args).await;
    }

    if args.listen {
        run_server(args).await
    } else if args.target.is_some() {
        run_client(args).await
    } else {
        eprintln!("Error: specify target or use -l to listen");
        std::process::exit(1)
    }
}

async fn run_server(args: Args) -> Result<()> {
    let listen_addr = if let Some(ref bind) = args.bind {
        if bind.contains(':') {
            bind.clone()
        } else {
            let port = args.port_flag.or(args.port).unwrap_or(quicnet::DEFAULT_PORT);
            format!("{}:{}", bind, port)
        }
    } else {
        let port = args.port_flag.or(args.port).unwrap_or(quicnet::DEFAULT_PORT);
        format!("[::]:{}", port)  // ipv6 by default
    };

    let identity = load_identity(&args)?;

    if !args.quiet {
        eprintln!("peer id: {}", identity.peer_id());
    }

    let addr: SocketAddr = listen_addr.parse()?;
    let server = Server::bind(addr, identity)?;

    if !args.quiet {
        eprintln!("listening on {}", server.local_addr()?);
    }

    while let Some(incoming) = server.accept().await {
        let verbose = args.verbose;
        let quiet = args.quiet;
        
        tokio::spawn(async move {
            let _ = handle_connection(incoming, verbose, quiet).await;
        });
    }

    Ok(())
}

async fn run_client(args: Args) -> Result<()> {
    let target_str = args.target.clone().unwrap();
    let default_port = args.port_flag.or(args.port).unwrap_or(quicnet::DEFAULT_PORT);
    let target = Target::parse(&target_str, default_port)?;

    let target = if let Some(port) = args.port {
        Target { port, ..target }
    } else {
        target
    };

    let identity = if let Some(hint) = &target.identity_hint {
        load_identity_with_hint(&args, hint)?
    } else {
        load_identity(&args)?
    };

    if !args.quiet {
        eprintln!("peer id: {}", identity.peer_id());
    }

    let bind_addr: SocketAddr = args.bind
        .as_deref()
        .unwrap_or("[::]:0")
        .parse()?;

    let client = Client::new(bind_addr, identity.clone())?;

    // handle --via coordinator relay
    if let Some(via) = &args.via {
        let coord_target = Target::parse(via, quicnet::DEFAULT_PORT)?;
        let coord_addr = coord_target.to_socket_addr()?;
        
        if !args.quiet {
            eprintln!("connecting via coordinator {}", coord_addr);
        }
        
        // connect to coordinator
        let (coord_conn, coord_id) = client.connect(coord_addr, None).await?;
        
        if !args.quiet {
            eprintln!("connected to coordinator {}", coord_id);
        }
        
        // request relay to target
        let (mut send, mut recv) = coord_conn.open_bi().await?;
        
        // send relay request
        let relay_request = format!("RELAY {}\n", target_str);
        send.write_all(relay_request.as_bytes()).await?;
        send.flush().await?;
        
        // check response
        let mut response = String::new();
        let mut reader = BufReader::new(&mut recv);
        reader.read_line(&mut response).await?;
        
        if !response.starts_with("OK") {
            anyhow::bail!("coordinator refused relay: {}", response.trim());
        }
        
        if !args.quiet {
            eprintln!("relay established to {}", target_str);
        }
        
        // now pipe stdin/stdout through coordinator
        pipe_through_connection(coord_conn).await?;
        
    } else {
        // direct connection
        let expected_peer = target.identity_hint.as_ref()
            .and_then(|h| PeerId::from_str(h).ok());

        let addr = target.to_socket_addr()?;

        if !args.quiet {
            eprintln!("connecting to {}", addr);
        }

        let (conn, peer_id) = client.connect(addr, expected_peer.as_ref()).await?;

        if !args.quiet {
            eprintln!("connected to {} ({})", peer_id, conn.remote_address());
        }

        pipe_through_connection(conn).await?;
    }

    Ok(())
}

async fn pipe_through_connection(conn: quinn::Connection) -> Result<()> {
    let (mut send, recv) = conn.open_bi().await?;

    // spawn reader
    tokio::spawn(async move {
        let mut reader = BufReader::new(recv);
        let mut line = String::new();

        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => {
                    eprintln!("connection closed");
                    std::process::exit(0);
                }
                Ok(_) => {
                    print!("{}", line);
                    let _ = std::io::stdout().flush();
                }
                Err(e) => {
                    eprintln!("read error: {}", e);
                    std::process::exit(1);
                }
            }
        }
    });

    // write stdin to server
    let mut stdin = BufReader::new(stdin());
    let mut line = String::new();

    loop {
        line.clear();
        match stdin.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {
                send.write_all(line.as_bytes()).await?;
                send.flush().await?;
            }
            Err(e) => {
                eprintln!("stdin error: {}", e);
                break;
            }
        }
    }

    conn.close(0u32.into(), b"");
    Ok(())
}

async fn handle_connection(
    incoming: quicnet::server::AuthenticatedIncoming,
    verbose: u8,
    quiet: bool,
) -> Result<()> {
    let remote = incoming.remote_address();
    let (conn, peer_id) = incoming.accept().await?;

    if !quiet {
        eprintln!("[{}] connected from {}", peer_id, remote);
    }

    let (mut send, recv) = conn.accept_bi().await?;
    let mut reader = BufReader::new(recv);

    // echo server
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {
                if verbose > 1 {
                    eprint!("[{}] < {}", peer_id, line);
                }
                send.write_all(line.as_bytes()).await?;
                send.flush().await?;
            }
            Err(e) => {
                if verbose > 0 {
                    eprintln!("[{}] error: {}", peer_id, e);
                }
                break;
            }
        }
    }

    if !quiet {
        eprintln!("[{}] disconnected", peer_id);
    }

    conn.close(0u32.into(), b"");
    Ok(())
}

#[cfg(feature = "coordinator")]
async fn run_coordinator(args: Args) -> Result<()> {
    use quicnet::coordinator::Coordinator;
    
    let listen_addr = args.bind
        .as_deref()
        .unwrap_or("[::]")
        .to_string();
    
    let port = args.port_flag.or(args.port).unwrap_or(quicnet::DEFAULT_PORT);
    let addr: SocketAddr = format!("{}:{}", listen_addr, port).parse()?;
    
    let identity = load_identity(&args)?;
    
    if !args.quiet {
        eprintln!("coordinator id: {}", identity.peer_id());
        eprintln!("listening on {}", addr);
    }
    
    let coordinator = Coordinator::new(addr, identity).await?;
    coordinator.run().await
}

fn load_identity(args: &Args) -> Result<Identity> {
    if let Some(path) = &args.identity {
        return Identity::from_file(path);
    }

    if let Ok(identity) = Identity::from_ssh_key(None) {
        return Ok(identity);
    }

    Identity::load_or_generate()
}

fn load_identity_with_hint(args: &Args, hint: &str) -> Result<Identity> {
    if let Some(path) = &args.identity {
        return Identity::from_file(path);
    }

    let ssh_paths = vec![
        dirs::home_dir().map(|h| h.join(".ssh").join(format!("id_ed25519_{}", hint))),
        dirs::home_dir().map(|h| h.join(".ssh").join(format!("id_{}", hint))),
        dirs::home_dir().map(|h| h.join(".ssh").join(hint)),
    ];

    for path in ssh_paths.into_iter().flatten() {
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

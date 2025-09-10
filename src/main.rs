// src/main.rs
use anyhow::Result;
use clap::Parser;
use quicnet::{Client, Identity, PeerId, Server};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::io::Write;
use tokio::io::{stdin, AsyncBufReadExt, AsyncWriteExt, BufReader};

#[derive(Parser)]
#[command(name = "quicnet")]
#[command(about = "peer-to-peer network protocol over quic")]
#[command(override_usage = "quicnet [OPTIONS] [TARGET] [PORT]\n       quicnet -l [OPTIONS] [PORT]")]
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
    
    /// bind address (client) or listen address (server)
    #[arg(short = 'b', long)]
    bind: Option<String>,
    
    /// port to listen on (alternative to positional)
    #[arg(short = 'p', long)]
    port_flag: Option<u16>,
    
    /// verbose output
    #[arg(short = 'v', action = clap::ArgAction::Count)]
    verbose: u8,
    
    /// quiet mode (no info messages)
    #[arg(short = 'q', long)]
    quiet: bool,
    
    /// save generated identity
    #[arg(long)]
    save: Option<PathBuf>,
}

// parse target with smart detection
#[derive(Debug)]
struct Target {
    identity_hint: Option<String>,
    host: String,
    port: u16,
}

impl Target {
    fn parse(s: &str, default_port: u16) -> Result<Self> {
        // split on @ if present
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
        
        // bare ipv6 (contains :: but no port)
        if s.contains("::") && !s.starts_with('[') {
            return Ok((s.to_string(), default_port));
        }
        
        // try host:port
        if let Some((host, port_str)) = s.rsplit_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                return Ok((host.to_string(), port));
            }
        }
        
        // just hostname/ip
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
    let args = Args::parse();
    
    // determine mode
    if args.listen || args.target.is_none() {
        run_server(args).await
    } else {
        run_client(args).await
    }
}

async fn run_server(args: Args) -> Result<()> {
    // determine listen address
    let listen_addr = if let Some(ref bind) = args.bind {  // Changed to ref bind
        if bind.contains(':') {
            bind.clone()  // clone the string since we're borrowing
        } else {
            let port = args.port_flag
                .or(args.port)
                .unwrap_or(quicnet::DEFAULT_PORT);
            format!("{}:{}", bind, port)
        }
    } else {
        let port = args.port_flag
            .or(args.port)
            .unwrap_or(quicnet::DEFAULT_PORT);
        format!("0.0.0.0:{}", port)
    };

    // load identity
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
        tokio::spawn(handle_connection(incoming, verbose, quiet));
    }

    Ok(())
}

async fn run_client(args: Args) -> Result<()> {
    let target_str = args.target.clone().unwrap();
    
    // parse target
    let default_port = args.port_flag.or(args.port).unwrap_or(quicnet::DEFAULT_PORT);
    let target = Target::parse(&target_str, default_port)?;
    
    // override port if specified
    let target = if let Some(port) = args.port {
        Target { port, ..target }
    } else {
        target
    };
    
    if args.verbose > 0 {
        eprintln!("target: {:?}", target);
    }
    
    // load identity
    let identity = if let Some(hint) = &target.identity_hint {
        load_identity_with_hint(&args, hint)?
    } else {
        load_identity(&args)?
    };
    
    if !args.quiet {
        eprintln!("peer id: {}", identity.peer_id());
    }
    
    // bind address
    let bind_addr: SocketAddr = args.bind
        .as_deref()
        .unwrap_or("0.0.0.0:0")
        .parse()?;
    
    let client = Client::new(bind_addr, identity)?;
    
    // check if hint is a peer id
    let peer_id = target.identity_hint.as_ref()
        .and_then(|h| PeerId::from_str(h).ok());
    
    let addr = target.to_socket_addr()?;
    
    if !args.quiet {
        eprintln!("connecting to {}", addr);
    }
    
    let conn = client.connect(addr, peer_id.as_ref()).await?;
    let remote_peer = quicnet::server::peer_id(&conn)?;
    
    if !args.quiet {
        eprintln!("connected to {} ({})", remote_peer, conn.remote_address());
    }
    
    // open stream
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

async fn handle_connection(incoming: quinn::Incoming, verbose: u8, quiet: bool) -> Result<()> {
    let conn = incoming.await?;
    let peer = quicnet::server::peer_id(&conn)?;
    let remote = conn.remote_address();
    
    if !quiet {
        eprintln!("[{}] connected from {}", peer, remote);
    }
    
    let (mut send, recv) = conn.accept_bi().await?;
    let mut reader = BufReader::new(recv);
    
    // echo server
    let mut line = String::new();
    
    #[cfg(feature = "irc")]
    let mut irc_mode = false;
    
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {
                if verbose > 1 {
                    eprint!("[{}] < {}", peer, line);
                }
                
                #[cfg(feature = "irc")]
                {
                    if !irc_mode && quicnet::irc::is_irc(&line) {
                        irc_mode = true;
                        if verbose > 0 {
                            eprintln!("[{}] irc mode", peer);
                        }
                    }
                    
                    if irc_mode {
                        handle_irc(&mut send, &line).await?;
                    } else {
                        send.write_all(line.as_bytes()).await?;
                    }
                }
                
                #[cfg(not(feature = "irc"))]
                send.write_all(line.as_bytes()).await?;
                
                send.flush().await?;
            }
            Err(e) => {
                if verbose > 0 {
                    eprintln!("[{}] error: {}", peer, e);
                }
                break;
            }
        }
    }
    
    if !quiet {
        eprintln!("[{}] disconnected", peer);
    }
    
    conn.close(0u32.into(), b"");
    Ok(())
}

#[cfg(feature = "irc")]
async fn handle_irc(send: &mut quinn::SendStream, line: &str) -> Result<()> {
    use quicnet::irc::Command;
    
    if let Ok(cmd) = Command::parse(line.trim()) {
        match cmd {
            Command::Ping(token) => {
                send.write_all(format!("PONG {}\n", token).as_bytes()).await?;
            }
            Command::Nick(nick) => {
                send.write_all(format!(":server 001 {} :Welcome\n", nick).as_bytes()).await?;
            }
            _ => {
                send.write_all(b":server 200 * :OK\n").await?;
            }
        }
    }
    Ok(())
}

fn load_identity(args: &Args) -> Result<Identity> {
    // explicit identity file
    if let Some(path) = &args.identity {
        return Identity::from_file(path);
    }
    
    // try ssh key ~/.ssh/id_ed25519
    if let Ok(identity) = Identity::from_ssh_key(None) {
        return Ok(identity);
    }
    
    // use or generate ~/.ssh/id_quicnet
    Identity::load_or_generate()
}

fn load_identity_with_hint(args: &Args, hint: &str) -> Result<Identity> {
    // explicit identity overrides hint
    if let Some(path) = &args.identity {
        return Identity::from_file(path);
    }
    
    // try hint as username for ssh key
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
    
    // fallback to default
    load_identity(args)
}

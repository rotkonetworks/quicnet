// native chat client
use anyhow::Result;
use quicnet::{Identity, Peer};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install crypto provider");

    let args: Vec<String> = std::env::args().collect();
    let target = args.get(1).unwrap_or(&"localhost".to_string()).clone();
    
    let addr = if let Ok(addr) = target.parse::<std::net::SocketAddr>() {
        addr
    } else if target.contains(':') {
        use std::net::ToSocketAddrs;
        target.to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow::anyhow!("cannot resolve {}", target))?
    } else {
        use std::net::ToSocketAddrs;
        format!("{}:4433", target).to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow::anyhow!("cannot resolve {}", target))?
    };

    let identity = Identity::load_or_generate()?;
    let peer = Peer::new("[::]:0".parse()?, identity)?;
    
    eprintln!("connecting to chat server at {}...", addr);
    let (conn, _peer_id) = peer.dial(addr, None).await?;
    
    let (mut send, recv) = conn.open_bi().await?;
    
    let my_nick = peer.identity().peer_id().short();
    eprintln!("connected! you are: {}", my_nick);
    eprintln!("type messages and press enter. ctrl-c to quit.\n");
    
    let mut reader = BufReader::new(recv);
    
    // reader task
    tokio::spawn(async move {
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => {
                    eprintln!("\nserver disconnected");
                    std::process::exit(0);
                }
                Ok(_) => {
                    print!("{}", line);
                    use std::io::Write;
                    let _ = std::io::stdout().flush();
                }
                Err(_) => break,
            }
        }
    });
    
    // keepalive
    let keepalive_conn = conn.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(20)).await;
            if let Ok(mut stream) = keepalive_conn.open_uni().await {
                let _ = stream.write_all(b"ping").await;
                let _ = stream.finish();
            }
        }
    });
    
    // send messages from stdin
    let stdin = tokio::io::stdin();
    let mut stdin_reader = BufReader::new(stdin);
    let mut input = String::new();
    
    loop {
        input.clear();
        match stdin_reader.read_line(&mut input).await {
            Ok(0) => break,
            Ok(_) => {
                if send.write_all(input.as_bytes()).await.is_err() {
                    eprintln!("connection lost");
                    break;
                }
                send.flush().await?;
            }
            Err(_) => break,
        }
    }
    
    send.finish()?;
    conn.close(0u32.into(), b"quit");
    Ok(())
}

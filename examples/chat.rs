// multi-user chat server using quicnet transport
use anyhow::Result;
use quicnet::{ServerBuilder, Identity, AuthenticatedStream, PeerId};
use tokio::sync::broadcast;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

type Peers = Arc<RwLock<HashMap<PeerId, broadcast::Sender<String>>>>;

#[tokio::main]
async fn main() -> Result<()> {
    let identity = Identity::load_or_generate()?;
    
    let server = ServerBuilder::new()
        .identity(identity)
        .bind("[::]:4433")
        .build()?;
    
    eprintln!("chat server listening on {}", server.local_addr()?);
    eprintln!("peer id: {}", server.identity().peer_id());
    
    let peers: Peers = Arc::new(RwLock::new(HashMap::new()));
    let (global_tx, _) = broadcast::channel(1024);
    
    while let Some(stream) = server.accept_authenticated().await {
        let peers = peers.clone();
        let global_tx = global_tx.clone();
        tokio::spawn(handle_chat(stream, peers, global_tx));
    }
    Ok(())
}

async fn handle_chat(
    stream: AuthenticatedStream,
    peers: Peers,
    global_tx: broadcast::Sender<String>,
) -> Result<()> {
    let peer_id = stream.peer_id();
    let nick = peer_id.short();
    
    // announce join
    let join_msg = format!("* {} joined\n", nick);
    let _ = global_tx.send(join_msg.clone());
    
    // register peer
    let (peer_tx, mut peer_rx) = broadcast::channel(256);
    peers.write().insert(peer_id, peer_tx);
    
    // subscribe to global
    let mut global_rx = global_tx.subscribe();
    
    let (send, recv) = stream.split();
    let mut send = send;
    let mut reader = BufReader::new(recv);
    
    loop {
        let mut line = String::new();
        
        tokio::select! {
            // read from peer
            result = reader.read_line(&mut line) => {
                match result {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        let msg = format!("{}: {}", nick, line);
                        let _ = global_tx.send(msg);
                    }
                }
            }
            
            // broadcast to peer
            result = global_rx.recv() => {
                if let Ok(msg) = result {
                    if send.write_all(msg.as_bytes()).await.is_err() {
                        break;
                    }
                }
            }
        }
    }
    
    // cleanup
    peers.write().remove(&peer_id);
    let leave_msg = format!("* {} left\n", nick);
    let _ = global_tx.send(leave_msg);
    
    Ok(())
}

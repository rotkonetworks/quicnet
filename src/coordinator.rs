// coordinator for relay and presence
use anyhow::Result;
use quinn::Connection;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::io::{AsyncBufReadExt, BufReader};
use crate::{Identity, PeerId, Server};

pub struct Coordinator {
    server: Server,
    peers: Arc<RwLock<HashMap<PeerId, PeerState>>>,
}

struct PeerState {
    conn: Connection,
    nick: Option<String>,
    addr: SocketAddr,
}

impl Coordinator {
    pub async fn new(addr: SocketAddr, identity: Identity) -> Result<Self> {
        let server = Server::bind(addr, identity)?;
        Ok(Self {
            server,
            peers: Arc::new(RwLock::new(HashMap::new())),
        })
    }
    
    pub async fn run(self) -> Result<()> {
        while let Some(incoming) = self.server.accept().await {
            let peers = self.peers.clone();
            tokio::spawn(async move {
                let _ = handle_peer(incoming, peers).await;
            });
        }
        Ok(())
    }
}

async fn handle_peer(
    incoming: crate::server::AuthenticatedIncoming,
    peers: Arc<RwLock<HashMap<PeerId, PeerState>>>,
) -> Result<()> {
    let addr = incoming.remote_address();
    let (conn, peer_id) = incoming.accept().await?;
    
    eprintln!("[coordinator] {} connected from {}", peer_id, addr);
    
    // add to peer list
    {
        let mut peers = peers.write().await;
        peers.insert(peer_id, PeerState {
            conn: conn.clone(),
            nick: None,
            addr,
        });
    }
    
    // broadcast presence to all peers
    broadcast_presence(&peers, &peer_id, true).await;
    
    // handle messages
    let (mut send, recv) = conn.accept_bi().await?;
    let mut reader = BufReader::new(recv);
    let mut line = String::new();
    
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {
                // parse and route messages
                if let Some((cmd, rest)) = line.trim().split_once(' ') {
                    match cmd {
                        "NICK" => {
                            let mut peers = peers.write().await;
                            if let Some(peer) = peers.get_mut(&peer_id) {
                                peer.nick = Some(rest.to_string());
                            }
                        }
                        "MSG" => {
                            // relay to all except sender
                            relay_message(&peers, &peer_id, &line).await;
                        }
                        "DM" => {
                            // direct message to specific peer
                            if let Some((target, _msg)) = rest.split_once(' ') {
                                if let Ok(target_id) = PeerId::from_str(target) {
                                    send_to_peer(&peers, &target_id, &line).await;
                                }
                            }
                        }
                        "LIST" => {
                            // send peer list with addresses for debugging
                            let response = list_peers(&peers).await;
                            let _ = send.write_all(response.as_bytes()).await;
                        }
                        _ => {}
                    }
                }
            }
            Err(_) => break,
        }
    }
    
    // remove from peer list
    {
        let mut peers = peers.write().await;
        peers.remove(&peer_id);
    }
    
    // broadcast departure
    broadcast_presence(&peers, &peer_id, false).await;
    
    eprintln!("[coordinator] {} disconnected", peer_id);
    conn.close(0u32.into(), b"");
    Ok(())
}

async fn broadcast_presence(
    peers: &Arc<RwLock<HashMap<PeerId, PeerState>>>,
    peer_id: &PeerId,
    joined: bool,
) {
    let msg = format!("PRESENCE {} {}\n", peer_id, if joined { "JOIN" } else { "PART" });
    relay_message(peers, peer_id, &msg).await;
}

async fn relay_message(
    peers: &Arc<RwLock<HashMap<PeerId, PeerState>>>,
    sender: &PeerId,
    msg: &str,
) {
    let peers = peers.read().await;
    for (id, peer) in peers.iter() {
        if id != sender {
            if let Ok((mut send, _)) = peer.conn.open_bi().await {
                let _ = send.write_all(msg.as_bytes()).await;
            }
        }
    }
}

async fn send_to_peer(
    peers: &Arc<RwLock<HashMap<PeerId, PeerState>>>,
    target: &PeerId,
    msg: &str,
) {
    let peers = peers.read().await;
    if let Some(peer) = peers.get(target) {
        if let Ok((mut send, _)) = peer.conn.open_bi().await {
            let _ = send.write_all(msg.as_bytes()).await;
        }
    }
}

async fn list_peers(peers: &Arc<RwLock<HashMap<PeerId, PeerState>>>) -> String {
    let peers = peers.read().await;
    let mut response = String::from("PEERS");
    for (id, peer) in peers.iter() {
        response.push_str(&format!(" {}:{}@{}", 
            id, 
            peer.nick.as_deref().unwrap_or("?"),
            peer.addr
        ));
    }
    response.push('\n');
    response
}

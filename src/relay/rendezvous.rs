// rendezvous protocol for coordinating nat traversal
//
// peers coordinate through rendezvous points without revealing
// their relationship to the relay or each other to observers

use crate::identity::{Identity, PeerId};
use crate::peer::Peer;
use anyhow::Result;
use arrayref::array_ref;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use quinn::{Connection, RecvStream, SendStream};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;
use x25519_dalek::{EphemeralSecret, PublicKey};

// protocol messages between peer and relay
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RelayMessage {
    // request to store rendezvous message
    StoreRendezvous {
        rendezvous_id: [u8; 32],
        ciphertext: Vec<u8>,
        ephemeral_id: [u8; 16],
    },
    // request to retrieve rendezvous message
    RetrieveRendezvous {
        rendezvous_id: [u8; 32],
    },
    // response with retrieved message
    RendezvousFound {
        ciphertext: Vec<u8>,
    },
    // no message found
    RendezvousEmpty,
    // forward to another relay (for entry->rendezvous routing)
    Forward {
        next_hop: SocketAddr,
        payload: Vec<u8>,
    },
}

// information exchanged at rendezvous for hole punching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PunchInfo {
    // peer's external endpoints as seen by entry relay
    external_addrs: Vec<SocketAddr>,
    // peer's local endpoints for same-network optimization
    local_addrs: Vec<SocketAddr>,
    // ephemeral key for this session
    session_key: [u8; 32],
    // random nonce for coordination
    nonce: [u8; 16],
}

pub struct RendezvousProtocol {
    identity: Identity,
}

impl RendezvousProtocol {
    pub fn new(identity: Identity) -> Self {
        Self { identity }
    }

    // initiate rendezvous with target peer
    pub async fn initiate_rendezvous(
        &self,
        peer: &Peer,
        target: &PeerId,
        entry_relay: SocketAddr,
        rendezvous_relay: SocketAddr,
    ) -> Result<PunchInfo> {
        // connect to entry relay
        let (conn, _relay_id) = peer.dial(entry_relay, None).await?;

        // calculate rendezvous point
        let my_id = self.identity.peer_id();
        let rendezvous_id = super::RelayNode::calculate_rendezvous(&my_id, target);

        // prepare punch info
        let my_punch_info = PunchInfo {
            external_addrs: vec![],  // relay will fill this
            local_addrs: self.get_local_addrs()?,
            session_key: OsRng.gen::<[u8; 32]>(),
            nonce: OsRng.gen::<[u8; 16]>(),
        };

        // encrypt punch info for target
        let ciphertext = self.encrypt_for_peer(target, &my_punch_info)?;

        // send store request through entry relay
        let msg = RelayMessage::StoreRendezvous {
            rendezvous_id,
            ciphertext: ciphertext.clone(),
            ephemeral_id: OsRng.gen::<[u8; 16]>(),
        };

        self.send_via_relay(&conn, rendezvous_relay, msg).await?;

        // wait and retrieve response
        tokio::time::sleep(Duration::from_millis(500)).await;

        let retrieve_msg = RelayMessage::RetrieveRendezvous { rendezvous_id };
        let response = self.send_via_relay(&conn, rendezvous_relay, retrieve_msg).await?;

        match response {
            RelayMessage::RendezvousFound { ciphertext } => {
                // decrypt peer's punch info
                let peer_info: PunchInfo = self.decrypt_from_peer(target, &ciphertext)?;
                Ok(peer_info)
            }
            RelayMessage::RendezvousEmpty => {
                // we're first, wait for peer
                self.wait_for_peer(&conn, rendezvous_relay, rendezvous_id, target).await
            }
            _ => anyhow::bail!("unexpected relay response"),
        }
    }

    // wait for peer to arrive at rendezvous
    async fn wait_for_peer(
        &self,
        conn: &Connection,
        rendezvous_relay: SocketAddr,
        rendezvous_id: [u8; 32],
        peer: &PeerId,
    ) -> Result<PunchInfo> {
        let mut attempts = 0;
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;

            let msg = RelayMessage::RetrieveRendezvous { rendezvous_id };
            let response = self.send_via_relay(conn, rendezvous_relay, msg).await?;

            match response {
                RelayMessage::RendezvousFound { ciphertext } => {
                    let peer_info: PunchInfo = self.decrypt_from_peer(peer, &ciphertext)?;
                    return Ok(peer_info);
                }
                RelayMessage::RendezvousEmpty => {
                    attempts += 1;
                    if attempts > 30 {
                        anyhow::bail!("rendezvous timeout");
                    }
                }
                _ => anyhow::bail!("unexpected relay response"),
            }
        }
    }

    // send message through relay with forward wrapping
    async fn send_via_relay(
        &self,
        conn: &Connection,
        relay_addr: SocketAddr,
        msg: RelayMessage,
    ) -> Result<RelayMessage> {
        let (mut send, mut recv) = conn.open_bi().await?;

        // serialize inner message
        let inner_payload = bincode::serialize(&msg)?;

        // wrap in forward message
        let forward_msg = RelayMessage::Forward {
            next_hop: relay_addr,
            payload: inner_payload,
        };

        // send to entry relay
        let data = bincode::serialize(&forward_msg)?;
        send.write_all(&data).await?;
        send.finish()?;

        // read response
        let response_data = recv.read_to_end(65536).await?;
        let response: RelayMessage = bincode::deserialize(&response_data)?;
        Ok(response)
    }

    // encrypt data for specific peer using ecdh
    fn encrypt_for_peer(&self, peer: &PeerId, data: &PunchInfo) -> Result<Vec<u8>> {
        // ephemeral ecdh
        let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        // convert peer's ed25519 to x25519 for ecdh
        let peer_x25519 = self.ed25519_to_x25519(peer.as_bytes())?;
        let shared_secret = ephemeral_secret.diffie_hellman(&peer_x25519);

        // derive encryption key
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"quicnet-rendezvous-v1");
        hasher.update(shared_secret.as_bytes());
        let key = hasher.finalize();

        // encrypt with chacha20poly1305
        let cipher = ChaCha20Poly1305::new_from_slice(&key.as_bytes()[..32])?;
        let nonce = Nonce::from_slice(&[0u8; 12]);
        let plaintext = bincode::serialize(data)?;
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())?;

        // prepend ephemeral public key
        let mut result = ephemeral_public.as_bytes().to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    // decrypt data from specific peer
    fn decrypt_from_peer(&self, peer: &PeerId, data: &[u8]) -> Result<PunchInfo> {
        if data.len() < 32 {
            anyhow::bail!("invalid ciphertext");
        }

        // extract ephemeral public key
        let ephemeral_public = PublicKey::from(*array_ref![data, 0, 32]);
        let ciphertext = &data[32..];

        // ecdh with our identity
        let our_secret = self.identity_to_x25519()?;
        let shared_secret = our_secret.diffie_hellman(&ephemeral_public);

        // derive decryption key
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"quicnet-rendezvous-v1");
        hasher.update(shared_secret.as_bytes());
        let key = hasher.finalize();

        // decrypt
        let cipher = ChaCha20Poly1305::new_from_slice(&key.as_bytes()[..32])?;
        let nonce = Nonce::from_slice(&[0u8; 12]);
        let plaintext = cipher.decrypt(nonce, ciphertext)?;

        let punch_info: PunchInfo = bincode::deserialize(&plaintext)?;
        Ok(punch_info)
    }

    // convert ed25519 public key to x25519
    fn ed25519_to_x25519(&self, ed_public: &[u8]) -> Result<PublicKey> {
        // montgomery conversion for ecdh
        // this is safe because we're only using it for ephemeral key agreement
        let point = curve25519_dalek::edwards::CompressedEdwardsY::from_slice(ed_public)?
            .decompress()
            .ok_or_else(|| anyhow::anyhow!("invalid ed25519 point"))?;

        let montgomery = point.to_montgomery();
        Ok(PublicKey::from(montgomery.to_bytes()))
    }

    // convert our ed25519 identity to x25519 secret
    fn identity_to_x25519(&self) -> Result<x25519_dalek::StaticSecret> {
        // derive x25519 key from ed25519 identity
        // using hash to avoid exposing actual private key bits
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"quicnet-x25519-derive");
        hasher.update(&self.identity.to_bytes());
        let hash = hasher.finalize();

        Ok(x25519_dalek::StaticSecret::from(*array_ref![hash.as_bytes(), 0, 32]))
    }

    // get local network addresses for same-lan optimization
    fn get_local_addrs(&self) -> Result<Vec<SocketAddr>> {
        // todo: enumerate local interfaces
        // for now return empty, relay will add external addresses
        Ok(vec![])
    }
}


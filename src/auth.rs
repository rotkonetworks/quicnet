// unified symmetric authentication using ed25519 challenge-response
use anyhow::Result;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use quinn::Connection;
use crate::identity::{Identity, PeerId};

const AUTH_MAGIC: &[u8; 8] = b"QUICNET1";

pub async fn handshake(conn: &Connection, identity: &Identity, initiator: bool) -> Result<PeerId> {
    let (mut send, mut recv) = if initiator {
        conn.open_bi().await?
    } else {
        conn.accept_bi().await?
    };

    // protocol version
    send.write_all(AUTH_MAGIC).await?;
    
    // check protocol version
    let mut magic = [0u8; 8];
    recv.read_exact(&mut magic).await?;
    if &magic != AUTH_MAGIC {
        anyhow::bail!("wrong protocol");
    }
    
    // both sides send challenge
    let our_challenge = rand::random::<[u8; 32]>();
    send.write_all(&our_challenge).await?;
    
    // read their challenge
    let mut their_challenge = [0u8; 32];
    recv.read_exact(&mut their_challenge).await?;
    
    // sign their challenge and send with our pubkey
    let our_sig = identity.sign(&their_challenge);
    send.write_all(&our_sig).await?;
    send.write_all(identity.peer_id().as_bytes()).await?;
    send.finish()?;
    
    // read their signature and pubkey
    let mut their_sig = [0u8; 64];
    recv.read_exact(&mut their_sig).await?;
    let mut their_pubkey = [0u8; 32];
    recv.read_exact(&mut their_pubkey).await?;
    
    // verify
    let verifying_key = VerifyingKey::from_bytes(&their_pubkey)?;
    verifying_key
        .verify(&our_challenge, &Signature::from_bytes(&their_sig))
        .map_err(|_| anyhow::anyhow!("peer auth failed"))?;
    
    Ok(PeerId::from_public_key(&their_pubkey))
}

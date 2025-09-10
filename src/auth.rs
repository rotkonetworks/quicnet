// application-layer authentication using ed25519 challenge-response
use anyhow::Result;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use quinn::Connection;
use crate::identity::{Identity, PeerId};

const AUTH_MAGIC: &[u8; 8] = b"QUICNET1";

pub async fn handshake_client(
    conn: &Connection,
    identity: &Identity,
) -> Result<PeerId> {
    let (mut send, mut recv) = conn.open_bi().await?;
    
    // protocol version
    send.write_all(AUTH_MAGIC).await?;
    
    // read server challenge
    let mut challenge = [0u8; 32];
    recv.read_exact(&mut challenge).await?;
    
    // sign and send response with pubkey
    let signature = identity.sign(&challenge);
    send.write_all(&signature).await?;
    send.write_all(identity.peer_id().as_bytes()).await?;
    
    // send our challenge
    let our_challenge = rand::random::<[u8; 32]>();
    send.write_all(&our_challenge).await?;
    send.finish()?;
    
    // read server's signature and pubkey
    let mut server_sig = [0u8; 64];
    recv.read_exact(&mut server_sig).await?;
    let mut server_pubkey = [0u8; 32];
    recv.read_exact(&mut server_pubkey).await?;
    
    // verify server
    let verifying_key = VerifyingKey::from_bytes(&server_pubkey)?;
    verifying_key.verify(&our_challenge, &Signature::from_bytes(&server_sig))
        .map_err(|_| anyhow::anyhow!("server auth failed"))?;
    
    Ok(PeerId::from_public_key(&server_pubkey))
}

pub async fn handshake_server(
    conn: &Connection,
    identity: &Identity,
) -> Result<PeerId> {
    let (mut send, mut recv) = conn.accept_bi().await?;
    
    // check protocol version
    let mut magic = [0u8; 8];
    recv.read_exact(&mut magic).await?;
    if &magic != AUTH_MAGIC {
        anyhow::bail!("wrong protocol");
    }
    
    // send challenge
    let challenge = rand::random::<[u8; 32]>();
    send.write_all(&challenge).await?;
    
    // read client's signature and pubkey
    let mut client_sig = [0u8; 64];
    recv.read_exact(&mut client_sig).await?;
    let mut client_pubkey = [0u8; 32];
    recv.read_exact(&mut client_pubkey).await?;
    
    // verify client
    let verifying_key = VerifyingKey::from_bytes(&client_pubkey)?;
    verifying_key.verify(&challenge, &Signature::from_bytes(&client_sig))
        .map_err(|_| anyhow::anyhow!("client auth failed"))?;
    
    // read client's challenge
    let mut client_challenge = [0u8; 32];
    recv.read_exact(&mut client_challenge).await?;
    
    // sign and respond
    let our_sig = identity.sign(&client_challenge);
    send.write_all(&our_sig).await?;
    send.write_all(identity.peer_id().as_bytes()).await?;
    send.finish()?;
    
    Ok(PeerId::from_public_key(&client_pubkey))
}

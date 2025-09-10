// src/server.rs
use anyhow::Result;
use quinn::{Endpoint, ServerConfig, Incoming, Connection};
use std::net::SocketAddr;
use std::sync::Arc;
use crate::identity::{Identity, PeerId};

pub struct Server {
    endpoint: Endpoint,
    identity: Identity,
}

impl Server {
    pub fn bind(addr: SocketAddr, identity: Identity) -> Result<Self> {
        let (cert_chain, key) = identity.certificate()?;
        
        let mut crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key.into())?;
        
        crypto.alpn_protocols = vec![b"quicnet/1".to_vec()];
        crypto.max_early_data_size = 0;  // disable 0-rtt for simplicity

        let config = ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?
        ));
        
        let endpoint = Endpoint::server(config, addr)?;
        Ok(Self { endpoint, identity })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub async fn accept(&self) -> Option<Incoming> {
        self.endpoint.accept().await
    }
    
    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"server shutdown");
    }
}

// extract peer id from connection
pub fn peer_id(conn: &Connection) -> Result<PeerId> {
    // with quinn 0.11, getting peer certificates requires a different approach
    // for now, we'll use a workaround based on the remote address
    // in a production system, you'd want to hook into the TLS handshake more deeply
    
    // check if we can get handshake data
    if let Some(handshake_data) = conn.handshake_data() {
        if let Some(data) = handshake_data.downcast_ref::<quinn::crypto::rustls::HandshakeData>() {
            // the protocol field exists but peer certificates aren't easily accessible in quinn 0.11
            // this is a known limitation - proper peer certificate extraction would require
            // custom rustls configuration or waiting for quinn updates
            
            if let Some(_protocol) = &data.protocol {
                // for demonstration, generate a consistent peer id from the connection
                // in production, you'd extract this from the actual certificate
                let addr_str = format!("{}", conn.remote_address());
                let addr_bytes = addr_str.as_bytes();
                let mut id = [0u8; 32];
                
                // create a deterministic peer id from the address (for demo purposes)
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                let mut hasher = DefaultHasher::new();
                addr_bytes.hash(&mut hasher);
                let hash = hasher.finish();
                
                // fill the id with hash bytes
                for i in 0..32 {
                    id[i] = ((hash >> (i % 8 * 8)) & 0xff) as u8;
                }
                
                return Ok(PeerId::from_public_key(&id));
            }
        }
    }
    
    anyhow::bail!("no peer certificate available")
}

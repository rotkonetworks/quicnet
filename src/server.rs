// quic server with proper authentication
use anyhow::Result;
use quinn::{Endpoint, ServerConfig, Incoming, Connection};
use std::net::SocketAddr;
use std::sync::Arc;
use crate::identity::{Identity, PeerId};
use crate::auth;

pub struct Server {
    endpoint: Endpoint,
    identity: Identity,
}

impl Server {
    pub fn bind(addr: SocketAddr, identity: Identity) -> Result<Self> {
        // generate ephemeral cert for TLS layer
        let cert = rcgen::generate_simple_self_signed(vec!["quicnet".to_string()])?;
        let cert_chain = vec![cert.cert.der().clone()];
        let key_der = cert.key_pair.serialize_der();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(key_der);
        
        let mut crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key.into())?;
        
        crypto.alpn_protocols = vec![b"quicnet/1".to_vec()];
        crypto.max_early_data_size = 0;

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

    pub async fn accept(&self) -> Option<AuthenticatedIncoming> {
        let incoming = self.endpoint.accept().await?;
        Some(AuthenticatedIncoming {
            incoming,
            identity: self.identity.clone(),
        })
    }
    
    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"shutdown");
    }
}

pub struct AuthenticatedIncoming {
    incoming: Incoming,
    identity: Identity,
}

impl AuthenticatedIncoming {
    pub async fn accept(self) -> Result<(Connection, PeerId)> {
        let conn = self.incoming.await?;
        let peer_id = auth::handshake_server(&conn, &self.identity).await?;
        Ok((conn, peer_id))
    }
    
    pub fn remote_address(&self) -> SocketAddr {
        self.incoming.remote_address()
    }
}

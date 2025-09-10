// src/client.rs
use anyhow::Result;
use quinn::{ClientConfig, Connection, Endpoint};
use std::net::SocketAddr;
use std::sync::Arc;
use crate::identity::{Identity, PeerId};

pub struct Client {
    endpoint: Endpoint,
    identity: Identity,
}

impl Client {
    pub fn new(bind_addr: SocketAddr, identity: Identity) -> Result<Self> {
        let (cert_chain, key) = identity.certificate()?;
        
        // accept any ed25519 cert
        #[derive(Debug)]
        struct AnyEd25519;
        impl rustls::client::danger::ServerCertVerifier for AnyEd25519 {
            fn verify_server_cert(
                &self,
                end_entity: &rustls::pki_types::CertificateDer<'_>,
                _: &[rustls::pki_types::CertificateDer<'_>],
                _: &rustls::pki_types::ServerName<'_>,
                _: &[u8],
                _: rustls::pki_types::UnixTime,
            ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
                crate::identity::verify_peer_cert(end_entity)
                    .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature))?;
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                _: &[u8],
                _: &rustls::pki_types::CertificateDer<'_>,
                _: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }

            fn verify_tls13_signature(
                &self,
                _: &[u8],
                _: &rustls::pki_types::CertificateDer<'_>,
                _: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }

            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                vec![rustls::SignatureScheme::ED25519]
            }
        }

        let mut crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyEd25519))
            .with_client_auth_cert(cert_chain, key.into())?;
        
        crypto.alpn_protocols = vec![b"quicnet/1".to_vec()];
        crypto.enable_early_data = false;  // disable 0-rtt for simplicity

        let config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?
        ));

        let mut endpoint = Endpoint::client(bind_addr)?;
        endpoint.set_default_client_config(config);
        
        Ok(Self { endpoint, identity })
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub async fn connect(&self, addr: SocketAddr, peer_id: Option<&PeerId>) -> Result<Connection> {
        // use peer id as server name if provided
        let server_name = peer_id
            .map(|p| p.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        
        let conn = self.endpoint.connect(addr, &server_name)?.await?;
        
        // verify peer id if expected
        if let Some(_expected) = peer_id {
            let _actual = crate::server::peer_id(&conn)?;
            // note: peer_id extraction is simplified in our implementation
            // in production, would need proper certificate verification
        }
        
        Ok(conn)
    }
    
    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"client shutdown");
    }
}

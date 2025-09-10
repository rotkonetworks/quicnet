// quic client with proper authentication
use anyhow::Result;
use quinn::{ClientConfig, Connection, Endpoint};
use std::net::SocketAddr;
use std::sync::Arc;
use crate::identity::{Identity, PeerId};
use crate::auth;

pub struct Client {
    endpoint: Endpoint,
    identity: Identity,
}

impl Client {
    pub fn new(bind_addr: SocketAddr, identity: Identity) -> Result<Self> {
        // generate ephemeral cert for TLS layer
        let cert = rcgen::generate_simple_self_signed(vec!["quicnet".to_string()])?;
        let cert_chain = vec![cert.cert.der().clone()];
        let key_der = cert.key_pair.serialize_der();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(key_der);
        
        // accept any cert since we do app-layer auth
        #[derive(Debug)]
        struct PermissiveVerifier;
        
        impl rustls::client::danger::ServerCertVerifier for PermissiveVerifier {
            fn verify_server_cert(
                &self,
                _end_entity: &rustls::pki_types::CertificateDer<'_>,
                _intermediates: &[rustls::pki_types::CertificateDer<'_>],
                _server_name: &rustls::pki_types::ServerName<'_>,
                _ocsp: &[u8],
                _now: rustls::pki_types::UnixTime,
            ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &rustls::pki_types::CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }

            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &rustls::pki_types::CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }

            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                vec![
                    rustls::SignatureScheme::ED25519,
                    rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                    rustls::SignatureScheme::RSA_PSS_SHA256,
                ]
            }
        }

        let mut crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PermissiveVerifier))
            .with_client_auth_cert(cert_chain, key.into())?;
        
        crypto.alpn_protocols = vec![b"quicnet/1".to_vec()];
        crypto.enable_early_data = false;

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

    pub async fn connect(&self, addr: SocketAddr, expected_peer: Option<&PeerId>) -> Result<(Connection, PeerId)> {
        let conn = self.endpoint.connect(addr, "quicnet")?.await?;
        
        // authenticate at application layer
        let peer_id = auth::handshake_client(&conn, &self.identity).await?;
        
        if let Some(expected) = expected_peer {
            if peer_id != *expected {
                conn.close(0u32.into(), b"wrong peer");
                anyhow::bail!("expected {} but got {}", expected, peer_id);
            }
        }
        
        Ok((conn, peer_id))
    }
    
    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"shutdown");
    }
}

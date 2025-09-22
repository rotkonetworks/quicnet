// unified peer that can dial or accept
use crate::auth;
use crate::identity::{Identity, PeerId};
use crate::security::{AuditEvent, AuditLog, RateLimiter};
use anyhow::Result;
use quinn::{ClientConfig, Connection, Endpoint, Incoming, ServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;

pub struct Peer {
    endpoint: Endpoint,
    identity: Identity,
    pub(crate) rate_limiter: Option<RateLimiter>,
    pub(crate) audit_log: AuditLog,
    pub(crate) authorized_peers_file: Option<std::path::PathBuf>,
}

impl Peer {
    pub fn new(bind_addr: SocketAddr, identity: Identity) -> Result<Self> {
        let (cert_chain, key) = tls_cert_from_identity(&identity)?;

        // server config for accepting
        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key.into())?;
        server_crypto.alpn_protocols = vec![b"quicnet/1".to_vec()];
        server_crypto.max_early_data_size = 0;

        let server_config = ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
        ));

        // start endpoint with server config
        let endpoint = Endpoint::server(server_config, bind_addr)?;

        Ok(Self {
            endpoint,
            identity,
            rate_limiter: None,
            audit_log: AuditLog::disabled(),
            authorized_peers_file: None,
        })
    }

    pub async fn dial(
        &self,
        addr: SocketAddr,
        expected_peer: Option<&PeerId>,
    ) -> Result<(Connection, PeerId)> {
        let (cert_chain, key) = tls_cert_from_identity(&self.identity)?;
        let verifier = Arc::new(PeerIdVerifier {
            expected: expected_peer.copied(),
        });

        let mut crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(cert_chain, key.into())?;
        crypto.alpn_protocols = vec![b"quicnet/1".to_vec()];
        crypto.enable_early_data = false;

        let client_cfg = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
        ));

        let connecting = self.endpoint.connect_with(client_cfg, addr, "quicnet")?;
        let conn = connecting.await?;

        // unified handshake as initiator
        let peer_id = auth::handshake(&conn, &self.identity, true).await?;

        if let Some(expected) = expected_peer
            && peer_id != *expected {
                conn.close(0u32.into(), b"wrong peer");
                anyhow::bail!("expected {} but got {}", expected, peer_id);
            }

        Ok((conn, peer_id))
    }

    pub async fn accept(&self) -> Option<IncomingConnection> {
        let incoming = self.endpoint.accept().await?;
        Some(IncomingConnection {
            incoming,
            identity: self.identity.clone(),
        })
    }

    pub async fn accept_authenticated(&self) -> Option<crate::transport::AuthenticatedStream> {
        let incoming = self.accept().await?;
        let remote = incoming.remote_address();

        // Rate limiting by IP
        if let Some(limiter) = &self.rate_limiter
            && !limiter.check(remote.ip()) {
                self.audit_log.log(AuditEvent::RateLimited {
                    addr: remote.to_string(),
                });
            }

        match incoming.accept().await {
            Ok((conn, peer_id)) => {
                // Authorization (optional)
                if let Some(path) = &self.authorized_peers_file {
                    let ap = match crate::authorized_peers::AuthorizedPeers::load_path(path) {
                        Ok(ap) => ap,
                        Err(_) => {
                            self.audit_log.log(AuditEvent::ConnectionRejected {
                                peer: peer_id,
                                addr: remote.to_string(),
                                reason: "authz file unreadable".into(),
                            });
                            conn.close(0u32.into(), b"authorization config error");
                            return None;
                        }
                    };
                    if !ap.is_authorized(&peer_id) {
                        self.audit_log.log(AuditEvent::ConnectionRejected {
                            peer: peer_id,
                            addr: remote.to_string(),
                            reason: "unauthorized".into(),
                        });
                        conn.close(0u32.into(), b"unauthorized");
                        return None;
                    }
                }
                self.audit_log.log(AuditEvent::ConnectionAccepted {
                    peer: peer_id,
                    addr: remote.to_string(),
                });
                crate::transport::AuthenticatedStream::server(conn, peer_id)
                    .await
                    .ok()
            }
            Err(_e) => {
                self.audit_log.log(AuditEvent::AuthenticationFailed {
                    addr: remote.to_string(),
                });
                None
            }
        }
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"shutdown");
    }
}

pub struct IncomingConnection {
    incoming: Incoming,
    identity: Identity,
}

impl IncomingConnection {
    pub async fn accept(self) -> Result<(Connection, PeerId)> {
        let conn = self.incoming.await?;
        let peer_id = auth::handshake(&conn, &self.identity, false).await?;
        Ok((conn, peer_id))
    }

    pub fn remote_address(&self) -> SocketAddr {
        self.incoming.remote_address()
    }
}

// shared tls cert generation
fn tls_cert_from_identity(
    identity: &Identity,
) -> Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivatePkcs8KeyDer<'static>,
)> {
    use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

    let pkcs8 = identity.pkcs8_der()?;
    let pk = PrivatePkcs8KeyDer::from(pkcs8);
    let kp = KeyPair::from_pkcs8_der_and_sign_algo(&pk, &PKCS_ED25519)?;

    let params = CertificateParams::new(vec!["quicnet".to_string()])?;
    let cert = params.self_signed(&kp)?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    Ok((vec![cert_der], pk))
}

#[derive(Debug)]
struct PeerIdVerifier {
    expected: Option<PeerId>,
}

impl rustls::client::danger::ServerCertVerifier for PeerIdVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if let Some(expected) = self.expected {
            use x509_parser::prelude::FromDer;
            let (_, cert) =
                x509_parser::certificate::X509Certificate::from_der(end_entity.as_ref())
                    .map_err(|_| rustls::Error::General("x509 parse error".into()))?;
            let spki = &cert.tbs_certificate.subject_pki;
            let oid_ed25519 = x509_parser::oid_registry::OID_SIG_ED25519;
            if spki.algorithm.algorithm != oid_ed25519 {
                return Err(rustls::Error::General("server cert not Ed25519".into()));
            }
            let pk_bits = spki.subject_public_key.data.to_owned();
            if pk_bits.as_ref() != expected.as_bytes() {
                return Err(rustls::Error::General(
                    "peer id mismatch (SPKI != expected)".into(),
                ));
            }
        }
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

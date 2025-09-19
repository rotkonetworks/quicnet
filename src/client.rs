// quic client with identity-bound TLS and application auth
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
        let endpoint = Endpoint::client(bind_addr)?;
        Ok(Self { endpoint, identity })
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub async fn connect(
        &self,
        addr: SocketAddr,
        expected_peer: Option<&PeerId>,
    ) -> Result<(Connection, PeerId)> {
        // Build per-connection rustls config so the verifier can use expected_peer
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

        // application-layer mutual auth
        let peer_id = crate::auth::handshake_client(&conn, &self.identity).await?;

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

fn tls_cert_from_identity(
    identity: &Identity,
) -> Result<(Vec<rustls::pki_types::CertificateDer<'static>>, rustls::pki_types::PrivatePkcs8KeyDer<'static>)> {
    use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

    let pkcs8 = identity.pkcs8_der()?;
    let pk = PrivatePkcs8KeyDer::from(pkcs8);
    let kp = KeyPair::from_pkcs8_der_and_sign_algo(&pk, &PKCS_ED25519)?;

    let params = CertificateParams::new(vec!["quicnet".to_string()])?;
    // SubjectAltName “quicnet” is fine; we verify SPKI not DNS.
    let cert = params.self_signed(&kp)?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    Ok((vec![cert_der], pk))
}

/// Custom rustls verifier: if an expected PeerId is provided, enforce
/// that the server's certificate SPKI (Ed25519) matches it.
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
            // parse x509 and extract Ed25519 SPKI
            use x509_parser::prelude::FromDer;
            let (_, cert) = x509_parser::certificate::X509Certificate::from_der(end_entity.as_ref())
                .map_err(|_| rustls::Error::General("x509 parse error".into()))?;
            let spki = &cert.tbs_certificate.subject_pki;
            // 1.3.101.112 is Ed25519
            let oid_ed25519 = x509_parser::oid_registry::OID_SIG_ED25519;
            if spki.algorithm.algorithm != oid_ed25519 {
                return Err(rustls::Error::General(
                    "server cert not Ed25519".into(),
                ));
            }
            let pk_bits = spki
                .subject_public_key
                .data
                .to_owned(); // raw 32 bytes
            if pk_bits.as_ref() != expected.as_bytes() {
                return Err(rustls::Error::General(
                    "peer id mismatch (SPKI != expected)".into(),
                ));
            }
        } else {
            // No expected peer: allow, but this is TOFU territory.
            // (Would be better to store mapping; out of scope for now.)
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

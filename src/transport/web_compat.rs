// src/transport/web_compat.rs
#[cfg(feature = "webtransport")]
use anyhow::Result;
#[cfg(feature = "webtransport")]
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
#[cfg(feature = "webtransport")]
use std::sync::Arc;
#[cfg(feature = "webtransport")]
use std::net::SocketAddr;
#[cfg(feature = "webtransport")]
use crate::Identity;

#[cfg(feature = "webtransport")]
pub struct WebCompatServer {
    endpoint: h3_quinn::quinn::Endpoint,
    identity: Identity,
    cert_hash: String,
}

#[cfg(feature = "webtransport")]
impl WebCompatServer {
    pub async fn new(addr: SocketAddr, identity: Identity) -> Result<Self> {
        let (cert_chain, key) = generate_self_signed_cert(&identity)?;

        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&cert_chain[0]);
        let cert_hash = hex::encode(hasher.finalize());

        let mut crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)?;

        crypto.alpn_protocols = vec![b"h3".to_vec()];
        crypto.max_early_data_size = u32::MAX;

        let mut server_config = h3_quinn::quinn::ServerConfig::with_crypto(Arc::new(
            h3_quinn::quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?
        ));

        let mut transport_config = h3_quinn::quinn::TransportConfig::default();
        transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
        server_config.transport = Arc::new(transport_config);

        let endpoint = h3_quinn::quinn::Endpoint::server(server_config, addr)?;

        eprintln!("webtransport server on https://{}", addr);
        eprintln!("cert hash: {}", cert_hash);

        Ok(Self { endpoint, identity, cert_hash })
    }

    pub async fn accept_webtransport(&self) -> Option<h3_webtransport::server::WebTransportSession<h3_quinn::Connection, bytes::Bytes>> {
        use bytes::Bytes;
        use h3::ext::Protocol;
        use http::Method;

        loop {
            let incoming = self.endpoint.accept().await?;
            let conn = match incoming.await {
                Ok(c) => c,
                Err(_) => continue,
            };

            // spawn task to handle this connection
            let handle = tokio::spawn(async move {
                let h3_conn = h3::server::builder()
                    .enable_webtransport(true)
                    .enable_extended_connect(true)
                    .enable_datagram(true)
                    .build(h3_quinn::Connection::new(conn))
                    .await
                    .ok()?;

                let mut h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes> = h3_conn;

                // accept first request on this connection
                loop {
                    match h3_conn.accept().await {
                        Ok(Some(resolver)) => {
                            let (req, stream) = match resolver.resolve_request().await {
                                Ok(r) => r,
                                Err(_) => continue,
                            };

                            let ext = req.extensions();
                            if req.method() == &Method::CONNECT
                                && ext.get::<Protocol>() == Some(&Protocol::WEB_TRANSPORT) {
                                return h3_webtransport::server::WebTransportSession::accept(
                                    req, stream, h3_conn
                                ).await.ok();
                            }
                        }
                        Ok(None) => return None,
                        Err(_) => return None,
                    }
                }
            });

            if let Ok(Some(session)) = handle.await {
                return Some(session);
            }
        }
    }

    pub fn cert_hash(&self) -> &str { &self.cert_hash }
    pub fn identity(&self) -> &Identity { &self.identity }
}

#[cfg(feature = "webtransport")]
fn generate_self_signed_cert(
    identity: &Identity,
) -> Result<(Vec<CertificateDer<'static>>, rustls::pki_types::PrivateKeyDer<'static>)> {
    use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};

    let pkcs8_vec = identity.pkcs8_der()?;
    let pkcs8_der = PrivatePkcs8KeyDer::from(pkcs8_vec.as_slice());
    let kp = KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8_der, &PKCS_ED25519)?;

    let mut params = CertificateParams::new(vec![])?;
    params.not_before = rcgen::date_time_ymd(2025, 1, 1);
    params.not_after = rcgen::date_time_ymd(2025, 1, 14);

    let cert = params.self_signed(&kp)?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        PrivatePkcs8KeyDer::from(pkcs8_vec)
    );

    Ok((vec![cert_der], key_der))
}

// stub for when feature is disabled
#[cfg(not(feature = "webtransport"))]
pub struct WebCompatServer;

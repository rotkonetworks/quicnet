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
        let (cert_chain, key, cert_hash) = generate_self_signed_cert()?;

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
        transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into()?));
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
fn generate_self_signed_cert() -> Result<(Vec<CertificateDer<'static>>, rustls::pki_types::PrivateKeyDer<'static>, String)> {
    use rcgen::{CertificateParams, KeyPair, CustomExtension};
    use sha2::{Sha256, Digest};

    // generate ECDSA P-256 key for WebTransport compatibility
    let kp = KeyPair::generate()?;
    let key_der_bytes = kp.serialized_der().to_vec();

    let mut params = CertificateParams::new(vec![])?;
    
    // certificate valid from 2024 to 2026
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2026, 1, 1);

    // add subject alt names
    params.subject_alt_names = vec![
        rcgen::SanType::DnsName("localhost".try_into()?),
    ];

    // add custom extension for WebTransport (OID 1.3.6.1.4.1.57123.1)
    // this OID signals the cert is for WebTransport
    let webtransport_oid = vec![1, 3, 6, 1, 4, 1, 0x83, 0xdb, 0x63, 1];
    params.custom_extensions = vec![
        CustomExtension::from_oid_content(
            &webtransport_oid,
            vec![0x05, 0x00], // ASN.1 NULL
        )
    ];

    let cert = params.self_signed(&kp)?;
    let cert_der = cert.der().to_vec();
    
    // hash the entire certificate DER
    let mut hasher = Sha256::new();
    hasher.update(&cert_der);
    let cert_hash = hex::encode(hasher.finalize());
    
    let cert_der = CertificateDer::from(cert_der);
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        PrivatePkcs8KeyDer::from(key_der_bytes)
    );

    Ok((vec![cert_der], key_der, cert_hash))
}

// stub for when feature is disabled
#[cfg(not(feature = "webtransport"))]
pub struct WebCompatServer;

// src/transport/web_compat.rs
#[cfg(feature = "webtransport")]
use crate::Identity;
#[cfg(feature = "webtransport")]
use anyhow::Result;
#[cfg(feature = "webtransport")]
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
#[cfg(feature = "webtransport")]
use std::net::SocketAddr;
#[cfg(feature = "webtransport")]
use std::sync::Arc;
#[cfg(feature = "webtransport")]
use time::{Duration, OffsetDateTime};

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
            h3_quinn::quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?,
        ));

        let mut transport_config = h3_quinn::quinn::TransportConfig::default();
        transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
        transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into()?));
        server_config.transport = Arc::new(transport_config);

        let endpoint = h3_quinn::quinn::Endpoint::server(server_config, addr)?;

        eprintln!("webtransport server on https://{}", addr);
        eprintln!("cert hash: {}", cert_hash);

        Ok(Self {
            endpoint,
            identity,
            cert_hash,
        })
    }

    pub async fn accept_webtransport(
        &self,
    ) -> Option<h3_webtransport::server::WebTransportSession<h3_quinn::Connection, bytes::Bytes>>
    {
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
                                && ext.get::<Protocol>() == Some(&Protocol::WEB_TRANSPORT)
                            {
                                return h3_webtransport::server::WebTransportSession::accept(
                                    req, stream, h3_conn,
                                )
                                .await
                                .ok();
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

    pub fn cert_hash(&self) -> &str {
        &self.cert_hash
    }
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
}

#[cfg(feature = "webtransport")]
fn generate_self_signed_cert() -> Result<(
    Vec<CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
    String,
)> {
    use rcgen::{
        CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair,
        KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SanType,
    };
    use sha2::{Digest, Sha256};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    // 1) Explicit ECDSA P-256 keypair (required; RSA not allowed for this mode)
    //    (Spec requires ECDSA P-256 to be supported as the interoperable default.)
    let kp = KeyPair::generate()?;
    let key_der_bytes = kp.serialized_der().to_vec();

    // 2) Short-lived cert: now-1h .. now+10d  (must be <= 14 days)
    let now = OffsetDateTime::now_utc();
    let mut params = CertificateParams::new(vec!["localhost".to_string()])?;
    params.not_before = now - Duration::hours(1);
    params.not_after = now + Duration::days(10);

    // 3) SANs for localhost and loopback IPs
    params
        .subject_alt_names
        .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    params
        .subject_alt_names
        .push(SanType::IpAddress(IpAddr::V6(Ipv6Addr::LOCALHOST)));

    // 4) Nice-to-have metadata
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "localhost");
    params.distinguished_name = dn;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];

    // 5) Self-sign and compute the SHA-256 of the DER cert for pinning
    let cert = params.self_signed(&kp)?;
    let cert_der_bytes = cert.der().to_vec();
    let mut hasher = Sha256::new();
    hasher.update(&cert_der_bytes);
    let cert_hash = hex::encode(hasher.finalize()); // lower-case hex

    let cert_der = CertificateDer::from(cert_der_bytes);
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der_bytes));
    Ok((vec![cert_der], key_der, cert_hash))
}

// stub for when feature is disabled
#[cfg(not(feature = "webtransport"))]
pub struct WebCompatServer;

// src/identity.rs
use anyhow::Result;
use ed25519_dalek::{SigningKey, Signer};
use rand::rngs::OsRng;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::fmt;
use std::fs;
use std::path::Path;
use base64::Engine;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId([u8; 32]);

impl PeerId {
    pub fn from_public_key(key: &[u8; 32]) -> Self {
        Self(*key)
    }

    pub fn to_string(&self) -> String {
        base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &self.0).to_lowercase()
    }

    pub fn from_str(s: &str) -> Result<Self> {
        let decoded = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, s.to_uppercase().as_str())
            .ok_or_else(|| anyhow::anyhow!("invalid base32"))?;
        
        if decoded.len() != 32 {
            anyhow::bail!("invalid peer id length");
        }
        
        let mut id = [0u8; 32];
        id.copy_from_slice(&decoded);
        Ok(Self(id))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    
    // short form for display (first 8 chars)
    pub fn short(&self) -> String {
        self.to_string().chars().take(8).collect()
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.short())
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.short())
    }
}

pub struct Identity {
    signing_key: SigningKey,
    peer_id: PeerId,
}

impl Identity {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        // Generate random bytes and create signing key from them
        let mut secret = [0u8; 32];
        use rand::RngCore;
        rng.fill_bytes(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();
        let peer_id = PeerId::from_public_key(&verifying_key.to_bytes());
        Self { signing_key, peer_id }
    }

    pub fn from_bytes(secret: &[u8; 32]) -> Result<Self> {
        let signing_key = SigningKey::from_bytes(secret);
        let verifying_key = signing_key.verifying_key();
        let peer_id = PeerId::from_public_key(&verifying_key.to_bytes());
        Ok(Self { signing_key, peer_id })
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)?;
        if bytes.len() != 32 {
            anyhow::bail!("key file must be exactly 32 bytes");
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&bytes);
        Self::from_bytes(&secret)
    }

    pub fn from_ssh_key(path: Option<&Path>) -> Result<Self> {
        let path = match path {
            Some(p) => p.to_path_buf(),
            None => dirs::home_dir()
                .ok_or_else(|| anyhow::anyhow!("no home directory"))?
                .join(".ssh/id_ed25519"),
        };

        let contents = fs::read_to_string(&path)?;
        
        if !contents.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----") {
            anyhow::bail!("not an openssh private key");
        }

        let b64 = contents
            .lines()
            .skip(1)
            .take_while(|l| !l.starts_with("-----END"))
            .collect::<String>();
        
        let decoded = base64::engine::general_purpose::STANDARD.decode(&b64)?;
        
        // simplified openssh parser for unencrypted ed25519 keys
        const MAGIC: &[u8] = b"openssh-key-v1\0";
        if !decoded.starts_with(MAGIC) {
            anyhow::bail!("invalid openssh format");
        }
        
        // find ed25519 private key (hacky but works for standard keys)
        let marker = b"ssh-ed25519";
        let mut pos = MAGIC.len();
        
        // find second occurrence of ssh-ed25519 (first is in public key section)
        for _ in 0..2 {
            pos = decoded[pos..]
                .windows(marker.len())
                .position(|w| w == marker)
                .map(|p| pos + p + marker.len())
                .ok_or_else(|| anyhow::anyhow!("not an ed25519 key"))?;
        }
        
        // private key is ~36 bytes after second marker
        pos += 36;
        
        if pos + 32 > decoded.len() {
            anyhow::bail!("key not found at expected offset");
        }
        
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&decoded[pos..pos + 32]);
        
        Self::from_bytes(&secret)
    }

    pub fn load_or_generate() -> Result<Self> {
        let default_path = dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("no home directory"))?
            .join(crate::DEFAULT_IDENTITY);
        
        if default_path.exists() {
            Self::from_file(&default_path)
        } else {
            let identity = Self::generate();
            // ensure .ssh directory exists
            if let Some(parent) = default_path.parent() {
                fs::create_dir_all(parent)?;
            }
            identity.save(&default_path)?;
            eprintln!("generated new identity: {}", default_path.display());
            Ok(identity)
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        // ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        
        // save with restricted permissions (like ssh keys)
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            use std::fs::OpenOptions;
            use std::io::Write;
            
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600)  // read/write for owner only
                .open(path)?;
            
            file.write_all(&self.signing_key.to_bytes())?;
        }
        
        #[cfg(not(unix))]
        fs::write(path, self.signing_key.to_bytes())?;
        
        Ok(())
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing_key.sign(msg).to_bytes()
    }

    pub fn certificate(&self) -> Result<(Vec<CertificateDer<'static>>, PrivatePkcs8KeyDer<'static>)> {
        // create key pair from our ed25519 key
        let mut pkcs8 = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
            0x04, 0x22, 0x04, 0x20,
        ];
        pkcs8.extend_from_slice(&self.signing_key.to_bytes());
        
        let key_pair = rcgen::KeyPair::try_from(pkcs8.as_slice())?;
        
        // create certificate params with the new API
        let params = rcgen::CertificateParams::new(vec![self.peer_id.to_string()])?;
        // The algorithm is inferred from the key type (Ed25519)
        
        // generate self-signed certificate
        let cert = params.self_signed(&key_pair)?;
        
        Ok((
            vec![cert.der().clone()],
            PrivatePkcs8KeyDer::from(key_pair.serialize_der()),
        ))
    }
}

// extract peer id from certificate
pub fn verify_peer_cert(cert: &[u8]) -> Result<PeerId> {
    // minimal x509 parser - just extract the ed25519 public key
    let marker = &[0x2b, 0x65, 0x70]; // ed25519 oid
    
    let pos = cert.windows(marker.len())
        .position(|w| w == marker)
        .ok_or_else(|| anyhow::anyhow!("not an ed25519 cert"))?;
    
    // public key is ~10 bytes after oid
    let key_offset = pos + marker.len() + 10;
    
    if key_offset + 32 > cert.len() {
        anyhow::bail!("malformed certificate");
    }
    
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&cert[key_offset..key_offset + 32]);
    
    Ok(PeerId::from_public_key(&pubkey))
}

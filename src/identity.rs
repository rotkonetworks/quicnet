// ed25519 identity management
use anyhow::Result;
use ed25519_dalek::{SigningKey, Signer};
use rand::rngs::OsRng;
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
        bs58::encode(&self.0).into_string()
    }

    pub fn from_str(s: &str) -> Result<Self> {
        let decoded = bs58::decode(s)
            .into_vec()
            .map_err(|e| anyhow::anyhow!("invalid base58: {}", e))?;
        if decoded.len() != 32 {
            anyhow::bail!("invalid peer id length: expected 32, got {}", decoded.len());
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&decoded);
        Ok(Self(id))
    }

    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }

    pub fn short(&self) -> String {
        self.to_string().chars().take(12).collect()
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

#[derive(Clone)]
pub struct Identity {
    pub(crate) signing_key: SigningKey,
    peer_id: PeerId,
}

impl Identity {
    pub fn generate() -> Self {
        let mut rng = OsRng;
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

        // extremely simplified parser for unencrypted ed25519 OpenSSH keys
        const MAGIC: &[u8] = b"openssh-key-v1\0";
        if !decoded.starts_with(MAGIC) {
            anyhow::bail!("invalid openssh format");
        }

        let marker = b"ssh-ed25519";
        let mut pos = MAGIC.len();

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
            if let Some(parent) = default_path.parent() {
                fs::create_dir_all(parent)?;
            }
            identity.save(&default_path)?;
            eprintln!("generated new identity: {}", default_path.display());
            Ok(identity)
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        #[cfg(unix)]
        {
            use std::fs::OpenOptions;
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;

            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600)
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

    /// PKCS#8 DER (for rcgen/rustls)
    pub fn pkcs8_der(&self) -> Result<Vec<u8>> {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        let doc = self
            .signing_key
            .to_pkcs8_der()
            .map_err(|e| anyhow::anyhow!("pkcs8 encode: {e}"))?;
        Ok(doc.as_bytes().to_vec())
    }
}

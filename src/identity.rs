// src/identity.rs
use anyhow::Result;
use b256::Base256;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use std::fmt;
use std::fs;
use std::path::Path;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId([u8; 32]);

impl PeerId {
    pub fn from_public_key(key: &[u8; 32]) -> Self {
        Self(*key)
    }

    pub fn to_string(&self) -> String {
        let encoded = Base256::encode(&self.0);
        encoded.iter().collect()
    }

    pub fn from_str(s: &str) -> Result<Self> {
        // try b256 first
        if s.len() == 32 {
            let chars: Vec<char> = s.chars().collect();
            let mut char_array = ['\0'; 32];
            char_array.copy_from_slice(&chars);
            if let Some(bytes) = Base256::decode(&char_array) {
                return Ok(Self(bytes));
            }
        }
        // try hex
        if s.len() == 64 {
            let hex_bytes = s.as_bytes();
            let mut hex_array = [0u8; 64];
            hex_array.copy_from_slice(&hex_bytes[..64]);
            if let Some(bytes) = Base256::hex_to_bytes(&hex_array) {
                return Ok(Self(bytes));
            }
        }
        anyhow::bail!("invalid peer id: expected 32 b256 chars or 64 hex chars")
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn short(&self) -> String {
        self.to_string().chars().take(8).collect()
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}
impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
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
        Self {
            signing_key,
            peer_id,
        }
    }

    pub fn from_bytes(secret: &[u8; 32]) -> Result<Self> {
        let signing_key = SigningKey::from_bytes(secret);
        let verifying_key = signing_key.verifying_key();
        let peer_id = PeerId::from_public_key(&verifying_key.to_bytes());
        Ok(Self {
            signing_key,
            peer_id,
        })
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        // try openssh format first
        if let Ok(contents) = fs::read_to_string(path) {
            if contents.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----") {
                return Self::from_openssh_string(&contents);
            }
        }
        // fall back to raw 32 bytes
        let bytes = fs::read(path)?;
        if bytes.len() != 32 {
            anyhow::bail!("key file must be exactly 32 bytes or openssh format");
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&bytes);
        Self::from_bytes(&secret)
    }

    fn from_openssh_string(contents: &str) -> Result<Self> {
        use ssh_key::PrivateKey;

        let private_key = PrivateKey::from_openssh(contents)?;
        let private_key = if private_key.is_encrypted() {
            let passphrase = rpassword::prompt_password("Enter passphrase: ")?;
            private_key.decrypt(&passphrase)?
        } else {
            private_key
        };

        match private_key.key_data() {
            ssh_key::private::KeypairData::Ed25519(keypair) => {
                let secret = keypair.private.to_bytes();
                Self::from_bytes(&secret)
            }
            _ => anyhow::bail!("not an ed25519 key"),
        }
    }

    pub fn from_ssh_key(path: Option<&Path>) -> Result<Self> {
        let path = match path {
            Some(p) => p.to_path_buf(),
            None => dirs::home_dir()
                .ok_or_else(|| anyhow::anyhow!("no home directory"))?
                .join(".ssh/id_ed25519"),
        };
        Self::from_file(&path)
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
            identity.save_openssh(&default_path)?;
            eprintln!("generated new identity: {}", default_path.display());
            Ok(identity)
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        // deprecated in favor of save_openssh
        self.save_raw(path)
    }

    pub fn save_raw(&self, path: &Path) -> Result<()> {
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

    pub fn save_openssh(&self, path: &Path) -> Result<()> {
        use ssh_key::private::Ed25519PrivateKey;
        use ssh_key::public::Ed25519PublicKey;
        use ssh_key::{PrivateKey, PublicKey, private::Ed25519Keypair};

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // save private key
        let private = Ed25519PrivateKey::from(&self.signing_key);
        let public = self.signing_key.verifying_key();

        let keypair = Ed25519Keypair {
            private,
            public: public.into(),
        };

        let private_key = PrivateKey::from(keypair);
        let openssh_string = private_key.to_openssh(ssh_key::LineEnding::LF)?;

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
            file.write_all(openssh_string.as_bytes())?;
        }
        #[cfg(not(unix))]
        fs::write(path, openssh_string.as_bytes())?;

        // save public key with .pub extension
        let pub_path = path.with_extension("pub");
        let public_bytes = self.signing_key.verifying_key();
        let ed25519_public = Ed25519PublicKey::from(&public_bytes);
        let public_key = PublicKey::from(ed25519_public);

        // format: ssh-ed25519 BASE64 PEER_ID_B256
        let mut pub_string = public_key.to_openssh()?;
        pub_string.push(' ');
        pub_string.push_str(&self.peer_id.to_string());
        pub_string.push('\n');

        #[cfg(unix)]
        {
            use std::fs::OpenOptions;
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;

            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o644) // public key can be world-readable
                .open(&pub_path)?;
            file.write_all(pub_string.as_bytes())?;
        }
        #[cfg(not(unix))]
        fs::write(&pub_path, pub_string.as_bytes())?;

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

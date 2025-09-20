// access control list for incoming connections
use anyhow::Result;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use crate::PeerId;

pub struct AuthorizedPeers {
    peers: Option<HashSet<PeerId>>,  // None = allow all
}

impl AuthorizedPeers {
    pub fn load() -> Result<Self> {
        let path = dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("no home dir"))?
            .join(".quicnet/authorized_peers");
        Self::load_path(&path)
    }

    pub fn load_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Self { peers: None }); // allow all if no file
        }
        let mut peers = HashSet::new();
        for line in fs::read_to_string(path)?.lines() {
            let line = line.trim();
            if !line.is_empty() && !line.starts_with('#') {
                if let Ok(peer_id) = PeerId::from_str(line) {
                    peers.insert(peer_id);
                }
            }
        }
        Ok(Self { peers: Some(peers) })
    }

    pub fn is_authorized(&self, peer_id: &PeerId) -> bool {
        match &self.peers {
            None => true,
            Some(list) => list.contains(peer_id),
        }
    }
}

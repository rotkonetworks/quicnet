// track unauthenticated connections for potential authorization
use chrono;
use std::io::Write;
use anyhow::Result;
use std::fs;
use std::path::PathBuf;
use crate::PeerId;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct PendingPeers {
    path: PathBuf,
}

impl PendingPeers {
    pub fn new() -> Result<Self> {
        let path = dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("no home dir"))?
            .join(".quicnet/pending_peers");
        Ok(Self { path })
    }
    
    pub fn log(&self, peer_id: &PeerId, addr: &str) -> Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        
        let entry = format!("{} {} {} # first seen {}\n", 
            timestamp,
            peer_id,
            addr,
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
        );
        
        fs::create_dir_all(self.path.parent().unwrap())?;
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?
            .write_all(entry.as_bytes())?;
        Ok(())
    }
    
    pub fn list_recent(&self, hours: u64) -> Result<Vec<(PeerId, String, u64)>> {
        if !self.path.exists() {
            return Ok(vec![]);
        }
        
        let cutoff = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs() - (hours * 3600);
        
        let mut peers = Vec::new();
        let mut seen = std::collections::HashSet::new();
        
        // read in reverse to get most recent first
        for line in fs::read_to_string(&self.path)?.lines().rev() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                if let (Ok(timestamp), Ok(peer_id)) = 
                    (parts[0].parse::<u64>(), PeerId::from_str(parts[1])) {
                    if timestamp >= cutoff && seen.insert(peer_id) {
                        peers.push((peer_id, parts[2].to_string(), timestamp));
                    }
                }
            }
        }
        Ok(peers)
    }
}

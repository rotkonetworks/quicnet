// trust-on-first-use store for peer identities
use std::io::Write;
use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use crate::PeerId;

pub struct KnownHosts {
    path: PathBuf,
    hosts: HashMap<String, PeerId>,
}

impl KnownHosts {
    pub fn load() -> Result<Self> {
        let path = dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("no home dir"))?
            .join(".quicnet/known_hosts");
        
        let hosts = if path.exists() {
            Self::parse_file(&path)?
        } else {
            HashMap::new()
        };
        
        Ok(Self { path, hosts })
    }
    
    pub fn check(&self, host: &str, port: u16, peer_id: &PeerId) -> Trust {
        let key = format!("{}:{}", host, port);
        match self.hosts.get(&key) {
            Some(known) if known == peer_id => Trust::Known,
            Some(known) => Trust::Changed(*known),
            None => Trust::Unknown,
        }
    }
    
    pub fn add(&mut self, host: &str, port: u16, peer_id: PeerId) -> Result<()> {
        let key = format!("{}:{}", host, port);
        self.hosts.insert(key.clone(), peer_id);
        
        // append to file
        let line = format!("{} {}\n", key, peer_id);
        fs::create_dir_all(self.path.parent().unwrap())?;
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?
            .write_all(line.as_bytes())?;
        Ok(())
    }
    
    fn parse_file(path: &PathBuf) -> Result<HashMap<String, PeerId>> {
        let mut hosts = HashMap::new();
        for line in fs::read_to_string(path)?.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() == 2 {
                if let Ok(peer_id) = PeerId::from_str(parts[1]) {
                    hosts.insert(parts[0].to_string(), peer_id);
                }
            }
        }
        Ok(hosts)
    }
}

pub enum Trust {
    Known,
    Unknown,
    Changed(PeerId),
}

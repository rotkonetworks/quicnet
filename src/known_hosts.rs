// trust store with better UX than SSH
use std::io::Write;
use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use crate::PeerId;

pub struct KnownHosts {
    path: PathBuf,
    hosts: HashMap<String, Vec<PeerId>>,  // multiple keys per host allowed
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
            Some(known_ids) if known_ids.contains(peer_id) => Trust::Known,
            Some(known_ids) if !known_ids.is_empty() => Trust::Different(known_ids[0]),
            _ => Trust::Unknown,
        }
    }
    
    pub fn add(&mut self, host: &str, port: u16, peer_id: PeerId) -> Result<()> {
        let key = format!("{}:{}", host, port);
        self.hosts.entry(key.clone())
            .or_insert_with(Vec::new)
            .push(peer_id);
        
        // append to file (allows multiple keys per host)
        let line = format!("{} {}\n", key, peer_id);
        fs::create_dir_all(self.path.parent().unwrap())?;
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?
            .write_all(line.as_bytes())?;
        Ok(())
    }
    
    fn parse_file(path: &PathBuf) -> Result<HashMap<String, Vec<PeerId>>> {
        let mut hosts: HashMap<String, Vec<PeerId>> = HashMap::new();
        for line in fs::read_to_string(path)?.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() == 2 {
                if let Ok(peer_id) = PeerId::from_str(parts[1]) {
                    hosts.entry(parts[0].to_string())
                        .or_insert_with(Vec::new)
                        .push(peer_id);
                }
            }
        }
        Ok(hosts)
    }
}

pub enum Trust {
    Known,
    Unknown,  
    Different(PeerId),  // not "Changed" - less scary
}

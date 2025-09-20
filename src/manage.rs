// management utilities for peer authorization
use std::path::Path;
use std::fs;
use std::io::Write;
use anyhow::Result;
use crate::{PeerId, pending_peers::PendingPeers};

pub fn authorize_pending() -> Result<()> {
    let pending = PendingPeers::new()?;
    let recent = pending.list_recent(24)?;  // last 24 hours
    
    if recent.is_empty() {
        eprintln!("no pending peers in last 24 hours");
        return Ok(());
    }
    
    eprintln!("Recent unauthorized connection attempts:");
    eprintln!();
    for (i, (peer_id, addr, _)) in recent.iter().enumerate() {
        eprintln!("  {}. {} from {}", i + 1, peer_id, addr);
    }
    eprintln!();
    eprint!("Authorize which peers? (1,2,3 or all or none): ");
    
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let input = input.trim();
    
    let authorized_path = dirs::home_dir()
        .unwrap()
        .join(".quicnet/authorized_peers");
    
    if input == "all" {
        for (peer_id, _, _) in recent {
            append_authorized(&authorized_path, &peer_id)?;
            eprintln!("authorized: {}", peer_id);
        }
    } else if input != "none" {
        for part in input.split(',') {
            if let Ok(idx) = part.trim().parse::<usize>() {
                if idx > 0 && idx <= recent.len() {
                    let (peer_id, _, _) = &recent[idx - 1];
                    append_authorized(&authorized_path, peer_id)?;
                    eprintln!("authorized: {}", peer_id);
                }
            }
        }
    }
    Ok(())
}

fn append_authorized(path: &Path, peer_id: &PeerId) -> Result<()> {
    fs::create_dir_all(path.parent().unwrap())?;
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?
        .write_all(format!("{}\n", peer_id).as_bytes())?;
    Ok(())
}

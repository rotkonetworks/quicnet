// audit logging for security events
use crate::PeerId;
use chrono::Local;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

pub enum AuditEvent {
    ConnectionAccepted {
        peer: PeerId,
        addr: String,
    },
    ConnectionRejected {
        peer: PeerId,
        addr: String,
        reason: String,
    },
    AuthenticationFailed {
        addr: String,
    },
    RateLimited {
        addr: String,
    },
}

pub struct AuditLog {
    path: Option<std::path::PathBuf>,
}

impl AuditLog {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: Some(path.as_ref().to_path_buf()),
        }
    }

    pub fn disabled() -> Self {
        Self { path: None }
    }

    pub fn log(&self, event: AuditEvent) {
        let Some(path) = &self.path else { return };

        let entry = match event {
            AuditEvent::ConnectionAccepted { peer, addr } => format!(
                "{} ACCEPT {} from {}\n",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                peer,
                addr
            ),
            AuditEvent::ConnectionRejected { peer, addr, reason } => format!(
                "{} REJECT {} from {} ({})\n",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                peer,
                addr,
                reason
            ),
            AuditEvent::AuthenticationFailed { addr } => format!(
                "{} AUTH_FAIL from {}\n",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                addr
            ),
            AuditEvent::RateLimited { addr } => format!(
                "{} RATE_LIMIT {}\n",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                addr
            ),
        };

        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = file.write_all(entry.as_bytes());
        }
    }
}

pub mod auth;
pub mod identity;
pub mod peer;
pub mod authorized_peers;
pub mod known_hosts;
pub mod pending_peers;
pub mod manage;
pub mod transport;
pub mod security;

pub use identity::{Identity, PeerId};
pub use peer::{Peer, IncomingConnection};
pub use known_hosts::{KnownHosts, Trust};
pub use authorized_peers::AuthorizedPeers;
pub use pending_peers::PendingPeers;
pub use transport::{AuthenticatedStream, ServerBuilder, ClientBuilder};
pub use security::{RateLimiter, AuditLog, AuditEvent};

pub const DEFAULT_PORT: u16 = 4433;
pub const DEFAULT_IDENTITY: &str = ".quicnet/id_ed25519";

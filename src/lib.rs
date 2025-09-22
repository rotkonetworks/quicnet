pub mod auth;
pub mod authorized_peers;
pub mod identity;
pub mod known_hosts;
pub mod manage;
pub mod peer;
pub mod pending_peers;
pub mod security;
pub mod transport;

pub use authorized_peers::AuthorizedPeers;
pub use identity::{Identity, PeerId};
pub use known_hosts::{KnownHosts, Trust};
pub use peer::{IncomingConnection, Peer};
pub use pending_peers::PendingPeers;
pub use security::{AuditEvent, AuditLog, RateLimiter};
pub use transport::{AuthenticatedStream, ClientBuilder, ServerBuilder};

pub const DEFAULT_PORT: u16 = 4433;
pub const DEFAULT_IDENTITY: &str = ".quicnet/id_ed25519";

// src/lib.rs
pub mod identity;
pub mod server;
pub mod client;

#[cfg(feature = "irc")]
pub mod irc;

pub use identity::{Identity, PeerId};
pub use server::Server;
pub use client::Client;

pub const DEFAULT_PORT: u16 = 4433;
pub const DEFAULT_IDENTITY: &str = ".ssh/id_quicnet";

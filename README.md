# README.md

minimal peer-to-peer network protocol using QUIC transport and ed25519 identities.

## Build and Development Commands

### Building
```bash
cargo build                           # Debug build
cargo build --release                 # Release build with optimizations
cargo build --features webtransport   # Build with webtransport support
```

### Running
```bash
cargo run -- -l              # Run server mode
cargo run -- localhost       # Run client mode
cargo run --example shell    # Run shell example
cargo run --example chat     # Run chat example
cargo run --features webtransport --example webtransport_chat
```

## Architecture Overview

quicnet is a minimal peer-to-peer network protocol built on QUIC transport with
Ed25519 identity-based authentication. The architecture binds cryptographic
identities directly to the TLS layer, eliminating the need for certificate
authorities.

### Core Identity System
- **PeerId**: 32-byte Ed25519 public key, encoded in base256 format (with hex
fallback)
- **Identity**: Ed25519 keypair stored in SSH-compatible format (default:
`~/.quicnet/id_ed25519`)
- TLS certificates are self-signed and derived from the Ed25519 identity
- The SPKI (Subject Public Key Info) in the X.509 certificate equals the PeerId,
preventing MITM attacks
- Base256 encoding creates visually distinctive, copy-paste-only peer identifiers

### Module Structure

**Core Modules** (`src/`)
- `identity.rs`: Ed25519 keypair management, SSH key parsing, PeerId generation
with base256/hex encoding
- `peer.rs`: Unified peer implementation that can both dial and accept connections
- `auth.rs`: Symmetric application-layer challenge-response authentication protocol

**Transport Layer** (`src/transport/`)
- `stream.rs`: Authenticated bidirectional stream abstraction
- `builder.rs`: Peer configuration builders with rate limiting and audit options
- `web_compat.rs`: WebTransport compatibility layer (optional feature)

**Security Features** (`src/security/`)
- `rate_limit.rs`: Connection rate limiting per IP address
- `audit.rs`: Security event logging system

**Peer Management**
- `authorized_peers.rs`: Whitelist of allowed peer identities
- `known_hosts.rs`: Trust-on-first-use (TOFU) store for peer identities
- `pending_peers.rs`: Queue for peers awaiting authorization

### Protocol Flow
1. Either peer initiates QUIC connection with self-signed Ed25519 certificate
2. Remote peer accepts with its own Ed25519 certificate
3. Both sides verify the peer's SPKI matches expected PeerId (if provided)
4. Symmetric application-layer challenge-response confirms mutual authentication
5. First bi-stream is opened for stdin/stdout piping

### Key Design Decisions
- **No central authority**: Identities are cryptographic keys, not certificates from a CA
- **Symmetric design**: Single `Peer` type handles both dialing and accepting
- **TLS binding**: Prevents relay MITM attacks during handshake
- **SSH compatibility**: Reuses existing Ed25519 SSH keys when available
- **Visual distinctiveness**: Base256 encoding forces copy-paste behavior for security
- **WebTransport ready**: Optional feature for browser compatibility

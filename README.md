# quicnet

minimal peer-to-peer network protocol using quic transport and ed25519 identities.

## what it is

quicnet provides encrypted, authenticated connections without dns or certificate
authorities. every peer has an ed25519 identity. peers connect directly using ip
addresses and verify each other cryptographically.

think of it as ssh meets netcat over quic - your identity is your keypair, not a
domain name.

## installation

```bash
cargo install --path .

# or with coordinator support
cargo install --path . --features coordinator
```

## quick start

```bash
# server (auto-generates ~/.ssh/id_quicnet on first run)
quicnet -l

# client (uses same identity)
quicnet localhost

# ssh-style with user hint
quicnet alice@192.168.1.100

# connect by peer id
quicnet 3n4hxrj7@192.168.1.100:4433
```

## usage

### server mode

```bash
# listen on default port (4433)
quicnet -l

# listen on specific port
quicnet -l -p 6667

# bind to specific address
quicnet -l -b 192.168.1.100

# use specific identity
quicnet -l -i ~/.ssh/id_ed25519

# echo mode for testing
quicnet -l --echo
```

### client mode

```bash
# connect to host
quicnet example.com
quicnet example.com:6667

# ssh-style with identity hint
quicnet alice@example.com
quicnet alice@192.168.1.100:6667

# connect with peer id verification
quicnet 3n4hxrj7@example.com:6667

# ipv6
quicnet 2001:db8::1
quicnet alice@2001:db8::1
quicnet [2001:db8::1]:6667
quicnet alice@[2001:db8::1]:6667

# explicit identity
quicnet -i ~/.ssh/id_ed25519 example.com

# relay via coordinator
quicnet --via coordinator.local target.local
```

### identity management

```bash
# default identity is ~/.ssh/id_quicnet (auto-generated)
quicnet -l

# use existing ssh key
quicnet -i ~/.ssh/id_ed25519 -l

# identity hints try these paths:
# 1. ~/.ssh/id_ed25519_alice
# 2. ~/.ssh/id_alice  
# 3. ~/.ssh/alice
# 4. ~/.ssh/id_ed25519
# 5. ~/.ssh/id_quicnet (or generate)
quicnet alice@example.com
```

### piping data

```bash
# send file
cat data.txt | quicnet server.local

# receive file
quicnet -l > output.txt

# tunnel connection
quicnet -l | nc localhost 80
nc -l 8080 | quicnet remote:80
```

## protocol design

### identity

every peer has an ed25519 keypair:
- 32-byte public key becomes peer id
- base58 encoded for text representation
- self-signed certificates for quic transport

### transport

quic provides:
- mandatory encryption (tls 1.3)
- multiplexed streams
- connection migration
- congestion control

### authentication

mutual ed25519 authentication over application layer:
- quic handshake uses ephemeral certificates for transport security
- application-layer challenge-response verifies ed25519 identities
- both peers must prove possession of private keys
- connections fail if peer identity doesn't match expectation

### wire format

binary streams over quic:
- authentication handshake on first stream
- subsequent streams carry application data
- supports stdin/stdout piping and custom protocols

## security

### protected

- all data encrypted with chacha20-poly1305 (quic/tls 1.3)
- forward secrecy via ephemeral keys
- mutual authentication via ed25519 challenge-response
- protection against replay attacks
- no dns hijacking
- no ca compromise

### visible

- quic packet structure and timing
- connection metadata
- peer ids are public
- ip addresses

### trust model

explicit peer verification:
- peer ids can be specified in connection string
- first connection establishes peer identity
- subsequent connections verify same identity
- manual verification via peer id comparison

## examples

### chat server

```bash
# server
quicnet -l

# clients connect and type messages
quicnet server.local
quicnet bob@server.local
```

### file transfer

```bash
# receiver
quicnet -l > received.tar.gz

# sender  
tar czf - /path/to/files | quicnet receiver.local
```

### secure tunnel

```bash
# on remote (expose local service)
quicnet -l | nc localhost 80

# on local (connect to remote service)
curl -x quicnet://remote.local http://localhost/
```

### peer verification

```bash
# server shows peer id on startup
quicnet -l
# peer id: 5KJvsngHvtMtyQcjhwAL6DDQw2X4LzyKQyl6CStBUuHCyaDhHV

# client verifies specific peer
quicnet 5KJvsngHvtMtyQcjhwAL6DDQw2X4LzyKQyl6CStBUuHCyaDhHV@server.local
```

## comparison

| feature | quicnet | ssh | telnet | netcat |
|---------|---------|-----|--------|--------|
| encryption | always | yes | no | no |
| authentication | mutual | server | no | no |
| identity | ed25519 | various | none | none |
| transport | quic | tcp | tcp | tcp/udp |
| dns required | no | optional | yes | optional |
| ca required | no | optional | n/a | n/a |
| shell | no | yes | yes | no |
| multiplexing | yes | yes | no | no |

## limitations

- openssh key parser uses simplified parsing that may not work with all key formats
- no built-in peer discovery mechanism
- coordinator relay functionality is basic
- trust-on-first-use requires manual verification of peer ids

## license

mit or apache-2.0, at your option

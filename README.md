# quicnet

minimal peer-to-peer network protocol using quic transport and ed25519 identities.

## what it is

quicnet provides encrypted, authenticated connections without dns or certificate authorities. every peer has an ed25519 identity. peers connect directly using ip addresses and verify each other cryptographically.

think of it as ssh meets netcat over quic - your identity is your keypair, not a domain name.

## installation

```bash
cargo install --path .

# or with irc support
cargo install --path . --features irc
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
quicnet -l 6667
quicnet -l -p 6667

# bind to specific address
quicnet -l -b 192.168.1.100 6667

# use specific identity
quicnet -l -i ~/.ssh/id_ed25519
```

### client mode

```bash
# connect to host
quicnet example.com
quicnet example.com 6667

# ssh-style with identity hint
quicnet alice@example.com
quicnet alice@192.168.1.100:6667

# uri-style with port
quicnet example.com:6667
quicnet alice@example.com:6667

# ipv6
quicnet 2001:db8::1
quicnet alice@2001:db8::1
quicnet [2001:db8::1]:6667
quicnet alice@[2001:db8::1]:6667

# explicit identity
quicnet -i ~/.ssh/id_ed25519 example.com
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
quicnet -l 8080 | nc localhost 80
nc -l 8080 | quicnet remote:80
```

## protocol design

### identity

every peer has an ed25519 keypair:
- 32-byte public key becomes peer id
- base32 encoded for text representation
- self-signed certificates for quic

### transport

quic provides:
- mandatory encryption (tls 1.3)
- multiplexed streams
- connection migration
- congestion control

### authentication

mutual authentication by default:
- both peers present ed25519 certificates
- peer ids extracted from certificates
- no certificate authorities needed

### wire format

simple text protocol over bidirectional streams:
- utf-8 encoded
- newline delimited
- optional irc protocol detection

## security

### protected

- all data encrypted with chacha20-poly1305
- forward secrecy via ephemeral keys
- authentication via ed25519
- no dns hijacking
- no ca compromise

### visible

- quic packet structure
- connection timing/size
- peer ids in handshake
- ip addresses

### trust model

trust on first use (tofu):
- first connection establishes peer id
- subsequent connections verify same id
- save known peers for persistence

## examples

### chat server

```bash
# server
quicnet -l 6667

# clients
quicnet alice@server.local:6667
quicnet bob@server.local:6667
```

### file transfer

```bash
# receiver
quicnet -l > received.tar.gz

# sender  
tar czf - /path/to/files | quicnet receiver.local
```

### port forwarding

```bash
# on remote
quicnet -l 8080 | nc localhost 80

# on local
nc -l 8080 | quicnet remote:8080
```

### peer-to-peer

```bash
# both peers run
quicnet -l 4433 &
quicnet peer_id@other_host
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
| shell  | no | no | n/a | n/a |

## license

mit or apache-2.0, at your option

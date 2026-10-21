
## Secure Bidirectional TUN Tunnel

The project implements an authenticated, encrypted IP tunnel between two Linux network namespaces.

### Features

- X25519 ephemeral key exchange
- Pre-shared key authentication using HMAC
- HKDF-based session and directional key derivation
- AES-256-GCM authenticated encryption
- Unique nonces per session and direction
- 64-packet replay protection window
- Bidirectional TUN-to-UDP packet forwarding
- IPv4 and TCP connectivity between PC1 and PC2

### Network Topology

PC1 (10.0.1.1)
    |
Device1 (10.0.1.2 / 10.0.2.1)
    |
Encrypted UDP Tunnel (port 9003)
    |
Device2 (10.0.2.2 / 10.0.3.1)
    |
PC2 (10.0.3.2)

### Running the Tunnel

Compile the secure_tunnel executable using the project's C source files and OpenSSL libcrypto.

Start Device2:

    sudo ip netns exec device2 ./secure_tunnel 2

Start Device1:

    sudo ip netns exec device1 ./secure_tunnel 1

Configure tunnel
## Secure Bidirectional TUN Tunnel

This project implements an authenticated, encrypted tunnel between two Linux devices.

### Security Features
- X25519 key exchange
- PSK authentication with HMAC
- HKDF key derivation
- AES-256-GCM encryption
- Replay protection
- Bidirectional UDP/TUN communication

### Network Topology
PC1 -> Device1 -> Encrypted Tunnel -> Device2 -> PC2

### Testing
- Authenticated handshake: successful
- Encrypted packet transmission: successful
- Bidirectional communication: successful
- ICMP ping: successful
- TCP HTTP connection: successful

### Limitations
This is an educational prototype, not a production-ready VPN.

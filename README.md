# Post-Quantum VPN Router - Cloudflare Tunnel

<p align="center">
  <strong>Open Source Post-Quantum Ingress with Cloudflare Tunnel</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/PQC-Cloudflare%20TLS-blue?style=for-the-badge" alt="PQC TLS"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="MIT"/>
  <img src="https://img.shields.io/badge/Zero-Trust-orange?style=for-the-badge" alt="Zero Trust"/>
</p>

---

## Overview

Open source implementation focusing on **post-quantum security for Cloudflare Tunnel**, using TLS 1.3 with Kyber key agreement at the edge.

**Easiest to deploy** - leverages Cloudflare's built-in PQC support.

### How It Works

```mermaid
sequenceDiagram
    participant U as User
    participant CF as Cloudflare Edge
    participant T as Cloudflared
    participant A as Application
    
    U->>CF: HTTPS Request
    Note over U,CF: TLS 1.3 + Kyber Key Agreement
    CF->>T: Tunnel Protocol
    T->>A: localhost Request
    A-->>T: Response
    T-->>CF: Tunnel Protocol
    CF-->>U: HTTPS Response
```

## Quick Start

```bash
git clone https://github.com/vinzabe/post-quantum-vpn-cloudflare-tunnel.git
cd post-quantum-vpn-cloudflare-tunnel
./scripts/setup.sh
docker compose up -d
```

## Cloudflare PQC Configuration

Cloudflare automatically negotiates post-quantum key agreement when supported:

```yaml
# cloudflared config
tunnel: your-tunnel-id
credentials-file: /etc/cloudflared/credentials.json

# PQC is enabled by default in modern cloudflared
post-quantum: true
```

## Verify PQC is Active

```bash
# Check cloudflared logs
docker logs cloudflare-tunnel 2>&1 | grep -i "post-quantum"

# Or check Cloudflare dashboard for PQC indicator
```

## License

MIT License - See LICENSE file.

## Enterprise Support

**Email:** grant@abejar.net

---

Developed by Abejar | Open Source Edition

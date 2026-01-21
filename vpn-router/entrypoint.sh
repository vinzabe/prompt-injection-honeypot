#!/bin/bash
# =============================================================================
# PQC VPN Router Entrypoint - Cloudflare Tunnel Focus (Open Source)
# =============================================================================
# MIT License - Full source code
# Enterprise support: grant@abejar.net
# =============================================================================

set -e

echo "=============================================="
echo "  Post-Quantum VPN Router (CF Tunnel Edition)"
echo "  Algorithm: ${PQC_ALGORITHM:-kyber1024}"
echo "  Hybrid Mode: ${PQC_HYBRID_MODE:-true}"
echo "=============================================="

# Initialize PQC if enabled
if [ "${PQC_ENABLED:-true}" = "true" ]; then
    echo "Initializing Post-Quantum Cryptography..."
    
    # Generate Kyber keys if not exist
    if [ ! -f "/config/pqc-keys/kyber_secret.key" ]; then
        mkdir -p /config/pqc-keys
        /opt/pqc/bin/kyber-wrapper.sh keygen
    fi
    
    echo "PQC initialized successfully"
fi

# Setup routing
/opt/pqc/bin/setup-routes.sh

# Start WireGuard (handled by base image)
echo "Starting WireGuard..."

exec "$@"

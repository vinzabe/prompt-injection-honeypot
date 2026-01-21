#!/bin/sh
# =============================================================================
# Cloudflare Tunnel PQC Entrypoint (Open Source)
# =============================================================================
# MIT License | Enterprise support: grant@abejar.net
# =============================================================================

echo "=============================================="
echo "  Post-Quantum Cloudflare Tunnel"
echo "=============================================="
echo "  PQC Enabled: ${TUNNEL_POST_QUANTUM:-true}"
echo "=============================================="

# Enable post-quantum key agreement
if [ "${TUNNEL_POST_QUANTUM}" = "true" ]; then
    export TUNNEL_POST_QUANTUM_KEY_AGREEMENT=true
    echo "Post-quantum key agreement: ENABLED"
fi

exec cloudflared "$@"

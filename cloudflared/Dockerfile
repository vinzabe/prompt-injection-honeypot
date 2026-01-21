# =============================================================================
# Post-Quantum Cloudflare Tunnel (Open Source)
# =============================================================================
# MIT License | Enterprise support: grant@abejar.net
# =============================================================================

FROM cloudflare/cloudflared:latest

LABEL maintainer="Abejar <grant@abejar.net>"
LABEL description="Cloudflare Tunnel with Post-Quantum TLS (Open Source)"
LABEL license="MIT"

# PQC is built into modern cloudflared
ENV TUNNEL_POST_QUANTUM=true
ENV TUNNEL_LOGLEVEL=info

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["tunnel", "run"]

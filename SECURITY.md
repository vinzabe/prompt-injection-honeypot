# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in **Prompt Injection Honeypot**,
please report it privately. Do **not** open a public GitHub issue.

**Email:** security@vinzabe.dev (or open a GitHub Security Advisory)

Please include:
- A clear description of the issue
- Steps to reproduce (PoC preferred)
- The version / commit SHA you tested against
- Any suggested mitigation

We aim to acknowledge new reports within **72 hours** and to publish a
fix or mitigation within **30 days** for high-severity issues.

## Scope

In scope:
- Canary token leakage (canaries should NEVER appear in honeypot responses)
- Persona spoofing / cross-persona contamination
- Threat-feed endpoints (`/feed/*`) leaking attacker PII inadvertently
- XSS / SQLi / path-traversal in the dashboard
- Auth bypass on `/dashboard`
- DoS vectors

Out of scope:
- "The honeypot is a honeypot" — yes, that is the entire design
- Discoverability of the honeypot (it's meant to be discoverable)
- Issues that require root on the honeypot host

## Threat model

This system is **deliberately exposed to attackers** to collect threat
intelligence. We assume:

- 100% of inbound traffic is potentially adversarial
- Attackers may attempt to fingerprint and avoid the honeypot
- Attackers may attempt to **poison** the threat feed with false IOCs
- The host runs in an isolated network segment (no lateral movement)
- The threat-feed consumers are trusted

## Hardening checklist for production deployments

- [ ] Deploy in a **DMZ / isolated VPC** — never on a corp network
- [ ] Run as an **unprivileged user** in a container with read-only FS
- [ ] Egress firewall: deny all outbound except to upstream LLM endpoint
- [ ] Rate-limit per source IP at the edge
- [ ] Rotate canary tokens periodically and re-publish
- [ ] Forward `data/honeypot.db` to a write-only collector (S3 + bucket lock)
- [ ] Restrict `/dashboard` to operator IPs / VPN
- [ ] Subscribe consumers of `/feed/*` should validate IOC quality
      (the honeypot publishes raw observations, not curated intel)
- [ ] Set `HP_DATA_DIR` to a volume with sufficient quota — attacker
      can fill the disk via prompt spam

## Operational warnings

- Personas reference fictional companies (ACME, FirstNational,
  MedCenter, AcmeTech, GlobalCorp). **Do not** rename to real companies
  — that would constitute trademark/passing-off issues.
- Any **real** secret accidentally placed in a persona system prompt
  becomes attacker-discoverable. Use only synthetic credentials.
- Do not connect the honeypot to a production upstream LLM that has
  access to real internal data (it does not need such access — it just
  needs to *appear* to).

## Supply chain

- All Python deps are pinned via `requirements.txt`
- The shared `llm_client.py` is vendored (not a third-party package)

# 3. HMAC-derived tokens per placement; bait that only causes a fetch

Date: 2026-08-24
Status: Accepted

## Context
Two design questions with security consequences: how are tokens generated, and what
does the bait ask the agent to do?

## Decision
**Tokens:** `HMAC-SHA256(secret, placement_id + surface)`, truncated. Unique per
placement (so a trigger localises which surface was scraped) and unforgeable without
the secret. `Registry.record_trigger` rejects any token that was never planted.

**Bait:** a single benign instruction to retrieve a URL. It never requests
credentials, data exfiltration, or any destructive action.

## Consequences
- A trigger is attributable to a specific page/email/document, which is what turns
  an anecdote into a finding.
- Forged or guessed tokens cannot create findings (`test_forged_token_is_rejected`).
- Deterministic minting means the same placement always yields the same token, so
  re-planting is idempotent and the registry needs no coordination.
- The harmless-bait constraint is enforced by a test that scans the rendered bait
  for dangerous verbs. It means the honeypot cannot be repurposed as an injection
  payload — a deliberate limit on its own capability.

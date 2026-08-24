# Threat model, scope & responsible use

## What this is
A detection tool: canary tokens planted in **your own** content that reveal when an
automated agent has read it and acted on embedded instructions.

## Responsible use
Plant canaries only in content you control. The bait is intentionally inert (it asks
for a URL fetch and nothing else), so this cannot be used as an injection payload
against someone else's agent — and that limit is enforced by test, not just policy.

## What a trigger proves — and doesn't
- **Proves:** something retrieved a URL that appeared only inside your content, and
  in most cases retrieved the host page first.
- **Does not prove:** *which* agent, *whose* agent, or that any harmful action
  followed. Attribution is graded and counter-evidence is always reported; the
  correct answer is often `inconclusive`.

## Trust boundaries
- **The secret is the security boundary.** With it, tokens can be minted and
  triggers forged. Keep it out of the repo (the CLI takes it via env).
- **Trigger metadata is attacker-influenceable.** User agent is trivially spoofed,
  so behavioural signals (host-page fetch, timing, asset loading) carry the real
  weight — but a sophisticated agent can mimic a browser and be misattributed.
- **The registry is unencrypted** and holds your placement map; treat it as
  security-relevant.

## Limits, stated plainly
- **Crawler denylist is incomplete by nature.** A novel crawler will be misread as
  a possible agent. The `\w*bot\b` fix closed a large family; new ones are a
  maintenance item.
- **Agents that don't follow instructions are invisible.** An agent that reads your
  page but ignores injected text produces no trigger. Absence of triggers is not
  evidence of absence of scraping.
- **No timing correlation across placements.** A campaign hitting many surfaces is
  visible in the report, but the tool does not cluster triggers into campaigns.
- **Hidden bait may be stripped** by sanitisers or not seen by agents that render
  rather than parse.

## Non-goals
- Blocking or defending against injection (see the companion `llm-firewall-v2`).
- Identifying a specific vendor's agent with certainty.
- Serving the canary endpoint — you host that; this mints, attributes, and reports.

## Reporting
A misattribution (crawler scored as an actionable agent, or vice versa) is the most
useful bug here — report to **gabejar@usa.com** with the trigger metadata.

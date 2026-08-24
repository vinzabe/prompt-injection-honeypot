# 2. Attribution is graded with counter-evidence; never inflated

Date: 2026-08-24
Status: Accepted

## Context
A canary fetch is easy to detect and easy to over-interpret. Link-preview bots,
security scanners, and humans following a URL all produce a fetch. A tool that
reports every trigger as "an AI agent read your page" will be wrong most of the
time and will be ignored — the same trust failure that kills noisy WAFs.

## Options considered
- **A. Any trigger = agent detected.** Rejected: crawlers dominate real traffic, so
  precision would be terrible.
- **B. Filter out known crawler UAs, treat the rest as agents.** Better, but a
  UA is trivially spoofed/absent and this still forces a binary claim.
- **C. Graded attribution with explicit counter-evidence (chosen).**

## Decision
Four verdicts (`llm-agent`, `crawler`, `human`, `inconclusive`) each with a
confidence and BOTH supporting reasons and counter-evidence. Only
`llm-agent` at ≥0.6 is `actionable`. Behavioural signals beyond the UA carry real
weight — chiefly whether the same client fetched the host page (instruction read in
context) versus fetching the canary URL alone (URL scraping).

## Consequences
- The output is defensible: an operator sees exactly why something was or wasn't
  called an agent, including the evidence against.
- `inconclusive` is a first-class outcome rather than a rounding-up to "agent".
- The crawler denylist is inherently incomplete, and a real gap was found this way
  (`\bbot\b` missing the `*bot` suffix family). It is now `\w*bot\b` with a
  regression test; new crawler families remain a maintenance item, documented in the
  threat model.

"""Attribution: what a trigger actually proves, and what it doesn't.

This module exists because the honest answer is uncomfortable. A canary fetch tells
you *something* retrieved the URL and followed an embedded instruction. Whether that
was an autonomous agent, a link-preview crawler, a security scanner, or a curious
human is a separate question that the evidence may or may not settle.

So attribution is graded, with the reasons attached, and the tool will say
"inconclusive" rather than inflate a crawler into an agent.
"""
from __future__ import annotations

import dataclasses
import enum
import re


class Actor(enum.Enum):
    LLM_AGENT = "llm-agent"
    CRAWLER = "crawler"
    HUMAN = "human"
    INCONCLUSIVE = "inconclusive"


@dataclasses.dataclass(frozen=True, slots=True)
class Trigger:
    """An observed fetch of a canary URL."""
    token: str
    user_agent: str = ""
    referrer: str = ""
    seconds_after_placement: float = 0.0
    fetched_bait_page: bool = True     # did the same client fetch the host page?
    rendered_assets: bool = False      # did it also load images/CSS (browser-like)?
    request_count: int = 1


# Known crawler/preview signatures — these fetch links without "acting on
# instructions", so they are the dominant false positive.
# NOTE the `\w*bot\b` form rather than `\bbot\b`: the common crawler UAs put
# "bot" as a SUFFIX (Googlebot, Bingbot, Yandexbot, Slackbot), so a leading word
# boundary silently misses the entire family — Googlebot was attributed as
# "inconclusive" until this was fixed.
_CRAWLER_UA = re.compile(
    r"(?i)(\w*bot\b|\bcrawler\b|\bspider\b|\bslurp\b|\bpreview\b|"
    r"\bfacebookexternalhit\b|\bwhatsapp\b|\bcurl\b|\bwget\b|"
    r"\bpython-requests\b|\bheadless\b|\bscrapy\b|\bokhttp\b)")
_BROWSER_UA = re.compile(r"(?i)\b(mozilla|chrome|safari|firefox|edge)\b")
_AGENT_UA = re.compile(r"(?i)\b(gpt|claude|llm|openai|anthropic|agent|langchain)\b")


@dataclasses.dataclass(frozen=True, slots=True)
class Attribution:
    actor: Actor
    confidence: float           # [0,1]
    reasons: tuple[str, ...]
    counter_evidence: tuple[str, ...]

    @property
    def actionable(self) -> bool:
        """Only a reasonably-confident agent attribution is worth acting on."""
        return self.actor is Actor.LLM_AGENT and self.confidence >= 0.6


def attribute(trigger: Trigger) -> Attribution:
    reasons: list[str] = []
    counter: list[str] = []
    ua = trigger.user_agent

    if _AGENT_UA.search(ua):
        reasons.append(f"user agent self-identifies as an LLM tool: {ua[:60]!r}")
    if _CRAWLER_UA.search(ua):
        counter.append(f"user agent matches a known crawler/preview fetcher: "
                       f"{ua[:60]!r}")
    if trigger.rendered_assets:
        counter.append("client also loaded page assets (images/CSS), which is "
                       "browser-like rather than agent-like")
    if _BROWSER_UA.search(ua) and not _AGENT_UA.search(ua):
        counter.append("user agent looks like a normal browser")

    if trigger.fetched_bait_page:
        reasons.append("the same client fetched the host page before the canary, "
                       "so the instruction was read in context")
    else:
        counter.append("the canary URL was fetched without the host page — "
                       "consistent with URL scraping rather than instruction "
                       "following")
    if 0 < trigger.seconds_after_placement <= 120:
        reasons.append("fetched within seconds of reading the page, consistent "
                       "with automated processing")
    if trigger.request_count == 1 and not trigger.rendered_assets:
        reasons.append("a single bare fetch with no asset loading")

    # --- grade it -------------------------------------------------------
    if _CRAWLER_UA.search(ua) and not _AGENT_UA.search(ua):
        return Attribution(Actor.CRAWLER, 0.8, tuple(reasons), tuple(counter))
    if trigger.rendered_assets and _BROWSER_UA.search(ua):
        return Attribution(Actor.HUMAN, 0.6, tuple(reasons), tuple(counter))
    if _AGENT_UA.search(ua) and trigger.fetched_bait_page:
        return Attribution(Actor.LLM_AGENT, 0.9, tuple(reasons), tuple(counter))
    if trigger.fetched_bait_page and not counter:
        # instruction read in context, nothing pointing elsewhere
        return Attribution(Actor.LLM_AGENT, 0.65, tuple(reasons), tuple(counter))
    return Attribution(Actor.INCONCLUSIVE, 0.3, tuple(reasons), tuple(counter))

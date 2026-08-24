"""Attribution must be graded and must not inflate a crawler into an agent."""
from pihoney.attribution import Actor, Trigger, attribute


def _t(**kw):
    base = dict(token="t", user_agent="", seconds_after_placement=5.0,
                fetched_bait_page=True, rendered_assets=False, request_count=1)
    base.update(kw)
    return Trigger(**base)


def test_self_identified_agent_is_high_confidence():
    a = attribute(_t(user_agent="LangChain-Agent/0.1 openai"))
    assert a.actor is Actor.LLM_AGENT
    assert a.confidence >= 0.85 and a.actionable


def test_known_crawler_is_not_an_agent():
    a = attribute(_t(user_agent="Slackbot-LinkExpanding 1.0",
                     fetched_bait_page=False))
    assert a.actor is Actor.CRAWLER
    assert not a.actionable


def test_browser_with_assets_is_human():
    a = attribute(_t(user_agent="Mozilla/5.0 Chrome/120", rendered_assets=True))
    assert a.actor is Actor.HUMAN
    assert not a.actionable


def test_bare_fetch_in_context_is_a_likely_agent():
    a = attribute(_t(user_agent="", fetched_bait_page=True))
    assert a.actor is Actor.LLM_AGENT
    assert 0.6 <= a.confidence < 0.9


def test_missing_host_page_weakens_attribution():
    """Fetching the canary URL without the page suggests URL scraping, not
    instruction following."""
    a = attribute(_t(user_agent="", fetched_bait_page=False))
    assert a.actor is Actor.INCONCLUSIVE
    assert not a.actionable
    assert any("without the host page" in c for c in a.counter_evidence)


def test_counter_evidence_is_always_reported():
    a = attribute(_t(user_agent="Mozilla/5.0 Chrome/120", rendered_assets=True))
    assert a.counter_evidence


def test_confidence_bounded():
    for ua in ("", "Mozilla/5.0", "GPT-agent", "curl/8"):
        a = attribute(_t(user_agent=ua))
        assert 0.0 <= a.confidence <= 1.0


def test_bot_suffix_crawlers_are_recognised():
    """Regression: `\\bbot\\b` missed Googlebot/Bingbot/YandexBot because "bot" is a
    SUFFIX in those UAs, so the whole crawler family was scored inconclusive."""
    for ua in ("Googlebot/2.1", "Bingbot", "YandexBot/3.0",
               "Mozilla/5.0 (compatible; AhrefsBot/7.0)", "Slackbot-LinkExpanding"):
        a = attribute(_t(user_agent=ua))
        assert a.actor is Actor.CRAWLER, f"{ua} was {a.actor}"
        assert not a.actionable

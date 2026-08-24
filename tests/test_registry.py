import pytest

from pihoney.attribution import Trigger
from pihoney.canary import Placement
from pihoney.registry import Registry, UnknownToken


def _reg(tmp_path):
    return Registry(tmp_path / "r.db", "test-secret")


def test_plant_and_report(tmp_path):
    with _reg(tmp_path) as reg:
        reg.plant(Placement("docs/a.html", "web"))
        surfaces = reg.surfaces()
        assert len(surfaces) == 1
        assert surfaces[0].triggers == 0


def test_forged_token_is_rejected(tmp_path):
    """A trigger for a token we never planted must not create a finding."""
    with _reg(tmp_path) as reg, pytest.raises(UnknownToken):
        reg.record_trigger(Trigger(token="deadbeef" * 3))


def test_trigger_recorded_and_attributed(tmp_path):
    with _reg(tmp_path) as reg:
        c = reg.plant(Placement("docs/a.html", "web"))
        att = reg.record_trigger(Trigger(token=c.token,
                                         user_agent="claude-agent/1",
                                         fetched_bait_page=True))
        assert att.actionable
        assert reg.surfaces()[0].agent_triggers == 1


def test_crawler_trigger_not_counted_as_agent(tmp_path):
    with _reg(tmp_path) as reg:
        c = reg.plant(Placement("docs/a.html", "web"))
        reg.record_trigger(Trigger(token=c.token, user_agent="Googlebot/2.1",
                                   fetched_bait_page=False))
        s = reg.surfaces()[0]
        assert s.triggers == 1 and s.agent_triggers == 0


def test_surfaces_rank_agent_activity_first(tmp_path):
    with _reg(tmp_path) as reg:
        quiet = reg.plant(Placement("docs/quiet.html", "web"))
        hot = reg.plant(Placement("docs/hot.html", "web"))
        reg.record_trigger(Trigger(token=hot.token, user_agent="gpt-agent",
                                   fetched_bait_page=True))
        assert reg.surfaces()[0].placement_id == "docs/hot.html"
        assert quiet.token != hot.token


def test_counts_by_actor(tmp_path):
    with _reg(tmp_path) as reg:
        c = reg.plant(Placement("a", "web"))
        reg.record_trigger(Trigger(token=c.token, user_agent="gpt-agent",
                                   fetched_bait_page=True))
        reg.record_trigger(Trigger(token=c.token, user_agent="Googlebot",
                                   fetched_bait_page=False))
        counts = reg.counts_by_actor()
        assert counts.get("llm-agent") == 1 and counts.get("crawler") == 1


def test_schema_mismatch_fails_loudly(tmp_path):
    import sqlite3
    db = tmp_path / "r.db"
    with Registry(db, "s"):
        pass
    conn = sqlite3.connect(db)
    conn.execute("UPDATE meta SET value='99' WHERE key='schema_version'")
    conn.commit()
    conn.close()
    with pytest.raises(RuntimeError, match="schema"):
        Registry(db, "s")

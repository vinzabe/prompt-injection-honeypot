"""Durable registry of placements and triggers.

The registry answers the question that makes this useful: which of my surfaces are
being scraped by agents, and how often. It also rejects triggers for tokens it never
minted, so a forged or guessed token cannot pollute the findings.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import sqlite3
from pathlib import Path

from .attribution import Attribution, Trigger, attribute
from .canary import Canary, Placement, mint_token

SCHEMA_VERSION = 1
_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS placements (
    token TEXT PRIMARY KEY, placement_id TEXT NOT NULL, surface TEXT NOT NULL,
    visible INTEGER NOT NULL, planted_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS triggers (
    id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT NOT NULL,
    user_agent TEXT, actor TEXT NOT NULL, confidence REAL NOT NULL,
    reasons TEXT, counter TEXT, at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_trig_token ON triggers(token);
"""


class UnknownToken(KeyError):
    pass


@dataclasses.dataclass(frozen=True, slots=True)
class SurfaceReport:
    placement_id: str
    surface: str
    triggers: int
    agent_triggers: int


class Registry:
    def __init__(self, path: Path | str, secret: str) -> None:
        self.secret = secret
        self._c = sqlite3.connect(Path(path), isolation_level=None)
        self._c.row_factory = sqlite3.Row
        self._c.execute("PRAGMA journal_mode=WAL")
        self._c.executescript(_SCHEMA)
        row = self._c.execute(
            "SELECT value FROM meta WHERE key='schema_version'").fetchone()
        if row is None:
            self._c.execute("INSERT INTO meta VALUES('schema_version',?)",
                            (str(SCHEMA_VERSION),))
        elif int(row["value"]) != SCHEMA_VERSION:
            raise RuntimeError(f"registry schema {row['value']} != {SCHEMA_VERSION}")

    def close(self) -> None:
        self._c.close()

    def __enter__(self) -> Registry:
        return self

    def __exit__(self, *e: object) -> None:
        self.close()

    @staticmethod
    def _now() -> str:
        return dt.datetime.now(dt.UTC).isoformat()

    def plant(self, placement: Placement) -> Canary:
        token = mint_token(self.secret, placement)
        self._c.execute(
            "INSERT INTO placements(token,placement_id,surface,visible,planted_at)"
            " VALUES(?,?,?,?,?) ON CONFLICT(token) DO NOTHING",
            (token, placement.placement_id, placement.surface,
             int(placement.visible), self._now()))
        return Canary(token=token, placement=placement)

    def record_trigger(self, trigger: Trigger) -> Attribution:
        """Record a fetch. Raises UnknownToken for a token we never minted, so a
        forged trigger cannot create a finding."""
        row = self._c.execute("SELECT 1 FROM placements WHERE token=?",
                             (trigger.token,)).fetchone()
        if row is None:
            raise UnknownToken(
                f"token {trigger.token[:8]}… was never planted; refusing to "
                "record a trigger for it")
        att = attribute(trigger)
        self._c.execute(
            "INSERT INTO triggers(token,user_agent,actor,confidence,reasons,"
            "counter,at) VALUES(?,?,?,?,?,?,?)",
            (trigger.token, trigger.user_agent, att.actor.value, att.confidence,
             " | ".join(att.reasons), " | ".join(att.counter_evidence),
             self._now()))
        return att

    def surfaces(self) -> list[SurfaceReport]:
        rows = self._c.execute(
            "SELECT p.placement_id, p.surface, "
            "  COUNT(t.id) AS n, "
            "  SUM(CASE WHEN t.actor='llm-agent' AND t.confidence>=0.6 "
            "      THEN 1 ELSE 0 END) AS agents "
            "FROM placements p LEFT JOIN triggers t ON t.token = p.token "
            "GROUP BY p.token ORDER BY agents DESC, n DESC").fetchall()
        return [SurfaceReport(r["placement_id"], r["surface"], r["n"] or 0,
                              r["agents"] or 0) for r in rows]

    def counts_by_actor(self) -> dict[str, int]:
        return {r["actor"]: r["n"] for r in self._c.execute(
            "SELECT actor, COUNT(*) AS n FROM triggers GROUP BY actor")}

"""Storage for captured attacker traffic + threat-intel feed."""
from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from threading import Lock


@dataclass
class CapturedAttack:
    capture_id: str
    ts: float
    persona: str
    src_ip: str
    src_user_agent: str
    raw_prompt: str
    fingerprint: str
    families: list[str]
    confidence: float
    canary_attempted: bool
    notes: list[str]
    canary_returned: bool = False  # did our fake response include a canary?

    def to_dict(self) -> dict:
        return asdict(self)


class AttackStore:
    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._init()

    def _init(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("""CREATE TABLE IF NOT EXISTS attacks(
                capture_id TEXT PRIMARY KEY,
                ts REAL NOT NULL,
                persona TEXT NOT NULL,
                src_ip TEXT,
                src_user_agent TEXT,
                raw_prompt TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                families_json TEXT NOT NULL,
                confidence REAL NOT NULL,
                canary_attempted INTEGER NOT NULL,
                canary_returned INTEGER NOT NULL,
                notes_json TEXT NOT NULL
            )""")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_atk_ts ON attacks(ts)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_atk_fp ON attacks(fingerprint)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_atk_persona ON attacks(persona)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_atk_src ON attacks(src_ip)")
            self._conn.commit()

    def record(self, atk: CapturedAttack) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("""INSERT OR REPLACE INTO attacks VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""", (
                atk.capture_id, atk.ts, atk.persona, atk.src_ip, atk.src_user_agent,
                atk.raw_prompt, atk.fingerprint, json.dumps(atk.families),
                atk.confidence,
                1 if atk.canary_attempted else 0,
                1 if atk.canary_returned else 0,
                json.dumps(atk.notes),
            ))
            self._conn.commit()

    def query(self, since: float = 0.0, limit: int = 100,
              persona: str | None = None,
              family: str | None = None,
              src_ip: str | None = None) -> list[dict]:
        with self._lock:
            cur = self._conn.cursor()
            sql = "SELECT * FROM attacks WHERE ts >= ?"
            args: list = [since]
            if persona:
                sql += " AND persona = ?"; args.append(persona)
            if src_ip:
                sql += " AND src_ip = ?"; args.append(src_ip)
            sql += " ORDER BY ts DESC LIMIT ?"
            args.append(limit)
            rows = cur.execute(sql, args).fetchall()
            cols = [d[0] for d in cur.description]
            out = []
            for r in rows:
                d = dict(zip(cols, r))
                d["families"] = json.loads(d.pop("families_json"))
                d["notes"] = json.loads(d.pop("notes_json"))
                d["canary_attempted"] = bool(d["canary_attempted"])
                d["canary_returned"] = bool(d["canary_returned"])
                if family and family not in d["families"]:
                    continue
                out.append(d)
            return out

    def stats(self) -> dict:
        with self._lock:
            cur = self._conn.cursor()
            total = cur.execute("SELECT COUNT(*) FROM attacks").fetchone()[0]
            unique_fp = cur.execute(
                "SELECT COUNT(DISTINCT fingerprint) FROM attacks").fetchone()[0]
            unique_ips = cur.execute(
                "SELECT COUNT(DISTINCT src_ip) FROM attacks").fetchone()[0]
            canary_attempts = cur.execute(
                "SELECT COUNT(*) FROM attacks WHERE canary_attempted=1").fetchone()[0]
            canary_returned = cur.execute(
                "SELECT COUNT(*) FROM attacks WHERE canary_returned=1").fetchone()[0]
            top_personas = cur.execute(
                "SELECT persona, COUNT(*) FROM attacks GROUP BY persona "
                "ORDER BY 2 DESC LIMIT 10").fetchall()
            return {
                "total_captures": total,
                "unique_fingerprints": unique_fp,
                "unique_source_ips": unique_ips,
                "canary_query_attempts": canary_attempts,
                "canary_in_responses": canary_returned,
                "top_personas": [{"persona": p, "count": c} for p, c in top_personas],
            }

    def family_breakdown(self) -> dict[str, int]:
        out: dict[str, int] = {}
        with self._lock:
            cur = self._conn.cursor()
            for (fams_json,) in cur.execute("SELECT families_json FROM attacks").fetchall():
                for f in json.loads(fams_json):
                    out[f] = out.get(f, 0) + 1
        return out

    def top_attackers(self, limit: int = 10) -> list[dict]:
        with self._lock:
            cur = self._conn.cursor()
            rows = cur.execute(
                "SELECT src_ip, COUNT(*) as n FROM attacks "
                "WHERE src_ip IS NOT NULL GROUP BY src_ip ORDER BY n DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [{"src_ip": r[0], "count": r[1]} for r in rows]

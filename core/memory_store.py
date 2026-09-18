"""
Persistent memory store for APIOT — SQLite-backed session, finding,
tool-history, patch, and device-profile tracking across agent runs.
"""

import json
import sqlite3
import time
import uuid
from pathlib import Path

_DEFAULT_DB = Path(__file__).resolve().parent.parent / "data" / "memory.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id              TEXT PRIMARY KEY,
    start_time      REAL,
    end_time        REAL,
    model           TEXT,
    summary         TEXT,
    outcome         TEXT,
    devices_tested  INTEGER,
    vulns_found     INTEGER,
    patches_applied INTEGER
);

CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    session_id      TEXT,
    ip              TEXT,
    device_name     TEXT,
    finding_type    TEXT,
    tool_used       TEXT,
    details_json    TEXT,
    status          TEXT DEFAULT 'open',
    created_at      REAL
);

CREATE TABLE IF NOT EXISTS tool_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT,
    ip              TEXT,
    tool_name       TEXT,
    args_json       TEXT,
    result_summary  TEXT,
    success         INTEGER,
    created_at      REAL,
    turn_number     INTEGER DEFAULT 0,
    overseer_flag   TEXT    DEFAULT 'none',
    token_count     INTEGER DEFAULT 0,
    mission_phase   TEXT    DEFAULT 'red'
);

CREATE TABLE IF NOT EXISTS patches (
    id              TEXT PRIMARY KEY,
    finding_id      TEXT,
    ip              TEXT,
    attack_name     TEXT,
    rule            TEXT,
    signature_json  TEXT,
    applied_at      REAL,
    verified        INTEGER DEFAULT 0,
    verified_at     REAL
);

CREATE TABLE IF NOT EXISTS device_profiles (
    ip                      TEXT PRIMARY KEY,
    firmware_id             TEXT,
    arch                    TEXT,
    device_name             TEXT,
    first_seen              REAL,
    last_seen               REAL,
    known_creds             TEXT,
    services_json           TEXT,
    attack_history_summary  TEXT,
    status                  TEXT DEFAULT 'unknown'
);
"""


def _row_to_dict(cursor: sqlite3.Cursor, row: sqlite3.Row) -> dict:
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}


class MemoryStore:
    def __init__(self, db_path: str | Path | None = None):
        self._db_path = str(db_path or _DEFAULT_DB)
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self._db_path)
        self._conn.row_factory = _row_to_dict
        self._conn.executescript(_SCHEMA)
        self._migrate_tool_history()
        self._conn.commit()

    def _migrate_tool_history(self) -> None:
        """Add EXT4 columns to tool_history if they don't exist yet (idempotent)."""
        cur = self._conn.execute("PRAGMA table_info(tool_history)")
        existing = {row["name"] for row in cur.fetchall()}
        migrations = [
            ("turn_number",   "INTEGER DEFAULT 0"),
            ("overseer_flag", "TEXT    DEFAULT 'none'"),
            ("token_count",   "INTEGER DEFAULT 0"),
            ("mission_phase", "TEXT    DEFAULT 'red'"),
        ]
        for col, typedef in migrations:
            if col not in existing:
                self._conn.execute(
                    f"ALTER TABLE tool_history ADD COLUMN {col} {typedef}"
                )

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------

    def start_session(self, model: str) -> str:
        session_id = str(uuid.uuid4())
        self._conn.execute(
            "INSERT INTO sessions (id, start_time, model) VALUES (?, ?, ?)",
            (session_id, time.time(), model),
        )
        self._conn.commit()
        return session_id

    def end_session(
        self,
        session_id: str,
        summary: str,
        outcome: str,
        devices_tested: int,
        vulns_found: int,
        patches_applied: int,
    ) -> None:
        self._conn.execute(
            """UPDATE sessions
               SET end_time = ?, summary = ?, outcome = ?,
                   devices_tested = ?, vulns_found = ?, patches_applied = ?
             WHERE id = ?""",
            (time.time(), summary, outcome, devices_tested, vulns_found, patches_applied, session_id),
        )
        self._conn.commit()

    def get_session_history(self, limit: int = 10) -> list[dict]:
        cur = self._conn.execute(
            "SELECT * FROM sessions ORDER BY start_time DESC LIMIT ?", (limit,)
        )
        return cur.fetchall()

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def log_finding(
        self,
        session_id: str,
        ip: str,
        device_name: str,
        finding_type: str,
        tool_used: str,
        details: dict,
        status: str = "open",
    ) -> str:
        finding_id = str(uuid.uuid4())
        self._conn.execute(
            """INSERT INTO findings
               (id, session_id, ip, device_name, finding_type, tool_used, details_json, status, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (finding_id, session_id, ip, device_name, finding_type, tool_used, json.dumps(details), status, time.time()),
        )
        self._conn.commit()
        return finding_id

    def get_findings_for_device(self, ip: str) -> list[dict]:
        cur = self._conn.execute(
            "SELECT * FROM findings WHERE ip = ? ORDER BY created_at DESC", (ip,)
        )
        return cur.fetchall()

    def get_open_findings(self) -> list[dict]:
        cur = self._conn.execute(
            "SELECT * FROM findings WHERE status = 'open' ORDER BY created_at DESC"
        )
        return cur.fetchall()

    # ------------------------------------------------------------------
    # Tool history
    # ------------------------------------------------------------------

    def log_tool_call(
        self,
        session_id: str,
        ip: str,
        tool_name: str,
        args: dict,
        result_summary: str,
        success: bool,
        turn_number: int = 0,
        overseer_flag: str = "none",
        token_count: int = 0,
        mission_phase: str = "red",
    ) -> None:
        self._conn.execute(
            """INSERT INTO tool_history
               (session_id, ip, tool_name, args_json, result_summary, success, created_at,
                turn_number, overseer_flag, token_count, mission_phase)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (session_id, ip, tool_name, json.dumps(args), result_summary, int(success), time.time(),
             turn_number, overseer_flag, token_count, mission_phase),
        )
        self._conn.commit()

    def get_tool_history_for_device(self, ip: str, limit: int = 50) -> list[dict]:
        cur = self._conn.execute(
            "SELECT * FROM tool_history WHERE ip = ? ORDER BY created_at DESC LIMIT ?",
            (ip, limit),
        )
        return cur.fetchall()

    # ------------------------------------------------------------------
    # Patches
    # ------------------------------------------------------------------

    def log_patch(
        self,
        finding_id: str,
        ip: str,
        attack_name: str,
        rule: str,
        signature: dict,
        verified: bool = False,
    ) -> str:
        patch_id = str(uuid.uuid4())
        now = time.time()
        self._conn.execute(
            """INSERT INTO patches
               (id, finding_id, ip, attack_name, rule, signature_json, applied_at, verified, verified_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (patch_id, finding_id, ip, attack_name, rule, json.dumps(signature), now, int(verified), now if verified else None),
        )
        self._conn.commit()
        return patch_id

    def mark_patch_verified(self, patch_id: str) -> None:
        self._conn.execute(
            "UPDATE patches SET verified = 1, verified_at = ? WHERE id = ?",
            (time.time(), patch_id),
        )
        self._conn.commit()

    def get_patches_for_device(self, ip: str) -> list[dict]:
        cur = self._conn.execute(
            "SELECT * FROM patches WHERE ip = ? ORDER BY applied_at DESC", (ip,)
        )
        return cur.fetchall()

    def get_active_patches(self) -> list[dict]:
        cur = self._conn.execute(
            "SELECT * FROM patches ORDER BY applied_at DESC"
        )
        return cur.fetchall()

    def is_already_patched(self, ip: str, attack_name: str) -> bool:
        cur = self._conn.execute(
            "SELECT 1 FROM patches WHERE ip = ? AND attack_name = ? AND verified = 1 LIMIT 1",
            (ip, attack_name),
        )
        return cur.fetchone() is not None

    # ------------------------------------------------------------------
    # Device profiles
    # ------------------------------------------------------------------

    def get_device_profile(self, ip: str) -> dict | None:
        cur = self._conn.execute(
            "SELECT * FROM device_profiles WHERE ip = ?", (ip,)
        )
        return cur.fetchone()

    def upsert_device_profile(
        self,
        ip: str,
        firmware_id: str | None = None,
        arch: str | None = None,
        device_name: str | None = None,
        known_creds: str | None = None,
        services: str | None = None,
        status: str | None = None,
    ) -> None:
        now = time.time()
        existing = self.get_device_profile(ip)
        if existing is None:
            self._conn.execute(
                """INSERT INTO device_profiles
                   (ip, firmware_id, arch, device_name, first_seen, last_seen,
                    known_creds, services_json, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (ip, firmware_id, arch, device_name, now, now, known_creds, services, status or "unknown"),
            )
        else:
            fields: list[str] = ["last_seen = ?"]
            values: list = [now]
            if firmware_id is not None:
                fields.append("firmware_id = ?")
                values.append(firmware_id)
            if arch is not None:
                fields.append("arch = ?")
                values.append(arch)
            if device_name is not None:
                fields.append("device_name = ?")
                values.append(device_name)
            if known_creds is not None:
                fields.append("known_creds = ?")
                values.append(known_creds)
            if services is not None:
                fields.append("services_json = ?")
                values.append(services)
            if status is not None:
                fields.append("status = ?")
                values.append(status)
            values.append(ip)
            self._conn.execute(
                f"UPDATE device_profiles SET {', '.join(fields)} WHERE ip = ?",
                values,
            )
        self._conn.commit()

    def get_all_device_profiles(self) -> list[dict]:
        cur = self._conn.execute(
            "SELECT * FROM device_profiles ORDER BY last_seen DESC"
        )
        return cur.fetchall()

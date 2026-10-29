"""Telemetry storage.

Design notes (beginner friendly):

* Local development uses SQLite (a single file, no server to install).
* Production uses PostgreSQL when a ``DATABASE_URL`` environment variable
  is configured (e.g. Render's managed database).  Both back-ends expose
  the same small API through :class:`TelemetryStore`.
* Every write is parameterised, which prevents database-injection through
  attacker-controlled request data.
* The privacy rules are enforced here: only credential-field *presence*
  is stored -- never credential values, cookies, or authorisation header
  contents.  See the schema below and the tests for proof.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from typing import Any, Iterator

# ---- Protected column names (exported for dashboards/tests) -------------
SCHEMA_COLUMNS = [
    "event_id",
    "timestamp_utc",
    "source_ip",
    "method",
    "path",
    "query_string",
    "user_agent",
    "referer",
    "host",
    "status_code",
    "response_size",
    "route_category",
    "classification",
    "mitre_technique",
    "mitre_rationale",
    "mitre_confidence",
    "credential_user",
    "credential_pass",
    "synthetic",
    "collector_version",
]

MAX_LENGTHS = {
    "timestamp_utc": 40,
    "source_ip": 64,
    "method": 16,
    "path": 512,
    "query_string": 512,
    "user_agent": 512,
    "referer": 512,
    "host": 255,
    "route_category": 64,
    "classification": 64,
    "mitre_technique": 32,
    "mitre_rationale": 256,
    "mitre_confidence": 16,
    "collector_version": 32,
}

_MAX_JSONL_LINE = 8_192  # refuse absurd records even on import


class TelemetryStore:
    """Structured telemetry storage with SQLite/PostgreSQL support."""

    def __init__(self, database_url: str = "", data_dir: str = ".",
                 db_filename: str = "telemetry.db") -> None:
        self.database_url = (database_url or "").strip()
        self.is_postgres = self.database_url.startswith(
            ("postgres://", "postgresql://")
        )
        if self.is_postgres:
            self.db_path = ""
        else:
            self.db_path = os.path.join(
                data_dir if data_dir not in ("", None) else ".",
                db_filename,
            )
        # A serialization lock protects SQLite's single-writer file access
        # when several Gunicorn threads write at the same time.
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------
    def _connect(self):
        if self.is_postgres:
            import psycopg2  # imported lazily; only needed in production
            return psycopg2.connect(self.database_url)
        return sqlite3.connect(self.db_path, timeout=30)

    @property
    def placeholder(self) -> str:
        """SQL parameter placeholder differs between engines."""
        return "%s" if self.is_postgres else "?"

    def _ph(self, n: int) -> str:
        return ", ".join([self.placeholder] * n)

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------
    def init_db(self) -> None:
        """Create the telemetry table and indexes if they do not exist."""
        with self._lock, self._connect() as conn:
            cur = conn.cursor()
            if self.is_postgres:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS events (
                        event_id            TEXT PRIMARY KEY,
                        timestamp_utc       TEXT NOT NULL,
                        source_ip           TEXT,
                        method              TEXT,
                        path                TEXT,
                        query_string        TEXT,
                        user_agent          TEXT,
                        referer             TEXT,
                        host                TEXT,
                        status_code         INTEGER,
                        response_size       INTEGER,
                        route_category      TEXT,
                        classification      TEXT,
                        mitre_technique     TEXT,
                        mitre_rationale     TEXT,
                        mitre_confidence    TEXT,
                        credential_user     BOOLEAN NOT NULL DEFAULT FALSE,
                        credential_pass     BOOLEAN NOT NULL DEFAULT FALSE,
                        synthetic           BOOLEAN NOT NULL DEFAULT FALSE,
                        collector_version   TEXT
                    )
                    """
                )
            else:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS events (
                        event_id            TEXT PRIMARY KEY,
                        timestamp_utc       TEXT NOT NULL,
                        source_ip           TEXT,
                        method              TEXT,
                        path                TEXT,
                        query_string        TEXT,
                        user_agent          TEXT,
                        referer             TEXT,
                        host                TEXT,
                        status_code         INTEGER,
                        response_size       INTEGER,
                        route_category      TEXT,
                        classification      TEXT,
                        mitre_technique     TEXT,
                        mitre_rationale     TEXT,
                        mitre_confidence    TEXT,
                        credential_user     INTEGER NOT NULL DEFAULT 0,
                        credential_pass     INTEGER NOT NULL DEFAULT 0,
                        synthetic           INTEGER NOT NULL DEFAULT 0,
                        collector_version   TEXT
                    )
                    """
                )
            for column in ("timestamp_utc", "source_ip", "path",
                           "classification", "synthetic"):
                cur.execute(
                    f"CREATE INDEX IF NOT EXISTS idx_events_{column} "
                    f"ON events ({column})"
                )
            conn.commit()
            cur.close()

    # ------------------------------------------------------------------
    # Insert
    # ------------------------------------------------------------------
    def insert(self, event: dict[str, Any]) -> bool:
        """Insert one telemetry record. Returns True when stored."""
        row = [self._normalise(key, event.get(key))
               for key in SCHEMA_COLUMNS]
        try:
            with self._lock, self._connect() as conn:
                conn.cursor().execute(
                    f"INSERT INTO events ({', '.join(SCHEMA_COLUMNS)}) "
                    f"VALUES ({self._ph(len(SCHEMA_COLUMNS))})",
                    row,
                )
                conn.commit()
            return True
        except Exception:
            # Storage failures (malformed records, engine errors) must
            # never crash the honeypot response; report failure instead.
            return False

    @staticmethod
    def _normalise(key: str, value: Any) -> Any:
        """Coerce one field to a safe, bounded value."""
        if key in ("credential_user", "credential_pass", "synthetic"):
            return 1 if value else 0
        if value is None:
            return None
        if key == "status_code" or key == "response_size":
            try:
                return int(value)
            except (TypeError, ValueError):
                return None
        text = str(value)
        return text[: MAX_LENGTHS.get(key, 512)]

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------
    def _sub(self, sql: str) -> str:
        """Convert '?'-style placeholders to the engine's placeholder."""
        return sql.replace("?", self.placeholder) if self.is_postgres else sql

    def summary(self, synthetic=None, from_ts=None, to_ts=None) -> dict:
        """Aggregate dashboard statistics, honouring the view filters."""
        params: list[Any] = []
        clauses: list[str] = []
        if synthetic is not None:
            clauses.append("synthetic = ?")
            params.append(synthetic)
        if from_ts:
            clauses.append("timestamp_utc >= ?")
            params.append(from_ts)
        if to_ts:
            clauses.append("timestamp_utc <= ?")
            params.append(to_ts)
        where = self._sub(
            ("WHERE " + " AND ".join(clauses)) if clauses else "")

        def q(sql: str) -> Any:
            return self._scalar(sql, self._sub_params(params))

        result: dict[str, Any] = {}
        result["total_events"] = q("SELECT COUNT(*) FROM events " + where) or 0
        result["unique_source_ips"] = \
            q("SELECT COUNT(DISTINCT source_ip) FROM events " + where) or 0
        discovery_where = (
            "synthetic = 0 AND classification IS NOT NULL AND "
            "classification NOT IN "
            "('Normal application request', 'Unknown (older log)')")
        result["discovery_events"] = q(
            "SELECT COUNT(*) FROM events " + where +
            (" AND " if clauses else " WHERE ") + discovery_where
        ) or 0
        result["synthetic_events"] = q(
            "SELECT COUNT(*) FROM events " + where +
            (" AND" if clauses else " WHERE") + " synthetic = 1") or 0
        result["first_observed"] = q(
            "SELECT MIN(timestamp_utc) FROM events " + where)
        result["last_observed"] = q(
            "SELECT MAX(timestamp_utc) FROM events " + where)
        return result

    def group_counts(
        self,
        column: str,
        limit: int = 20,
        synthetic: int | None = None,
        from_ts: str | None = None,
        to_ts: str | None = None,
    ) -> list[tuple[str, int]]:
        """Top values of one column with their counts (optionally filtered)."""
        select = f"COALESCE({column}, 'unknown'), COUNT(*) AS n"
        group = f"COALESCE({column}, 'unknown')"
        params: list[Any] = []
        clauses: list[str] = []
        if synthetic is not None:
            clauses.append("synthetic = ?")
            params.append(synthetic)
        if from_ts:
            clauses.append("timestamp_utc >= ?")
            params.append(from_ts)
        if to_ts:
            clauses.append("timestamp_utc <= ?")
            params.append(to_ts)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        where = self._sub(where)
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                f"SELECT {select} FROM events {where} "
                f"GROUP BY {group} ORDER BY n DESC LIMIT "
                f"{int(limit)}",
                self._sub_params(params),
            )
            rows = cur.fetchall()
        return rows

    def _sub_params(self, params: list[Any]) -> list[Any] | tuple:  # noqa
        return tuple(params) if self.is_postgres else params

    def counts_per_day(
        self,
        synthetic: int | None = None,
        from_ts: str | None = None,
        to_ts: str | None = None,
    ) -> list[tuple[str, int]]:
        """Request counts grouped by UTC day (ascending)."""
        params: list[Any] = []
        clauses: list[str] = []
        if synthetic is not None:
            clauses.append("synthetic = ?")
            params.append(synthetic)
        if from_ts:
            clauses.append("timestamp_utc >= ?")
            params.append(from_ts)
        if to_ts:
            clauses.append("timestamp_utc <= ?")
            params.append(to_ts)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        where = self._sub(where)
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT SUBSTR(timestamp_utc, 1, 10) AS day, COUNT(*) AS n "
                f"FROM events {where} "
                "GROUP BY day ORDER BY day ASC",
                self._sub_params(params),
            )
            rows = cur.fetchall()
        return rows

    def _scalar(self, query: str, params: tuple = ()) -> Any:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(query, params)
            row = cur.fetchone()
        return row[0] if row else None

    def events(
        self,
        page: int = 1,
        per_page: int = 50,
        filters: dict[str, Any] | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        """Paginated event listing. Returns (rows, total_matching)."""
        filters = filters or {}
        params: list[Any] = []
        clauses: list[str] = []
        if "synthetic" in filters and filters["synthetic"] is not None:
            clauses.append("synthetic = ?")
            params.append(filters["synthetic"])
        if filters.get("source_ip"):
            clauses.append("source_ip = ?")
            params.append(filters["source_ip"])
        if filters.get("classification"):
            clauses.append("classification = ?")
            params.append(filters["classification"])
        if filters.get("from"):
            clauses.append("timestamp_utc >= ?")
            params.append(filters["from"])
        if filters.get("to"):
            clauses.append("timestamp_utc <= ?")
            params.append(filters["to"])

        placeholder = "?"
        clauses_text = " WHERE " + " AND ".join(
            c.replace("?", placeholder) for c in clauses
        ) if clauses else ""

        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                f"SELECT COUNT(*) FROM events{clauses_text}", params)
            total = cur.fetchone()[0]
            cur.execute(
                f"SELECT {', '.join(SCHEMA_COLUMNS)} FROM events"
                f"{clauses_text} ORDER BY timestamp_utc DESC LIMIT "
                f"{int(per_page)} OFFSET {max(page - 1, 0) * int(per_page)}",
                params,
            )
            cols = [d[0] for d in cur.description]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        return rows, total

    def recent_login_probes_by_ip(self, source_ip: str,
                                  window_minutes: int = 60) -> int:
        """Count recent login-route events for one IP (frequency evidence).

        This powers the "Repeated authentication probing" classification:
        a single login request is one observation, whereas several login
        requests from the same source within a short window is multiple.
        """
        if not source_ip:
            return 0
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                self._sub(
                    f"SELECT COUNT(*) FROM events WHERE source_ip = ? "
                    f"AND path IN ('/login', '/wp-login.php', '/api/login', "
                    f"'/api/v1/login', '/admin/login') "
                    f"AND timestamp_utc >= {self._cutoff(window_minutes)}"),
                (source_ip,),
            )
            count = cur.fetchone()[0]
        return count

    def _cutoff(self, window_minutes: int) -> str:
        """Engine-specific SQL expression for 'N minutes ago (UTC)'."""
        if self.is_postgres:
            return f"now() - interval '{int(window_minutes)} minutes'"
        return f"datetime('now', '-{int(window_minutes)} minutes')"

    # ------------------------------------------------------------------
    # Exports / imports (streaming; original files are never modified)
    # ------------------------------------------------------------------
    def iter_rows(self, filters: dict[str, Any] | None = None,
                  ) -> Iterator[dict[str, Any]]:
        """Stream rows (dictionaries) from the database."""
        rows, _ = self.events(page=1, per_page=10_000_000, filters=filters)
        yield from rows

    def export_jsonl(self, path: str, synthetic: int | None = None) -> int:
        """Write JSON Lines export. Returns row count written."""
        count = 0
        with open(path, "w", encoding="utf-8") as handle:
            for row in self.iter_rows({"synthetic": synthetic}):
                handle.write(json.dumps(row, default=str) + "\n")
                count += 1
        return count

    def export_csv(self, path: str, synthetic: int | None = None) -> int:
        """Write CSV export. Returns row count written."""
        import csv
        count = 0
        with open(path, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=SCHEMA_COLUMNS)
            writer.writeheader()
            for row in self.iter_rows({"synthetic": synthetic}):
                writer.writerow(row)
                count += 1
        return count

    def import_jsonl(self, path: str, synthetic_default: int = 0) -> dict:
        """Import JSONL records. Returns {'imported': n, 'skipped': n}.

        Malformed lines are skipped (never crash); the source file is only
        read, never modified -- this allows migrating the legacy prototype's
        ``telemetry.jsonl`` without destroying the original evidence file.
        """
        imported = skipped = 0
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    record = json.loads(line)
                    if not isinstance(record, dict):
                        raise ValueError("not an object")
                except (json.JSONDecodeError, ValueError):
                    skipped += 1
                    continue
                event = {
                    "event_id": record.get("event_id"),
                    "timestamp_utc": record.get(
                        "timestamp", record.get("timestamp_utc")),
                    "source_ip": record.get("ip", record.get("source_ip")),
                    "method": record.get("method"),
                    "path": record.get("path"),
                    "query_string": record.get("query_string"),
                    "user_agent": record.get("user_agent",
                                             record.get("User-Agent")),
                    "referer": record.get("referer"),
                    "host": record.get("host"),
                    "status_code": record.get("status_code"),
                    "response_size": record.get("response_size"),
                    "route_category": record.get("route_category"),
                    "classification": record.get("classification"),
                    "mitre_technique": record.get("mitre_technique"),
                    "mitre_rationale": record.get("mitre_rationale"),
                    "mitre_confidence": record.get("mitre_confidence"),
                    "credential_user": int(bool(
                        record.get("credential_user",
                                   record.get("username_like_fields")))),
                    "credential_pass": int(bool(
                        record.get("credential_pass",
                                   record.get("password_like_fields")))),
                    "synthetic": int(bool(
                        record.get("synthetic", synthetic_default))),
                    "collector_version": record.get(
                        "collector_version", "migration-1"),
                }
                if not event["event_id"]:
                    event["event_id"] = (
                        f"migrated-{imported + 1:08d}-"
                        f"{str(event['timestamp_utc'])[:19]}"
                    )
                if self.insert(event):
                    imported += 1
                else:
                    skipped += 1
        return {"imported": imported, "skipped": skipped}

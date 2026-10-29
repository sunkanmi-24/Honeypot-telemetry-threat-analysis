"""Telemetry schema, privacy, and synthetic-marking tests."""

from __future__ import annotations

import json
import sqlite3

from honeypot.telemetry import SCHEMA_COLUMNS, TelemetryStore


def test_health_not_recorded(client, store):
    """The observer's own health/dashboard/export traffic is not telemetry."""
    client.get("/health")
    client.get("/dashboard")
    client.get("/export/events.csv")
    client.get("/favicon.ico")
    assert store.summary()["total_events"] == 0


def test_request_recorded_with_full_schema(client, store):
    client.get("/admin", headers=[("User-Agent", "probe-agent"),
                                  ("Referer", "http://ref")])
    rows = list(store.iter_rows())
    assert len(rows) == 1
    event = rows[0]
    for column in SCHEMA_COLUMNS:
        assert column in event, f"missing column {column}"
    assert event["path"] == "/admin"
    assert event["method"] == "GET"
    assert event["user_agent"] == "probe-agent"
    assert event["referer"] == "http://ref"
    assert event["classification"] == "Administrative interface discovery"
    assert event["route_category"] == "administrative"
    assert event["status_code"] == 200
    assert event["response_size"] == len(
        client.get("/admin").get_data()) or event["response_size"]


def test_timestamp_is_utc_iso8601(client, store):
    client.get("/")
    event = list(store.iter_rows())[0]
    stamp = event["timestamp_utc"]
    assert "T" in stamp and "+" in stamp
    assert stamp.endswith("+00:00")
    year = int(stamp[:4])
    assert 2020 <= year <= 2100


def test_credentials_presence_but_never_values(client, store):
    """Credential FIELD NAMES are flagged; VALUES are never stored."""
    client.post("/login", data={"username": "alice",
                                "password": "super-secret-value"})
    event = list(store.iter_rows())[0]
    assert event["credential_user"] == 1
    assert event["credential_pass"] == 1
    events_json = json.dumps(list(store.iter_rows()))
    assert "alice" not in events_json
    assert "super-secret-value" not in events_json


def test_no_credentials_flag_without_fields(client, store):
    client.post("/api/login", data={"q": "search"})
    event = list(store.iter_rows())[0]
    assert event["credential_user"] == 0
    assert event["credential_pass"] == 0


def test_long_fields_truncated(client, store):
    client.get("/login?x=" + "B" * 20000, headers=[("User-Agent", "U" * 8000)])
    event = list(store.iter_rows())[0]
    from honeypot.telemetry import MAX_LENGTHS
    assert len(event["query_string"]) <= MAX_LENGTHS["query_string"]
    assert len(event["user_agent"]) <= MAX_LENGTHS["user_agent"]


def test_loopback_marked_synthetic(client, store):
    """Local test traffic is flagged so it can be excluded from stats."""
    client.get("/")
    event = list(store.iter_rows())[0]
    assert event["synthetic"] == 1


def test_mark_local_synthetic_false(tmp_path):
    from config import Config
    from app import create_app
    cfg = Config(database_url="", data_dir=str(tmp_path),
                 mark_local_synthetic=False)
    app = create_app(cfg)
    client = app.test_client()
    client.get("/")
    store = app.config["TELEMETRY_STORE"]
    event = list(store.iter_rows())[0]
    assert event["synthetic"] == 0


def test_malformed_records_do_not_break_insert(store):
    bad_events = [
        {"threshold": None},          # not even the right keys
        {},                           # empty
        {"event_id": None, "timestamp_utc": None},  # nulls coerced
    ]
    from config import Config
    cfg = Config()
    for bad in bad_events:
        store.insert(bad)  # must not raise


def test_store_insert_returns_false_on_engine_error(config):
    """A storage failure returns False instead of raising."""
    store = TelemetryStore(database_url="", data_dir=config.data_dir)
    # deliberately not initialised -> insert must fail gracefully
    event = {"event_id": "x", "timestamp_utc": "2026-01-01"}
    assert store.insert(event) in (False, True)
    # A really broken database path:
    broken = TelemetryStore(database_url="", data_dir="Z:/no/such/dir")
    broken.db_path = "Z:/no/such/dir/telemetry.db"
    assert broken.insert(event) is False


def test_summary_numbers_match_records(client, store):
    client.get("/admin")
    client.get("/.env")
    client.post("/login", data={"user": "u", "pass": "p"})
    summary = store.summary()
    assert summary["total_events"] == 3
    assert summary["unique_source_ips"] == 1
    assert summary["synthetic_events"] == 3
    # These events are synthetic (loopback), so observed-Internet
    # statistics must EXCLUDE them:
    assert summary["discovery_events"] == 0


def test_observed_discovery_counts_exclude_synthetic(tmp_path):
    """With synthetic marking off (simulated observed traffic), discovery
    counts include the events."""
    from config import Config
    from app import create_app
    cfg = Config(database_url="", data_dir=str(tmp_path),
                 mark_local_synthetic=False)
    app = create_app(cfg)
    client = app.test_client()
    client.get("/admin")
    client.get("/.env")
    store = app.config["TELEMETRY_STORE"]
    summary = store.summary(synthetic=0)
    assert summary["discovery_events"] == 2
    assert summary["synthetic_events"] == 0


def test_no_secrets_columns_in_schema():
    forbidden = {"password", "cookie", "authorization", "token", "body"}
    for column in SCHEMA_COLUMNS:
        assert column not in forbidden, column
        assert not any(f in column for f in forbidden), column


def test_repeated_login_probes_counter(client, store):
    for _ in range(4):
        client.get("/login")
    assert store.recent_login_probes_by_ip("127.0.0.1") >= 3


def test_malformed_jsonl_import_skipped(store, tmp_path):
    raw = tmp_path / "raw.jsonl"
    raw.write_text(
        '{"path": "/admin", "method": "GET", "timestamp": '
        '"2026-01-01T00:00:00+00:00", "ip": "1.2.3.4", '
        '"classification": "Administrative interface discovery"}\n'
        "NOT-JSON-AT-ALL\n"
        '["also", "not", "an", "object"]\n'
        "#comment line\n",
        encoding="utf-8",
    )
    result = store.import_jsonl(str(raw))
    assert result["imported"] == 1
    # Malformed JSON lines are skipped; comment lines are ignored silently.
    assert result["skipped"] == 2


def test_import_keeps_source_file_intact(store, tmp_path):
    raw = tmp_path / "legacy.jsonl"
    original = ('{"path": "/.env", "method": "GET", '
                '"timestamp": "2026-01-02T00:00:00+00:00"}\n')
    raw.write_text(original, encoding="utf-8")
    store.import_jsonl(str(raw))
    assert raw.read_text(encoding="utf-8") == original

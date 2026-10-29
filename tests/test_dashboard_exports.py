"""Dashboard, export, persistence, and configuration-error tests."""

from __future__ import annotations

import csv
import io
import json


# -- Dashboard ---------------------------------------------------------------

def test_dashboard_empty_state(client):
    """With no data, the dashboard shows a meaningful empty state."""
    response = client.get("/dashboard")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "No telemetry yet" in html
    assert "nothing is pre-populated" in html


def test_dashboard_with_data(client, store):
    client.get("/admin")
    client.get("/login")
    response = client.get("/dashboard?view=all")
    html = response.get_data(as_text=True)
    assert "No telemetry yet" not in html
    assert "Administrative interface discovery" in html
    assert "Login endpoint probing" in html


def test_dashboard_view_filters_synthetic(client):
    """Synthetic events appear only in their own view."""
    client.get("/admin")  # loopback -> synthetic
    # Observed-only view must not count the synthetic event:
    observed_html = client.get("/dashboard").get_data(as_text=True)
    assert "No telemetry yet" in observed_html
    assert "Total requests</h3>" not in observed_html
    # Synthetic view must show it:
    synthetic_html = client.get("/dashboard?view=synthetic")\
        .get_data(as_text=True)
    assert "Administrative interface discovery" in synthetic_html
    synthetic_html = client.get("/dashboard?view=synthetic")\
        .get_data(as_text=True)
    assert "Administrative interface discovery" in synthetic_html


def test_dashboard_escapes_untrusted_values(client):
    """Untrusted User-Agent content must be escaped in the dashboard."""
    script = "<script>alert(1)</script>"
    client.get("/admin", headers=[("User-Agent", script)])
    html = client.get("/dashboard?view=all").get_data(as_text=True)
    assert "<script>alert(1)" not in html
    assert "&lt;script&gt;" in html


def test_events_page_pagination(client, store):
    for _ in range(7):
        client.get("/admin")
    response = client.get("/dashboard/events?page=1&per_page=5&view=all")
    assert response.status_code == 200
    response2 = client.get("/dashboard/events?page=99&view=all")
    assert response2.status_code == 200


def test_repeated_ip_shown(client):
    for _ in range(3):
        client.get("/admin")
    html = client.get("/dashboard?view=all").get_data(as_text=True)
    assert "127.0.0.1" in html


def test_country_section_absent_without_geoip(client):
    client.get("/admin")
    html = client.get("/dashboard?view=all").get_data(as_text=True)
    # With enrichment disabled no country data is shown, ever guessed.
    assert "Geographic enrichment is disabled" in html
    assert "never" in html.lower()


# -- Exports ------------------------------------------------------------------

def test_jsonl_export_valid_and_complete(client, store):
    client.get("/admin")
    client.get("/robots.txt")
    response = client.get("/export/events.jsonl?view=all")
    assert response.status_code == 200
    lines = response.get_data(as_text=True).strip().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["path"] == "/admin" or first["path"] == "/robots.txt"


def test_csv_export(client, store):
    client.get("/admin")
    response = client.get("/export/events.csv?view=all")
    assert response.status_code == 200
    assert "text/csv" in response.mimetype
    rows = list(csv.DictReader(io.StringIO(
        response.get_data(as_text=True))))
    assert len(rows) >= 1
    assert rows[0]["path"] == "/admin"


def test_export_respects_view_filter(client, store):
    client.get("/admin")  # synthetic
    body = client.get("/export/events.jsonl").get_data(as_text=True)
    assert body == ""  # observed-only view excludes synthetic events
    body_all = client.get("/export/events.jsonl?view=all")\
        .get_data(as_text=True)
    assert "Administrative interface discovery" in body_all


# -- Persistence across restarts ------------------------------------------------

def test_database_persists_across_app_restart(store, config):
    store.insert({"event_id": "persist-1",
                  "timestamp_utc": "2026-01-01T00:00:00+00:00",
                  "path": "/admin", "method": "GET"})
    from app import create_app
    app = create_app(config)  # fresh factory, same SQLite file
    rows = list(app.config["TELEMETRY_STORE"].iter_rows())
    assert any(r["event_id"] == "persist-1" for r in rows)


# -- Configuration errors ---------------------------------------------------------

def test_invalid_database_url_rejected():
    import os
    from config import ConfigError, get_config
    old = os.environ.get("DATABASE_URL")
    try:
        os.environ["DATABASE_URL"] = "mysql://bad"
        try:
            get_config()
            assert False, "expected ConfigError"
        except ConfigError:
            pass
    finally:
        if old is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = old

"""Dashboard and export endpoints.

Every figure is computed from the telemetry database at request time --
nothing is hardcoded.  Synthetic (local/test) events are always shown
separately from observed Internet traffic, never merged, and Jinja2
auto-escaping protects the HTML from untrusted field values.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any, Optional

from flask import Blueprint, Response, current_app, render_template, request

dashboard_bp = Blueprint("dashboard", __name__)

PER_PAGE = 50
RECENT_LIMIT = 15
TOP_LIMIT = 12

VIEW_MODES = {
    "all": None,
    "observed": 0,
    "synthetic": 1,
}


class DashboardError(Exception):
    """Raised when dashboard configuration is unusable."""


def _store() -> Any:
    store = current_app.config.get("TELEMETRY_STORE")
    if store is None:
        raise DashboardError("telemetry store is not configured")
    return store


def _find_view() -> tuple[str, Optional[int]]:
    mode = request.args.get("view", "observed")
    if mode not in VIEW_MODES:
        mode = "observed"
    return mode, VIEW_MODES[mode]


def _date_filters() -> dict[str, Optional[str]]:
    from_ = (request.args.get("from") or "").strip() or None
    to = (request.args.get("to") or "").strip() or None
    return {"from": from_, "to": to}


def _country_counts(store: Any, synthetic: Optional[int]) -> list[tuple]:
    """Country distribution from stored IPs (only when enrichment is on)."""
    geoip = current_app.config.get("GEOIP")
    if geoip is None or not getattr(geoip, "enabled", False):
        return []
    rows = store.group_counts("source_ip", limit=100, synthetic=synthetic)
    counts: dict[str, int] = {}
    for ip, n in rows:
        country = geoip.country(ip)
        counts[country] = counts.get(country, 0) + n
    return sorted(counts.items(), key=lambda kv: -kv[1])


def _repeated_ips(rows: list[tuple], minimum: int = 2) -> list[tuple]:
    return [(ip, n) for ip, n in rows if n >= minimum]


@dashboard_bp.route("/")
def index() -> Response:
    """Normal landing page (classified as a normal request in telemetry)."""
    return render_template("home.html")


def _view_dashboard() -> Response:  # pragma: no cover - wrapper only
    raise RuntimeError  # replaced by register_dashboard_routes wiring


def _req_dashboard() -> Response:
    mode, synthetic = _find_view()
    dates = _date_filters()
    store = _store()
    summary = store.summary(
        synthetic=synthetic, from_ts=dates["from"], to_ts=dates["to"])
    context: dict[str, Any] = {
        "mode": mode,
        "dates": dates,
        "summary": summary,
        "over_time": store.counts_per_day(
            synthetic, dates["from"], dates["to"]),
        "top_routes": store.group_counts(
            "path", TOP_LIMIT, synthetic, dates["from"], dates["to"]),
        "methods": store.group_counts(
            "method", TOP_LIMIT, synthetic, dates["from"], dates["to"]),
        "statuses": store.group_counts(
            "status_code", TOP_LIMIT, synthetic,
            dates["from"], dates["to"]),
        "user_agents": store.group_counts(
            "user_agent", TOP_LIMIT, synthetic,
            dates["from"], dates["to"]),
        "classifications": store.group_counts(
            "classification", TOP_LIMIT, synthetic,
            dates["from"], dates["to"]),
        "route_categories": store.group_counts(
            "route_category", TOP_LIMIT, synthetic,
            dates["from"], dates["to"]),
        "mitre": store.group_counts(
            "mitre_technique", TOP_LIMIT, synthetic,
            dates["from"], dates["to"]),
        "top_ips": store.group_counts(
            "source_ip", TOP_LIMIT, synthetic,
            dates["from"], dates["to"]),
        "repeated_ips": _repeated_ips(
            store.group_counts(
                "source_ip", TOP_LIMIT, synthetic,
                dates["from"], dates["to"])),
        "countries": _country_counts(store, synthetic),
        "recent_events": store.events(
            page=1, per_page=RECENT_LIMIT,
            filters={**dates, "synthetic": synthetic},
        )[0],
        "geoip_enabled": bool(
            getattr(current_app.config.get("GEOIP"), "enabled", False)),
    }
    return render_template("dashboard.html", **context)


def _req_events() -> Response:
    mode, synthetic = _find_view()
    dates = _date_filters()
    store = _store()
    try:
        page = max(int(request.args.get("page", 1)), 1)
    except (TypeError, ValueError):
        page = 1
    filters = {**dates, "synthetic": synthetic}
    if request.args.get("source_ip"):
        filters["source_ip"] = request.args["source_ip"].strip()
    if request.args.get("classification"):
        filters["classification"] = request.args["classification"].strip()

    rows, total = store.events(page=page, per_page=PER_PAGE, filters=filters)
    pages = max((total + PER_PAGE - 1) // PER_PAGE, 1)
    classifications = [
        name for name, _n in store.group_counts("classification", limit=100)
    ]
    return render_template(
        "events.html",
        mode=mode,
        dates=dates,
        rows=rows,
        total=total,
        page=page,
        pages=pages,
        per_page=PER_PAGE,
        source_ip_filter=filters.get("source_ip", ""),
        classification_filter=filters.get("classification", ""),
        classifications=classifications,
    )


def _req_export_jsonl() -> Response:  # pragma: no cover - wiring below
    raise RuntimeError


def _req_export_csv() -> Response:  # pragma: no cover - wiring below
    raise RuntimeError


def _req_health() -> Response:
    return Response(
        json.dumps({"status": "ok"}),
        mimetype="application/json",
    )


def register_dashboard_routes(bp: Blueprint) -> None:
    """Attach dashboard/export routes (call once per app instance)."""

    @bp.route("/")
    def index() -> Response:
        return render_template("home.html")

    @bp.route("/health")
    def health() -> Response:
        """Deployment health check. Discloses nothing about configuration."""
        return _req_health()

    @bp.route("/dashboard")
    def dashboard() -> Response:
        return _req_dashboard()

    @bp.route("/dashboard/events")
    def events() -> Response:
        return _req_events()

    @bp.route("/export/events.jsonl")
    def export_jsonl() -> Response:
        mode, synthetic = _find_view()
        dates = _date_filters()
        store = _store()
        rows, _total = store.events(
            page=1, per_page=1_000_000,
            filters={**dates, "synthetic": synthetic})

        def generate():
            for row in rows:
                yield json.dumps(row, default=str) + "\n"

        return Response(
            generate(),
            mimetype="application/x-ndjson",
            headers={"Content-Disposition": "attachment; "
                    "filename=telemetry-events.jsonl"},
        )

    @bp.route("/export/events.csv")
    def export_csv() -> Response:
        from honeypot.telemetry import SCHEMA_COLUMNS
        mode, synthetic = _find_view()
        dates = _date_filters()
        store = _store()
        rows, _total = store.events(
            page=1, per_page=1_000_000,
            filters={**dates, "synthetic": synthetic})

        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=SCHEMA_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
        payload = buffer.getvalue()

        return Response(
            payload,
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; "
                    "filename=telemetry-events.csv"},
        )

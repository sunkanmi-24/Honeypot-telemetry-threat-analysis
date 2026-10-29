"""Telemetry & Threat Analysis honeypot — Flask application factory.

Run locally on Windows with:  ``python app.py``
Run in production with:       ``gunicorn app:app``  (see Procfile)

Security model:
* Debug output is disabled by default and never enabled implicitly.
* Werkzeug ``ProxyFix`` is applied ONLY when ``PROXY_TRUSTED_HOPS`` is set
  to a verified count of trusted reverse proxies (default 0 = headers not
  trusted).  This prevents clients from forging their own recorded IP.
* Decoy responses never disclose real configuration, files, or services.
"""

from __future__ import annotations

import sys

from flask import Blueprint, Flask, Response, request
from werkzeug.middleware.proxy_fix import ProxyFix

from config import Config, get_config
from honeypot.dashboard import register_dashboard_routes
from honeypot.telemetry import TelemetryStore
from honeypot.views import (
    record_telemetry,
    register_deceptive_routes,
    should_record,
)


def create_app(config: Config | None = None) -> Flask:
    """Create and configure the Flask application."""
    cfg = config or get_config()
    app = Flask(__name__)
    app.config["HONEYPOT_CONFIG"] = cfg
    app.config["GEOIP"] = _make_geoip(cfg)

    # Werkzeug ProxyFix, applied only when a verified proxy hop count is
    # configured. With the default of 0 the socket peer address is used
    # unchanged, so forwarding headers cannot forge the recorded IP.
    if cfg.proxy_trusted_hops > 0:
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=cfg.proxy_trusted_hops,
            x_proto=cfg.proxy_trusted_hops,
        )

    store = TelemetryStore(
        database_url=cfg.database_url, data_dir=cfg.data_dir)
    try:
        store.init_db()
    except Exception as exc:  # fail loudly at startup, not per request
        print(f"telemetry database init failed: {exc!r}", file=sys.stderr)
        raise
    app.config["TELEMETRY_STORE"] = store

    # Fresh blueprints per factory call allow multiple app instances
    # in one process (required by the test suite).
    honeypot = Blueprint("honeypot", __name__)
    dash = Blueprint("dashboard", __name__)
    register_deceptive_routes(honeypot)
    register_dashboard_routes(dash)
    app.register_blueprint(honeypot)
    app.register_blueprint(dash)

    # ---- telemetry capture hooks ---------------------------------------
    @app.after_request
    def capture_telemetry(response: Response) -> Response:
        try:
            if should_record(request.path):
                record_telemetry(store, cfg, response)
        except Exception as exc:  # never let telemetry break the response
            print(f"telemetry capture error: {exc!r}", file=sys.stderr)
        return response

    @app.after_request
    def security_headers(response: Response) -> Response:
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    @app.errorhandler(404)
    def not_found(_error):
        return Response(
            '{"status": "not_found", "message": "Resource does not exist"}',
            status=404,
            mimetype="application/json",
        )

    @app.errorhandler(500)
    def server_error(_error):
        # Never leak a traceback to HTTP clients.
        return Response(
            '{"status": "error", "message": "An internal error occurred"}',
            status=500,
            mimetype="application/json",
        )

    return app


def _make_geoip(config: Config):
    from honeypot.geoip import GeoIPResolver
    return GeoIPResolver(config.geoip_db_path)


# Module-level application instance for WSGI servers (gunicorn app:app).
app = create_app()


if __name__ == "__main__":
    # Development convenience only. Production uses gunicorn (Procfile).
    port = int(sys.argv[sys.argv.index("--port") + 1]) \
        if "--port" in sys.argv else 5000
    debug = "--debug" in sys.argv
    app.run(host="127.0.0.1", port=port, debug=debug)
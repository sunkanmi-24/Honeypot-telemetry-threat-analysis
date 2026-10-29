"""HTTP endpoints: deceptive honeypot routes and telemetry capture.

Safety doctrine for every deceptive route:

* Responses are controlled, static fakes generated in code.  The honeypot
  never serves local files, never executes attacker input, and never
  connects a decoy login form to any real authentication.
* Credential fields are never parsed for values -- only their presence is
  recorded -- and credential-like values are never echoed back.

Deceptive routes are registered from one table through one shared view
factory so route logic is never duplicated.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from flask import Blueprint, Response, request

from .classification import (
    PASSWORD_KEY_HINTS,
    USERNAME_KEY_HINTS,
    classify,
)
from .clientip import resolve_client_ip
from .mitre import map_event

honeypot_bp = Blueprint("honeypot", __name__)

# Paths that must NEVER be recorded: the observer's own traffic.
_MONITORING_PREFIXES = (
    "/health",
    "/dashboard",
    "/export",
    "/static/",
    "/favicon.ico",
)

_EVENT_ID_LOCK = threading.Lock()
_EVENT_ID_COUNTER = 0


def generate_event_id() -> str:
    """Collision-safe, time-orderable event identifier."""
    global _EVENT_ID_COUNTER
    with _EVENT_ID_LOCK:
        _EVENT_ID_COUNTER += 1
        counter = _EVENT_ID_COUNTER
    return f"{time.time_ns():020d}-{counter:08d}-{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# Controlled fake responses
# ---------------------------------------------------------------------------

_LOGIN_PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<!-- Decoy page: not connected to any authentication system. -->
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  body {{ font-family: Arial, Helvetica, sans-serif; background: #f2f4f8;
         display: flex; align-items: center; justify-content: center;
         min-height: 100vh; margin: 0; }}
  .panel {{ background: #ffffff; border: 1px solid #d8dee9;
            border-radius: 10px; padding: 32px; width: 300px;
            box-shadow: 0 2px 10px rgba(30, 40, 70, .12); }}
  h1 {{ font-size: 18px; color: #2c3e50; margin-top: 0;
        text-align: center; }}
  input {{ width: 100%; box-sizing: border-box; padding: 10px;
           margin: 8px 0; border: 1px solid #ccd4e0; border-radius: 6px; }}
  button {{ width: 100%; padding: 10px; background: #34495e; color: #fff;
            border: 0; border-radius: 6px; cursor: pointer; }}
  .note {{ font-size: 11px; color: #9aa4b2; text-align: center;
           margin-top: 14px; }}
</style>
</head>
<body>
<div class="panel">
  <h1>{title}</h1>
  <form method="post" action="{action}">
    <input type="text" name="username" autocomplete="off">
    <input type="password" name="password" autocomplete="off">
    <button type="submit">Sign in</button>
  </form>
  <p class="note">Maintenance mode</p>
</div>
</body>
</html>
"""


def _login_page(title: str, action: str) -> str:
    """A static fake login form. Never wired to authentication."""
    return _LOGIN_PAGE_TEMPLATE.format(title=title, action=action)


def _json_200(payload: str) -> tuple[str, str, int]:
    return (payload, "application/json; charset=utf-8", 200)


def _json_403() -> tuple[str, str, int]:
    return ('{"status": "unauthorized", '
            '"message": "Authentication is disabled"}',
            "application/json; charset=utf-8", 403)


def _json_404() -> tuple[str, str, int]:
    return ('{"status": "not_found", '
            '"message": "Resource does not exist"}',
            "application/json; charset=utf-8", 404)


def _html(body: str, status: int = 200) -> tuple[str, str, int]:
    return (body, "text/html; charset=utf-8", status)


def _xml(body: str) -> tuple[str, str, int]:
    return (body, "text/xml; charset=utf-8", 200)


_XMLRPC_FAULT = (
    '<?xml version="1.0" encoding="utf-8"?>'
    "<methodResponse><fault><value><struct>"
    "<member><name>faultCode</name><value><int>403</int></value></member>"
    "<member><name>faultString</name>"
    "<value><string>XML-RPC disabled</string></value></member>"
    "</struct></value></fault></methodResponse>"
)

_SYSTEM_STATUS_PAGE = (
    "<!DOCTYPE html>"
    '<html lang="en"><head><meta charset="utf-8">'
    "<title>Server Status</title></head>"
    "<body><h1>Apache Server Status (decoy)</h1>"
    "<ul><li>Server uptime: unavailable</li>"
    "<li>Active connections: unavailable</li></ul>"
    "<!-- Controlled honeypot response; contains no real host data -->"
    "</body></html>"
)

_PHPINFO_PAGE = (
    "<!DOCTYPE html>"
    '<html lang="en"><head><meta charset="utf-8">'
    "<title>phpinfo()</title></head>"
    "<body><h2>PHP Version</h2>"
    "<p>PHP Version <em>unavailable</em></p>"
    "<h2>Configuration</h2>"
    "<table><tr><th>Directive</th><th>Value</th></tr>"
    "<tr><td>display_errors</td><td><em>unavailable</em></td></tr>"
    "<tr><td>max_execution_time</td>"
    "<td><em>unavailable</em></td></tr></table>"
    "<!-- Controlled honeypot response; no real system values -->"
    "</body></html>"
)

_ROBOTS_TXT = "User-agent: *\nDisallow: /admin/\n"


class DeceptiveRoute:
    """One registered deceptive route and its controlled responses."""

    def __init__(self, path: str, methods: list[str],
                 get_response: tuple[str, str, int],
                 post_response: Optional[tuple[str, str, int]] = None,
                 ) -> None:
        self.path = path
        self.methods = methods
        self.get_response = get_response
        self.post_response = post_response or get_response

    @property
    def endpoint(self) -> str:
        slug = self.path.strip("/").replace("/", "_").replace(".", "_")
        return f"decoy_{slug or 'root'}"


DECEPTIVE_ROUTES: list[DeceptiveRoute] = [
    DeceptiveRoute("/admin", ["GET", "POST"],
                   _html(_login_page("Admin Login", "/admin")),
                   _json_403()),
    DeceptiveRoute("/administrator", ["GET", "POST"],
                   _html(_login_page("Administrator Login",
                                     "/administrator")),
                   _json_403()),
    DeceptiveRoute("/admin/login", ["GET", "POST"],
                   _html(_login_page("Admin Login", "/admin/login")),
                   _json_403()),
    DeceptiveRoute("/login", ["GET", "POST"],
                   _html(_login_page("Sign in", "/login")),
                   _json_403()),
    DeceptiveRoute("/wp-admin", ["GET", "POST"],
                   _html(_login_page("WordPress Admin", "/wp-admin")),
                   _json_403()),
    DeceptiveRoute("/wp-admin/index.php", ["GET", "POST"],
                   _html(_login_page("WordPress Admin",
                                     "/wp-admin/index.php")),
                   _json_403()),
    DeceptiveRoute("/wp-admin.php", ["GET", "POST"],
                   _html(_login_page("WordPress Admin", "/wp-admin.php")),
                   _json_403()),
    DeceptiveRoute("/wp-login.php", ["GET", "POST"],
                   _html(_login_page("Log In - WordPress",
                                     "/wp-login.php")),
                   _json_403()),
    DeceptiveRoute("/wp-content/login.php", ["GET", "POST"],
                   _html(_login_page("Log In", "/wp-content/login.php")),
                   _json_403()),
    DeceptiveRoute("/xmlrpc.php", ["GET", "POST"], _xml(_XMLRPC_FAULT)),
    DeceptiveRoute("/phpmyadmin", ["GET", "POST"],
                   _html(_login_page("phpMyAdmin", "/phpmyadmin")),
                   _json_403()),
    DeceptiveRoute("/server-status", ["GET"],
                   _html(_SYSTEM_STATUS_PAGE)),
    DeceptiveRoute("/server-info", ["GET"], _html(_SYSTEM_STATUS_PAGE)),
    DeceptiveRoute("/phpinfo.php", ["GET"], _html(_PHPINFO_PAGE)),
    DeceptiveRoute("/info.php", ["GET"], _html(_PHPINFO_PAGE)),
    # The next block returns 404-style JSON only: configuration files,
    # repository metadata, and backups are never produced or downloaded.
    DeceptiveRoute("/.env", ["GET"], _json_404()),
    DeceptiveRoute("/.git/config", ["GET"], _json_404()),
    DeceptiveRoute("/.git/HEAD", ["GET"], _json_404()),
    DeceptiveRoute("/.git/index", ["GET"], _json_404()),
    DeceptiveRoute("/config.php", ["GET"], _json_404()),
    DeceptiveRoute("/configuration.php", ["GET"], _json_404()),
    DeceptiveRoute("/configuration.php.bak", ["GET"], _json_404()),
    DeceptiveRoute("/database.sql", ["GET"], _json_404()),
    DeceptiveRoute("/backup.zip", ["GET"], _json_404()),
    DeceptiveRoute("/backup.sql", ["GET"], _json_404()),
    DeceptiveRoute("/backup.sql.gz", ["GET"], _json_404()),
    DeceptiveRoute("/api", ["GET"],
                   _json_200('{"status": "degraded", '
                             '"message": "API is degraded"}')),
    DeceptiveRoute("/api/v1", ["GET"],
                   _json_200('{"status": "degraded", '
                             '"message": "API is degraded"}')),
    DeceptiveRoute("/api/login", ["GET", "POST"],
                   _json_403(),
                   _json_403()),
    DeceptiveRoute("/api/v1/login", ["GET", "POST"],
                   _json_403(),
                   _json_403()),
    DeceptiveRoute("/console", ["GET"], _json_404()),
    DeceptiveRoute("/debug", ["GET"], _json_404()),
    DeceptiveRoute("/test", ["GET"], _json_404()),
    DeceptiveRoute("/actuator", ["GET"],
                   _json_200('{"status": "UP", '
                             '"components": {"self": "up"}}')),
    DeceptiveRoute("/actuator/env", ["GET"],
                   ('{"_links": {"self": {"href": "/decoy"}}}',
                    "application/json; charset=utf-8", 403)),
    DeceptiveRoute("/manager/html", ["GET", "POST"],
                   _html(_login_page("Apache Tomcat Manager",
                                     "/manager/html")),
                   _json_403()),
]

LOGIN_ROUTES = {
    "/login", "/wp-login.php", "/api/login", "/api/v1/login",
    "/admin/login",
}


def register_deceptive_routes(bp: Blueprint) -> None:
    """Register every deceptive route through one shared view factory."""

    def make_view(route: DeceptiveRoute) -> Callable:
        def view() -> Response:
            body, content_type, status = (
                route.post_response
                if request.method == "POST" else route.get_response
            )
            return Response(body, status=status, content_type=content_type)
        view.__name__ = route.endpoint
        view.__doc__ = f"Controlled decoy response for {route.path}."
        return view

    @bp.route("/robots.txt", methods=["GET"])
    def robots() -> Response:
        return Response(
            _ROBOTS_TXT, content_type="text/plain; charset=utf-8")

    for route in DECEPTIVE_ROUTES:
        bp.add_url_rule(
            route.path,
            endpoint=route.endpoint,
            view_func=make_view(route),
            methods=route.methods,
        )


def endpoint_for_path(path: str) -> Optional[DeceptiveRoute]:
    for route in DECEPTIVE_ROUTES:
        if route.path == path:
            return route
    return None


# ---------------------------------------------------------------------------
# Telemetry capture
# ---------------------------------------------------------------------------

def should_record(path: str) -> bool:
    """True when the request is recorded (the observer's paths are not)."""
    return not path.startswith(_MONITORING_PREFIXES)


def looks_local(ip: Optional[str]) -> bool:
    """True for loopback/private addresses (local or internal traffic)."""
    if not ip:
        return True
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_loopback or addr.is_private


def credential_field_presence() -> tuple[bool, bool]:
    """Detect credential-like field NAMES in form, query, or small JSON.

    Only field names are inspected; field values are never read or
    stored anywhere.
    """
    keys: set[str] = set()
    try:
        keys.update(k.lower() for k in request.form.keys())
    except Exception:
        pass
    try:
        keys.update(k.lower() for k in request.args.keys())
    except Exception:
        pass
    if request.method == "POST" and \
            request.mimetype == "application/json":
        try:
            body = request.get_data(cache=True)
            if body is not None and len(body) <= 4096:
                parsed = json.loads(body.decode("utf-8", "replace"))
                if isinstance(parsed, dict):
                    keys.update(str(k).lower() for k in parsed.keys())
        except Exception:
            pass
    user_like = any(k in USERNAME_KEY_HINTS for k in keys)
    password_like = any(k in PASSWORD_KEY_HINTS for k in keys)
    return user_like, password_like


def resolve_source_ip(config: Any) -> Optional[str]:
    """Resolve the defensible client IP for the current request.

    When ``PROXY_TRUSTED_HOPS`` is 0 (default), forwarded headers are
    ignored entirely and the socket peer address is used, so a client
    cannot forge its own recorded IP.  Werkzeug ``ProxyFix`` has already
    adjusted ``request.remote_addr`` when trusted hops are configured;
    the tested :mod:`honeypot.clientip` defines those semantics.
    """
    hops = config.proxy_trusted_hops
    forwarded = (
        request.headers.get("X-Forwarded-For") if hops > 0 else None
    )
    return resolve_client_ip(request.remote_addr, forwarded, hops)


def record_telemetry(store: Any, config: Any, response: Response) -> None:
    """Build and store the structured telemetry record for this request.

    Storage failures are swallowed (recorded to stderr for the operator)
    so a telemetry problem can never break the HTTP response itself.
    """
    source_ip = resolve_source_ip(config)
    is_login = request.path in LOGIN_ROUTES

    prior_probes = 0
    if is_login and source_ip:
        try:
            prior_probes = store.recent_login_probes_by_ip(source_ip)
        except Exception:
            prior_probes = 0

    user_field, password_field = credential_field_presence()

    classification = classify(
        request.method, request.path,
        prior_login_probes=prior_probes,
    )
    mapping = map_event(
        classification.classification,
        credential_user=user_field,
        credential_pass=password_field,
    )

    synthetic = (
        looks_local(source_ip) if config.mark_local_synthetic else False
    )

    try:
        content_length = response.calculate_content_length()
    except Exception:
        content_length = None

    event: dict[str, Any] = {
        "event_id": generate_event_id(),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source_ip": source_ip,
        "method": request.method,
        "path": request.path,
        "query_string": (request.query_string or b"").decode(
            "utf-8", "replace"),
        "user_agent": request.headers.get("User-Agent", ""),
        "referer": request.headers.get("Referer", ""),
        "host": request.host or "",
        "status_code": response.status_code,
        "response_size": content_length,
        "route_category": classification.route_category,
        "classification": classification.classification,
        "mitre_technique": mapping.technique_id if mapping else None,
        "mitre_rationale": (
            mapping.technique_name if mapping else None
        ),
        "mitre_confidence": mapping.confidence if mapping else None,
        "credential_user": int(user_field),
        "credential_pass": int(password_field),
        "synthetic": int(bool(synthetic)),
        "collector_version": config.collector_version,
    }

    try:
        stored = store.insert(event)
    except Exception as exc:  # unexpected storage failure
        print(f"telemetry error: {exc!r}", file=sys_stderr())
        return
    if not stored:
        print("telemetry insert failed", file=sys_stderr())


def sys_stderr():
    import sys
    return sys.stderr

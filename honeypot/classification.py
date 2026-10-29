"""Behavioral classification of honeypot requests.

Important epistemology (kept explicitly in code and docs):

* Classification is an *inference* about observed behaviour, not a fact.
  A single request to ``/admin`` is a discovery observation, not proof of
  an attack, compromise, or a malicious actor.
* Every category below has a confidence level with documented limitations.
* The functions are pure and reproducible: the same inputs always produce
  the same classification.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Optional


@dataclass(frozen=True)
class Classification:
    """A classification result: observed-fact category plus confidence."""

    classification: str
    confidence: str  # "high" | "medium" | "low"
    route_category: str  # factual routing label, not an inference


# -- Observed-fact route categories (what the request *hit*) ---------------

ROUTE_CATEGORIES: dict[str, str] = {
    "/": "root",
    "/health": "health",
    "/robots.txt": "robots",
    "/admin": "administrative",
    "/admin/login": "administrative",
    "/administrator": "administrative",
    "/wp-admin": "cms",
    "/wp-admin/index.php": "cms",
    "/wp-admin.php": "cms",
    "/wp-login.php": "cms",
    "/xmlrpc.php": "cms",
    "/configuration.php": "cms",
    "/login": "login",
    "/api/login": "login",
    "/api/v1/login": "login",
    "/wp-content/login.php": "cms",
    "/.env": "configuration_file",
    "/config.php": "configuration_file",
    "/configuration.php.bak": "backup",
    "/database.sql": "backup",
    "/backup.zip": "backup",
    "/backup.sql": "backup",
    "/.git/config": "version_control",
    "/.git/HEAD": "version_control",
    "/.git/index": "version_control",
    "/server-status": "server_information",
    "/server-info": "server_information",
    "/phpinfo.php": "server_information",
    "/info.php": "server_information",
    "/api": "api",
    "/api/v1": "api",
    "/console": "service_console",
    "/debug": "service_console",
    "/actuator": "service_console",
    "/actuator/env": "service_console",
    "/manager/html": "administrative",
    "/test": "service_console",
}

_LOG_BUTTON_ROUTES = {
    "/login", "/wp-login.php", "/api/login", "/api/v1/login",
    "/admin/login",
}

# Keys whose *presence* suggests a credential submission attempt.
# Values are never read or stored.
USERNAME_KEY_HINTS = {
    "user", "username", "user_name", "login", "email", "userid",
    "user_id", "auth-user",
}
PASSWORD_KEY_HINTS = {
    "password", "passwd", "pass", "pwd", "userpassword",
    "auth-password", "passwort",
}

REPEATED_PROBE_THRESHOLD = 3  # same-IP login hits within the window


def route_category(path: str) -> str:
    """Factual route category of a request path (no assumptions)."""
    if path in ROUTE_CATEGORIES:
        return ROUTE_CATEGORIES[path]
    lowered = (path or "").lower()
    # Prefix rules for scanner variations the probe table does not list.
    if lowered.startswith("/.git/"):
        return "version_control"
    if lowered.startswith("/wp-"):
        return "cms"
    if lowered.startswith("/phpmyadmin"):
        return "administrative"
    if lowered.startswith("/api/"):
        return "api"
    if lowered.endswith((".sql", ".zip", ".bak", ".7z", ".tar.gz")):
        return "backup"
    if lowered.startswith(("/backup", "/dump", "/db")) and lowered.endswith(
        (".sql", ".zip", ".gz")
    ):
        return "backup"
    if lowered in ("/dashboard", "/dashboard/events", "/export",
                   "/export/events.jsonl", "/export/events.csv",
                   "/favicon.ico"):
        return "self_dashboard"
    if lowered.startswith("/static/"):
        return "asset"
    return "other"


def is_login_route(path: str) -> bool:
    """True when the path is a deceptive login endpoint."""
    return path in _LOG_BUTTON_ROUTES or path == "/wp-login.php"


@lru_cache(maxsize=4096)
def classify(method: str, path: str,
             prior_login_probes: int = 0) -> Optional[Classification]:
    """Classify one observed request.

    ``prior_login_probes`` is the number of login-endpoint hits already
    recorded for this source IP inside the recent window; it is *evidence*
    used only for the repeated-probing category, never an assumption.
    """
    route = route_category(path)
    login_probe = path in _LOG_BUTTON_ROUTES

    if login_probe:
        if prior_login_probes >= REPEATED_PROBE_THRESHOLD:
            return Classification(
                "Repeated authentication probing", "medium", route)
        return Classification("Login endpoint probing", "medium", route)

    mapping = {
        "administrative": ("Administrative interface discovery", "medium"),
        "configuration_file": ("Configuration file probing", "high"),
        "version_control": ("Repository metadata probing", "high"),
        "backup": ("Backup and database file discovery", "high"),
        "cms": ("CMS endpoint discovery", "medium"),
        "server_information": ("Server information discovery", "medium"),
        "api": ("API discovery", "medium"),
        "service_console": ("Service console discovery", "medium"),
    }
    if route in mapping:
        name, confidence = mapping[route]
        return Classification(name, confidence, route)

    if route in ("root", "health", "robots", "asset", "self_dashboard",):
        return Classification("Normal application request", "high", route)

    # Everything else: a request to a route the honeypot does not serve.
    # It may be a scanner placeholder, a mistyped URL, or random noise.
    return Classification("Unclassified suspicious request", "low", route)

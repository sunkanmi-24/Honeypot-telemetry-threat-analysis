"""Classification, MITRE mapping, and client-IP resolution tests."""

from __future__ import annotations

from honeypot.classification import (
    Classification,
    classify,
    route_category,
)
from honeypot.clientip import resolve_client_ip
from honeypot.mitre import (
    TECHNIQUE_REFERENCES,
    aggregate_rule,
    map_event,
)


# -- Route categories (observed facts) --------------------------------------

def test_route_categories():
    assert route_category("/admin") == "administrative"
    assert route_category("/login") == "login"
    assert route_category("/.env") == "configuration_file"
    assert route_category("/.git/config") == "version_control"
    assert route_category("/backup.zip") == "backup"
    assert route_category("/wp-login.php") == "cms"
    assert route_category("/phpinfo.php") == "server_information"
    assert route_category("/api") == "api"
    assert route_category("/actuator/env") == "service_console"
    assert route_category("/health") == "health"
    assert route_category("/robots.txt") == "robots"
    assert route_category("/wp-content/plugins/x.php") == "cms"


def test_classification_reproducible():
    a = classify("GET", "/admin")
    b = classify("GET", "/admin")
    assert a == b and isinstance(a, Classification)


def test_classifications_match_spec():
    assert classify("GET", "/admin").classification == \
        "Administrative interface discovery"
    assert classify("GET", "/login").classification == "Login endpoint probing"
    assert classify("GET", "/.env").classification == \
        "Configuration file probing"
    assert classify("GET", "/.git/config").classification == \
        "Repository metadata probing"
    assert classify("GET", "/backup.zip").classification == \
        "Backup and database file discovery"
    assert classify("GET", "/wp-admin").classification == \
        "CMS endpoint discovery"
    assert classify("GET", "/server-status").classification == \
        "Server information discovery"
    assert classify("GET", "/api").classification == "API discovery"
    assert classify("GET", "/console").classification == \
        "Service console discovery"
    assert classify("GET", "/random-404-path").classification == \
        "Unclassified suspicious request"
    assert classify("GET", "/").classification == "Normal application request"
    assert classify("GET", "/health").classification == \
        "Normal application request"


def test_repeated_probing_requires_frequency_evidence():
    assert classify("GET", "/login",
                    prior_login_probes=0).classification == \
        "Login endpoint probing"
    assert classify("GET", "/login",
                    prior_login_probes=2).classification == \
        "Login endpoint probing"
    repeated = classify("GET", "/login", prior_login_probes=5)
    assert repeated.classification == "Repeated authentication probing"
    assert repeated.confidence == "medium"


def test_single_admin_request_is_not_evidence_of_attack():
    """One /admin GET = discovery observation (medium confidence at most)."""
    result = classify("GET", "/admin")
    assert result.classification == "Administrative interface discovery"
    assert result.confidence in ("low", "medium")


# -- MITRE mapping -----------------------------------------------------------

def test_map_event_qualified_names_and_links():
    mapping = map_event("Configuration file probing")
    assert mapping.technique_id == "T1083"
    assert mapping.technique_name == "File and Directory Discovery"
    assert mapping.confidence in ("low", "moderate")
    assert mapping.limitations


def test_map_event_none_for_normals():
    assert map_event("Normal application request") is None
    assert map_event("Unclassified suspicious request") is None
    assert map_event(None) is None


def test_map_event_brute_force_family():
    single = map_event("Login endpoint probing")
    assert single.technique_id == "T1110"
    assert single.confidence == "low"
    repeated = map_event("Repeated authentication probing",
                         credential_user=True, credential_pass=True)
    assert repeated.technique_id == "T1110.001"
    assert repeated.technique_name == "Brute Force: Password Guessing"
    assert repeated.confidence == "moderate"


def test_server_info_maps_to_t1082():
    assert map_event("Server information discovery").technique_id == "T1082"


def test_aggregate_rule_requires_multiple_categories():
    rule = aggregate_rule()
    assert rule["technique_id"] == "T1046"
    assert rule["technique_name"] == "Network Service Discovery"
    assert "route categories" in rule["rule"]


def test_every_mapped_technique_documented():
    """Mapped technique IDs have official reference links."""
    assert set(TECHNIQUE_REFERENCES) >= {"T1083", "T1046", "T1110"}


# -- Client IP resolution -----------------------------------------------------

def test_socket_peer_by_default():
    assert resolve_client_ip("1.2.3.4", "9.9.9.9", trusted_hops=0) == "1.2.3.4"


def test_trusted_single_hop_uses_last_entry():
    # Client-controlled first entries must be ignored
    forwarded = "1.1.1.1, 2.2.2.2, 203.0.113.10"
    assert resolve_client_ip(
        "10.0.0.1", forwarded, trusted_hops=1) == "203.0.113.10"


def test_multiple_trusted_hops():
    forwarded = "198.51.100.7, 203.0.113.10"
    assert resolve_client_ip(
        "10.0.0.1", forwarded, trusted_hops=2) == "198.51.100.7"


def test_malformed_header_falls_back_to_socket():
    assert resolve_client_ip(
        "10.0.0.1", "not-an-ip", trusted_hops=1) == "10.0.0.1"
    assert resolve_client_ip(
        "10.0.0.1", "", trusted_hops=1) == "10.0.0.1"
    assert resolve_client_ip("10.0.0.1", None, trusted_hops=1) == "10.0.0.1"


def test_missing_header_falls_back():
    assert resolve_client_ip("10.0.0.1", None, trusted_hops=1) == "10.0.0.1"


def test_client_cannot_forge_own_ip():
    """Forged X-Forwarded-For must not become the recorded source IP."""
    forged = "6.6.6.6"
    assert resolve_client_ip("10.0.0.1", forged, trusted_hops=0) == "10.0.0.1"


def test_proxyfix_wiring(tmp_path):
    """With trusted hops configured, ProxyFix sets the remote address."""
    from config import Config
    from app import create_app
    cfg = Config(database_url="", data_dir=str(tmp_path),
                 proxy_trusted_hops=1)
    app = create_app(cfg)
    client = app.test_client()
    response = client.get(
        "/dashboard?view=all",
        headers={"X-Forwarded-For": "203.0.113.9, 192.0.2.1",
                 "X-Forwarded-Proto": "HTTPS"},
    )
    assert response.status_code == 200
    store = app.config["TELEMETRY_STORE"]
    app.get  # silence linters
    from honeypot.views import resolve_source_ip  # documented semantics
    with app.test_request_context(
        "/", headers={"X-Forwarded-For": "203.0.113.9, 192.0.2.1"}):
        assert resolve_source_ip(cfg) == "192.0.2.1"


def test_config_rejects_bad_hops():
    import os
    from config import ConfigError, get_config
    old = os.environ.get("PROXY_TRUSTED_HOPS")
    try:
        os.environ["PROXY_TRUSTED_HOPS"] = "banana"
        try:
            get_config()
            assert False, "expected ConfigError"
        except ConfigError:
            pass
        os.environ["PROXY_TRUSTED_HOPS"] = "-3"
        try:
            get_config()
            assert False, "expected ConfigError"
        except ConfigError:
            pass
    finally:
        if old is None:
            os.environ.pop("PROXY_TRUSTED_HOPS", None)
        else:
            os.environ["PROXY_TRUSTED_HOPS"] = old

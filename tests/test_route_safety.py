"""Safety tests: every deceptive route must behave safely."""

from __future__ import annotations

from honeypot.views import DECEPTIVE_ROUTES, LOGIN_ROUTES

# Routes that legitimately return 404-style JSON bodies.
EXPECTED_404_ROUTES = {
    "/.env", "/.git/config", "/.git/HEAD", "/.git/index",
    "/config.php", "/configuration.php", "/configuration.php.bak",
    "/database.sql", "/backup.zip", "/backup.sql", "/backup.sql.gz",
    "/console", "/debug", "/test",
}


def test_all_deceptive_routes_present(client):
    for route in DECEPTIVE_ROUTES:
        response = client.get(route.path)
        assert response.status_code in (200, 403, 404), (
            f"unexpected status for {route.path}"
        )


def test_never_serves_real_configuration_content(client):
    """File-like probes must return the generic 404 JSON, never content."""
    for path in EXPECTED_404_ROUTES:
        response = client.get(path)
        assert response.status_code == 404, path
        body = response.get_data(as_text=True)
        assert "not_found" in body
        # no plausible secret/file content
        assert "DB_PASSWORD" not in body
        assert "</html>" not in body and "<html" not in body


def test_login_pages_are_static_and_not_connected(client):
    for path in LOGIN_ROUTES:
        response = client.get(path)
        # HTML decoys render 200; JSON login endpoints answer 403 "disabled"
        assert response.status_code in (200, 403), path
        body = response.get_data(as_text=True)
        if response.status_code == 200:
            assert "<form" in body
            assert "Decoy page" in body
        else:
            assert "Authentication is disabled" in body


def test_login_post_rejected(client):
    for path in LOGIN_ROUTES:
        response = client.post(path, data={"username": "x", "password": "y"})
        assert response.status_code == 403, path
        body = response.get_data(as_text=True)
        assert "Authentication is disabled" in body


def test_post_credential_values_nowhere_in_response(client):
    response = client.post(
        "/login", data={"username": "secret-user", "password": "s3cret!"}
    )
    body = response.get_data(as_text=True)
    assert "secret-user" not in body
    assert "s3cret!" not in body


def test_health_discloses_nothing_sensitive(client):
    response = client.get("/health")
    body = response.get_data(as_text=True)
    assert set(body) <= set('{"status": "ok"}')
    assert len(body) < 60


def test_unknown_methods_rejected(client):
    response = client.put("/admin", data={})
    assert response.status_code == 405


def test_robots_txt_is_static(client):
    response = client.get("/robots.txt")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert body.startswith("User-agent: *")
    assert "s3cret" not in body and "password" not in body


def test_malformed_input_does_not_crash(client):
    """Weird, oversized, and binary payloads get safe responses."""
    assert client.get("/login?x=" + "A" * 9000).status_code == 200
    assert client.post(
        "/login", data={"x": "\xff\xfe"}).status_code in (200, 403)
    response = client.post("/api/v1/login", json={"password": "x"})
    assert response.status_code in (200, 403)


def test_no_debug_tracebacks_on_404(client):
    response = client.get("/definitely/not/here")
    assert response.status_code == 404
    assert "Traceback" not in response.get_data(as_text=True)


def test_security_headers_present(client):
    response = client.get("/health")
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("Referrer-Policy") == "no-referrer"

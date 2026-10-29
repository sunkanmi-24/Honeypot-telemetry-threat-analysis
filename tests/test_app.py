from app import create_app
from config import get_config


def test_health_endpoint():
    client = create_app(get_config()).test_client()
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"


def test_home_page_renders():
    client = create_app(get_config()).test_client()
    response = client.get("/")
    assert response.status_code == 200
    assert "Telemetry" in response.get_data(as_text=True)


def test_startup_creates_database():
    """Startup must succeed and create the telemetry database."""
    app = create_app(get_config())
    assert app.config["TELEMETRY_STORE"] is not None

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


def test_supabase_style_database_url_accepted():
    """A Supabase-style managed PostgreSQL URL is accepted by config/store."""
    import os
    from config import get_config
    from honeypot.telemetry import TelemetryStore
    saved = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = (
        "postgresql://postgres:your-password@db.abcdefgh.supabase.co:5432/postgres"
        "?sslmode=require"
    )
    try:
        cfg = get_config()
        assert cfg.database_url.startswith("postgresql://")
        store = TelemetryStore(database_url=cfg.database_url)
        assert store.is_postgres is True
        assert store.db_path == ""
    finally:
        if saved is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = saved

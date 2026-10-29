"""Shared pytest fixtures.

Each test run uses its own temporary SQLite database so tests never touch
the developer's local telemetry, and synthetic marking can be verified.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config  # noqa: E402
from honeypot.telemetry import TelemetryStore  # noqa: E402


@pytest.fixture
def config(tmp_path):
    """Standard test configuration with an isolated storage directory."""
    return Config(
        database_url="",
        data_dir=str(tmp_path),
        proxy_trusted_hops=0,
        mark_local_synthetic=True,
        geoip_db_path="",
    )


@pytest.fixture
def store(config):
    """Initialised telemetry store on an isolated SQLite file."""
    store = TelemetryStore(database_url="", data_dir=config.data_dir)
    store.init_db()
    return store


@pytest.fixture
def app(config):
    """Flask application instance backed by the isolated store."""
    from app import create_app
    return create_app(config)


@pytest.fixture
def client(app):
    """Test HTTP client for the application."""
    return app.test_client()

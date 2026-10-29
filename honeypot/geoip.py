"""Optional, replaceable geographic enrichment.

Rules:

* Disabled by default: with no provider configured, ``country`` is simply
  unknown.  A country is NEVER guessed from an IP address or a hostname.
* No API keys are hardcoded.  The only supported source is a GeoLite2
  MMDB file (documented, permitted for academic use) referenced through
  the ``GEOIP_DB_PATH`` environment variable, requiring the separate
  ``geoip2`` package to be installed.
* Provider failures, rate limits, and missing data degrade gracefully to
  unknown -- they never block telemetry collection or dashboards.
"""

from __future__ import annotations

from typing import Optional


class GeoIPResolver:
    """Look up country names/ISO codes from an optional local MMDB file."""

    def __init__(self, db_path: str = "") -> None:
        self.db_path = (db_path or "").strip()
        self._reader = None
        if self.db_path:
            try:
                import geoip2.database  # optional dependency
                self._reader = geoip2.database.Reader(self.db_path)
            except Exception:  # missing package or unreadable file
                self._reader = None

    @property
    def enabled(self) -> bool:
        return self._reader is not None

    def country(self, source_ip: Optional[str]) -> str:
        """Resolve an IP to a country name, or 'unknown' when not available.

        Private, loopback, and unparseable addresses are always unknown.
        """
        if self._reader is None or not source_ip:
            return "unknown"
        try:
            import ipaddress
            addr = ipaddress.ip_address(source_ip)
            if addr.is_private or addr.is_loopback or addr.is_unspecified:
                return "unknown"
            response = self._reader.country(str(addr))
            name = getattr(response.country, "name", None)
            return name or "unknown"
        except Exception:
            # Library error, unsupported address family, or address not
            # present in the database: degrade to unknown.
            return "unknown"

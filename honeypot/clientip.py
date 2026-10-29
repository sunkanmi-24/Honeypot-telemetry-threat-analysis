"""Trusted reverse-proxy client IP resolution.

Rules (see docs/DEPLOYMENT.md for the exact deployment configuration):

* By default ONLY the socket peer address (``request.remote_addr``) is
  trusted.  A client cannot choose its own recorded IP.
* Forwarded headers are trusted only when the number of reverse proxies
  between the Internet and this application is verified and configured
  through ``PROXY_TRUSTED_HOPS``.
* The semantics mirror maintained Werkzeug ``ProxyFix`` middleware, which
  is what the application actually uses; :func:`resolve_client_ip` is a
  pure, testable function used by the tests and documentation.
"""

from __future__ import annotations

import ipaddress
from typing import Optional


def resolve_client_ip(
    remote_addr: Optional[str],
    forwarded_for: Optional[str] = None,
    trusted_hops: int = 0,
) -> Optional[str]:
    """Return the defensible client IP for a proxy chain.

    :param remote_addr: socket peer address (always available).
    :param forwarded_for: raw ``X-Forwarded-For`` header value or None.
    :param trusted_hops: verified number of trusted proxies in front of
        the application. ``0`` means "never trust forwarded headers".
    :return: the best-supported client address, or None if unknown.

    Malformed entries in the header are ignored; if the resulting chain
    is unusable, the socket peer address is returned (safe fallback).
    """
    if trusted_hops <= 0:
        return remote_addr
    if not forwarded_for:
        return remote_addr

    parts = [part.strip() for part in forwarded_for.split(",")
             if part.strip()]
    # Keep syntactically plausible addresses only.
    valid = []
    for part in parts:
        try:
            ipaddress.ip_address(part)
            valid.append(part)
        except ValueError:
            return remote_addr  # malformed header: do not trust it
    if not valid:
        return remote_addr

    hops = min(trusted_hops, len(valid))
    # With 1 trusted proxy the LAST entry is the client as that proxy saw
    # it; earlier entries were client-controlled and must be ignored.
    return valid[-hops]

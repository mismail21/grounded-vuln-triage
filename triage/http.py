"""Small HTTP helper with an on-disk JSON cache and per-host rate limiting.

Caching keeps evaluation runs reproducible and fast, and keeps us inside the
NVD public rate limit (5 requests / 30 s without an API key).
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

CACHE_DIR = Path(os.environ.get("TRIAGE_CACHE_DIR", Path.home() / ".cache" / "grounded-vuln-triage"))
DEFAULT_TTL = int(os.environ.get("TRIAGE_CACHE_TTL", 24 * 3600))
USER_AGENT = "grounded-vuln-triage/0.1 (+https://github.com/mismail21/grounded-vuln-triage)"

# Minimum seconds between requests to a host.
_MIN_INTERVAL = {
    "services.nvd.nist.gov": 1.0 if os.environ.get("NVD_API_KEY") else 6.2,
}
_last_call: dict[str, float] = {}
_host_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()

_client: httpx.Client | None = None


class FetchError(RuntimeError):
    pass


def _get_client() -> httpx.Client:
    global _client
    if _client is None:
        _client = httpx.Client(timeout=30.0, headers={"User-Agent": USER_AGENT}, follow_redirects=True)
    return _client


def _cache_path(method: str, url: str, body: Any) -> Path:
    key = json.dumps([method, url, body], sort_keys=True)
    digest = hashlib.sha256(key.encode()).hexdigest()
    return CACHE_DIR / digest[:2] / f"{digest}.json"


def _throttle(host: str) -> None:
    interval = _MIN_INTERVAL.get(host)
    if not interval:
        return
    with _locks_guard:
        lock = _host_locks.setdefault(host, threading.Lock())
    with lock:
        wait = _last_call.get(host, 0) + interval - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        _last_call[host] = time.monotonic()


def fetch_json(
    url: str,
    *,
    method: str = "GET",
    body: Any = None,
    headers: dict[str, str] | None = None,
    ttl: int = DEFAULT_TTL,
    retries: int = 3,
) -> Any:
    """Fetch a URL and return parsed JSON, using the disk cache when fresh."""
    path = _cache_path(method, url, body)
    if ttl > 0 and path.exists() and time.time() - path.stat().st_mtime < ttl:
        try:
            return json.loads(path.read_text())
        except json.JSONDecodeError:
            path.unlink(missing_ok=True)

    host = urlparse(url).netloc
    last_err: Exception | None = None
    for attempt in range(retries):
        _throttle(host)
        try:
            resp = _get_client().request(method, url, json=body, headers=headers)
            if resp.status_code in (403, 429, 500, 502, 503, 504):
                raise FetchError(f"{host} returned HTTP {resp.status_code}")
            if resp.status_code == 404:
                data: Any = None
            else:
                resp.raise_for_status()
                data = resp.json()
            if ttl > 0:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(data))
            return data
        except (httpx.HTTPError, FetchError, json.JSONDecodeError) as e:
            last_err = e
            time.sleep(2 * (attempt + 1) + (6 if host == "services.nvd.nist.gov" else 0))
    raise FetchError(f"GET {url} failed after {retries} attempts: {last_err}")

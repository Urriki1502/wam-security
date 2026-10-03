"""Read-only live probes for official/public WAM monitoring endpoints."""

from __future__ import annotations

from dataclasses import dataclass
import json
import socket
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class Probe:
    ok: bool
    status: int | None
    data: Any
    error: str | None


def fetch_json(url: str, *, timeout: float = 8.0) -> Probe:
    req = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "wam-security-v7/0.7",
        },
        method="GET",
    )
    try:
        with urlopen(req, timeout=timeout) as response:
            raw = response.read(2 * 1024 * 1024)
            status = getattr(response, "status", 200)
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            return Probe(False, status, None, f"invalid JSON: {exc}")
        return Probe(200 <= status < 300, status, data, None)
    except HTTPError as exc:
        body = None
        try:
            body = json.loads(exc.read(64 * 1024).decode("utf-8"))
        except Exception:
            pass
        return Probe(False, exc.code, body, f"HTTP {exc.code}")
    except (URLError, socket.timeout, TimeoutError, OSError) as exc:
        return Probe(False, None, None, str(exc))


def get_path(value: Any, *path: str) -> Any:
    cur = value
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur

"""Immutable dependency identity lock helpers."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class LockedIdentity:
    name: str
    repository: str
    ref: str
    commit: str
    kind: str

    def validate(self) -> None:
        if len(self.commit) != 40 or any(c not in "0123456789abcdefABCDEF" for c in self.commit):
            raise ValueError(f"{self.name}: commit must be a 40-hex SHA")
        if not self.repository.startswith("https://github.com/"):
            raise ValueError(f"{self.name}: repository must be an https://github.com URL")
        if not self.ref.startswith("refs/"):
            raise ValueError(f"{self.name}: ref must be a full refs/... name")


def load_identity_lock(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("schema") != "wam-security-supply-chain-lock/v1":
        raise ValueError("unsupported supply-chain lock schema")

    target = data.get("target_wam", {})
    commit = target.get("commit", "")
    if len(commit) != 40 or any(c not in "0123456789abcdefABCDEF" for c in commit):
        raise ValueError("target_wam.commit must be a full SHA")

    entries = data.get("identities", [])
    if not entries:
        raise ValueError("identity lock has no entries")

    seen: set[str] = set()
    for raw in entries:
        item = LockedIdentity(**raw)
        item.validate()
        if item.name in seen:
            raise ValueError(f"duplicate identity name: {item.name}")
        seen.add(item.name)
    return data


def locked_identities(data: dict[str, Any]) -> list[LockedIdentity]:
    return [LockedIdentity(**raw) for raw in data["identities"]]


def identity_map(data: dict[str, Any]) -> dict[str, str]:
    return {entry.name: entry.commit.lower() for entry in locked_identities(data)}

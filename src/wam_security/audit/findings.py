"""Finding model shared by source and workflow audits."""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Finding:
    finding_id: str
    severity: str
    confidence: str
    title: str
    path: str
    evidence: str
    impact: str
    recommendation: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)

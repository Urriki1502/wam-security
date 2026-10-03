"""SLSA-style provenance and SPDX SBOM generation using only stdlib."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from typing import Iterable, Mapping

from wam_security.supplychain.identities import locked_identities


def sha256_file(path: str | Path) -> str:
    h = sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def artifact_subjects(paths: Iterable[str | Path], base: str | Path | None = None) -> list[dict]:
    base_path = Path(base).resolve() if base is not None else None
    subjects = []
    for item in sorted((Path(p) for p in paths), key=lambda p: p.as_posix()):
        resolved = item.resolve()
        name = resolved.relative_to(base_path).as_posix() if base_path is not None else item.name
        subjects.append({
            "name": name,
            "digest": {"sha256": sha256_file(resolved)},
            "size": resolved.stat().st_size,
        })
    return subjects


def create_provenance(
    *,
    source_repository: str,
    source_commit: str,
    lock: Mapping,
    artifacts: Iterable[str | Path],
    artifact_base: str | Path | None = None,
    builder_id: str = "https://github.com/Urriki1502/wam-security/actions",
    build_type: str = "https://wamcoin.org/security/buildtypes/release-assurance/v1",
    parameters: Mapping | None = None,
) -> dict:
    deps = []
    for entry in locked_identities(dict(lock)):
        deps.append({
            "uri": f"{entry.repository}@{entry.ref}",
            "digest": {"gitCommit": entry.commit.lower()},
            "name": entry.name,
            "kind": entry.kind,
        })

    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": artifact_subjects(artifacts, artifact_base),
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": build_type,
                "externalParameters": dict(sorted((parameters or {}).items())),
                "internalParameters": {},
                "resolvedDependencies": deps,
            },
            "runDetails": {
                "builder": {"id": builder_id},
                "metadata": {
                    "source": {
                        "repository": source_repository,
                        "commit": source_commit.lower(),
                    }
                },
            },
        },
    }


def provenance_digest(statement: Mapping) -> str:
    return sha256(canonical_json_bytes(statement)).hexdigest()


def verify_subjects(statement: Mapping, base: str | Path) -> None:
    root = Path(base)
    seen: set[str] = set()
    for subject in statement.get("subject", []):
        name = subject["name"]
        if name in seen:
            raise AssertionError(f"duplicate provenance subject: {name}")
        seen.add(name)
        path = root / name
        if not path.is_file():
            raise AssertionError(f"provenance subject missing: {name}")
        expected = subject["digest"]["sha256"]
        actual = sha256_file(path)
        if actual != expected:
            raise AssertionError(f"digest mismatch for {name}: {actual} != {expected}")
        if path.stat().st_size != subject.get("size"):
            raise AssertionError(f"size mismatch for {name}")


def create_spdx_sbom(
    *,
    document_name: str,
    namespace: str,
    wam_repository: str,
    wam_commit: str,
    lock: Mapping,
    created: str = "2026-10-03T00:00:00Z",
) -> dict:
    packages = [{
        "name": "wam-coin",
        "SPDXID": "SPDXRef-Package-wam-coin",
        "versionInfo": wam_commit.lower(),
        "downloadLocation": f"{wam_repository}@{wam_commit.lower()}",
        "filesAnalyzed": False,
    }]
    relationships = []

    for index, entry in enumerate(locked_identities(dict(lock)), start=1):
        spdx_id = f"SPDXRef-Package-dependency-{index}"
        packages.append({
            "name": entry.name,
            "SPDXID": spdx_id,
            "versionInfo": entry.ref,
            "downloadLocation": f"{entry.repository}@{entry.commit.lower()}",
            "filesAnalyzed": False,
            "externalRefs": [{
                "referenceCategory": "OTHER",
                "referenceType": "vcs",
                "referenceLocator": f"git+{entry.repository}@{entry.commit.lower()}",
            }],
        })
        relationships.append({
            "spdxElementId": "SPDXRef-Package-wam-coin",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": spdx_id,
        })

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": document_name,
        "documentNamespace": namespace,
        "creationInfo": {
            "created": created,
            "creators": ["Tool: wam-security-v5"],
        },
        "packages": packages,
        "relationships": relationships,
    }

"""Release state machine used for V6 formal/exhaustive assurance."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Iterable


@dataclass(frozen=True)
class ReleaseState:
    source_locked: bool = False
    deps_locked: bool = False
    built: bool = False
    provenance: bool = False
    sbom: bool = False
    reviews: int = 0
    approved: bool = False
    published: bool = False


def initial() -> ReleaseState:
    return ReleaseState()


def successors(state: ReleaseState) -> Iterable[tuple[str, ReleaseState]]:
    if not state.source_locked:
        yield "lock-source", replace(state, source_locked=True)

    if not state.deps_locked:
        yield "lock-dependencies", replace(state, deps_locked=True)

    if state.source_locked and state.deps_locked and not state.built:
        yield "build-readonly", replace(state, built=True)

    if state.built and not state.provenance:
        yield "create-provenance", replace(state, provenance=True)

    if state.built and not state.sbom:
        yield "create-sbom", replace(state, sbom=True)

    if state.built and state.reviews < 2:
        yield "independent-review", replace(state, reviews=state.reviews + 1)

    if (
        state.built
        and state.provenance
        and state.sbom
        and state.reviews >= 2
        and not state.approved
    ):
        yield "approve", replace(state, approved=True)

    if state.approved and not state.published:
        yield "publish", replace(state, published=True)

    if state.published:
        yield "stable", state


def invariants() -> dict[str, callable]:
    return {
        "ReviewBound": lambda s: 0 <= s.reviews <= 2,
        "BuildUsesLockedInputs": lambda s: (
            not s.built or (s.source_locked and s.deps_locked)
        ),
        "ApprovalRequiresEvidence": lambda s: (
            not s.approved
            or (
                s.built
                and s.provenance
                and s.sbom
                and s.reviews >= 2
                and s.source_locked
                and s.deps_locked
            )
        ),
        "PublishRequiresTwoReviews": lambda s: (
            not s.published or s.reviews >= 2
        ),
        "PublishRequiresProvenance": lambda s: (
            not s.published or s.provenance
        ),
        "PublishRequiresSBOM": lambda s: (
            not s.published or s.sbom
        ),
        "PublishRequiresLockedInputs": lambda s: (
            not s.published or (s.source_locked and s.deps_locked)
        ),
    }


def mutant_one_review_publish(state: ReleaseState) -> Iterable[tuple[str, ReleaseState]]:
    yield from successors(state)
    if (
        state.built
        and state.provenance
        and state.sbom
        and state.reviews == 1
        and not state.published
    ):
        yield "MUTANT-publish-one-review", replace(
            state, published=True
        )


def mutant_publish_without_provenance(state: ReleaseState) -> Iterable[tuple[str, ReleaseState]]:
    yield from successors(state)
    if state.built and state.reviews >= 2 and not state.provenance and not state.published:
        yield "MUTANT-publish-no-provenance", replace(
            state, approved=True, published=True
        )

---- MODULE ReleaseSafety ----
EXTENDS Naturals

VARIABLES sourceLocked, depsLocked, built, provenance, sbom, reviews, approved, published

vars == <<sourceLocked, depsLocked, built, provenance, sbom, reviews, approved, published>>

Init ==
    /\ sourceLocked = FALSE
    /\ depsLocked = FALSE
    /\ built = FALSE
    /\ provenance = FALSE
    /\ sbom = FALSE
    /\ reviews = 0
    /\ approved = FALSE
    /\ published = FALSE

LockSource ==
    /\ ~sourceLocked
    /\ sourceLocked' = TRUE
    /\ UNCHANGED <<depsLocked, built, provenance, sbom, reviews, approved, published>>

LockDeps ==
    /\ ~depsLocked
    /\ depsLocked' = TRUE
    /\ UNCHANGED <<sourceLocked, built, provenance, sbom, reviews, approved, published>>

Build ==
    /\ sourceLocked
    /\ depsLocked
    /\ ~built
    /\ built' = TRUE
    /\ UNCHANGED <<sourceLocked, depsLocked, provenance, sbom, reviews, approved, published>>

Provenance ==
    /\ built
    /\ ~provenance
    /\ provenance' = TRUE
    /\ UNCHANGED <<sourceLocked, depsLocked, built, sbom, reviews, approved, published>>

SBOM ==
    /\ built
    /\ ~sbom
    /\ sbom' = TRUE
    /\ UNCHANGED <<sourceLocked, depsLocked, built, provenance, reviews, approved, published>>

Review ==
    /\ built
    /\ reviews < 2
    /\ reviews' = reviews + 1
    /\ UNCHANGED <<sourceLocked, depsLocked, built, provenance, sbom, approved, published>>

Approve ==
    /\ built
    /\ provenance
    /\ sbom
    /\ reviews >= 2
    /\ ~approved
    /\ approved' = TRUE
    /\ UNCHANGED <<sourceLocked, depsLocked, built, provenance, sbom, reviews, published>>

Publish ==
    /\ approved
    /\ ~published
    /\ published' = TRUE
    /\ UNCHANGED <<sourceLocked, depsLocked, built, provenance, sbom, reviews, approved>>

Stable ==
    /\ published
    /\ UNCHANGED vars

Next == LockSource \/ LockDeps \/ Build \/ Provenance \/ SBOM \/ Review \/ Approve \/ Publish \/ Stable

Spec == Init /\ [][Next]_vars

ReviewBound == reviews \in 0..2
BuildUsesLockedInputs == built => sourceLocked /\ depsLocked
ApprovalRequiresEvidence ==
    approved => built /\ provenance /\ sbom /\ reviews >= 2 /\ sourceLocked /\ depsLocked
PublishRequiresTwoReviews == published => reviews >= 2
PublishRequiresProvenance == published => provenance
PublishRequiresSBOM == published => sbom
PublishRequiresLockedInputs == published => sourceLocked /\ depsLocked

=============================================================================

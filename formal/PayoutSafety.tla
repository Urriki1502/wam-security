---- MODULE PayoutSafety ----
EXTENDS Naturals

VARIABLES phase, identity, identitiesCreated, seen, commits, attempted

vars == <<phase, identity, identitiesCreated, seen, commits, attempted>>

Phases == {"idle", "reserved", "signed", "unknown", "seen", "committed"}

Init ==
    /\ phase = "idle"
    /\ identity = 0
    /\ identitiesCreated = 0
    /\ seen = FALSE
    /\ commits = 0
    /\ attempted = FALSE

Reserve ==
    /\ phase = "idle"
    /\ phase' = "reserved"
    /\ UNCHANGED <<identity, identitiesCreated, seen, commits, attempted>>

Sign ==
    /\ phase = "reserved"
    /\ phase' = "signed"
    /\ identity' = 1
    /\ identitiesCreated' = 1
    /\ UNCHANGED <<seen, commits, attempted>>

BroadcastAck ==
    /\ phase \in {"signed", "unknown"}
    /\ phase' = "seen"
    /\ seen' = TRUE
    /\ attempted' = TRUE
    /\ UNCHANGED <<identity, identitiesCreated, commits>>

TimeoutAccepted ==
    /\ phase \in {"signed", "unknown"}
    /\ phase' = "unknown"
    /\ seen' = TRUE
    /\ attempted' = TRUE
    /\ UNCHANGED <<identity, identitiesCreated, commits>>

TimeoutDropped ==
    /\ phase \in {"signed", "unknown"}
    /\ phase' = "unknown"
    /\ attempted' = TRUE
    /\ UNCHANGED <<identity, identitiesCreated, seen, commits>>

ReconcileSeen ==
    /\ phase = "unknown"
    /\ seen
    /\ phase' = "seen"
    /\ UNCHANGED <<identity, identitiesCreated, seen, commits, attempted>>

RetrySame ==
    /\ phase = "unknown"
    /\ ~seen
    /\ UNCHANGED vars

Commit ==
    /\ phase = "seen"
    /\ phase' = "committed"
    /\ commits' = commits + 1
    /\ UNCHANGED <<identity, identitiesCreated, seen, attempted>>

Crash ==
    /\ phase \in {"reserved", "signed", "unknown", "seen"}
    /\ UNCHANGED vars

Stable ==
    /\ phase = "committed"
    /\ UNCHANGED vars

Next ==
    Reserve \/ Sign \/ BroadcastAck \/ TimeoutAccepted \/ TimeoutDropped \/
    ReconcileSeen \/ RetrySame \/ Commit \/ Crash \/ Stable

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ phase \in Phases
    /\ identity \in {0, 1}
    /\ identitiesCreated \in Nat
    /\ commits \in Nat
    /\ seen \in BOOLEAN
    /\ attempted \in BOOLEAN

AtMostOneIdentity == identitiesCreated <= 1
AtMostOneCommit == commits <= 1
UnknownRetainsIdentity == phase = "unknown" => identity = 1 /\ identitiesCreated = 1
CommitOnlyAfterSeen == commits = 1 => phase = "committed" /\ seen
AttemptNeverForgetsIdentity == attempted => identity = 1

=============================================================================

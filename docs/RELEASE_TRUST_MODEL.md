# WAM release trust and first-contact verification

## Locked target

- WAM repository: `wamcoin-core-dev/wam-coin`
- reviewed commit: `bd71b0bd645286a3867dad6b2bfefd911ec8a5b6`
- release fixture: published v0.1.11 assets
- scope: verification and trust-root design only; no production release or DNS mutation

## Current verification path

A fresh user is told to obtain `SHA256SUMS`, `SHA256SUMS.asc`, `verify_release.sh`,
`SIGNING-KEY.asc`, and one release artifact. The verifier imports the public key into
a throwaway GnuPG home, verifies the detached signature over `SHA256SUMS`, extracts
`VALIDSIG`, compares that fingerprint with its compiled expectation, then verifies
that at least one downloaded artifact matches the signed checksum list.

The regression harness exercises this exact first-contact shape with an otherwise
empty keyring. It requires all of the following to fail closed: an altered artifact,
an altered signed manifest, and a replacement public key plus a cryptographically
valid signature from that replacement key.

## Trust-root observation

`SECURITY.md` states that the signing fingerprint is published there and "in no\nother place". At the locked commit that statement is not literally true: the same\nfingerprint also appears in release/signing scripts, generated site material, release\nnotes and announcement text. The verifier necessarily embeds it in `EXPECT` so that\nimporting a substituted `SIGNING-KEY.asc` is not circular trust. These repository\ncopies are useful consistency pins, but none is an independent trust anchor: one\nrepository/distribution compromise can replace the repository text, key file and\nverifier together.

The problem is therefore not signature verification. The cryptographic path already
checks the correct things. The missing property is an independently administered
first-contact key-identity anchor.

## Recommended independent anchor

Use the already-reserved `wamcoin.net` domain as a second administrative trust root,
separate from the repository and `wamcoin.org` distribution path. `CHANNELS.txt`
already documents that `wamcoin.net` is held at a different company/account/address.
Publish a DNSSEC-authenticated TXT record such as:

```text
_release-key.wamcoin.net TXT "v=1;fpr=4BD4A8D3AFD43F5CBCB500E23798462FE00ADBA4;uid=WAM Coin release signing"
```

This is a design recommendation, not a change made by this branch. Production DNS,
registrar configuration and release automation remain maintainer-controlled.

For first contact, verification should require agreement between the repository
fingerprint and the DNSSEC-authenticated independent anchor. A mismatch is fatal.
If the independent anchor cannot be authenticated, automated first-contact trust
should stop rather than silently fall back to whatever key came with the download.
Returning users may additionally retain a local previously accepted fingerprint and
warn on any drift.

This does not weaken the anti-impersonation model: social media, chat, email and
unsigned mirrors remain non-authoritative. It adds a second failure domain instead
of creating more informal places from which a fingerprint may be copied.

## Key rotation

Normal rotation should be cross-signed by the old release key, published in the
repository, and independently updated under the DNSSEC anchor before new releases
are accepted. If the old key is lost or revoked, rotation requires an explicit
recovery ceremony documented in both trust roots; there must be no automatic
"accept the new key because the repository says so" path.

## Regression closure

`run_release_trust_regression.py` records only synthetic/adversarial verification
results and the public fingerprint. It never handles a release private key. CI may
read WAM's own public release assets; no third-party infrastructure is probed.

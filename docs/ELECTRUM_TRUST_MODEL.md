# WAM Electrum trust boundary

## Two separate threats

### 1. Endpoint/server impersonation

The locked WAM health checker verifies TLS using the platform trust store and SNI,
queries `server.version`, obtains the chain genesis through `server.features`, obtains
the advertised height through `blockchain.headers.subscribe`, and can compare height
and genesis against a WAM node. These checks answer whether the endpoint is the
intended TLS name, is speaking Electrum, identifies the intended chain and is not
obviously stale.

### 2. Accepted server returns incomplete or misleading wallet state

That is a different problem. A valid merkle branch proves that a transaction the
server *did return* is committed under a particular block merkle root. It does not
prove that the server returned every transaction relevant to a wallet. An omitted
history entry has no proof object to reject.

## What current WAM-owned software actually receives

There is an important architecture distinction. The current first-party WAM Silent
Wallet does **not** receive wallet state from Electrum; it uses WAM SDK against a local
validating WAM Core node. WAM Core owns the ElectrumX deployment/configuration and
publishes Electrum endpoints for ecosystem clients such as the Komodo integration.
The downstream third-party wallet implementation is not WAM-owned code and is not
asserted here.

Within WAM-owned code, `scripts/check_electrum.py` receives exactly these health data:

- `server.version` response;
- `server.features.genesis_hash`;
- `blockchain.headers.subscribe.height`;
- TLS certificate identity on SSL endpoints.

It does not request wallet scripthash history, listunspent state, wallet transactions
or merkle proofs, so it cannot make a completeness claim about a wallet balance.

## Omission model

For a light client that does use standard Electrum wallet methods, the trust split is:

- returned transaction + valid merkle proof: inclusion can be independently checked
  against a trusted header;
- returned history/listunspent: internally consistent data may still be incomplete;
- transaction never disclosed by the server: single-server merkle verification cannot
  detect the omission;
- two accepted servers: disagreement reveals a problem but does not by itself identify
  which server is truthful;
- validating node/block-derived expected history: provides an authoritative local
  oracle for the regression harness and detects the omitted transaction.

`src/wam_security/electrum/trust.py` models these properties with local synthetic
fixtures only. No public Electrum server is contacted or impersonated.

## Practical consequence

Endpoint authentication and response inclusion proofs should not be described as
"the server tells the complete wallet truth". Any future first-party light-wallet
mode must either accept server completeness as a trust assumption, cross-check
independent sources with a stated ambiguity policy, or derive the relevant history
from a validating node/block source. The existing Silent Payments architecture takes
the last approach by trusting local Core for chain truth.

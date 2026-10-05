#!/usr/bin/env python3
"""Apply the block-spool recovery fix candidate to exact WAM bb6d521.

This mutates only a local checkout used by regression CI. It refuses any other
base revision and uses exact source anchors so drift cannot silently produce a
different patch.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import subprocess

BASE = "bb6d5214f2f5de3b7464587cc1b2949d221dcd18"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one source anchor, found {count}")
    return text.replace(old, new, 1)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("wam_root", type=Path)
    args = ap.parse_args()
    root = args.wam_root.resolve()
    head = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip()
    if head != BASE:
        raise SystemExit(f"candidate requires {BASE}, got {head}")

    repo = Path(__file__).resolve().parents[1]
    source = repo / "reference/upstream_patch/block_spool_recovery/blockRecovery.js"
    target = root / "pool/lib/blockRecovery.js"
    shutil.copy2(source, target)

    job_path = root / "pool/lib/jobManager.js"
    job = job_path.read_text(encoding="utf-8")

    job = replace_once(
        job,
        "        this._record = async () => {};\n",
        """        this._record = async () => {};
        // Production server.js injects the durable block-recovery hooks. Tests
        // and embedders without them retain the pre-candidate behavior.
        this._prepareBlockRecovery = null;
        this._recordCandidateShare = null;
        this._commitBlockRecovery = null;
        this._settleBlockRecovery = null;
""",
        "job-manager hooks",
    )

    old_record = """            try {
                await this._record(share);
            } catch (err) {
                this.log.error(`could not record a share from ${workerName}: ` +
                               `${err.message}`);
                return this._reject(REJECT.UNAVAILABLE, workerName);
            }

            credited = true;
            this.emit('share', share);

            // And the block's payout accounting last of all, so the snapshot
            // it takes of the round already contains the share that found it.
            if (isBlockCandidate && share.blockAccepted) {
                this.emit('block', share);
            }
            return { valid: true, share };
"""
    new_record = """            try {
                if (isBlockCandidate && share.blockRecovery &&
                    this._recordCandidateShare) {
                    await this._recordCandidateShare(share.blockRecovery);
                } else {
                    await this._record(share);
                }
            } catch (err) {
                this.log.error(`could not record a share from ${workerName}: ` +
                               `${err.message}`);
                return this._reject(REJECT.UNAVAILABLE, workerName);
            }

            credited = true;
            this.emit('share', share);

            // The recovery hook owns durable block accounting when configured.
            // It uses the snapshot written before submission and removes the
            // spool only in the same atomic transition that records the block.
            if (isBlockCandidate && share.blockAccepted) {
                if (share.blockRecovery && this._commitBlockRecovery) {
                    try {
                        await this._commitBlockRecovery(share.blockRecovery);
                        this.emit('block', share);
                    } catch (err) {
                        this.log.error(`block ${share.height} is accepted but its ` +
                                       `accounting is still pending: ${err.message}`);
                    }
                } else {
                    this.emit('block', share);
                }
            } else if (isBlockCandidate && share.blockRecovery &&
                       share.blockFinalRefusal && this._settleBlockRecovery) {
                try {
                    await this._settleBlockRecovery(
                        share.blockRecovery, 'refused',
                        (share.rejectReasons || []).join(' | '));
                } catch (err) {
                    this.log.error(`could not settle refused block ${share.height}: ` +
                                   `${err.message}`);
                }
            }
            return { valid: true, share };
"""
    job = replace_once(job, old_record, new_record, "candidate share accounting")

    start = job.index("    async drainSpool() {")
    end = job.index("    async _submitBlock(", start)
    new_drain = """    async drainSpool() {
        if (!this._spoolStore) return { offered: 0, settled: 0 };
        let entries;
        try {
            entries = await this._spoolStore.all();
        } catch (err) {
            this.log.error(`could not read the block spool: ${err.message}`);
            return { offered: 0, settled: 0 };
        }

        let settled = 0;
        for (const e of entries) {
            let result;
            try {
                result = await this.daemon.submitBlock(e.hex);
            } catch (err) {
                this.log.warn(`spooled block ${e.height} could not be offered: ` +
                              `${err.message}`);
                continue;
            }

            if (result.accepted) {
                if (this._commitBlockRecovery && e.blockRecord) {
                    try {
                        const applied = await this._commitBlockRecovery(e);
                        if (applied) this.stats.blocksFound++;
                        settled++;
                    } catch (err) {
                        this.log.error(`spooled block ${e.height} was accepted but ` +
                                       `accounting remains pending: ${err.message}`);
                    }
                } else {
                    this.stats.blocksFound++;
                    await this._unspool(e.hash);
                    settled++;
                    this.emit('block', { height: e.height, blockHash: e.hash,
                                         worker: e.worker, blockAccepted: true,
                                         fromSpool: true });
                }
                continue;
            }

            const looked = result.results.some((r) => r.ok || r.error === null);
            const duplicateLike = result.reasons.some((r) =>
                /(^|: )(duplicate|inconclusive|duplicate-inconclusive)$/i
                    .test(String(r)));

            if (duplicateLike && this._commitBlockRecovery &&
                this._settleBlockRecovery && e.blockRecord) {
                let chainState = 'unknown';
                try {
                    const block = await this.daemon.getBlock(e.hash, 1);
                    if (block && Number.isInteger(block.confirmations)) {
                        chainState = block.confirmations >= 0 ? 'active' : 'inactive';
                    }
                } catch {
                    chainState = 'unknown';
                }

                if (chainState === 'active') {
                    try {
                        const applied = await this._commitBlockRecovery(e);
                        if (applied) this.stats.blocksFound++;
                        settled++;
                    } catch (err) {
                        this.log.error(`spooled block ${e.height} is active but ` +
                                       `accounting remains pending: ${err.message}`);
                    }
                } else if (chainState === 'inactive') {
                    await this._settleBlockRecovery(
                        e, 'lost-race', result.reasons.join(' | '));
                    settled++;
                }
                continue;
            }

            if (result.reasons.some((r) => /duplicate|inconclusive/i.test(String(r)))) {
                this.log.info(`spooled block ${e.height} is already on the node`);
                await this._unspool(e.hash);
                settled++;
            } else if (looked) {
                if (this._settleBlockRecovery && e.blockRecord) {
                    await this._settleBlockRecovery(
                        e, 'refused', result.reasons.join(' | '));
                } else {
                    await this._unspool(e.hash, result.reasons.join(' | '));
                }
                settled++;
            }
            // Nobody answered, or duplicate-like status could not be tied to
            // the active chain: keep the exact bytes and accounting snapshot.
        }
        return { offered: entries.length, settled };
    }

"""
    job = job[:start] + new_drain + job[end:]

    old_spool = """        const spooled = { height: job.height, hash: blockHash, hex: blockHex,
                          worker: share.worker, foundAt: Date.now() };
        try {
            await this._spool(spooled);
        } catch (err) {
            this.log.error(`could not spool block ${job.height} before ` +
                           `submitting it (${err.message}); submitting anyway`);
        }

        let result = await this.daemon.submitBlock(blockHex);
"""
    new_spool = """        let spooled = { height: job.height, hash: blockHash, hex: blockHex,
                        worker: share.worker, foundAt: share.time };
        if (this._prepareBlockRecovery) {
            spooled = await this._prepareBlockRecovery(share, blockHex, blockHash);
        }
        share.blockRecovery = spooled;
        try {
            await this._spool(spooled);
        } catch (err) {
            this.log.error(`could not spool block ${job.height} before ` +
                           `submitting it (${err.message})`);
            // A configured durable store is a safety boundary. If it failed,
            // do not create a block whose recovery state exists only in RAM.
            if (this._spoolStore) throw err;
        }

        let result = await this.daemon.submitBlock(blockHex);
"""
    job = replace_once(job, old_spool, new_spool, "durability barrier")

    old_accept_unspool = """            // It is on the chain; the spool has nothing left to protect.
            this._unspool(blockHash).catch((e) =>
                this.log.warn(`block ${job.height} is accepted but could not be ` +
                              `removed from the spool: ${e.message}`));
"""
    new_accept_unspool = """            // With the durable recovery hook the spool is removed only by
            // the atomic economic commit after processShare records the winner.
            if (!this._commitBlockRecovery) {
                this._unspool(blockHash).catch((e) =>
                    this.log.warn(`block ${job.height} is accepted but could not be ` +
                                  `removed from the spool: ${e.message}`));
            }
"""
    job = replace_once(
        job, old_accept_unspool, new_accept_unspool, "accepted spool lifetime"
    )

    old_refusal = """            const looked = result.results.some((r) => r.ok || r.error === null);
            if (looked) {
                this.log.error(`    the block is kept for inspection but will not ` +
                               `be retried: the node read it and refused it`);
                this._unspool(blockHash, result.reasons.join(' | ')).catch(() => {});
            } else {
                this.log.error(`    NOT discarded -- it is spooled and will be ` +
                               `offered again when a node answers`);
            }
"""
    new_refusal = """            const looked = result.results.some((r) => r.ok || r.error === null);
            const duplicateLike = result.reasons.some((r) =>
                /duplicate|inconclusive/i.test(String(r)));
            if (looked && !duplicateLike) {
                share.blockFinalRefusal = true;
                this.log.error(`    the node read and refused it; the durable ` +
                               `recovery entry will settle after the share is recorded`);
                if (!this._settleBlockRecovery) {
                    this._unspool(blockHash, result.reasons.join(' | ')).catch(() => {});
                }
            } else {
                this.log.error(`    NOT discarded -- it is spooled and will be ` +
                               `reconciled against the exact block hash`);
            }
"""
    job = replace_once(job, old_refusal, new_refusal, "refusal settlement")
    job_path.write_text(job, encoding="utf-8")

    server_path = root / "pool/server.js"
    server = server_path.read_text(encoding="utf-8")
    server = replace_once(
        server,
        "const ShareProcessor = require('./lib/shareProcessor');\n",
        "const ShareProcessor = require('./lib/shareProcessor');\n"
        "const BlockRecovery = require('./lib/blockRecovery');\n",
        "server require",
    )
    server = replace_once(
        server,
        """    shareProcessor.setNetworkDifficulty(chainInfo.difficulty);
    shareProcessor.start();

""",
        """    shareProcessor.setNetworkDifficulty(chainInfo.difficulty);
    shareProcessor.start();
    const blockRecovery = new BlockRecovery(
        redis, shareProcessor, logger.scope('block-recovery'));

""",
        "server recovery construction",
    )
    server = replace_once(
        server,
        """    jobManager._record = (share) => inOrder('a share',
        () => shareProcessor.recordShare(share));

""",
        """    jobManager._record = (share) => inOrder('a share',
        () => shareProcessor.recordShare(share));
    jobManager._prepareBlockRecovery = (share, hex, hash) =>
        blockRecovery.prepare(share, hex, hash);
    jobManager._recordCandidateShare = (entry) =>
        inOrder(`block-finding share ${entry.height}`,
            () => blockRecovery.recordCandidateShare(entry));
    jobManager._commitBlockRecovery = (entry) =>
        inOrder(`block ${entry.height} recovery`,
            () => blockRecovery.commitAccepted(entry));
    jobManager._settleBlockRecovery = (entry, phase, reason) =>
        inOrder(`block ${entry.height} ${phase}`,
            () => blockRecovery.settle(entry, phase, reason));

""",
        "server recovery hooks",
    )
    server = replace_once(
        server,
        """    jobManager.on('block', (share) => {
        inOrder(`block ${share.height}`, () => shareProcessor.recordBlock(share));
    });
""",
        """    jobManager.on('block', (share) => {
        // Recovery-aware candidates have already crossed the atomic accounting
        // transition before this observational event is emitted.
        if (!share.blockRecovery) {
            inOrder(`block ${share.height}`, () => shareProcessor.recordBlock(share));
        }
    });
""",
        "server block listener",
    )
    server_path.write_text(server, encoding="utf-8")

    print("block-spool recovery candidate applied to", head)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

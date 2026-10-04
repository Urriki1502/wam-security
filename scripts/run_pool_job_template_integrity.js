#!/usr/bin/env node
'use strict';

/**
 * Local integration validation for the WAM pool job/template lifecycle.
 *
 * Scope:
 * - exact open-source WAM checkout supplied on the command line;
 * - mocked daemon responses and synthetic Stratum submissions;
 * - actual upstream BlockTemplate/JobManager source;
 * - optional local RandomX C helper for one deterministic header hash.
 *
 * No sockets, public nodes, public pools, miners, credentials, or external
 * traffic are used by this runner.
 */

const assert = require('assert');
const fs = require('fs');
const Module = require('module');
const path = require('path');
const { spawnSync } = require('child_process');

const EXPECTED_WAM = 'bd71b0bd645286a3867dad6b2bfefd911ec8a5b6';

function argValue(name, fallback = null) {
    const i = process.argv.indexOf(name);
    return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : fallback;
}

const wamRootArg = argValue('--wam-root');
if (!wamRootArg) {
    console.error('usage: run_pool_job_template_integrity.js --wam-root <path> [--expected-commit <sha>] [--randomx-probe <path>] [--out <path>]');
    process.exit(2);
}

const wamRoot = path.resolve(wamRootArg);
const expectedCommit = argValue('--expected-commit', EXPECTED_WAM);
const probePath = argValue('--randomx-probe');
const outPath = path.resolve(argValue('--out', 'security-reports/pool-job-template-integrity.json'));
const poolRoot = path.join(wamRoot, 'pool');
const jobManagerPath = path.join(poolRoot, 'lib', 'jobManager.js');
const blockTemplatePath = path.join(poolRoot, 'lib', 'blockTemplate.js');
const constantsPath = path.join(poolRoot, 'lib', 'constants.js');
const utilPath = path.join(poolRoot, 'lib', 'util.js');
const stratumServerPath = path.join(poolRoot, 'lib', 'stratumServer.js');
const serverPath = path.join(poolRoot, 'server.js');

function gitHead(root) {
    const r = spawnSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' });
    if (r.status !== 0) throw new Error('git rev-parse failed: ' + (r.stderr || r.stdout));
    return r.stdout.trim();
}

const wamHead = gitHead(wamRoot);
if (wamHead !== expectedCommit) {
    throw new Error('WAM checkout is ' + wamHead + ', expected ' + expectedCommit);
}

for (const p of [jobManagerPath, blockTemplatePath, constantsPath, utilPath, stratumServerPath, serverPath]) {
    if (!fs.existsSync(p)) throw new Error('missing upstream source: ' + p);
}

const C = require(constantsPath);
const util = require(utilPath);
const BlockTemplate = require(blockTemplatePath);

const quiet = { info() {}, warn() {}, error() {}, debug() {} };

class FakeRandomX {
    constructor() {
        this.handler = async () => Buffer.alloc(32);
        this.calls = [];
    }
    configure() {}
    selfTest() { return '11'.repeat(32); }
    stats() { return { localFixture: true }; }
    flush() {}
    async hash(seed, header) {
        this.calls.push({ seed: Buffer.from(seed), header: Buffer.from(header) });
        return this.handler(seed, header);
    }
}

function loadJobManager(fakeRandomx) {
    const originalLoad = Module._load;
    delete require.cache[require.resolve(jobManagerPath)];

    Module._load = function(request, parent, isMain) {
        if (request === '../native' && parent && path.resolve(parent.filename) === path.resolve(jobManagerPath)) {
            return fakeRandomx;
        }
        return originalLoad.apply(this, arguments);
    };

    try {
        return require(jobManagerPath);
    } finally {
        Module._load = originalLoad;
    }
}

function template(overrides = {}) {
    const subsidy = 50 * C.COIN;
    return Object.assign({
        height: 500,
        version: 0x20000000,
        curtime: 1700000000,
        bits: '1d00ffff',
        previousblockhash: '11'.repeat(32),
        transactions: [],
        coinbasevalue: subsidy,
        devfee: {
            amount: Math.floor(subsidy * C.DEVFEE_PERCENT / 100),
            script: '76a914' + '22'.repeat(20) + '88ac',
            percent: C.DEVFEE_PERCENT
        },
        randomx_seedhash: 'aa'.repeat(32),
        randomx_seedheight: 0
    }, overrides);
}

const config = {
    poolAddress: 'wamrt1qwpz49ds2qwtkt7m0claxr03naqqjmx8c48qj39',
    netVersions: C.ADDRESS_VERSIONS.regtest,
    coinbaseSignature: '/WAM-Pool/',
    maxJobHistory: 4,
    randomxEpochBlocks: C.RANDOMX_EPOCH_BLOCKS,
    randomxEpochLag: C.RANDOMX_EPOCH_LAG,
    jobRebroadcastTimeout: 55
};

class ScriptedDaemon {
    constructor(templates = []) {
        this.templates = templates;
        this.templateIndex = 0;
        this.submitResults = [];
        this.submitCalls = [];
    }
    async getBlockTemplate() {
        if (this.templates.length === 0) throw new Error('no template scripted');
        const idx = Math.min(this.templateIndex, this.templates.length - 1);
        const value = this.templates[idx];
        this.templateIndex++;
        return structuredClone(value);
    }
    async submitBlock(hex) {
        this.submitCalls.push(hex);
        if (this.submitResults.length === 0) {
            return {
                accepted: false,
                reasons: ['local-fixture: rejected'],
                results: [{ daemon: 'local-fixture', ok: true, result: 'rejected', error: null }]
            };
        }
        return structuredClone(this.submitResults.shift());
    }
}

function bigintToLE(value, len = 32) {
    let v = BigInt(value);
    const out = Buffer.alloc(len);
    for (let i = 0; i < len; i++) {
        out[i] = Number(v & 0xffn);
        v >>= 8n;
    }
    if (v !== 0n) throw new Error('integer does not fit');
    return out;
}

function baseSubmission(job, overrides = {}) {
    return Object.assign({
        jobId: job.jobId,
        extranonce1: Buffer.from('01020304', 'hex'),
        extranonce2Hex: '00000000',
        nTimeHex: job.curTime.toString(16).padStart(8, '0'),
        nonceHex: '00000001',
        workerName: 'wamrt-local-fixture.worker',
        difficulty: 0.5,
        ipAddress: '127.0.0.1'
    }, overrides);
}

function sourceContract() {
    const job = fs.readFileSync(jobManagerPath, 'utf8');
    const block = fs.readFileSync(blockTemplatePath, 'utf8');
    const stratum = fs.readFileSync(stratumServerPath, 'utf8');
    const server = fs.readFileSync(serverPath, 'utf8');

    const processStart = job.indexOf('async processShare(submission)');
    const processEnd = job.indexOf('async _submitBlock(', processStart);
    const processBody = job.slice(processStart, processEnd);
    const hashPos = processBody.indexOf('await randomx.hash(job.seedHash, header)');
    const creditPos = processBody.indexOf('credited = true');
    const afterHash = hashPos >= 0 && creditPos > hashPos
        ? processBody.slice(hashPos, creditPos)
        : '';

    const checks = {
        job_binds_previous_hash_height_bits_target:
            block.includes('this.height = rpcTemplate.height') &&
            block.includes('this.bits = rpcTemplate.bits') &&
            block.includes('this.target = rpcTemplate.target') &&
            block.includes('this.previousBlockHash = rpcTemplate.previousblockhash'),
        job_binds_daemon_randomx_seed:
            job.includes('const seedHex = rpc.randomx_seedhash') &&
            job.includes('template.seedHash = seed') &&
            job.includes('template.seedHeight = seedHeight'),
        malformed_seed_fails_closed:
            job.includes('getblocktemplate did not return a usable \`randomx_seedhash\`'),
        new_tip_clears_old_jobs:
            job.includes('if (isNewBlock)') &&
            job.includes('this.validJobs.clear()') &&
            job.includes('this.validJobs.set(template.jobId, template)'),
        duplicate_claim_is_synchronous:
            block.includes('if (this.submits.has(key)) return false') &&
            block.includes('this.submits.add(key)'),
        rejected_share_releases_claim:
            job.includes('if (!credited)') &&
            job.includes('job.releaseSubmit('),
        randomx_hash_drives_candidate:
            job.includes('powHash = await randomx.hash(job.seedHash, header)') &&
            job.includes('const isBlockCandidate = hashValue <= job.target'),
        sha256d_header_is_block_id:
            job.includes('sha256d(header)') &&
            job.includes('share.blockHash = blockHash'),
        submit_retry_distinguishes_no_answer_from_rejection:
            job.includes('result.results.every((r) => !r.ok)') &&
            job.includes('if (!noDaemonAnswered) break'),
        stratum_seed_notice_precedes_job_notice:
            stratum.includes("this.notify('mining.set_seedhash'") &&
            stratum.indexOf("this.notify('mining.set_seedhash'") < stratum.indexOf("this.notify('mining.notify'"),
        new_tip_is_broadcast_as_clean_job:
            stratum.includes("jobManager.on('newJob', (job, isNewBlock) => this.broadcastJob(job, isNewBlock))") &&
            stratum.includes('client.sendJob(job, isNewBlock)'),
        share_event_flows_to_accounting:
            server.includes("jobManager.on('share', (share) =>") &&
            server.includes('shareProcessor.recordShare(share)'),
        no_post_hash_stale_job_recheck:
            hashPos >= 0 && creditPos > hashPos &&
            !afterHash.includes('validJobs.get(') &&
            !afterHash.includes('currentJob') &&
            !afterHash.includes('JOB_NOT_FOUND')
    };

    const missing = Object.entries(checks).filter(([, ok]) => !ok).map(([k]) => k);
    if (missing.length) throw new Error('source contract mismatch: ' + missing.join(', '));
    return checks;
}

async function main() {
    const fakeRandomx = new FakeRandomX();
    const JobManager = loadJobManager(fakeRandomx);

    const evidence = {
        schema: 'wam-security-pool-job-template-integrity/v1',
        target: {
            repository: 'wamcoin-core-dev/wam-coin',
            wam_commit: wamHead,
            wam_security_head: process.env.SECURITY_TARGET_SHA || null
        },
        scope: {
            local_fixtures_only: true,
            mocked_daemon: true,
            synthetic_stratum_submissions: true,
            public_pool: false,
            public_node: false,
            real_miners: false,
            third_party_infrastructure: false,
            credentials: false,
            network_traffic: false
        },
        source_contract: sourceContract(),
        checks: {},
        finding: null,
        native_randomx: null
    };

    {
        const daemon = new ScriptedDaemon([template()]);
        const jm = new JobManager(daemon, config, quiet);
        await jm.refreshTemplate(true);
        const job = jm.currentJob;

        assert.strictEqual(job.height, 500);
        assert.strictEqual(job.previousBlockHash, '11'.repeat(32));
        assert.strictEqual(job.nBits, parseInt('1d00ffff', 16));
        assert.strictEqual(job.target, util.bitsToTarget(job.nBits));
        assert.strictEqual(job.devFeeAmount + job.distributableValue, job.coinbaseValue);

        const expectedSeed = Buffer.from('aa'.repeat(32), 'hex').reverse();
        assert(job.seedHash.equals(expectedSeed));
        assert.strictEqual(job.seedHeight, 0);
        assert.strictEqual(job.getJobParams(false)[9], expectedSeed.toString('hex'));

        const coinbase = job.serializeCoinbase(Buffer.from('01020304', 'hex'), Buffer.alloc(4));
        const header = job.serializeHeader(job.computeMerkleRoot(coinbase), job.curTime, 1);
        assert.strictEqual(header.length, 80);
        assert.strictEqual(
            header.subarray(4, 36).toString('hex'),
            Buffer.from(job.previousBlockHash, 'hex').reverse().toString('hex')
        );
        assert.strictEqual(header.readUInt32LE(72), job.nBits);

        evidence.checks.job_template_binding = {
            pass: true,
            job_id: job.jobId,
            height: job.height,
            previousblockhash: job.previousBlockHash,
            bits: job.bits,
            target_hex: job.target.toString(16).padStart(64, '0'),
            seed_height: job.seedHeight,
            seed_internal_hex: job.seedHash.toString('hex'),
            coinbase_conservation: true
        };

        if (probePath) {
            const probe = path.resolve(probePath);
            const args = [job.seedHash.toString('hex'), header.toString('hex')];
            const a = spawnSync(probe, args, { encoding: 'utf8' });
            const b = spawnSync(probe, args, { encoding: 'utf8' });
            if (a.status !== 0 || b.status !== 0) {
                throw new Error('local RandomX probe failed:\n' + a.stdout + a.stderr + '\n' + b.stdout + b.stderr);
            }
            const ha = (a.stdout.match(/hash=([0-9a-f]{64})/i) || [])[1];
            const hb = (b.stdout.match(/hash=([0-9a-f]{64})/i) || [])[1];
            assert(ha && hb, 'RandomX probe did not return a 32-byte hash');
            assert.strictEqual(ha, hb, 'RandomX hash is not deterministic');

            const blockId = util.reverseBuffer(util.sha256d(header)).toString('hex');
            assert.notStrictEqual(ha, blockId, 'RandomX work hash unexpectedly equals SHA256d block id');
            evidence.native_randomx = {
                pass: true,
                deterministic: true,
                header_bytes: 80,
                randomx_hash_internal_hex: ha,
                sha256d_block_id: blockId,
                distinct_id_and_work_hash: true
            };
        }
    }

    {
        for (const bad of [undefined, null, '00', 'zz'.repeat(32)]) {
            const t = template();
            if (bad === undefined) delete t.randomx_seedhash;
            else t.randomx_seedhash = bad;
            const jm = new JobManager(new ScriptedDaemon([t]), config, quiet);
            await assert.rejects(() => jm.refreshTemplate(true), /usable \`randomx_seedhash\`/);
            assert.strictEqual(jm.currentJob, null);
            assert.strictEqual(jm.validJobs.size, 0);
        }
        evidence.checks.malformed_seed_fails_closed = { pass: true, cases: 4 };
    }

    {
        const a = template({
            height: 2111,
            previousblockhash: '11'.repeat(32),
            randomx_seedhash: 'aa'.repeat(32),
            randomx_seedheight: 0
        });
        const b = template({
            height: 2112,
            previousblockhash: '22'.repeat(32),
            randomx_seedhash: 'bb'.repeat(32),
            randomx_seedheight: 2048
        });
        const daemon = new ScriptedDaemon([a, b]);
        const jm = new JobManager(daemon, config, quiet);
        await jm.refreshTemplate(true);
        const old = jm.currentJob;
        await jm.refreshTemplate(true);
        const fresh = jm.currentJob;

        assert.notStrictEqual(old.jobId, fresh.jobId);
        assert.strictEqual(jm.validJobs.size, 1);
        assert.strictEqual(jm.validJobs.has(old.jobId), false);
        assert.strictEqual(jm.validJobs.has(fresh.jobId), true);
        assert.strictEqual(fresh.seedHeight, 2048);
        assert.strictEqual(jm.stats.seedRotations, 1);

        const hashCallsBefore = fakeRandomx.calls.length;
        const stale = await jm.processShare(baseSubmission(old));
        assert.strictEqual(stale.valid, false);
        assert.strictEqual(stale.error[0], 21);
        assert.strictEqual(fakeRandomx.calls.length, hashCallsBefore, 'stale lookup reached RandomX hashing');

        evidence.checks.tip_change_invalidates_old_jobs = {
            pass: true,
            old_job: old.jobId,
            new_job: fresh.jobId,
            valid_jobs_after_tip_change: jm.validJobs.size,
            seed_rotations: jm.stats.seedRotations,
            old_job_reject_code: stale.error[0]
        };
    }

    {
        const daemon = new ScriptedDaemon([template()]);
        const jm = new JobManager(daemon, config, quiet);
        await jm.refreshTemplate(true);
        const job = jm.currentJob;

        fakeRandomx.handler = async () => bigintToLE(job.target + 1n);

        let shares = 0;
        jm.on('share', () => shares++);
        const sub = baseSubmission(job, { difficulty: 0.5 });
        const first = await jm.processShare(sub);
        const second = await jm.processShare(sub);

        assert.strictEqual(first.valid, true);
        assert.strictEqual(first.share.blockCandidate, false);
        assert.strictEqual(second.valid, false);
        assert.strictEqual(second.error[0], 22);
        assert.strictEqual(shares, 1);

        evidence.checks.accepted_share_duplicate_guard = {
            pass: true,
            credited_events: shares,
            second_submit_reject_code: second.error[0]
        };
    }

    {
        const daemon = new ScriptedDaemon([template()]);
        const jm = new JobManager(daemon, config, quiet);
        await jm.refreshTemplate(true);
        const job = jm.currentJob;
        const sub = baseSubmission(job, { nonceHex: '00000002', difficulty: 0.5 });

        let shares = 0;
        jm.on('share', () => shares++);

        fakeRandomx.handler = async () => Buffer.alloc(32, 0xff);
        const rejected = await jm.processShare(sub);
        assert.strictEqual(rejected.valid, false);
        assert.strictEqual(rejected.error[0], 23);

        fakeRandomx.handler = async () => bigintToLE(job.target + 1n);
        const retried = await jm.processShare(sub);
        assert.strictEqual(retried.valid, true);
        assert.strictEqual(shares, 1);

        const duplicate = await jm.processShare(sub);
        assert.strictEqual(duplicate.valid, false);
        assert.strictEqual(duplicate.error[0], 22);

        evidence.checks.rejected_share_claim_release = {
            pass: true,
            first_reject_code: rejected.error[0],
            retry_credited: true,
            third_submit_duplicate_code: duplicate.error[0],
            credited_events: shares
        };
    }

    {
        const transientDaemon = new ScriptedDaemon([template()]);
        transientDaemon.submitResults.push(
            {
                accepted: false,
                reasons: ['local-fixture: no daemon answered'],
                results: [{ daemon: 'local-fixture', ok: false, result: null, error: 'ECONNREFUSED' }]
            },
            {
                accepted: true,
                reasons: [],
                results: [{ daemon: 'local-fixture', ok: true, result: null, error: null }]
            }
        );

        const jm = new JobManager(transientDaemon, config, quiet);
        await jm.refreshTemplate(true);
        fakeRandomx.handler = async () => Buffer.alloc(32);

        let shareEvents = 0;
        let blockEvents = 0;
        jm.on('share', () => shareEvents++);
        jm.on('block', () => blockEvents++);

        const accepted = await jm.processShare(baseSubmission(jm.currentJob, {
            nonceHex: '00000003',
            difficulty: 0.5
        }));
        assert.strictEqual(accepted.valid, true);
        assert.strictEqual(accepted.share.blockCandidate, true);
        assert.strictEqual(accepted.share.blockAccepted, true);
        assert.strictEqual(transientDaemon.submitCalls.length, 2);
        assert.strictEqual(shareEvents, 1);
        assert.strictEqual(blockEvents, 1);

        const definitiveDaemon = new ScriptedDaemon([template({ previousblockhash: '33'.repeat(32) })]);
        definitiveDaemon.submitResults.push({
            accepted: false,
            reasons: ['local-fixture: high-hash'],
            results: [{ daemon: 'local-fixture', ok: true, result: 'high-hash', error: null }]
        });
        const jm2 = new JobManager(definitiveDaemon, config, quiet);
        await jm2.refreshTemplate(true);
        fakeRandomx.handler = async () => Buffer.alloc(32);

        let rejectedBlocks = 0;
        jm2.on('blockRejected', () => rejectedBlocks++);
        const rejected = await jm2.processShare(baseSubmission(jm2.currentJob, {
            nonceHex: '00000004',
            difficulty: 0.5
        }));

        assert.strictEqual(rejected.valid, true);
        assert.strictEqual(rejected.share.blockAccepted, false);
        assert.strictEqual(definitiveDaemon.submitCalls.length, 1);
        assert.strictEqual(rejectedBlocks, 1);

        evidence.checks.submitblock_retry_classification = {
            pass: true,
            transient_submit_attempts: transientDaemon.submitCalls.length,
            transient_block_events: blockEvents,
            transient_share_events: shareEvents,
            definitive_submit_attempts: definitiveDaemon.submitCalls.length,
            definitive_reject_events: rejectedBlocks,
            duplicate_accounting_events_observed: false
        };
    }

    {
        const a = template({
            height: 900,
            previousblockhash: '44'.repeat(32),
            randomx_seedhash: 'aa'.repeat(32),
            randomx_seedheight: 0
        });
        const b = template({
            height: 901,
            previousblockhash: '55'.repeat(32),
            randomx_seedhash: 'bb'.repeat(32),
            randomx_seedheight: 0
        });

        const daemon = new ScriptedDaemon([a, b]);
        daemon.submitResults.push({
            accepted: false,
            reasons: ['local-fixture: stale-prevblk'],
            results: [{ daemon: 'local-fixture', ok: true, result: 'stale-prevblk', error: null }]
        });

        const jm = new JobManager(daemon, config, quiet);
        await jm.refreshTemplate(true);
        const oldJob = jm.currentJob;

        let hashEnteredResolve;
        const hashEntered = new Promise((resolve) => { hashEnteredResolve = resolve; });
        let releaseHash;
        fakeRandomx.handler = () => new Promise((resolve) => {
            releaseHash = resolve;
            hashEnteredResolve();
        });

        let shareEvents = 0;
        let rejectedBlockEvents = 0;
        jm.on('share', () => shareEvents++);
        jm.on('blockRejected', () => rejectedBlockEvents++);

        const pending = jm.processShare(baseSubmission(oldJob, {
            nonceHex: '00000005',
            difficulty: 0.5
        }));

        await hashEntered;
        await jm.refreshTemplate(true);
        const newJob = jm.currentJob;

        assert.strictEqual(jm.validJobs.has(oldJob.jobId), false);
        assert.notStrictEqual(newJob.jobId, oldJob.jobId);

        releaseHash(Buffer.alloc(32));
        const result = await pending;

        const confirmedRace =
            result.valid === true &&
            shareEvents === 1 &&
            daemon.submitCalls.length === 1 &&
            rejectedBlockEvents === 1;

        const safeRecheck =
            result.valid === false &&
            shareEvents === 0 &&
            daemon.submitCalls.length === 0;

        assert(confirmedRace || safeRecheck, 'unexpected stale in-flight behavior');

        evidence.checks.inflight_stale_job = {
            old_job: oldJob.jobId,
            new_job: newJob.jobId,
            old_job_removed_before_hash_returned: true,
            result_valid: result.valid,
            credited_share_events: shareEvents,
            block_submit_attempts: daemon.submitCalls.length,
            block_rejected_events: rejectedBlockEvents,
            safe_post_hash_recheck_present: safeRecheck,
            race_reproduced: confirmedRace
        };

        if (confirmedRace) {
            evidence.finding = {
                id: 'WS-POOL-JOB-001',
                confidence: 'CONFIRMED-LOCAL-DETERMINISTIC',
                title: 'In-flight share can outlive a tip change and still be credited',
                class: 'POOL_ACCOUNTING_STALE_JOB_RACE',
                root_cause:
                    'processShare validates jobId before awaiting asynchronous RandomX hashing, but does not re-check job validity after the await. refreshTemplate clears old jobs on a new tip during that window.',
                observed_effects: [
                    'old job removed from validJobs before RandomX returned',
                    'old-job share still returned valid=true',
                    'share event still emitted and therefore reaches recordShare in server.js',
                    'old block candidate was submitted and definitively rejected as stale in the local fixture'
                ],
                node_consensus_bypass: false,
                public_network_tested: false
            };
        }
    }

    evidence.classification = evidence.finding
        ? 'CONFIRMED_POOL_STALE_JOB_ACCOUNTING_RACE_NO_NODE_CONSENSUS_BYPASS'
        : 'POOL_JOB_TEMPLATE_INVARIANTS_PASS';

    evidence.result = 'PASS';

    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, JSON.stringify(evidence, null, 2) + '\n');
    console.log(JSON.stringify({
        result: evidence.result,
        classification: evidence.classification,
        finding: evidence.finding ? evidence.finding.id : null,
        evidence: outPath
    }));
}

main().catch((err) => {
    console.error(err.stack || err.message);
    process.exit(1);
});

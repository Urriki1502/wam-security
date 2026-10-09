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

const EXPECTED_WAM = '260bc468e5adffea7ce68d8f97fac3e27e4c50b2';

function argValue(name, fallback = null) {
    const i = process.argv.indexOf(name);
    return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : fallback;
}

const wamRootArg = argValue('--wam-root');
if (!wamRootArg) {
    console.error('usage: reproduce_ws_pool_job_001.js --wam-root <path> [--expected-commit <sha>] [--randomx-probe <path>] [--out <path>]');
    process.exit(2);
}

const wamRoot = path.resolve(wamRootArg);
const expectedCommit = argValue('--expected-commit', EXPECTED_WAM);
const probePath = argValue('--randomx-probe');
const outPath = path.resolve(argValue('--out', 'security-reports/ws-pool-job-001-260bc468.json'));
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


async function main() {
    const source = fs.readFileSync(jobManagerPath, 'utf8');
    const processStart = source.indexOf('async processShare(submission)');
    const processEnd = source.indexOf('async _hashWithOneVm(', processStart);
    assert(processStart >= 0 && processEnd > processStart, 'unknown upstream processShare layout');
    const processBody = source.slice(processStart, processEnd);
    const startCheck = processBody.indexOf('this.validJobs.get(jobId)');
    const hashCall = processBody.indexOf('await this._hashWithOneVm(job.seedHash, header)');
    const recordCall = processBody.indexOf('await this._record(share)');
    assert(startCheck >= 0 && hashCall > startCheck && recordCall > hashCall,
           'unexpected source lifecycle; manual review required');
    const afterHash = processBody.slice(hashCall, recordCall);
    const explicitRecheck = /this\.validJobs\.get\s*\(|this\.validJobs\.has\s*\(|this\.currentJob\s*(?:===|!==)|JOB_NOT_FOUND/.test(afterHash);
    const evidence = {
        schema: 'wam-security-ws-pool-job-001-current-main/v1',
        target: {repository: 'wamcoin-core-dev/wam-coin',
                 expected_commit: expectedCommit, observed_commit: wamHead},
        scope: 'local mocked daemon, actual upstream JobManager and BlockTemplate, synthetic miners only',
        source: {job_lookup_before_await: true, record_after_await: true,
                 explicit_post_await_stale_check_found: explicitRecheck},
        controls: {}, observation: {}, result: 'NOT_RUN'
    };
    const fake = new FakeRandomX();
    const JobManager = loadJobManager(fake);
    const a = template({height: 901, previousblockhash: '11'.repeat(32)});
    const b = template({height: 902, previousblockhash: '22'.repeat(32)});
    const daemon = new ScriptedDaemon([a, b]);
    daemon.submitResults.push({
        accepted: false,
        reasons: ['local-fixture: stale-prevblk'],
        results: [{daemon: 'local-fixture', ok: true, result: 'stale-prevblk', error: null}]
    });
    const jm = new JobManager(daemon, config, quiet);
    await jm.refreshTemplate(true);
    const old = jm.currentJob;
    const oldId = old.jobId;
    assert(jm.validJobs.has(oldId));
    let hashStarted;
    const entered = new Promise(resolve => {hashStarted = resolve;});
    let releaseHash;
    fake.handler = () => new Promise(resolve => {
        releaseHash = resolve;
        hashStarted();
    });
    let shares = 0, rejectedBlocks = 0, persisted = 0;
    jm._record = async () => {persisted++;};
    jm.on('share', () => {shares++;});
    jm.on('blockRejected', () => {rejectedBlocks++;});
    const pending = jm.processShare(baseSubmission(old, {
        nonceHex: '00000005', difficulty: 0.5
    }));
    await entered;
    await jm.refreshTemplate(true);
    const current = jm.currentJob;
    assert.notStrictEqual(current.jobId, oldId, 'tip change did not yield a new job');
    assert.strictEqual(jm.validJobs.has(oldId), false, 'old job still valid');
    evidence.controls.old_job_invalidated_during_hash = true;
    evidence.controls.new_height = current.height;
    releaseHash(Buffer.alloc(32)); // synthetic candidate, no real miner or hash work
    const result = await pending;
    evidence.observation = {
        accepted_after_invalidation: result.valid === true,
        returned_block_candidate: result.share?.blockCandidate === true,
        share_events: shares,
        durable_record_calls: persisted,
        stale_candidate_submit_calls: daemon.submitCalls.length,
        rejected_candidate_events: rejectedBlocks
    };
    const finding = result.valid === true && shares === 1 && persisted === 1 &&
                    daemon.submitCalls.length === 1 && rejectedBlocks === 1 &&
                    !explicitRecheck;
    evidence.result = finding
        ? 'CONFIRMED_POOL_STALE_JOB_ACCOUNTING_RACE_NO_NODE_CONSENSUS_BYPASS'
        : 'NOT_REPRODUCED_REVIEW_REQUIRED';
    fs.mkdirSync(path.dirname(outPath), {recursive: true});
    fs.writeFileSync(outPath, JSON.stringify(evidence, null, 2) + '\n');
    console.log(JSON.stringify(evidence, null, 2));
    // We expect the known issue to reproduce on this exact reviewed source.
    // A future upstream fix changes the expected outcome and REQUIRES review;
    // it must never silently turn the finding into a passing security gate.
    assert.strictEqual(evidence.result,
        'CONFIRMED_POOL_STALE_JOB_ACCOUNTING_RACE_NO_NODE_CONSENSUS_BYPASS',
        'current-main behavior changed; inspect the evidence and classify anew');
}
main().catch(err => {
    console.error(err.stack || String(err));
    process.exitCode = 1;
});

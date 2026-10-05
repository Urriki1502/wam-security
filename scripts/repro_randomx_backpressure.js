#!/usr/bin/env node
'use strict';

/**
 * Deterministic source-level validation of WAM's RandomX admission bound.
 *
 * This is intentionally non-invasive: it reads an exact local checkout,
 * models the admission formula already present in jobManager.js, and verifies
 * the native addon's scheduling shape. It opens no sockets and hashes nothing.
 */

const fs = require('fs');
const path = require('path');
const cp = require('child_process');

const EXPECTED = 'bb6d5214f2f5de3b7464587cc1b2949d221dcd18';
const root = path.resolve(process.argv[2] || 'wam-coin');
const out = path.resolve(
  process.argv[3] || 'security-reports/randomx-backpressure-finding.json'
);

const head = cp.execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], {
  encoding: 'utf8'
}).trim();
if (head !== EXPECTED) {
  throw new Error(`expected ${EXPECTED}, got ${head}`);
}

const jmPath = path.join(root, 'pool/lib/jobManager.js');
const nativePath = path.join(root, 'pool/native/src/randomx_binding.cc');
const testPath = path.join(root, 'pool/test/verify-backpressure.test.js');

const jm = fs.readFileSync(jmPath, 'utf8');
const native = fs.readFileSync(nativePath, 'utf8');
const existingTest = fs.readFileSync(testPath, 'utf8');

const checks = {
  js_limit_has_floor_32: /Math\.max\(32,\s*vms\s*\*\s*4\)/.test(jm),
  native_worker_uses_asyncworker: /class\s+HashWorker\s*:\s*public\s+Napi::AsyncWorker/.test(native),
  native_worker_acquires_vm_inside_execute:
    /void\s+Execute\(\)\s+override[\s\S]*?ctx->acquire\(\)[\s\S]*?randomx_calculate_hash/.test(native),
  native_acquire_blocks_on_condition_variable:
    /int\s+acquire\(\)[\s\S]*?cv\.wait\(/.test(native),
  existing_test_requires_floor_32:
    /_maxVerifying,\s*32[\s\S]*?floor of 32/.test(existingTest)
};

const scenarios = [1, 2, 4, 16].map((vmCount) => {
  const admitted = Math.max(32, vmCount * 4);
  return {
    vmCount,
    admitted,
    workersBeyondVmSlots: admitted - vmCount,
    admissionExceedsVmSlots: admitted > vmCount
  };
});

const sourceShapeConfirmed = Object.values(checks).every(Boolean);
const gapConfirmed =
  sourceShapeConfirmed &&
  scenarios.every((s) => s.admissionExceedsVmSlots);

const report = {
  schema: 'wam-security-randomx-backpressure-source-model/v1',
  target: {
    repository: 'wamcoin-core-dev/wam-coin',
    expectedCommit: EXPECTED,
    observedCommit: head
  },
  invariant:
    'Do not admit more native async hash workers than can make progress without waiting for a RandomX VM slot inside the shared worker pool.',
  sourceChecks: checks,
  scenarios,
  classification: gapConfirmed
    ? 'STRUCTURAL_GAP_CONFIRMED'
    : 'NOT_REPRODUCED',
  interpretation: gapConfirmed
    ? [
        'The JS admission limit is greater than the configured VM count.',
        'Each admitted hash is a Napi::AsyncWorker.',
        'A worker that has no free VM waits inside SeedContext::acquire().',
        'Therefore admitted work can occupy shared worker threads while waiting for a VM slot.',
        'Runtime latency impact is not measured by this source-only harness.'
      ]
    : [],
  result: gapConfirmed ? 'REPRODUCED' : 'NOT_REPRODUCED'
};

fs.mkdirSync(path.dirname(out), {recursive: true});
fs.writeFileSync(out, JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report, null, 2));
process.exit(gapConfirmed ? 0 : 1);

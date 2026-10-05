'use strict';

// Reference candidate for wam-coin@bb6d521.
// Raw block recovery and economic accounting are one durable protocol.

const { computeBlockRewards } = require('./rewards');

const RECORD_SHARE = String.raw`
if redis.call('HEXISTS', KEYS[1], ARGV[1]) == 1 then
    return 0
end
redis.call('HINCRBYFLOAT', KEYS[2], ARGV[2], ARGV[3])
redis.call('LPUSH', KEYS[3], ARGV[4])
redis.call('LTRIM', KEYS[3], 0, tonumber(ARGV[6]) - 1)
redis.call('ZADD', KEYS[4], ARGV[5], ARGV[4])
redis.call('HSET', KEYS[1], ARGV[1], '1')
return 1
`;

const MARK_ACCEPTED = String.raw`
local raw = redis.call('HGET', KEYS[1], ARGV[1])
if not raw then
    return 0
end
local entry = cjson.decode(raw)
entry['phase'] = 'accepted-unaccounted'
redis.call('HSET', KEYS[1], ARGV[1], cjson.encode(entry))
return 1
`;

const COMMIT_ACCEPTED = String.raw`
if redis.call('HEXISTS', KEYS[1], ARGV[1]) == 1 then
    redis.call('HDEL', KEYS[8], ARGV[1])
    redis.call('HDEL', KEYS[2], ARGV[1])
    return 0
end

if redis.call('HEXISTS', KEYS[2], ARGV[1]) == 0 then
    redis.call('HINCRBYFLOAT', KEYS[3], ARGV[2], ARGV[3])
    redis.call('LPUSH', KEYS[4], ARGV[4])
    redis.call('LTRIM', KEYS[4], 0, tonumber(ARGV[6]) - 1)
    redis.call('ZADD', KEYS[5], ARGV[5], ARGV[4])
    redis.call('HSET', KEYS[2], ARGV[1], '1')
end

redis.call('HSET', KEYS[6], ARGV[1], ARGV[7])
redis.call('DEL', KEYS[3])
redis.call('INCRBY', KEYS[7], ARGV[8])
redis.call('HSET', KEYS[1], ARGV[1], '1')
redis.call('HDEL', KEYS[2], ARGV[1])
redis.call('HDEL', KEYS[8], ARGV[1])
return 1
`;

const SETTLE = String.raw`
local raw = redis.call('HGET', KEYS[1], ARGV[1])
if not raw then
    redis.call('HDEL', KEYS[3], ARGV[1])
    return 0
end
local entry = cjson.decode(raw)
entry['phase'] = ARGV[2]
entry['settledReason'] = ARGV[3]
entry['settledAt'] = tonumber(ARGV[4])
redis.call('HSET', KEYS[2], ARGV[1], cjson.encode(entry))
redis.call('HDEL', KEYS[1], ARGV[1])
redis.call('HDEL', KEYS[3], ARGV[1])
return 1
`;

class BlockRecovery {
    constructor(redis, shareProcessor, logger) {
        this.redis = redis;
        this.processor = shareProcessor;
        this.log = logger;
    }

    k(...parts) {
        return this.processor.k(...parts);
    }

    _validate(entry) {
        const share = entry && entry.share;
        const record = entry && entry.blockRecord;
        if (!entry || entry.version !== 1 ||
            !/^[0-9a-f]{64}$/.test(String(entry.hash || '')) ||
            typeof entry.hex !== 'string' || entry.hex.length === 0 ||
            entry.hex.length % 2 !== 0 ||
            entry.phase !== 'spooled' && entry.phase !== 'accepted-unaccounted' ||
            !share || !record ||
            record.blockHash !== entry.hash ||
            share.blockHash !== entry.hash ||
            share.height !== record.height ||
            share.worker !== record.finder ||
            !Number.isInteger(share.coinbaseValue) ||
            !Number.isInteger(share.devFeeAmount) ||
            !Number.isInteger(share.distributableValue) ||
            share.coinbaseValue - share.devFeeAmount !== share.distributableValue ||
            !Number.isFinite(share.difficulty) || share.difficulty <= 0 ||
            typeof entry.shareEntry !== 'string' ||
            !Number.isInteger(entry.shareTime) || entry.shareTime < 0 ||
            !Number.isInteger(entry.pplnsTrim) || entry.pplnsTrim < 1 ||
            !Number.isInteger(entry.poolFee) || entry.poolFee < 0) {
            throw new Error('invalid block recovery entry');
        }
        return entry;
    }

    async prepare(share, blockHex, blockHash) {
        if (!share || share.blockHash !== blockHash) {
            throw new Error('block recovery share/hash mismatch');
        }

        const shareTime = Math.floor(share.time / 1000);
        const shareEntry = JSON.stringify({
            w: share.worker,
            d: share.difficulty,
            t: shareTime,
            n: `block-${blockHash}`
        });

        const [existingShares, currentRound] = await Promise.all([
            this.processor.mode === 'pplns'
                ? this.processor.getPplnsShares()
                : Promise.resolve([]),
            this.processor.getRoundContributions()
        ]);

        const shares = [
            { worker: share.worker, difficulty: share.difficulty, time: shareTime },
            ...existingShares
        ];
        const roundContributions = new Map(currentRound);
        roundContributions.set(
            share.worker,
            (roundContributions.get(share.worker) || 0) + share.difficulty
        );

        const rewards = computeBlockRewards({
            mode: this.processor.mode,
            blockValue: share.distributableValue,
            coinbaseValue: share.coinbaseValue,
            devFeeAmount: share.devFeeAmount,
            poolFeePercent: this.processor.poolFeePercent,
            shares,
            roundContributions,
            networkDifficulty: this.processor.networkDifficulty,
            pplnsMultiplier: this.processor.pplnsMultiplier
        });

        const blockRecord = {
            height: share.height,
            blockHash,
            finder: share.worker,
            time: share.time,
            coinbaseValue: share.coinbaseValue,
            devFeeAmount: share.devFeeAmount,
            distributableValue: share.distributableValue,
            poolFee: rewards.poolFee,
            minerPot: rewards.minerPot,
            payouts: Object.fromEntries(rewards.payouts),
            workers: rewards.workers,
            window: rewards.window,
            mode: this.processor.mode,
            confirmations: 0
        };

        return this._validate({
            version: 1,
            phase: 'spooled',
            height: share.height,
            hash: blockHash,
            hex: blockHex,
            worker: share.worker,
            foundAt: share.time,
            share: { ...share },
            shareEntry,
            shareTime,
            pplnsTrim: this.processor._pplnsBufferSize(),
            poolFee: rewards.poolFee,
            blockRecord
        });
    }

    async recordCandidateShare(entry) {
        entry = this._validate(entry);
        return this.redis.eval(
            RECORD_SHARE,
            4,
            this.k('blocks:winner-share-recorded'),
            this.k('round'),
            this.k('pplns'),
            this.k('hashrate'),
            entry.hash,
            entry.share.worker,
            String(entry.share.difficulty),
            entry.shareEntry,
            String(entry.shareTime),
            String(entry.pplnsTrim)
        );
    }

    async markAccepted(entry) {
        entry = this._validate(entry);
        const changed = await this.redis.eval(
            MARK_ACCEPTED,
            1,
            this.k('blocks:unsent'),
            entry.hash
        );
        if (!changed) {
            throw new Error('block recovery entry disappeared before accounting');
        }
        entry.phase = 'accepted-unaccounted';
        return entry;
    }

    async commitAccepted(entry) {
        entry = this._validate(entry);
        if (entry.phase !== 'accepted-unaccounted') {
            await this.markAccepted(entry);
        }
        return this.redis.eval(
            COMMIT_ACCEPTED,
            8,
            this.k('blocks:accounted'),
            this.k('blocks:winner-share-recorded'),
            this.k('round'),
            this.k('pplns'),
            this.k('hashrate'),
            this.k('blocks:pending'),
            this.k('poolfees'),
            this.k('blocks:unsent'),
            entry.hash,
            entry.share.worker,
            String(entry.share.difficulty),
            entry.shareEntry,
            String(entry.shareTime),
            String(entry.pplnsTrim),
            JSON.stringify(entry.blockRecord),
            String(entry.poolFee)
        );
    }

    async settle(entry, phase, reason) {
        entry = this._validate(entry);
        if (!['lost-race', 'refused'].includes(phase)) {
            throw new Error('invalid block recovery terminal phase');
        }
        const terminal = phase === 'lost-race'
            ? this.k('blocks:lost-race')
            : this.k('blocks:refused');
        return this.redis.eval(
            SETTLE,
            3,
            this.k('blocks:unsent'),
            terminal,
            this.k('blocks:winner-share-recorded'),
            entry.hash,
            phase,
            String(reason || phase),
            String(Date.now())
        );
    }
}

module.exports = BlockRecovery;

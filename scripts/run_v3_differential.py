#!/usr/bin/env python3
from __future__ import annotations

import argparse
import random
import subprocess

from wam_security.consensus.compact import compact_to_target, target_to_compact
from wam_security.consensus.dgw import DgwBlock, DgwParams, check_pow_hash, dark_gravity_wave
from wam_security.consensus.randomx import MAINNET, REGTEST, TESTNET, seed_height


POW_LIMIT = int("00000fffff000000000000000000000000000000000000000000000000000000", 16)
DGW_PARAMS = DgwParams(pow_limit=POW_LIMIT)


def call(harness: str, *args: object) -> str:
    p = subprocess.run(
        [harness, *map(str, args)],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return p.stdout.strip()


def check_compact(harness: str, rng: random.Random, cases: int) -> int:
    done = 0
    known = [0, POW_LIMIT, compact_to_target(0x1E0FFFF0)[0], compact_to_target(0x207FFFFF)[0]]
    values = known + [rng.randrange(1, POW_LIMIT + 1) for _ in range(cases)]
    for target in values:
        py_bits = target_to_compact(target)
        native_bits = int(call(harness, "target-to-compact", hex(target)), 16)
        if native_bits != py_bits:
            raise AssertionError(f"target->compact mismatch target={target:x}: py={py_bits:x} native={native_bits:x}")

        py_target = compact_to_target(py_bits)[0]
        native_target = int(call(harness, "compact-to-target", hex(py_bits)), 16)
        if native_target != py_target:
            raise AssertionError(f"compact->target mismatch bits={py_bits:x}")
        done += 1
    return done


def check_pow(harness: str, rng: random.Random, cases: int) -> int:
    done = 0
    bits_values = [0x1E0FFFF0, 0x1E0FFFFF, 0x1D00FFFF]
    for _ in range(cases):
        target = rng.randrange(1, POW_LIMIT + 1)
        bits_values.append(target_to_compact(target))

    for bits in bits_values:
        target = compact_to_target(bits)[0]
        for hash_value in {0, max(0, target - 1), target, target + 1}:
            py_ok = check_pow_hash(hash_value, bits, POW_LIMIT)
            native_ok = call(harness, "checkpow", hex(hash_value), hex(bits), hex(POW_LIMIT)) == "1"
            if native_ok != py_ok:
                raise AssertionError(
                    f"checkpow mismatch bits={hex(bits)} hash={hash_value:x}: py={py_ok} native={native_ok}"
                )
            done += 1

    invalid_bits = [0, 0x1D80FFFF, 0x2300FFFF, target_to_compact(POW_LIMIT << 8)]
    for bits in invalid_bits:
        py_ok = check_pow_hash(0, bits, POW_LIMIT)
        native_ok = call(harness, "checkpow", "0x0", hex(bits), hex(POW_LIMIT)) == "1"
        if native_ok != py_ok or native_ok:
            raise AssertionError(f"invalid compact target accepted: {hex(bits)}")
        done += 1
    return done


def check_seedheight(harness: str, rng: random.Random, cases: int) -> int:
    done = 0
    for profile in (MAINNET, TESTNET, REGTEST):
        e, lag = profile.epoch_blocks, profile.epoch_lag
        heights = {
            0, lag, lag + 1, e - 1, e, e + lag - 1, e + lag, e + lag + 1,
            2 * e + lag - 1, 2 * e + lag, 2 * e + lag + 1,
        }
        heights.update(rng.randrange(0, 20 * e + lag + 1) for _ in range(cases))
        for h in sorted(heights):
            py = seed_height(h, profile)
            native = int(call(harness, "seedheight", e, lag, h))
            if native != py:
                raise AssertionError(f"seedheight mismatch {profile.name} h={h}: py={py} native={native}")
            done += 1
    return done


def _scenario(rng: random.Random, index: int) -> list[DgwBlock]:
    height = 1000 + index
    newest = 2_000_000 + index * 100_000
    spacing_choices = [1, 30, 120, 300, 10_000]
    nominal = spacing_choices[index % len(spacing_choices)]
    out = []
    t = newest
    for i in range(24):
        divisor = rng.randrange(2, 64)
        target = max(1, POW_LIMIT // divisor)
        bits = target_to_compact(target)
        if i:
            jitter = rng.randrange(-nominal // 2 if nominal > 1 else 0, nominal + 1)
            t -= max(-30, nominal + jitter)
        out.append(DgwBlock(height - i, t, bits))
    return out


def check_dgw(harness: str, rng: random.Random, cases: int) -> int:
    done = 0

    # Bootstrap boundaries.
    for h in range(24):
        py = dark_gravity_wave([DgwBlock(h, 1000, 0x1E0FFFF0)], DGW_PARAMS)
        native = int(call(
            harness, "dgw", hex(POW_LIMIT), 120, 24, 3, h, "1000,0x1e0ffff0"
        ), 16)
        if native != py:
            raise AssertionError(f"DGW bootstrap mismatch height={h}")
        done += 1

    for i in range(cases):
        blocks = _scenario(rng, i)
        py = dark_gravity_wave(blocks, DGW_PARAMS)
        series = ";".join(f"{b.timestamp},{hex(b.bits)}" for b in blocks)
        native = int(call(
            harness,
            "dgw",
            hex(POW_LIMIT),
            DGW_PARAMS.target_spacing,
            DGW_PARAMS.past_blocks,
            DGW_PARAMS.clamp_factor,
            blocks[0].height,
            series,
        ), 16)
        if native != py:
            raise AssertionError(
                f"DGW mismatch case={i}: py={hex(py)} native={hex(native)}"
            )
        done += 1
    return done


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--harness", required=True)
    p.add_argument("--seed", type=lambda x: int(x, 0), default=0x57414D)
    p.add_argument("--compact-cases", type=int, default=300)
    p.add_argument("--pow-cases", type=int, default=200)
    p.add_argument("--seed-cases", type=int, default=300)
    p.add_argument("--dgw-cases", type=int, default=200)
    args = p.parse_args()

    rng = random.Random(args.seed)
    compact = check_compact(args.harness, rng, args.compact_cases)
    pow_vectors = check_pow(args.harness, rng, args.pow_cases)
    seeds = check_seedheight(args.harness, rng, args.seed_cases)
    dgw = check_dgw(args.harness, rng, args.dgw_cases)
    print(f"compact differential: PASS ({compact} vectors)")
    print(f"PoW boundary differential: PASS ({pow_vectors} vectors)")
    print(f"RandomX seed-height differential: PASS ({seeds} vectors)")
    print(f"DGW differential: PASS ({dgw} vectors)")
    print(f"total cross-language vectors: PASS ({compact + pow_vectors + seeds + dgw})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

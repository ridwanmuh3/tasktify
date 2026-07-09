#!/usr/bin/env python3
"""Compare FN-DSA-Precomputed-512 and FN-DSA-512 with Welch t-test only."""

from __future__ import annotations

from benchmark_welch_all_baselines import run


if __name__ == "__main__":
    raise SystemExit(
        run(
            title="Welch T-Test: FN-DSA Only",
            default_baselines=("FN-DSA-512",),
            description="Compare only FN-DSA-Precomputed-512 and FN-DSA-512 with Welch t-test.",
        )
    )

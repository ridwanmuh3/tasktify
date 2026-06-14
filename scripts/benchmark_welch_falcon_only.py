#!/usr/bin/env python3
"""Compare Falcon-Precomputed-512 and Falcon-512 with Welch t-test only."""

from __future__ import annotations

from benchmark_welch_all_baselines import run


if __name__ == "__main__":
    raise SystemExit(
        run(
            title="Welch T-Test: Falcon Only",
            default_baselines=("Falcon-512",),
            description="Compare only Falcon-Precomputed-512 and Falcon-512 with Welch t-test.",
        )
    )

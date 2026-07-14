#!/usr/bin/env python3
"""Merge N benchmark_sign_result.json / adversarial_result.json runs into one
file per-metric via median, so figures reflect a stable value instead of a
single noisy run (this VPS shares its host with unrelated load).

Usage:
    python3 scripts/aggregate_benchmark_runs.py \
        --bench-glob 'backend/benchmark-results/runs/benchmark_sign_result_run_*.json' \
        --adversarial-glob 'backend/benchmark-results/runs/adversarial_result_run_*.json' \
        --bench-out backend/benchmark-results/benchmark_sign_result.json \
        --adversarial-out backend/benchmark-results/adversarial_result.json
"""

from __future__ import annotations

import argparse
import glob
import json
import statistics
from pathlib import Path

# List-of-dicts fields are matched across runs by one of these identity keys
# (first one present on the list's items wins) rather than list position,
# since scenario ordering is stable but this is more robust regardless.
LIST_KEY_CANDIDATES = ("algorithm", "vus", "id")


def merge_leaf(values: list) -> object:
    numeric = [v for v in values if isinstance(v, (int, float)) and not isinstance(v, bool)]
    if numeric:
        return statistics.median(numeric)
    for v in values:
        if v is not None:
            return v
    return None


def merge_nodes(nodes: list) -> object:
    nodes = [n for n in nodes if n is not None]
    if not nodes:
        return None

    sample = nodes[0]

    if isinstance(sample, dict):
        keys: set[str] = set()
        for n in nodes:
            keys.update(n.keys())
        return {k: merge_nodes([n.get(k) for n in nodes]) for k in keys}

    if isinstance(sample, list):
        if sample and isinstance(sample[0], dict):
            key_name = next((c for c in LIST_KEY_CANDIDATES if c in sample[0]), None)
            if key_name is not None:
                order: list = []
                seen: set = set()
                buckets: dict[object, list] = {}
                for n in nodes:
                    for item in n:
                        k = item.get(key_name)
                        if k not in seen:
                            seen.add(k)
                            order.append(k)
                        buckets.setdefault(k, []).append(item)
                return [merge_nodes(buckets[k]) for k in order]
        # No reliable identity key to align list items across runs (e.g. a
        # plain list of numbers/strings) — can't safely merge, keep first run.
        return sample

    return merge_leaf(nodes)


def load_all(pattern: str) -> list[dict]:
    paths = sorted(glob.glob(pattern))
    if not paths:
        raise FileNotFoundError(f"No files matched: {pattern}")
    return [json.loads(Path(p).read_text(encoding="utf-8")) for p in paths], paths


def aggregate(pattern: str, out_path: str, label: str) -> None:
    docs, paths = load_all(pattern)
    print(f"{label}: merging {len(docs)} run(s):")
    for p in paths:
        print(f"  - {p}")
    merged = merge_nodes(docs)
    merged["aggregation"] = {
        "method": "per-field median",
        "run_count": len(docs),
        "source_files": paths,
    }
    Path(out_path).write_text(json.dumps(merged, indent=2), encoding="utf-8")
    print(f"{label}: wrote {out_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bench-glob", required=True)
    parser.add_argument("--bench-out", required=True)
    parser.add_argument("--adversarial-glob")
    parser.add_argument("--adversarial-out")
    args = parser.parse_args()

    aggregate(args.bench_glob, args.bench_out, "benchmark")

    if args.adversarial_glob and args.adversarial_out:
        try:
            aggregate(args.adversarial_glob, args.adversarial_out, "adversarial")
        except FileNotFoundError as e:
            print(f"adversarial: skipped ({e})")


if __name__ == "__main__":
    main()

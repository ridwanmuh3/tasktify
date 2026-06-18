#!/usr/bin/env python3
"""Run or parse FN-DSA Falcon precompute ablation benchmarks."""

from __future__ import annotations

import argparse
import csv
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PKG_DIR = ROOT / "backend" / "pkg"
BENCH_RE = re.compile(
    r"^BenchmarkFalconPrecomputeAblation512/(?P<variant>\S+)-\d+\s+"
    r"(?P<iters>\d+)\s+"
    r"(?P<ns>[0-9.]+)\s+ns/op\s+"
    r"(?P<bytes>[0-9.]+)\s+B/op\s+"
    r"(?P<allocs>[0-9.]+)\s+allocs/op"
)
NS_PER_MS = 1_000_000.0
BYTES_PER_KB = 1024.0

VARIANT_NOTES = {
    "A0_Original": "Original: decode key, recompute G/hash, FFT basis, Gram, LDL tree during sign.",
    "A1_KeyMaterialDetached": "A0 + detach private-key decode, G recomputation, verifying-key hash.",
    "A2_FFTBasisDetached": "A1 + detach FFT basis b00/b01/b10/b11.",
    "A3_GramDetached": "A2 + detach Gram matrix.",
    "A4_LDLTreeDetached": "A3 + detach LDL tree; runtime uses precomputed sampler tree.",
    "A5_AllPrecomputedCombined": "A1-A4 combined through production PrecomputedSigner.",
}


@dataclass(frozen=True)
class BenchRow:
    variant: str
    iters: int
    ms_per_op: float
    kb_per_op: float
    allocs_per_op: float
    vs_a0_percent: float
    vs_a0_direction: str
    step_percent: float
    step_direction: str
    note: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Measure FN-DSA Falcon-512 ablation from original signer to detached "
            "precomputed LDL-tree signer. Reports ms/op, KB/op, and percentages."
        )
    )
    parser.add_argument(
        "--bench-output",
        type=Path,
        help="Parse existing go test benchmark output instead of running benchmark.",
    )
    parser.add_argument(
        "--benchtime",
        default="1s",
        help="Go benchmark benchtime when running. Default: 1s",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=1,
        help="Go benchmark count when running. Default: 1",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "csv"),
        default="markdown",
        help="Output format. Default: markdown",
    )
    return parser.parse_args()


def run_benchmark(benchtime: str, count: int) -> str:
    env = os.environ.copy()
    env.setdefault("GOCACHE", "/tmp/go-build-cache")
    cmd = [
        "go",
        "test",
        "./fndsa",
        "-run",
        "^$",
        "-bench",
        "^BenchmarkFalconPrecomputeAblation512/",
        "-benchmem",
        "-benchtime",
        benchtime,
        "-count",
        str(count),
    ]
    result = subprocess.run(
        cmd,
        cwd=PKG_DIR,
        env=env,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stdout)
    return result.stdout


def parse_benchmarks(text: str) -> list[BenchRow]:
    raw: list[tuple[str, int, float, float, float]] = []
    for line in text.splitlines():
        match = BENCH_RE.match(line)
        if not match:
            continue
        raw.append(
            (
                match.group("variant"),
                int(match.group("iters")),
                ns_to_ms(float(match.group("ns"))),
                bytes_to_kb(float(match.group("bytes"))),
                float(match.group("allocs")),
            )
        )

    if not raw:
        raise ValueError("no BenchmarkFalconPrecomputeAblation512 rows found")

    grouped: dict[str, list[tuple[int, float, float, float]]] = {}
    for variant, iters, ms_per_op, kb_per_op, allocs_per_op in raw:
        grouped.setdefault(variant, []).append((iters, ms_per_op, kb_per_op, allocs_per_op))

    if "A0_Original" not in grouped:
        raise ValueError("A0_Original benchmark row missing")

    by_variant = {
        variant: average_benches(values)
        for variant, values in grouped.items()
    }

    baseline_ms = by_variant["A0_Original"][1]
    previous_ms = baseline_ms
    rows: list[BenchRow] = []
    for variant in VARIANT_NOTES:
        if variant not in by_variant:
            continue
        iters, ms_per_op, kb_per_op, allocs_per_op = by_variant[variant]
        vs_a0_percent, vs_a0_direction = latency_change(baseline_ms, ms_per_op)
        if not rows:
            step_percent, step_direction = 0.0, "baseline"
        else:
            step_percent, step_direction = latency_change(previous_ms, ms_per_op)
        previous_ms = ms_per_op
        rows.append(
            BenchRow(
                variant=variant,
                iters=iters,
                ms_per_op=ms_per_op,
                kb_per_op=kb_per_op,
                allocs_per_op=allocs_per_op,
                vs_a0_percent=vs_a0_percent,
                vs_a0_direction=vs_a0_direction,
                step_percent=step_percent,
                step_direction=step_direction,
                note=VARIANT_NOTES[variant],
            )
        )
    return rows


def average_benches(values: list[tuple[int, float, float, float]]) -> tuple[int, float, float, float]:
    total = len(values)
    return (
        sum(value[0] for value in values),
        sum(value[1] for value in values) / total,
        sum(value[2] for value in values) / total,
        sum(value[3] for value in values) / total,
    )


def ns_to_ms(value: float) -> float:
    return value / NS_PER_MS


def bytes_to_kb(value: float) -> float:
    return value / BYTES_PER_KB


def latency_change(baseline: float, target: float) -> tuple[float, str]:
    if baseline == 0:
        return float("nan"), "n/a"
    if target == baseline:
        return 0.0, "same"
    if target < baseline:
        return (baseline - target) / baseline * 100, "faster"
    return (target - baseline) / baseline * 100, "slower"


def fmt_num(value: float, digits: int = 4) -> str:
    if abs(value) >= 1000:
        return f"{value:.2f}"
    return f"{value:.{digits}g}"


def print_markdown(rows: list[BenchRow], source: str) -> None:
    print("# FN-DSA Falcon Precompute Ablation")
    print()
    print(f"- Source: {source}")
    print("- Benchmark: `BenchmarkFalconPrecomputeAblation512`")
    print("- Sign input: valid JWT compact signing input, `base64url(header).base64url(payload)`.")
    print("- Percent: latency change magnitude. Lower `ms/op` is better.")
    print("- vs A0 percent: `abs(Ai ms/op - A0 ms/op) / A0 ms/op * 100`; direction says faster/slower.")
    print("- Step percent: `abs(current ms/op - previous ms/op) / previous ms/op * 100`; direction says faster/slower.")
    print("- No p-values. No effect sizes.")
    print()
    print("| Variant | ms/op | KB/op | allocs/op | vs A0 | Step | Detached component |")
    print("| --- | ---: | ---: | ---: | ---: | ---: | --- |")
    for row in rows:
        print(
            "| "
            + " | ".join(
                [
                    row.variant,
                    fmt_num(row.ms_per_op),
                    fmt_num(row.kb_per_op),
                    fmt_num(row.allocs_per_op),
                    format_change(row.vs_a0_percent, row.vs_a0_direction),
                    format_change(row.step_percent, row.step_direction),
                    row.note,
                ]
            )
            + " |"
        )


def format_change(percent: float, direction: str) -> str:
    if direction in {"baseline", "same"}:
        return direction
    if direction == "n/a":
        return "n/a"
    return f"{fmt_num(percent)}% {direction}"


def print_csv(rows: list[BenchRow]) -> None:
    fieldnames = [
        "variant",
        "iters",
        "ms_per_op",
        "kb_per_op",
        "allocs_per_op",
        "vs_a0_percent",
        "vs_a0_direction",
        "step_percent",
        "step_direction",
        "note",
    ]
    writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow(
            {
                "variant": row.variant,
                "iters": row.iters,
                "ms_per_op": row.ms_per_op,
                "kb_per_op": row.kb_per_op,
                "allocs_per_op": row.allocs_per_op,
                "vs_a0_percent": row.vs_a0_percent,
                "vs_a0_direction": row.vs_a0_direction,
                "step_percent": row.step_percent,
                "step_direction": row.step_direction,
                "note": row.note,
            }
        )


def main() -> int:
    args = parse_args()
    if args.bench_output:
        text = args.bench_output.read_text(encoding="utf-8")
        source = f"`{args.bench_output}`"
    else:
        text = run_benchmark(args.benchtime, args.count)
        source = "`go test ./fndsa -run '^$' -bench '^BenchmarkFalconPrecomputeAblation512/' -benchmem`"

    rows = parse_benchmarks(text)
    if args.format == "csv":
        print_csv(rows)
    else:
        print_markdown(rows, source)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

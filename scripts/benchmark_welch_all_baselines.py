#!/usr/bin/env python3
"""Compare benchmark algorithms with Welch independent t-test only."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

from benchmark_stat_tests import (
    DEFAULT_METRIC,
    MetricData,
    cohen_d,
    collect_metrics,
    effect_label,
    find_sample_file,
    fmt_num,
    fmt_p,
    hedges_g,
    improvement_pct,
    load_k6_samples,
    mean_diff_ci,
    read_json,
    welch_t_test,
)


DEFAULT_TARGET = "FN-DSA-Precomputed-512"


def parse_names(value: str) -> tuple[str, ...]:
    names = tuple(name.strip() for name in value.split(",") if name.strip())
    if not names:
        raise argparse.ArgumentTypeError("expected comma-separated algorithm names")
    return names


def parse_args(
    default_baselines: tuple[str, ...] | None,
    description: str,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "--input",
        type=Path,
        help="benchmark_sign_result.json path. Default: repo root or backend file.",
    )
    parser.add_argument(
        "--samples",
        type=Path,
        help="k6 JSON output path with per-iteration samples. Default: auto-detect.",
    )
    parser.add_argument(
        "--metric",
        default=DEFAULT_METRIC,
        help=f"Dot path under each algorithm object. Default: {DEFAULT_METRIC}",
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Algorithm compared against baselines. Default: {DEFAULT_TARGET}",
    )
    parser.add_argument(
        "--baselines",
        type=parse_names,
        default=default_baselines,
        help="Comma-separated baseline algorithms. Default: all algorithms except target.",
    )
    parser.add_argument(
        "--higher-is-better",
        action="store_true",
        help="Use improvement formula for metrics where higher value is better.",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "csv", "json"),
        default="markdown",
        help="Output format. Default: markdown",
    )
    return parser.parse_args()


def selected_baselines(
    metrics: dict[str, MetricData],
    target_name: str,
    requested: tuple[str, ...] | None,
) -> tuple[str, ...]:
    if target_name not in metrics:
        raise KeyError(f"target {target_name!r} not found. Choices: {', '.join(metrics)}")

    names = requested or tuple(name for name in metrics if name != target_name)
    missing = tuple(name for name in names if name not in metrics)
    if missing:
        raise KeyError(f"baseline not found: {', '.join(missing)}. Choices: {', '.join(metrics)}")
    return names


def result_row(
    target: MetricData,
    baseline: MetricData,
    higher_is_better: bool,
) -> dict[str, str]:
    test = welch_t_test(target, baseline)
    effect = cohen_d(target, baseline, higher_is_better)
    g = hedges_g(target, baseline, higher_is_better)
    ci = mean_diff_ci(target, baseline, higher_is_better)
    return {
        "target": target.algorithm,
        "baseline": baseline.algorithm,
        "target_n": str(target.n or "n/a"),
        "baseline_n": str(baseline.n or "n/a"),
        "target_mean": fmt_num(target.mean),
        "baseline_mean": fmt_num(baseline.mean),
        "target_sd": fmt_num(target.sd),
        "baseline_sd": fmt_num(baseline.sd),
        "test": test.name,
        "t_statistic": fmt_num(test.statistic),
        "p_value": fmt_p(test.p_value),
        "cohen_d": fmt_num(effect),
        "hedges_g": fmt_num(g),
        "effect_label": effect_label(g if g is not None else effect, "cohen_d"),
        "mean_diff": fmt_num(ci[0]) if ci else "n/a",
        "ci95_low": fmt_num(ci[1]) if ci else "n/a",
        "ci95_high": fmt_num(ci[2]) if ci else "n/a",
        "improvement_pct": fmt_num(improvement_pct(target, baseline, higher_is_better)),
        "detail": test.detail,
    }


def change_text(value: str, higher_is_better: bool) -> str:
    try:
        numeric = float(value)
    except ValueError:
        return f"{value}%"

    if numeric == 0:
        return "0%"

    if higher_is_better:
        label = "higher" if numeric > 0 else "lower"
    else:
        label = "faster" if numeric > 0 else "slower"
    return f"{fmt_num(abs(numeric))}% {label}"


def df_text(detail: str) -> str:
    return detail.removeprefix("df=") if detail.startswith("df=") else detail


def print_markdown(
    rows: list[dict[str, str]],
    source: Path,
    sample_source: Path | None,
    sample_count: int,
    metric: str,
    target: str,
    higher_is_better: bool,
    title: str,
) -> None:
    direction = "higher better" if higher_is_better else "lower better"
    print(f"# {title}")
    print()
    print(f"- Source: `{source}`")
    if sample_source and sample_count:
        print(f"- Samples: `{sample_source}` ({sample_count} values)")
    elif sample_source:
        print(f"- Samples: `{sample_source}` (no matching metric values; summary fallback active)")
    else:
        print("- Samples: not found; summary fallback active")
    print(f"- Metric: `{metric}` ({direction})")
    print(f"- Target: `{target}`")
    print("- Test: Welch independent t-test only.")
    print()

    for row in rows:
        print(f"## {row['target']} vs {row['baseline']}")
        print()
        print(f"| Metric | {row['target']} | {row['baseline']} |")
        print("| --- | --- | --- |")
        print(f"| n | {row['target_n']} | {row['baseline_n']} |")
        print(f"| mean (ms) | {row['target_mean']} | {row['baseline_mean']} |")
        print(f"| sd (ms) | {row['target_sd']} | {row['baseline_sd']} |")
        print()
        print(
            "| Welch t | df | p-value | Cohen's d | Hedges' g | Effect "
            "| Mean diff (ms) | 95% CI (ms) | Target change |"
        )
        print("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        print(
            "| "
            + " | ".join(
                [
                    row["t_statistic"],
                    df_text(row["detail"]),
                    row["p_value"],
                    row["cohen_d"],
                    row["hedges_g"],
                    row["effect_label"],
                    row["mean_diff"],
                    f"[{row['ci95_low']}, {row['ci95_high']}]",
                    change_text(row["improvement_pct"], higher_is_better),
                ]
            )
            + " |"
        )
        print()


def print_csv(rows: list[dict[str, str]]) -> None:
    if not rows:
        return
    writer = csv.DictWriter(sys.stdout, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)


def print_json(
    rows: list[dict[str, str]],
    source: Path,
    sample_source: Path | None,
    sample_count: int,
    metric: str,
    target: str,
    higher_is_better: bool,
) -> None:
    payload = {
        "source": str(source),
        "samples": str(sample_source) if sample_source else None,
        "sample_count": sample_count,
        "metric": metric,
        "target": target,
        "direction": "higher_is_better" if higher_is_better else "lower_is_better",
        "rows": rows,
    }
    json.dump(payload, sys.stdout, indent=2)
    print()


def run(
    *,
    title: str = "Welch T-Test: All Baseline Algorithms",
    default_baselines: tuple[str, ...] | None = None,
    description: str = "Compare target algorithm against baselines with Welch t-test only.",
) -> int:
    args = parse_args(default_baselines, description)
    source, data = read_json(args.input)
    sample_source = find_sample_file(args.samples)
    k6_samples = load_k6_samples(sample_source, args.metric)
    sample_count = sum(len(values) for values in k6_samples.values())
    metrics = collect_metrics(data, args.metric, k6_samples)
    baselines = selected_baselines(metrics, args.target, args.baselines)
    target = metrics[args.target]
    rows = [result_row(target, metrics[name], args.higher_is_better) for name in baselines]

    if args.format == "json":
        print_json(
            rows,
            source,
            sample_source,
            sample_count,
            args.metric,
            args.target,
            args.higher_is_better,
        )
    elif args.format == "csv":
        print_csv(rows)
    else:
        print_markdown(
            rows,
            source,
            sample_source,
            sample_count,
            args.metric,
            args.target,
            args.higher_is_better,
            title,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(run())

#!/usr/bin/env python3
"""Calculate benchmark improvements, effect sizes, and statistical tests."""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUTS = (
    ROOT / "benchmark-results" / "benchmark_sign_result.json",
    ROOT / "backend" / "benchmark-results" / "benchmark_sign_result.json",
    ROOT / "benchmark_sign_result.json",
    ROOT / "backend" / "benchmark_sign_result.json",
)
DEFAULT_SAMPLE_FILES = (
    ROOT / "benchmark-results" / "benchmark_sign_samples.ndjson",
    ROOT / "backend" / "benchmark-results" / "benchmark_sign_samples.ndjson",
    ROOT / "benchmark_sign_samples.ndjson",
    ROOT / "backend" / "benchmark_sign_samples.ndjson",
)
DEFAULT_METRIC = "isolated.token_generation_gc_free_ms"
DEFAULT_BASELINE = "FN-DSA-512"
SAMPLE_KEYS = ("samples", "observations", "raw_values")
K6_SAMPLE_METRICS = {
    "isolated.pure_signing_ms": "bench_pure_signing_sample",
    "isolated.pure_signing_gc_free_ms": "bench_pure_signing_gc_free_sample",
    "isolated.token_generation_ms": "bench_token_generation_sample",
    "isolated.token_generation_gc_free_ms": "bench_token_generation_gc_free_sample",
    "isolated.refresh_token_generation_ms": "bench_refresh_token_generation_sample",
    "isolated.refresh_token_generation_gc_free_ms": "bench_refresh_token_generation_gc_free_sample",
    "isolated.total_ms": "bench_total_sample",
}


@dataclass(frozen=True)
class MetricData:
    algorithm: str
    mean: float
    sd: float | None
    n: int | None
    samples: tuple[float, ...]


@dataclass(frozen=True)
class NormalityResult:
    status: str
    statistic: float | None
    p_value: float | None


@dataclass(frozen=True)
class TestResult:
    name: str
    statistic: float | None
    p_value: float | None
    detail: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Report percentage improvement, effect size, normality check, "
            "and pairwise test from benchmark_sign_result.json."
        )
    )
    parser.add_argument(
        "--input",
        type=Path,
        help="benchmark_sign_result.json path. Default: repo root or backend file.",
    )
    parser.add_argument(
        "--metric",
        default=DEFAULT_METRIC,
        help=f"Dot path under each algorithm object. Default: {DEFAULT_METRIC}",
    )
    parser.add_argument(
        "--baseline",
        default=DEFAULT_BASELINE,
        help=f"Baseline algorithm. Default: {DEFAULT_BASELINE}",
    )
    parser.add_argument(
        "--samples",
        type=Path,
        help="k6 JSON output path with per-iteration samples. Default: auto-detect benchmark_sign_samples.ndjson.",
    )
    parser.add_argument(
        "--alpha",
        type=float,
        default=0.05,
        help="Significance level for normality decision. Default: 0.05",
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


def read_json(path: Path | None) -> tuple[Path, dict]:
    candidates = (path,) if path else DEFAULT_INPUTS
    for candidate in candidates:
        if candidate and candidate.is_file():
            return candidate, json.loads(candidate.read_text(encoding="utf-8"))

    checked = "\n".join(f"  - {candidate}" for candidate in candidates if candidate)
    raise FileNotFoundError(f"benchmark result not found. Checked:\n{checked}")


def find_sample_file(path: Path | None) -> Path | None:
    if path:
        if path.is_file():
            return path
        raise FileNotFoundError(f"k6 sample file not found: {path}")

    for candidate in DEFAULT_SAMPLE_FILES:
        if candidate.is_file():
            return candidate
    return None


def load_k6_samples(path: Path | None, metric_path: str) -> dict[str, tuple[float, ...]]:
    if path is None:
        return {}

    metric_name = K6_SAMPLE_METRICS.get(metric_path)
    if metric_name is None:
        return {}

    samples: dict[str, list[float]] = {}
    with path.open(encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON in {path}:{line_no}: {exc}") from exc

            if item.get("type") != "Point":
                continue
            data = item.get("data") or {}
            if (item.get("metric") or data.get("metric")) != metric_name:
                continue

            value = as_float(data.get("value"))
            tags = data.get("tags") or {}
            algorithm = tags.get("alg")
            if value is None or not algorithm:
                continue
            samples.setdefault(str(algorithm), []).append(value)

    return {algorithm: tuple(values) for algorithm, values in samples.items()}


def get_path(data: dict, path: str) -> object:
    current: object = data
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            raise KeyError(path)
        current = current[part]
    return current


def as_float(value: object) -> float | None:
    if value is None:
        return None
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return None
    if math.isnan(numeric) or math.isinf(numeric):
        return None
    return numeric


def as_samples(value: object) -> tuple[float, ...]:
    if isinstance(value, dict):
        for key in SAMPLE_KEYS:
            found = as_samples(value.get(key))
            if found:
                return found
        return ()
    if not isinstance(value, list):
        return ()

    samples: list[float] = []
    for item in value:
        numeric = as_float(item)
        if numeric is None:
            return ()
        samples.append(numeric)
    return tuple(samples)


def metric_n(algorithm: dict, metric_path: str, samples: tuple[float, ...]) -> int | None:
    if samples:
        return len(samples)

    isolated = algorithm.get("isolated", {})
    if not isinstance(isolated, dict):
        return None

    iterations = isolated.get("iterations")
    try:
        n = int(iterations)
    except (TypeError, ValueError):
        return None

    if "gc_free" in metric_path:
        try:
            return n - int(isolated.get("gc_contaminated_count", 0))
        except (TypeError, ValueError):
            return n
    return n


def metric_mean(value: object, samples: tuple[float, ...]) -> float | None:
    if samples:
        return mean(samples)
    if isinstance(value, dict):
        return as_float(value.get("avg"))
    return as_float(value)


def metric_sd(value: object, samples: tuple[float, ...]) -> float | None:
    if len(samples) >= 2:
        return sample_sd(samples)
    if isinstance(value, dict):
        return as_float(value.get("sd"))
    return None


def collect_metrics(
    data: dict,
    metric_path: str,
    k6_samples: dict[str, tuple[float, ...]],
) -> dict[str, MetricData]:
    metrics: dict[str, MetricData] = {}
    for item in data.get("algorithms", []):
        if not isinstance(item, dict):
            continue
        algorithm = str(item.get("algorithm", ""))
        if not algorithm:
            continue
        value = get_path(item, metric_path)
        samples = as_samples(value) or k6_samples.get(algorithm, ())
        metric = MetricData(
            algorithm=algorithm,
            mean=required_float(metric_mean(value, samples), f"{algorithm} mean"),
            sd=metric_sd(value, samples),
            n=metric_n(item, metric_path, samples),
            samples=samples,
        )
        metrics[algorithm] = metric
    return metrics


def required_float(value: float | None, label: str) -> float:
    if value is None:
        raise ValueError(f"{label} missing or not numeric")
    return value


def mean(values: Iterable[float]) -> float:
    values = tuple(values)
    return sum(values) / len(values)


def sample_sd(values: Iterable[float]) -> float:
    values = tuple(values)
    if len(values) < 2:
        return math.nan
    m = mean(values)
    variance = sum((value - m) ** 2 for value in values) / (len(values) - 1)
    return math.sqrt(variance)


def jarque_bera_normality(samples: tuple[float, ...], alpha: float) -> NormalityResult:
    n = len(samples)
    if n < 8:
        return NormalityResult("unavailable", None, None)

    m = mean(samples)
    diffs = [value - m for value in samples]
    m2 = sum(value**2 for value in diffs) / n
    if m2 == 0:
        return NormalityResult("normal", 0.0, 1.0)

    m3 = sum(value**3 for value in diffs) / n
    m4 = sum(value**4 for value in diffs) / n
    skew = m3 / (m2**1.5)
    excess_kurtosis = m4 / (m2**2) - 3
    statistic = n / 6 * (skew**2 + (excess_kurtosis**2) / 4)
    p_value = math.exp(-statistic / 2)
    status = "normal" if p_value >= alpha else "not_normal"
    return NormalityResult(status, statistic, p_value)


def normal_cdf(value: float) -> float:
    return 0.5 * (1 + math.erf(value / math.sqrt(2)))


def betacf(a: float, b: float, x: float) -> float:
    max_iter = 200
    eps = 3e-14
    fpmin = 1e-300

    qab = a + b
    qap = a + 1
    qam = a - 1
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < fpmin:
        d = fpmin
    d = 1.0 / d
    h = d

    for m in range(1, max_iter + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < fpmin:
            d = fpmin
        c = 1.0 + aa / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        h *= d * c

        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < fpmin:
            d = fpmin
        c = 1.0 + aa / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < eps:
            break

    return h


def regularized_beta(a: float, b: float, x: float) -> float:
    if x <= 0:
        return 0.0
    if x >= 1:
        return 1.0

    log_bt = (
        math.lgamma(a + b)
        - math.lgamma(a)
        - math.lgamma(b)
        + a * math.log(x)
        + b * math.log1p(-x)
    )
    bt = math.exp(log_bt)
    if x < (a + 1) / (a + b + 2):
        return bt * betacf(a, b, x) / a
    return 1 - bt * betacf(b, a, 1 - x) / b


def student_t_cdf(value: float, df: float) -> float:
    if df <= 0:
        return math.nan
    x = df / (df + value * value)
    ibeta = regularized_beta(df / 2, 0.5, x)
    if value >= 0:
        return 1 - 0.5 * ibeta
    return 0.5 * ibeta


def welch_t_test(left: MetricData, right: MetricData) -> TestResult:
    if left.sd is None or right.sd is None or not left.n or not right.n:
        return TestResult("not_available", None, None, "mean/sd/n required")
    if left.n < 2 or right.n < 2:
        return TestResult("not_available", None, None, "n must be >= 2")

    left_var = left.sd**2 / left.n
    right_var = right.sd**2 / right.n
    se = math.sqrt(left_var + right_var)
    if se == 0:
        return TestResult("welch_independent_t", 0.0, 1.0, "zero variance")

    statistic = (left.mean - right.mean) / se
    df_denominator = (left_var**2 / (left.n - 1)) + (right_var**2 / (right.n - 1))
    if df_denominator == 0:
        return TestResult("welch_independent_t", statistic, None, "df unavailable")
    df = (left_var + right_var) ** 2 / df_denominator
    p_value = 2 * min(student_t_cdf(statistic, df), 1 - student_t_cdf(statistic, df))
    return TestResult("welch_independent_t", statistic, p_value, f"df={df:.2f}")


def mann_whitney_u_test(left: MetricData, right: MetricData) -> TestResult:
    if not left.samples or not right.samples:
        return TestResult("not_available", None, None, "raw samples required")

    n1 = len(left.samples)
    n2 = len(right.samples)
    combined = sorted((value, 0) for value in left.samples) + sorted((value, 1) for value in right.samples)
    combined.sort(key=lambda pair: pair[0])

    ranks: list[tuple[int, float]] = []
    tie_counts: list[int] = []
    idx = 0
    while idx < len(combined):
        end = idx + 1
        while end < len(combined) and combined[end][0] == combined[idx][0]:
            end += 1
        rank = (idx + 1 + end) / 2
        tie_counts.append(end - idx)
        for item_idx in range(idx, end):
            ranks.append((combined[item_idx][1], rank))
        idx = end

    rank_sum_left = sum(rank for group, rank in ranks if group == 0)
    u1 = rank_sum_left - n1 * (n1 + 1) / 2
    total = n1 + n2
    mean_u = n1 * n2 / 2
    tie_term = sum(count**3 - count for count in tie_counts)
    variance = n1 * n2 / 12 * (total + 1 - tie_term / (total * (total - 1)))
    if variance <= 0:
        return TestResult("mann_whitney_u", u1, None, "variance unavailable")

    correction = 0.5 if u1 > mean_u else -0.5 if u1 < mean_u else 0.0
    z = (u1 - mean_u - correction) / math.sqrt(variance)
    p_value = 2 * (1 - normal_cdf(abs(z)))
    return TestResult("mann_whitney_u", u1, p_value, f"z={z:.4g}")


def cohen_d(left: MetricData, right: MetricData, higher_is_better: bool) -> float | None:
    if left.sd is None or right.sd is None or not left.n or not right.n:
        return None
    if left.n < 2 or right.n < 2:
        return None

    pooled_num = (left.n - 1) * left.sd**2 + (right.n - 1) * right.sd**2
    pooled_den = left.n + right.n - 2
    if pooled_den <= 0:
        return None
    pooled = math.sqrt(pooled_num / pooled_den)
    if pooled == 0:
        return None

    diff = left.mean - right.mean if higher_is_better else right.mean - left.mean
    return diff / pooled


def rank_biserial(left: MetricData, right: MetricData, higher_is_better: bool) -> float | None:
    if not left.samples or not right.samples:
        return None
    greater = 0.0
    lower = 0.0
    for left_value in left.samples:
        for right_value in right.samples:
            if left_value > right_value:
                greater += 1
            elif left_value < right_value:
                lower += 1
    total = len(left.samples) * len(right.samples)
    if total == 0:
        return None
    effect = (greater - lower) / total
    return effect if higher_is_better else -effect


def effect_label(value: float | None, kind: str) -> str:
    if value is None:
        return "n/a"
    magnitude = abs(value)
    if kind == "rank_biserial":
        if magnitude >= 0.5:
            return "large"
        if magnitude >= 0.3:
            return "medium"
        if magnitude >= 0.1:
            return "small"
        return "negligible"

    if magnitude >= 0.8:
        return "large"
    if magnitude >= 0.5:
        return "medium"
    if magnitude >= 0.2:
        return "small"
    return "negligible"


def improvement_pct(left: MetricData, right: MetricData, higher_is_better: bool) -> float:
    if right.mean == 0:
        return math.nan
    if higher_is_better:
        return (left.mean - right.mean) / right.mean * 100
    return (right.mean - left.mean) / right.mean * 100


def choose_test(left: MetricData, right: MetricData, alpha: float) -> tuple[NormalityResult, NormalityResult, TestResult, str]:
    left_norm = jarque_bera_normality(left.samples, alpha) if left.samples else NormalityResult("unavailable", None, None)
    right_norm = jarque_bera_normality(right.samples, alpha) if right.samples else NormalityResult("unavailable", None, None)

    if left_norm.status == "normal" and right_norm.status == "normal":
        return left_norm, right_norm, welch_t_test(left, right), "cohen_d"
    if left_norm.status == "not_normal" or right_norm.status == "not_normal":
        return left_norm, right_norm, mann_whitney_u_test(left, right), "rank_biserial"

    return left_norm, right_norm, welch_t_test(left, right), "cohen_d"


def fmt_num(value: float | None, digits: int = 4) -> str:
    if value is None or math.isnan(value):
        return "n/a"
    if abs(value) >= 1000:
        return f"{value:.2f}"
    return f"{value:.{digits}g}"


def fmt_p(value: float | None) -> str:
    if value is None or math.isnan(value):
        return "n/a"
    if value == 0:
        return "<1e-300"
    return fmt_num(value)


def result_rows(
    metrics: dict[str, MetricData],
    baseline_name: str,
    alpha: float,
    higher_is_better: bool,
) -> list[dict[str, str]]:
    if baseline_name not in metrics:
        choices = ", ".join(metrics)
        raise KeyError(f"baseline {baseline_name!r} not found. Choices: {choices}")

    baseline = metrics[baseline_name]
    rows: list[dict[str, str]] = []
    for name, metric in metrics.items():
        if name == baseline_name:
            continue

        left_norm, right_norm, test, effect_kind = choose_test(metric, baseline, alpha)
        effect = (
            rank_biserial(metric, baseline, higher_is_better)
            if effect_kind == "rank_biserial"
            else cohen_d(metric, baseline, higher_is_better)
        )
        rows.append(
            {
                "algorithm": name,
                "baseline": baseline_name,
                "n": str(metric.n or "n/a"),
                "baseline_n": str(baseline.n or "n/a"),
                "mean": fmt_num(metric.mean),
                "baseline_mean": fmt_num(baseline.mean),
                "sd": fmt_num(metric.sd),
                "baseline_sd": fmt_num(baseline.sd),
                "normality": left_norm.status,
                "baseline_normality": right_norm.status,
                "test": test.name,
                "statistic": fmt_num(test.statistic),
                "p_value": fmt_p(test.p_value),
                "effect_size": fmt_num(effect),
                "effect_type": effect_kind,
                "effect_label": effect_label(effect, effect_kind),
                "improvement_pct": fmt_num(improvement_pct(metric, baseline, higher_is_better)),
                "detail": test.detail,
            }
        )
    return rows


def print_markdown(
    rows: list[dict[str, str]],
    source: Path,
    sample_source: Path | None,
    sample_count: int,
    metric: str,
    baseline: str,
    higher_is_better: bool,
) -> None:
    direction = "higher better" if higher_is_better else "lower better"
    print("# Benchmark Statistical Tests")
    print()
    print(f"- Source: `{source}`")
    if sample_source and sample_count:
        print(f"- Samples: `{sample_source}` ({sample_count} values)")
    elif sample_source:
        print(f"- Samples: `{sample_source}` (no matching metric values; summary fallback active)")
    else:
        print("- Samples: not found; summary fallback active")
    print(f"- Metric: `{metric}` ({direction})")
    print(f"- Baseline: `{baseline}`")
    print("- Normality: Jarque-Bera when raw samples exist; unavailable for summary-only JSON.")
    print("- Test rule: normal -> Welch independent t-test; not normal -> Mann-Whitney U.")
    print("- Summary-only fallback: Welch t-test from mean/sd/n; Mann-Whitney cannot run without raw samples.")
    print()

    headers = [
        "algorithm",
        "n",
        "mean",
        "baseline_mean",
        "sd",
        "normality",
        "baseline_normality",
        "test",
        "statistic",
        "p_value",
        "effect_type",
        "effect_size",
        "effect_label",
        "improvement_pct",
    ]
    print("| " + " | ".join(headers) + " |")
    print("| " + " | ".join(["---"] * len(headers)) + " |")
    for row in rows:
        print("| " + " | ".join(row[key] for key in headers) + " |")


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
    baseline: str,
    higher_is_better: bool,
) -> None:
    payload = {
        "source": str(source),
        "samples": str(sample_source) if sample_source else None,
        "sample_count": sample_count,
        "metric": metric,
        "baseline": baseline,
        "direction": "higher_is_better" if higher_is_better else "lower_is_better",
        "rows": rows,
    }
    json.dump(payload, sys.stdout, indent=2)
    print()


def main() -> int:
    args = parse_args()
    source, data = read_json(args.input)
    sample_source = find_sample_file(args.samples)
    k6_samples = load_k6_samples(sample_source, args.metric)
    sample_count = sum(len(values) for values in k6_samples.values())
    metrics = collect_metrics(data, args.metric, k6_samples)
    rows = result_rows(metrics, args.baseline, args.alpha, args.higher_is_better)

    if args.format == "json":
        print_json(
            rows,
            source,
            sample_source,
            sample_count,
            args.metric,
            args.baseline,
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
            args.baseline,
            args.higher_is_better,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

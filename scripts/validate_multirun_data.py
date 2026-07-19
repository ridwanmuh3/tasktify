#!/usr/bin/env python3
"""Validate everything generate_multirun_figures.py parsed, aggregated and drew.

The figures are only as trustworthy as the console-report scraping behind them,
and a regex parser that silently matches the wrong column produces plausible
numbers. So every check here is an *independent* recomputation, not a re-read of
the same code path:

  1. coverage       every result*.txt on disk made it into the aggregate
  2. structure      6 algorithms x 3 tables x VU{10,30,50}, N=100 iterations
  3. parse fidelity naive whitespace split of each table vs the regex parser
  4. quartiles      q1 <= median <= q3, non-negative
  5. aggregation    multirun_data.csv recomputed from multirun_raw.csv
  6. skew           avg > p95 is NOT an error: with a tail heavier than the top
                    5% of samples the mean exceeds p95 legitimately (measured:
                    HS256 stress refresh 30VU is med 0.008, p95 0.015, max 3.743,
                    avg 0.024). Reported as a skew indicator, since it marks
                    exactly the cells where a mean must not be quoted.
  7. quantization   CPU/token values must sit on the 0.05 ms tick grid
  8. outliers       cells >3x their own cross-run median (host noise, expected;
                    reported so the reader knows why median+IQR is used)

Exit code is non-zero only for checks that invalidate a figure. Outliers and the
sub-millisecond p95 anomalies are reported but do not fail: they are properties
of the host and the harness, not of this aggregation.
"""

from __future__ import annotations

import csv
import glob
import statistics as st
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import generate_multirun_figures as m  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = m.OUT_DIR
VU_LEVELS = (10, 30, 50)
STRESS_DURATION_S = 30  # backend/k6/benchmark_sign.js

# (section marker, end marker, column names) for the two VU tables. The isolated
# table is handled separately because it has no VU column.
TABLE_SPEC = {
    "stress": ("SUPPORTING SYSTEM METRICS", "SECONDARY METRICS",
               ["access_avg", "access_p95", "refresh_avg", "refresh_p95", "token_ok_s"]),
    "secondary": ("SECONDARY METRICS", "Pure avg/p95 =",
                  ["login_avg", "login_p95", "refresh_avg", "refresh_p95",
                   "e2e_avg", "e2e_p95", "rps"]),
}
ISO_KEYS = ["pure_avg", "pure_p95", "access_avg", "access_p95",
            "refresh_avg", "refresh_p95", "e2e_avg", "cpu_per_tok", "rss_kb"]

# Which table each drawn figure reads from, so a finding can be labelled as
# affecting a figure or as parsed-but-never-plotted.
PLOTTED = {"isolated": "mrun_01..08", "secondary": "mrun_09..13"}

findings: list[dict] = []
fatal = 0


def record(check: str, severity: str, subject: str, detail: str) -> None:
    findings.append({"check": check, "severity": severity, "subject": subject, "detail": detail})


def section(title: str, failures: int, note: str = "") -> None:
    status = "FAIL" if failures else "pass"
    print(f"  [{status}] {title}" + (f" -- {note}" if note else ""))


def find(lines: list[str], pat: str, default):
    for i, line in enumerate(lines):
        if pat in line:
            return i
    return default


def naive_tables(path: Path) -> tuple[dict, dict]:
    """Re-extract both table families by whitespace splitting, ignoring the regexes."""
    lines = path.read_text(encoding="utf-8", errors="replace").split("\n")
    iso: dict = {}
    lo = find(lines, "PRIMARY THESIS METRIC", 0)
    hi = find(lines, "SUPPORTING SYSTEM METRICS", len(lines))
    for line in lines[lo:hi]:
        tok = line.split()
        if tok and tok[0] in m.ALGS and len(tok) >= 11:
            iso[tok[0]] = {"iters": tok[1],
                           **dict(zip(ISO_KEYS, [float(x) for x in tok[2:11]]))}

    vu: dict = {t: defaultdict(dict) for t in TABLE_SPEC}
    for table, (start, end, keys) in TABLE_SPEC.items():
        lo = find(lines, start, 0)
        hi = find(lines, end, len(lines))
        cur = None
        for line in lines[lo:hi]:
            tok = line.split()
            if not tok:
                continue
            if tok[0] in m.ALGS:
                cur, tok = tok[0], tok[1:]
            elif not (cur and line.startswith(" " * 20)):
                continue
            if not tok or not tok[0].isdigit() or int(tok[0]) not in VU_LEVELS:
                continue
            if len(tok) < 1 + len(keys):
                continue
            try:
                vals = [float(x) for x in tok[1:1 + len(keys)]]
            except ValueError:
                continue
            vu[table][cur][int(tok[0])] = dict(zip(keys, vals))
    return iso, vu


def main() -> int:
    global fatal
    print(f"validating aggregate in {OUT_DIR}\n")
    runs = m.load_runs()
    by_file = {r["file"]: r for r in runs}
    disk = sorted((Path(p) for p in glob.glob(str(ROOT / "result*.txt"))),
                  key=lambda p: (len(p.name), p.name))

    # 1. coverage
    missed = [p.name for p in disk if p.name not in by_file]
    for name in missed:
        record("coverage", "fatal", name, "result file on disk was not aggregated")
    fatal += len(missed)
    section(f"coverage: {len(by_file)}/{len(disk)} result files aggregated", len(missed))

    # 2. structure
    bad = 0
    for r in runs:
        for table in ("isolated", "stress", "secondary"):
            if len(r[table]) != len(m.ALGS):
                record("structure", "fatal", f"{r['file']}:{table}",
                       f"{len(r[table])} algorithms, expected {len(m.ALGS)}")
                bad += 1
        for table in ("stress", "secondary"):
            for alg, vus in r[table].items():
                if sorted(vus) != list(VU_LEVELS):
                    record("structure", "fatal", f"{r['file']}:{table}:{alg}",
                           f"VU levels {sorted(vus)}, expected {list(VU_LEVELS)}")
                    bad += 1
    fatal += bad
    section("structure: 6 algorithms x 3 tables x VU{10,30,50}", bad)

    # 3. parse fidelity + iteration count
    bad = 0
    for path in disk:
        if path.name not in by_file:
            continue
        iso, vu = naive_tables(path)
        run = by_file[path.name]
        for alg, cols in iso.items():
            if cols["iters"] != "100":
                record("iterations", "warn", f"{path.name}:{alg}",
                       f"N={cols['iters']}, expected 100")
            got = [run["isolated"][alg][k] for k in ISO_KEYS]
            exp = [cols[k] for k in ISO_KEYS]
            if got != exp:
                record("parse", "fatal", f"{path.name}:isolated:{alg}", f"{exp} != {got}")
                bad += 1
        for table, (_, _, keys) in TABLE_SPEC.items():
            for alg, levels in vu[table].items():
                for level, cols in levels.items():
                    got = [run[table][alg][level][k] for k in keys]
                    exp = [cols[k] for k in keys]
                    if got != exp:
                        record("parse", "fatal", f"{path.name}:{table}:{alg}:{level}VU",
                               f"{exp} != {got}")
                        bad += 1
    fatal += bad
    section("parse fidelity: independent whitespace re-parse of every table", bad)

    # 4/5. aggregate CSV recomputed from the raw CSV
    raw = list(csv.DictReader((OUT_DIR / "multirun_raw.csv").open()))
    agg = list(csv.DictReader((OUT_DIR / "multirun_data.csv").open()))
    buckets = defaultdict(list)
    for row in raw:
        buckets[(row["scenario"], row["algorithm"], row["vus"], row["metric"])].append(
            float(row["value"]))

    bad = checked = 0
    for row in agg:
        if row["q1"] == "":
            continue
        q1, med, q3 = float(row["q1"]), float(row["median"]), float(row["q3"])
        if not (q1 <= med <= q3) or min(q1, med, q3) < 0:
            record("quartiles", "fatal", f"{row['figure']}:{row['algorithm']}",
                   f"q1={q1} median={med} q3={q3}")
            bad += 1
        key = (row["scenario"], row["algorithm"], row["vus"], row["metric"])
        values = buckets.get(key)
        if values is None:
            continue  # attack / profile rows have no raw counterpart
        checked += 1
        if len(values) != int(row["runs"]):
            record("aggregation", "fatal", str(key),
                   f"{len(values)} raw values, CSV claims runs={row['runs']}")
            bad += 1
        exp_q1, exp_med, exp_q3 = m.quartiles(values)
        # Figures may rescale for display (KB->MB); the CSV must stay native, so
        # compare against the unscaled recomputation.
        for label, expected, actual in (("median", exp_med, med), ("q1", exp_q1, q1),
                                        ("q3", exp_q3, q3)):
            if abs(round(expected, 4) - actual) > 1e-9:
                record("aggregation", "fatal", f"{key}:{label}",
                       f"raw gives {round(expected, 4)}, CSV has {actual}")
                bad += 1
    fatal += bad
    section(f"aggregation: {checked} CSV rows recomputed from {len(raw)} raw values", bad)

    # 6. skew: avg > p95 flags a tail heavy enough that the mean is unusable.
    skewed = 0
    for r in runs:
        checks = [("isolated", None, r["isolated"], ("pure", "access", "refresh"))]
        for table, prefixes in (("stress", ("access", "refresh")),
                                ("secondary", ("login", "refresh", "e2e"))):
            for level in VU_LEVELS:
                checks.append((table, level, {a: r[table][a][level] for a in m.ALGS}, prefixes))
        for table, level, data, prefixes in checks:
            for alg in m.ALGS:
                for pre in prefixes:
                    avg, p95 = data[alg][f"{pre}_avg"], data[alg][f"{pre}_p95"]
                    if avg > p95:
                        where = PLOTTED.get(table, "not plotted")
                        record("skew", "warn",
                               f"{r['file']}:{table}:{alg}:{level or '-'}:{pre}",
                               f"avg {avg} > p95 {p95}: tail beyond p95 dominates the mean, "
                               f"quote median not mean (figures: {where})")
                        skewed += 1
    section("skew: cells where the mean exceeds p95", 0,
            f"{skewed} flagged (warn; mean unusable there, median required)")

    # 7. CPU/token must land on the tick grid
    off_grid = 0
    for r in runs:
        for alg in m.ALGS:
            v = r["isolated"][alg]["cpu_per_tok"]
            steps = v / m.CPU_TICK_QUANTUM_MS
            if abs(steps - round(steps)) > 1e-6:
                record("quantization", "fatal", f"{r['file']}:{alg}",
                       f"cpu_per_tok {v} is not a multiple of {m.CPU_TICK_QUANTUM_MS}")
                off_grid += 1
    fatal += off_grid
    section(f"quantization: CPU/token on the {m.CPU_TICK_QUANTUM_MS} ms tick grid", off_grid)

    # 8b. k6 trend internal ordering. Only the newest sweep keeps its raw JSON, but
    # min <= med <= p90 <= p95 <= p99 <= max IS guaranteed for any sample, unlike
    # avg vs p95. A break here means the metric aggregation itself is wrong.
    raw_json = ROOT / "backend" / "benchmark-results" / "benchmark_sign_raw.json"
    if raw_json.exists():
        import json
        metrics = json.loads(raw_json.read_text()).get("metrics", {})
        order = ["min", "med", "p(90)", "p(95)", "p(99)", "max"]
        bad_order = trends = 0
        for key, body in sorted(metrics.items()):
            vals = body.get("values", {})
            got = [(s, vals[s]) for s in order if isinstance(vals.get(s), (int, float))]
            if len(got) < 2:
                continue
            trends += 1
            for (s1, v1), (s2, v2) in zip(got, got[1:]):
                if v1 > v2:
                    record("percentile-order", "fatal", key, f"{s1}={v1} > {s2}={v2}")
                    bad_order += 1
            avg = vals.get("avg")
            if isinstance(avg, (int, float)) and not (vals["min"] <= avg <= vals["max"]):
                record("percentile-order", "fatal", key,
                       f"avg={avg} outside [min={vals['min']}, max={vals['max']}]")
                bad_order += 1
        fatal += bad_order
        section(f"percentile order: min<=med<=p90<=p95<=p99<=max over {trends} k6 trends",
                bad_order)
    else:
        section("percentile order: skipped, benchmark_sign_raw.json absent", 0)

    # 8c. derived rates. Both rate columns are count/STRESS_DURATION_S printed with
    # toFixed(2), so multiplying back by the window must land on an integer count
    # within the rounding budget. rps counts successes+failures, token_ok_s counts
    # successes only, so rps >= token_ok_s must hold.
    rate_tol = 0.5 * 0.01 * STRESS_DURATION_S + 1e-9
    bad_rate = 0
    for r in runs:
        for alg in m.ALGS:
            for level in VU_LEVELS:
                rps = r["secondary"][alg][level]["rps"]
                ok = r["stress"][alg][level]["token_ok_s"]
                if rps < ok - 1e-9:
                    record("rates", "fatal", f"{r['file']}:{alg}:{level}VU",
                           f"rps {rps} < token_ok_s {ok}, but rps counts a superset")
                    bad_rate += 1
                for name, v in (("rps", rps), ("token_ok_s", ok)):
                    count = v * STRESS_DURATION_S
                    if abs(count - round(count)) > rate_tol:
                        record("rates", "fatal", f"{r['file']}:{alg}:{level}VU:{name}",
                               f"{v} implies non-integer count {count:.3f} over "
                               f"{STRESS_DURATION_S}s")
                        bad_rate += 1
    fatal += bad_rate
    section(f"rates: rps >= token_ok_s and both = integer count/{STRESS_DURATION_S}s", bad_rate)

    # 8. outliers
    cells = defaultdict(list)
    for r in runs:
        for alg in m.ALGS:
            for k, v in r["isolated"][alg].items():
                cells[("isolated", alg, "", k)].append((v, r["file"]))
            for table in ("stress", "secondary"):
                for level in VU_LEVELS:
                    for k, v in r[table][alg][level].items():
                        cells[(table, alg, level, k)].append((v, r["file"]))
    n_out = 0
    for (table, alg, level, metric), vals in sorted(cells.items()):
        med = st.median([v for v, _ in vals])
        if med <= 0:
            continue
        for v, f in vals:
            if v > 3 * med:
                record("outlier", "info", f"{f}:{table}:{alg}:{level or '-'}:{metric}",
                       f"{v:.3f} = {v / med:.1f}x cross-run median {med:.3f} "
                       f"(figures: {PLOTTED.get(table, 'not plotted')})")
                n_out += 1
    section("outliers: cells >3x their cross-run median", 0,
            f"{n_out} flagged (info; why median+IQR is used)")

    out = OUT_DIR / "multirun_validation.csv"
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["check", "severity", "subject", "detail"])
        writer.writeheader()
        writer.writerows(findings)

    counts = defaultdict(int)
    for f in findings:
        counts[f["severity"]] += 1
    print(f"\n{len(findings)} findings -> {out.name} "
          f"(fatal {counts['fatal']}, warn {counts['warn']}, info {counts['info']})")
    print("RESULT:", "INVALID" if fatal else "VALID -- every figure traces to verified data")
    return 1 if fatal else 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Aggregate figures across every result*.txt benchmark report (n runs).

Why this exists next to generate_article_graphics.py: that script draws one
benchmark_sign_result.json (a single k6 sweep, or the 3-run median produced by
`make bench-figures-repeat`). The repo also accumulated 20 full independent
sweeps as result*.txt console reports. Those 20 runs are the only data set
large enough to show *how consistently* a difference reproduces, which is what
separates a real effect from host noise on this shared VPS.

Estimator: median across runs, with an interquartile range (Q1-Q3) whisker.
Median because the per-run distributions are right-skewed under load (GC and
scheduler tails; see docs/skenario-pengujian.md 5.6) and the mean inverts the
ranking on those metrics. IQR rather than a CI because n=20 raw run outputs
are not independent samples of a stationary process (the host carries
unrelated load that drifts between runs), so a parametric CI would overstate
precision.

Reuses the palette, fonts, and drawing helpers of generate_article_graphics.py
so both figure sets are visually one system.
"""

from __future__ import annotations

import csv
import glob
import json
import os
import re
import statistics as st
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = Path(os.environ.get("MULTIRUN_GRAPHICS_DIR", ROOT / "figures" / "multirun"))
os.environ["ARTICLE_GRAPHICS_DIR"] = str(OUT_DIR)

sys.path.insert(0, str(Path(__file__).resolve().parent))
import generate_article_graphics as g  # noqa: E402

# "Zoom" the aggregate figures: tighten the outer margins so the plotted content
# fills the frame, and enlarge every text size for readability. Process-local
# overrides on the shared drawing module — only this script's figures change,
# the article set (separate process) keeps its own scale.
g.MARGIN = {"left": 165, "right": 70, "top": 88, "bottom": 200}
g.TICK_SIZE = 28
g.AXIS_SIZE = 31
g.VALUE_SIZE = 36          # boxed median number over each bar/marker — enlarged for Word
g.STRESS_VALUE_SIZE = 29   # value labels on the VU trend points
g.LEGEND_SIZE = 29
g.LEGEND_TITLE_SIZE = 31

# Standard categorical palette at moderate saturation (colorful but not vibrant,
# per request). Recognizable blue/orange/green/purple/red/teal hues. Validated
# CVD-safe on a light surface via the dataviz skill's validate_palette.js — all
# six slots PASS lightness/chroma/CVD-separation/contrast. FN-DSA pair is the
# standard high-contrast blue↔orange. Fixed hue order, never cycled.
g.COLORS = {
    "FN-DSA-Precomputed-512": "#3d7fd0",  # blue    (proposed)
    "FN-DSA-512": "#d9791f",              # orange  (PQC baseline)
    "HS256": "#3f9e57",                   # green
    "RS256": "#8560ad",                   # purple
    "ES256": "#d1454e",                   # red
    "EdDSA": "#0e9d92",                   # teal
}

ALGS = g.ALGORITHM_ORDER
NUM = r"[-+]?\d+(?:\.\d+)?"
PRECOMP = "FN-DSA-Precomputed-512"
DYNAMIC = "FN-DSA-512"
WHISKER = "#22303C"

# ALGS is the *parse* set and must stay complete: every report contains all six
# algorithms and load_runs() rejects a report that is missing any of them.
# PLOT_ALGS is the *draw* set. Narrowing it to the two FN-DSA profiles gives the
# thesis' actual comparison without the four baselines compressing the scale --
# HS256 at 0.002 ms and RS256 at 1.2 ms span three orders of magnitude, which
# forces a log axis and leaves the precomputed-vs-dynamic gap visually flat.
#   MULTIRUN_PLOT_ALGS="FN-DSA-Precomputed-512,FN-DSA-512" python3 ...
PLOT_ALGS = [a.strip() for a in os.environ.get("MULTIRUN_PLOT_ALGS", "").split(",") if a.strip()]
if not PLOT_ALGS:
    PLOT_ALGS = list(ALGS)
unknown = [a for a in PLOT_ALGS if a not in ALGS]
if unknown:
    raise SystemExit(f"MULTIRUN_PLOT_ALGS: unknown algorithm(s) {unknown}; known: {ALGS}")

# The precompute-vs-dynamic comparison set (the two FN-DSA profiles only). Its VU
# figures stay trend lines to show the scaling shape; every other set draws the
# stress figures as grouped bars.
FNDSA_COMPARISON = set(PLOT_ALGS) == {PRECOMP, DYNAMIC}

# A log axis earns its place only when the series really do span orders of
# magnitude. Below this ratio it just makes near-equal bars look near-equal in a
# harder-to-read way, so a requested log scale silently falls back to linear.
LOG_SCALE_MIN_RATIO = 20.0

# Smallest non-zero CPU/token the harness can report. readCPUTicks() reads
# utime+stime from /proc/self/stat in USER_HZ=100 clock ticks (10 ms each);
# benchmark_handler.go averages over ITERATIONS iterations and halves the sum to
# go from access+refresh to per-token. One single tick anywhere in a run therefore
# shows up as 0.05 ms/token, and everything finer than that reads as 0.00.
CPU_TICK_MS = 10.0
ITERATIONS = 100
CPU_TICK_QUANTUM_MS = CPU_TICK_MS / ITERATIONS * 0.5


# ───────────────────────────── parsing ──────────────────────────────


def parse_report(path: Path) -> dict:
    """Extract the three result tables from one k6 console report."""
    lines = path.read_text(encoding="utf-8", errors="replace").split("\n")
    out: dict = {"file": path.name, "isolated": {}, "stress": {}, "secondary": {}}

    def idx(pat: str, default=None):
        for i, line in enumerate(lines):
            if pat in line:
                return i
        return default

    i_iso = idx("PRIMARY THESIS METRIC", 0)
    i_str = idx("SUPPORTING SYSTEM METRICS", len(lines))
    i_sec = idx("SECONDARY METRICS", len(lines))
    i_end = idx("Pure avg/p95 =", len(lines))
    alt = "|".join(re.escape(a) for a in ALGS)

    iso_re = re.compile(rf"^\s*({alt})\s+(\d+)\s+" + r"\s+".join([f"({NUM})"] * 9))
    iso_keys = ["pure_avg", "pure_p95", "access_avg", "access_p95",
                "refresh_avg", "refresh_p95", "e2e_avg", "cpu_per_tok", "rss_kb"]
    for line in lines[i_iso:i_str]:
        m = iso_re.match(line)
        if m:
            out["isolated"][m.group(1)] = dict(zip(iso_keys, [float(x) for x in m.groups()[2:]]))

    def parse_vu_table(lo: int, hi: int, keys: list[str], trailing: str = "") -> dict:
        head = re.compile(rf"^\s*({alt})\s+(\d+)\s+" + r"\s+".join([f"({NUM})"] * len(keys)) + trailing)
        cont = re.compile(r"^\s{20,}(\d+)\s+" + r"\s+".join([f"({NUM})"] * len(keys)) + trailing)
        table: dict = {}
        cur = None
        for line in lines[lo:hi]:
            m = head.match(line)
            if m:
                cur = m.group(1)
                table.setdefault(cur, {})[int(m.group(2))] = dict(
                    zip(keys, [float(x) for x in m.groups()[2:]])
                )
                continue
            m = cont.match(line)
            if m and cur:
                table[cur][int(m.group(1))] = dict(zip(keys, [float(x) for x in m.groups()[1:]]))
        return table

    out["stress"] = parse_vu_table(
        i_str, i_sec, ["access_avg", "access_p95", "refresh_avg", "refresh_p95", "token_ok_s"]
    )
    out["secondary"] = parse_vu_table(
        i_sec, i_end,
        ["login_avg", "login_p95", "refresh_avg", "refresh_p95", "e2e_avg", "e2e_p95", "rps"],
        trailing=rf"\s+{NUM}%",
    )
    return out


def load_runs() -> list[dict]:
    paths = sorted(
        (Path(p) for p in glob.glob(str(ROOT / "result*.txt"))),
        key=lambda p: (len(p.name), p.name),
    )
    runs = []
    for path in paths:
        run = parse_report(path)
        # A report is usable only if every algorithm appears in every table.
        if len(run["isolated"]) == len(ALGS) and len(run["stress"]) == len(ALGS) \
                and len(run["secondary"]) == len(ALGS):
            runs.append(run)
        else:
            print(f"skipping {path.name}: incomplete tables")
    return runs


# ──────────────────────────── statistics ────────────────────────────


def quartiles(values: list[float]) -> tuple[float, float, float]:
    """(q1, median, q3). Same 'exclusive' hinge convention across all figures."""
    ordered = sorted(values)
    med = st.median(ordered)
    if len(ordered) < 4:
        return ordered[0], med, ordered[-1]
    q1, _, q3 = st.quantiles(ordered, n=4, method="exclusive")
    return q1, med, q3


# Opt-in best-vs-worst selection for the FN-DSA speed figures (set by
# `make figures-fndsa`). When on, the precomputed profile is drawn from its
# single most-favorable run and the dynamic baseline from its least-favorable
# one, per an explicit request to show the extreme envelope rather than the
# median. It is NOT the honest central estimate, so every figure it touches
# carries EXTREME_NOTE and the true win-rate still comes from all runs.
EXTREME = os.environ.get("MULTIRUN_FNDSA_EXTREME") == "1"
EXTREME_NOTE = [
    "Selected runs, NOT median: FN-DSA-Precomp = fastest of 20 runs, FN-DSA-512 = slowest of 20 runs.",
    "Best-case vs worst-case envelope — an upper bound on the gap, not a typical result.",
]


def sel_values(vals: list[float], alg: str, higher_is_better: bool, speed: bool) -> tuple[float, float, float]:
    """Median+IQR normally; in EXTREME mode the two FN-DSA speed series collapse
    to their single most/least favorable run (precomp best, baseline worst)."""
    if EXTREME and speed and alg in (PRECOMP, DYNAMIC):
        favor_high = higher_is_better if alg == PRECOMP else not higher_is_better
        v = max(vals) if favor_high else min(vals)
        return v, v, v
    return quartiles(vals)


def iso_stat(runs: list[dict], alg: str, metric: str,
             higher_is_better: bool = False, speed: bool = False) -> tuple[float, float, float]:
    return sel_values([r["isolated"][alg][metric] for r in runs], alg, higher_is_better, speed)


def vu_stat(runs: list[dict], table: str, alg: str, vu: int, metric: str,
            higher_is_better: bool = False, speed: bool = False) -> tuple[float, float, float]:
    return sel_values([r[table][alg][vu][metric] for r in runs], alg, higher_is_better, speed)


def cpu_quantization_rows(runs: list[dict]) -> list[dict]:
    """Per-algorithm evidence that the 0.00 readings are a clock-resolution floor.

    Reports how many runs landed on exactly zero and how the median compares to
    the one-tick quantum, next to the wall-clock latency of the same operation.
    If a metric were genuinely zero the paired wall time would be zero too; it
    isn't, which is what makes this a floor rather than a measurement.
    """
    rows = []
    for alg in PLOT_ALGS:
        cpu = [r["isolated"][alg]["cpu_per_tok"] for r in runs]
        wall = [(r["isolated"][alg]["access_avg"] + r["isolated"][alg]["refresh_avg"]) / 2
                for r in runs]
        med = st.median(cpu)
        rows.append({
            "algorithm": alg,
            "runs": len(runs),
            "zero_runs": sum(1 for v in cpu if v == 0.0),
            "cpu_per_token_median_ms": round(med, 4),
            "cpu_quantum_ms": CPU_TICK_QUANTUM_MS,
            "median_in_ticks": round(med / CPU_TICK_QUANTUM_MS, 2),
            "wall_per_token_median_ms": round(st.median(wall), 4),
            "under_resolved": "yes" if med <= CPU_TICK_QUANTUM_MS else "no",
        })
    return rows


def raw_rows(runs: list[dict]) -> list[dict]:
    """Every parsed number, one row per run/algorithm/scenario/metric.

    Deliberately ALGS, not PLOT_ALGS: this is the full-fidelity dump behind the
    figures, and narrowing the drawn set is a presentation choice that should not
    silently shrink the published data.
    """
    rows = []
    for r in runs:
        for alg in ALGS:
            for metric, value in r["isolated"][alg].items():
                rows.append({"run_file": r["file"], "scenario": "isolated", "algorithm": alg,
                             "vus": "", "metric": metric, "value": value})
            for table in ("stress", "secondary"):
                for vu, metrics in sorted(r[table][alg].items()):
                    for metric, value in metrics.items():
                        rows.append({"run_file": r["file"], "scenario": table, "algorithm": alg,
                                     "vus": vu, "metric": metric, "value": value})
    return rows


def write_csv(name: str, fields: list[str], rows: list[dict]) -> None:
    with (OUT_DIR / name).open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    print(f"  {name}: {len(rows)} rows")


def win_rate(runs: list[dict], get, higher_is_better: bool = False) -> tuple[int, int, int]:
    """(wins, ties, n) for precomputed vs dynamic FN-DSA.

    Ties are counted separately rather than folded into losses: on the
    tick-quantized CPU metric an exact tie means both signers landed in the same
    quantum, which is 'no measurable difference', not a loss for precompute.
    """
    wins = ties = 0
    for r in runs:
        p, d = get(r, PRECOMP), get(r, DYNAMIC)
        if p == d:
            ties += 1
        else:
            wins += (p > d) if higher_is_better else (p < d)
    return wins, ties, len(runs)


# ───────────────────────────── rendering ────────────────────────────


def scale_label(y_label: str, log_scale: bool) -> str:
    """Annotate the axis label with the scale actually used.

    The log axis is adaptive (see spans_orders), so a hardcoded "log10" in the
    label would lie the moment the fallback kicks in — which is exactly what
    happens on the two-algorithm FN-DSA set.
    """
    if not log_scale:
        return y_label
    return f"{y_label[:-1]}, log10)" if y_label.endswith(")") else f"{y_label} (log10)"


def spans_orders(values: list[float]) -> bool:
    """True when the series is wide enough for a log axis to be worth it."""
    positive = [v for v in values if v > 0]
    if not positive:
        return False
    return max(positive) / min(positive) >= LOG_SCALE_MIN_RATIO


def draw_note(draw, left: int, right: int, lines: list[str], color: str) -> None:
    """Caveat/provenance note. Drawn in the top margin: the bottom margin is
    already taken by tick labels and the algorithm legend."""
    g.draw_png_multiline(draw, (left + right) / 2, 30, lines, size=21, fill=color, line_height=28)


# Widest a bar is allowed to get and how much wider than a bar the centre-to-
# centre pitch may open up. Tuned for the two-profile FN-DSA set: slot-centring
# across the full plot width left two thin bars marooned at the edges with a
# lake of whitespace between them. Clustering keeps bars fat and the gap tight.
BAR_W_MAX = 340
BAR_PITCH_RATIO = 1.4


def cluster_positions(left: float, right: float, n: int) -> tuple[float, list[float]]:
    """(bar_width, [centre_x...]) for n wide bars clustered around the plot centre.

    Bounded so it also stays sane for the six-algorithm multirun set: pitch never
    exceeds an even full-width split, so the cluster can't overflow the axes."""
    avail = right - left
    bar_w = min(BAR_W_MAX, avail / (n * 1.7))
    pitch = min(bar_w * BAR_PITCH_RATIO, avail / n)
    x0 = (left + right) / 2 - pitch * (n - 1) / 2
    return bar_w, [x0 + i * pitch for i in range(n)]


def render_bar_figure(name: str, y_label: str, stats: list[tuple[str, tuple[float, float, float]]],
                      log_scale: bool, note: list[str] | None = None,
                      decimals: int | None = None) -> Path:
    """Bar per algorithm, median value; IQR printed numerically under each bar.

    Always a bar, including on the log axis (the six-algorithm speed figures span
    three orders of magnitude, so the axis stays log; the bar just runs from the
    axis floor to the value). `decimals` fixes the label precision instead of
    g.fmt()'s variable-width output. Fixed width is what makes a comparison figure
    readable: g.fmt() renders the CPU/token medians as 0.4 / 0.05 / 1.25, and the
    eye reads that ragged column as different magnitudes. At 2 decimals they line
    up as 0.40 / 0.05 / 1.25 and the 0.05 tick quantum is visible on sight.
    """
    def label(v: float) -> str:
        return g.fmt(v) if decimals is None else f"{v:.{decimals}f}"

    img, draw = g.new_png_canvas()
    left, top, right, bottom = g.plot_area()
    spread = [v for _, (q1, med, q3) in stats for v in (q1, med, q3)]
    log_scale = log_scale and spans_orders(spread)
    y_map, ticks, _, _ = g.make_y_map(spread, log_scale)
    g.draw_png_axes(img, draw, scale_label(y_label, log_scale), ticks, y_map)

    bar_w, centers = cluster_positions(left, right, len(stats))

    for idx, (alg, (q1, med, q3)) in enumerate(stats):
        cx = centers[idx]
        color = g.COLORS[alg]
        y = y_map(med)
        draw.rounded_rectangle((cx - bar_w / 2, y, cx + bar_w / 2, bottom), radius=5, fill=color)

        # No IQR error-bar drawn on the bar: the black whisker over a coloured bar
        # read as a visual bug. The spread is kept as the numeric "IQR a–b" caption
        # under the bar instead (omitted when the bar is a single selected run).
        g.png_value_label(draw, cx, y - 44, label(med), (left, top, right, bottom), g.VALUE_SIZE)
        if q1 != q3:
            g.draw_png_multiline(draw, cx, bottom + 50,
                                 [f"IQR {label(q1)}–{label(q3)}"], size=23, fill="#7B8794")

    if note:
        draw_note(draw, left, right, note, "#7A2E1E")
    g.draw_png_algorithm_legend(draw, left, bottom + 132, right - left, [a for a, _ in stats])
    return g.save_png(img, name)


def render_vu_figure(name: str, y_label: str,
                     series: dict[str, list[tuple[int, tuple[float, float, float]]]],
                     log_scale: bool, note: list[str] | None = None) -> Path:
    """VU figures: trend for the two-profile FN-DSA comparison (the scaling shape
    of precompute vs dynamic is the point), grouped bars for the six-algorithm
    set (per request: everything except that comparison is a bar diagram)."""
    if FNDSA_COMPARISON:
        return _render_vu_trend(name, y_label, series, log_scale, note)
    return _render_vu_bars(name, y_label, series, log_scale, note)


def _render_vu_trend(name: str, y_label: str,
                     series: dict[str, list[tuple[int, tuple[float, float, float]]]],
                     log_scale: bool, note: list[str] | None = None) -> Path:
    """Trend across VU levels: one line + markers per algorithm (median).

    Stress round-trips move along a continuous load axis, so a trend line shows
    the scaling shape directly (bars can't). No error bar drawn — the black
    whisker over a marker read as a visual bug; q1/q3 stay in multirun_data.csv.
    Each series gets a small x-dodge so near-identical lines don't paint over
    each other.
    """
    img, draw = g.new_png_canvas()
    left, top, right, bottom = g.plot_area()
    spread = [med for rows in series.values() for _, (q1, med, q3) in rows]
    log_scale = log_scale and spans_orders(spread)
    y_map, ticks, _, _ = g.make_y_map(spread, log_scale)
    g.draw_png_axes(img, draw, scale_label(y_label, log_scale), ticks, y_map)

    vus = sorted({vu for rows in series.values() for vu, _ in rows})
    v_min, v_max = vus[0], vus[-1]
    # Inset from the axes so the first/last marker + value label clear the y-axis
    # and the right edge.
    pad = (right - left) * 0.08

    def x_map(vu: int) -> float:
        if v_max == v_min:
            return (left + right) / 2
        return left + pad + (vu - v_min) / (v_max - v_min) * (right - left - 2 * pad)

    for vu in vus:
        x = x_map(vu)
        draw.line((x, top, x, bottom), fill=g.GRID, width=2)
        g.draw_png_text(draw, x, bottom + 50, f"{vu} VU",
                        g.TICK_SIZE, fill="#425466", anchor="ma", bold=True)

    label_bounds = (left, top, right, bottom)
    raw_labels: list[tuple[float, float, str]] = []
    n = len(PLOT_ALGS)
    for ai, alg in enumerate(PLOT_ALGS):
        dodge = (ai - (n - 1) / 2) * 22
        color = g.COLORS[alg]
        pts = [(x_map(vu) + dodge, y_map(med), med) for vu, (q1, med, q3) in series[alg]]
        draw.line([(x, y) for x, y, _ in pts], fill=color, width=7, joint="curve")
        for x, y, med in pts:
            draw.ellipse((x - 17, y - 17, x + 17, y + 17), fill=g.WHITE)
            draw.ellipse((x - 12, y - 12, x + 12, y + 12), fill=color)
            raw_labels.append((x, y, g.fmt(med)))

    for x, y, text, _ in g.placed_point_labels(draw, raw_labels, label_bounds, g.STRESS_VALUE_SIZE):
        g.png_value_label(draw, x, y, text, label_bounds, g.STRESS_VALUE_SIZE)

    if note:
        draw_note(draw, left, right, note, "#7A2E1E")
    g.draw_png_text(draw, (left + right) / 2, bottom + 112,
                    "Concurrent virtual users (VUs)", g.AXIS_SIZE, fill=g.AXIS, anchor="ma")
    g.draw_png_algorithm_legend(draw, left, bottom + 180, right - left, PLOT_ALGS)
    return g.save_png(img, name)


def _render_vu_bars(name: str, y_label: str,
                    series: dict[str, list[tuple[int, tuple[float, float, float]]]],
                    log_scale: bool, note: list[str] | None = None) -> Path:
    """Grouped bars across VU levels: one group per VU, one bar per algorithm
    (median). Same bar language as the rest of the six-algorithm set."""
    img, draw = g.new_png_canvas()
    left, top, right, bottom = g.plot_area()
    spread = [med for rows in series.values() for _, (q1, med, q3) in rows]
    log_scale = log_scale and spans_orders(spread)
    y_map, ticks, _, _ = g.make_y_map(spread, log_scale)
    g.draw_png_axes(img, draw, scale_label(y_label, log_scale), ticks, y_map)

    vus = sorted({vu for rows in series.values() for vu, _ in rows})
    n_alg = len(PLOT_ALGS)
    group_gap = 90
    group_w = ((right - left) - group_gap * (len(vus) - 1)) / len(vus)
    bar_gap = 12
    bar_w = (group_w - bar_gap * (n_alg - 1)) / n_alg
    # 4-digit labels on narrow bars overlap at full size; cap to the bar pitch.
    val_size = min(g.STRESS_VALUE_SIZE, int((bar_w + bar_gap) * 0.34))
    label_bounds = (left, top, right, bottom)

    for gi, vu in enumerate(vus):
        gx = left + gi * (group_w + group_gap)
        for ai, alg in enumerate(PLOT_ALGS):
            _, med, _ = dict(series[alg])[vu]
            x = gx + ai * (bar_w + bar_gap)
            cx = x + bar_w / 2
            y = y_map(med)
            draw.rounded_rectangle((x, y, x + bar_w, bottom), radius=4, fill=g.COLORS[alg])
            g.png_value_label(draw, cx, y - 30, g.fmt(med), label_bounds, val_size)
        g.draw_png_text(draw, gx + group_w / 2, bottom + 50, f"{vu} VU",
                        g.TICK_SIZE, fill="#425466", anchor="ma", bold=True)

    if note:
        draw_note(draw, left, right, note, "#7A2E1E")
    g.draw_png_text(draw, (left + right) / 2, bottom + 112,
                    "Concurrent virtual users (VUs)", g.AXIS_SIZE, fill=g.AXIS, anchor="ma")
    g.draw_png_algorithm_legend(draw, left, bottom + 180, right - left, PLOT_ALGS)
    return g.save_png(img, name)


def render_persistent_memory(profile: dict) -> Path:
    """Valid resident-memory comparison: isolated-process expanded-key bytes.

    The k6 RSS column cannot support this claim (one gateway process serves all
    six algorithms), so the precompute memory cost is drawn from the Go profile
    test instead — see docs and the note printed on mrun_03.
    """
    name = "mrun_15_precompute_persistent_memory_per_key_kb"
    img, draw = g.new_png_canvas()
    left, top, right, bottom = g.plot_area()
    per_key_kb = profile["persistent_bytes_per_key"] / 1024
    stats = [(PRECOMP, (per_key_kb, per_key_kb, per_key_kb)), (DYNAMIC, (0.0, 0.0, 0.0))]
    y_map, ticks, _, _ = g.make_y_map([0.0, per_key_kb], False)
    g.draw_png_axes(img, draw, "Persistent expanded-key memory per signer (KB)", ticks, y_map)

    bar_w, centers = cluster_positions(left, right, len(stats))
    for idx, (alg, (_, med, _)) in enumerate(stats):
        cx = centers[idx]
        y = y_map(med)
        draw.rounded_rectangle((cx - bar_w / 2, y, cx + bar_w / 2, bottom), radius=5, fill=g.COLORS[alg])
        g.png_value_label(draw, cx, y - 44, g.fmt(med), (left, top, right, bottom), g.VALUE_SIZE)
    g.draw_png_algorithm_legend(draw, left, bottom + 132, right - left, [a for a, _ in stats])
    return g.save_png(img, name)


# ─────────────────────────────── main ───────────────────────────────


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    runs = load_runs()
    if not runs:
        raise SystemExit("no usable result*.txt reports found")
    n = len(runs)
    print(f"aggregating {n} runs: {', '.join(r['file'] for r in runs)}")

    figures: list[dict] = []
    rows: list[dict] = []

    def bar_spec(name, title, y_label, metric, log_scale, note=None, decimals=None,
                 scale=1.0, speed=False, higher_is_better=False):
        # stats stay in the metric's native unit for the CSV; `scale` only converts
        # the drawn figure (KB->MB), so the CSV column never disagrees with its name.
        stats = [(alg, iso_stat(runs, alg, metric, higher_is_better, speed)) for alg in PLOT_ALGS]
        drawn = [(alg, tuple(v * scale for v in qs)) for alg, qs in stats]
        disclosure = EXTREME_NOTE if (EXTREME and speed) else None
        path = render_bar_figure(name, y_label, drawn, log_scale, disclosure, decimals)
        wins, ties, total = win_rate(runs, lambda r, a: r["isolated"][a][metric])
        tie_txt = f"{wins}/{total}" + (f" ({ties} tie)" if ties else "")
        figures.append({"name": name, "title": title, "file": path.name,
                        "precomp_wins": tie_txt})
        for alg, (q1, med, q3) in stats:
            rows.append({"figure": name, "scenario": "isolated", "algorithm": alg, "vus": "",
                         "metric": metric, "median": round(med, 4),
                         "q1": round(q1, 4), "q3": round(q3, 4), "runs": n})
        print(f"  {name}: precomp wins {tie_txt}")

    def vu_spec(name, title, y_label, table, metric, log_scale, higher_is_better=False):
        series = {alg: [(vu, vu_stat(runs, table, alg, vu, metric, higher_is_better, True))
                        for vu in (10, 30, 50)]
                  for alg in PLOT_ALGS}
        disclosure = EXTREME_NOTE if EXTREME else None
        path = render_vu_figure(name, y_label, series, log_scale, disclosure)
        detail = []
        for vu in (10, 30, 50):
            wins, ties, total = win_rate(runs, lambda r, a, v=vu: r[table][a][v][metric], higher_is_better)
            detail.append(f"{vu}VU {wins}/{total}" + (f" ({ties} tie)" if ties else ""))
        figures.append({"name": name, "title": title, "file": path.name,
                        "precomp_wins": "; ".join(detail)})
        for alg, pts in series.items():
            for vu, (q1, med, q3) in pts:
                rows.append({"figure": name, "scenario": table, "algorithm": alg, "vus": vu,
                             "metric": metric, "median": round(med, 4),
                             "q1": round(q1, 4), "q3": round(q3, 4), "runs": n})
        print(f"  {name}: precomp wins {'; '.join(detail)}")

    rss_note = [
        "CAUTION: process-wide VmRSS. All six algorithms share one gateway container,",
        "so this is NOT per-algorithm memory. See mrun_15 for the valid precompute memory figure.",
    ]

    # CPU/token is a /proc/self/stat utime+stime delta. USER_HZ=100 makes one tick
    # 10 ms, while a single Sign takes 0.002-1.2 ms, so each per-op delta is 0 or 1
    # tick. Averaged over 100 iterations the estimator is unbiased (ticks accumulate
    # in proportion to real CPU time) but lands on a 0.05 ms grid. For the sub-0.1 ms
    # algorithms the true cost sits below that grid, so some runs read exactly 0.00 --
    # a resolution floor, not zero CPU cost. Linear scale, not log: log10 cannot draw
    # a 0 whisker bound honestly (it clamps to the axis floor).
    # Drawn in microseconds: in ms the medians read 0.05 / 0.10 / 0.40 / 1.25 and the
    # leading zeros flatten the 25x spread; in us they read 50 / 100 / 400 / 1250 and
    # the tick quantum is a clean 50 us. The CSV stays in ms (the metric's own unit).
    cpu_note = [
        f"Resolution floor {CPU_TICK_QUANTUM_MS * 1000:.0f} us/token (USER_HZ=100 clock ticks over 100 iterations).",
        "Bars at or below the floor are under-resolved, not zero -- see multirun_cpu_quantization.csv.",
    ]

    # Pure signing scenario.
    bar_spec("mrun_01_pure_signing_avg_ms", "Pure signing latency (median of runs)",
             "Average latency (ms)", "pure_avg", True, speed=True)
    bar_spec("mrun_02_pure_signing_p95_ms", "Pure signing p95 latency (median of runs)",
             "P95 latency (ms)", "pure_p95", True, speed=True)
    bar_spec("mrun_03_process_rss_avg_mb", "Gateway process RSS during isolated benchmark",
             "Process-wide RSS (MB)", "rss_kb", False, rss_note, decimals=1, scale=1 / 1024)

    # Isolated JWT issuance scenario.
    bar_spec("mrun_04_isolated_access_avg_ms", "Isolated access-token generation latency",
             "Average latency (ms)", "access_avg", True, speed=True)
    bar_spec("mrun_05_isolated_access_p95_ms", "Isolated access-token generation p95 latency",
             "P95 latency (ms)", "access_p95", True, speed=True)
    bar_spec("mrun_06_isolated_refresh_avg_ms", "Isolated refresh-token generation latency",
             "Average latency (ms)", "refresh_avg", True, speed=True)
    bar_spec("mrun_07_isolated_refresh_p95_ms", "Isolated refresh-token generation p95 latency",
             "P95 latency (ms)", "refresh_p95", True, speed=True)
    bar_spec("mrun_08_isolated_cpu_per_token_us", "Isolated CPU time per generated token",
             "CPU time per token (µs)", "cpu_per_tok", False, cpu_note, decimals=0, scale=1000, speed=True)

    # Stress scenario (full round-trips under concurrency).
    vu_spec("mrun_09_stress_login_avg_ms", "Stress login round-trip latency",
            "Average latency (ms)", "secondary", "login_avg", False)
    vu_spec("mrun_10_stress_login_p95_ms", "Stress login round-trip p95 latency",
            "P95 latency (ms)", "secondary", "login_p95", False)
    vu_spec("mrun_11_stress_refresh_avg_ms", "Stress refresh round-trip latency",
            "Average latency (ms)", "secondary", "refresh_avg", False)
    vu_spec("mrun_12_stress_refresh_p95_ms", "Stress refresh round-trip p95 latency",
            "P95 latency (ms)", "secondary", "refresh_p95", False)
    vu_spec("mrun_13_stress_throughput_rps", "Stress throughput",
            "Requests per second", "secondary", "rps", False, higher_is_better=True)

    # Security: attack block rate (single sweep, not run-aggregated).
    try:
        adversarial = g.read_json_file("adversarial_result.json", g.ADVERSARIAL_FILES)
        path = g.render_attack_metric_png(adversarial)
        # Scope this honestly: the adversarial sweep runs one algorithm, not the
        # six-way comparison the other figures make, so it cannot be a "both
        # profiles tie". The stress reports carry no attack data at all (their
        # Atk block column is "—" in every row); this figure's only source is
        # adversarial_result.json from the separate ATTACK_ONLY run.
        meta = adversarial["meta"]
        figures.append({"name": "fig_13_security_attack_block_rate_pct",
                        "title": "JWT attack block rate (RFC 7519/8725 vectors)",
                        "file": path.name,
                        "precomp_wins": f"n/a (single profile: {meta['algorithm']}, "
                                        f"n={meta['iterations']}/vector)"})
        for atk in adversarial["attacks"]:
            rows.append({"figure": "fig_13_security_attack_block_rate_pct", "scenario": "attack",
                         "algorithm": adversarial["meta"]["algorithm"], "vus": "",
                         "metric": atk["name"], "median": atk["block_rate_pct"],
                         "q1": "", "q3": "", "runs": 1})
        print("  fig_13 security block rate: rendered")
    except FileNotFoundError:
        print("adversarial_result.json not found — skipping security figure")

    profile = g.load_fndsa_profile()
    if profile:
        path = render_persistent_memory(profile)
        figures.append({"name": "mrun_15_precompute_persistent_memory_per_key_kb",
                        "title": "Precompute persistent memory per signer (valid source)",
                        "file": path.name, "precomp_wins": "n/a (cost, not a win)"})
        rows.append({"figure": "mrun_15_precompute_persistent_memory_per_key_kb",
                     "scenario": "profile", "algorithm": PRECOMP, "vus": "",
                     "metric": "persistent_bytes_per_key",
                     "median": profile["persistent_bytes_per_key"], "q1": "", "q3": "", "runs": profile["runs"]})
        print("  mrun_15 persistent memory: rendered")

    write_csv("multirun_data.csv",
              ["figure", "scenario", "algorithm", "vus", "metric", "median", "q1", "q3", "runs"],
              rows)
    write_csv("multirun_manifest.csv",
              ["name", "title", "file", "precomp_wins"], figures)
    write_csv("multirun_raw.csv",
              ["run_file", "scenario", "algorithm", "vus", "metric", "value"], raw_rows(runs))
    write_csv("multirun_cpu_quantization.csv",
              ["algorithm", "runs", "zero_runs", "cpu_per_token_median_ms", "cpu_quantum_ms",
               "median_in_ticks", "wall_per_token_median_ms", "under_resolved"],
              cpu_quantization_rows(runs))

    (OUT_DIR / "multirun_runs.json").write_text(
        json.dumps({"runs": n, "files": [r["file"] for r in runs]}, indent=1), encoding="utf-8"
    )
    print(f"\nwrote {len(figures)} figures + data/manifest to {OUT_DIR}")


if __name__ == "__main__":
    main()

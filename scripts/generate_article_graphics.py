#!/usr/bin/env python3
"""Generate Falcon-only publication graphics from current benchmark result JSON files."""

from __future__ import annotations

import csv
import json
import math
import os
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_FILES = (
    ROOT / "benchmark_sign_result.json",
    ROOT / "backend" / "benchmark_sign_result.json",
)
ADVERSARIAL_FILES = (
    ROOT / "adversarial_result.json",
    ROOT / "backend" / "adversarial_result.json",
)
OUT_DIR = Path(os.environ.get("ARTICLE_GRAPHICS_DIR", ROOT / "figures" / "article_python"))

W = 1900
H = 1120
MARGIN = {
    "left": 175,
    "right": 120,
    "top": 105,
    "bottom": 245,
}

FONT_REGULAR = Path("/usr/share/fonts/google-droid-sans-fonts/DroidSans.ttf")
FONT_BOLD = Path("/usr/share/fonts/google-droid-sans-fonts/DroidSans-Bold.ttf")
TEXT = "#1F2933"
MUTED = "#5F6B7A"
GRID = "#E5E7EB"
AXIS = "#2F3A45"
WHITE = "#FFFFFF"

ALGORITHM_ORDER = [
    "Falcon-Precomputed-512",
    "Falcon-512",
]
ALGORITHM_SET = set(ALGORITHM_ORDER)

ALGORITHM_SHORT = {
    "Falcon-Precomputed-512": "Falcon-Precomp. 512",
    "Falcon-512": "Falcon-512",
}

ALGORITHM_WRAP = {
    "Falcon-Precomputed-512": ["Falcon-Precomp.", "512"],
    "Falcon-512": ["Falcon", "512"],
}

# Colorblind-safe palette. Keep mapping stable across every figure.
COLORS = {
    "Falcon-Precomputed-512": "#0072B2",
    "Falcon-512": "#E69F00",
}

ATTACK_COLOR = "#009E73"
LABEL_BG = "#FFFFFF"
LABEL_BORDER = "#D7DEE8"
VALUE_SIZE = 23
STRESS_VALUE_SIZE = 20
TICK_SIZE = 24
AXIS_SIZE = 26
LEGEND_TITLE_SIZE = 27
LEGEND_SIZE = 25


def read_json_file(label: str, candidates: tuple[Path, ...]) -> object:
    for path in candidates:
        if path.is_file():
            return json.loads(path.read_text(encoding="utf-8"))

    checked = "\n".join(f"  - {path}" for path in candidates)
    raise FileNotFoundError(f"{label} not found. Checked:\n{checked}")


def fmt(value: float) -> str:
    if value is None:
        return "n/a"
    if value == 0:
        return "0"
    value = float(value)
    if abs(value) < 1:
        return f"{value:.3f}".rstrip("0").rstrip(".")
    if abs(value) < 10:
        return f"{value:.2f}".rstrip("0").rstrip(".")
    if abs(value) < 100:
        return f"{value:.1f}".rstrip("0").rstrip(".")
    return f"{value:.0f}"


_FONT_CACHE: dict[tuple[int, bool], ImageFont.FreeTypeFont | ImageFont.ImageFont] = {}


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    key = (size, bold)
    if key not in _FONT_CACHE:
        path = FONT_BOLD if bold else FONT_REGULAR
        if path.exists():
            _FONT_CACHE[key] = ImageFont.truetype(str(path), size)
        else:
            _FONT_CACHE[key] = ImageFont.load_default()
    return _FONT_CACHE[key]


def new_png_canvas() -> tuple[Image.Image, ImageDraw.ImageDraw]:
    img = Image.new("RGB", (W, H), WHITE)
    draw = ImageDraw.Draw(img)
    return img, draw


def draw_png_text(
    draw: ImageDraw.ImageDraw,
    x: float,
    y: float,
    text: str,
    size: int,
    fill: str = TEXT,
    bold: bool = False,
    anchor: str = "la",
) -> None:
    draw.text((x, y), str(text), fill=fill, font=font(size, bold), anchor=anchor)


def draw_png_multiline(
    draw: ImageDraw.ImageDraw,
    x: float,
    y: float,
    lines: list[str],
    size: int = 23,
    fill: str = "#425466",
    anchor: str = "ma",
    line_height: int = 30,
) -> None:
    for idx, line in enumerate(lines):
        draw.text((x, y + idx * line_height), line, fill=fill, font=font(size), anchor=anchor)


def draw_rotated_png_text(
    img: Image.Image,
    x: float,
    y: float,
    text: str,
    size: int,
    fill: str = AXIS,
    bold: bool = False,
) -> None:
    text_font = font(size, bold)
    probe = Image.new("RGBA", (1, 1), (255, 255, 255, 0))
    probe_draw = ImageDraw.Draw(probe)
    bbox = probe_draw.textbbox((0, 0), text, font=text_font)
    tw = bbox[2] - bbox[0]
    th = bbox[3] - bbox[1]
    layer = Image.new("RGBA", (tw + 20, th + 20), (255, 255, 255, 0))
    layer_draw = ImageDraw.Draw(layer)
    layer_draw.text((10, 10), text, fill=fill, font=text_font)
    rotated = layer.rotate(90, expand=True)
    img.paste(rotated, (int(x - rotated.width / 2), int(y - rotated.height / 2)), rotated)


def draw_png_algorithm_legend(
    draw: ImageDraw.ImageDraw,
    left: int,
    y: int,
    width: int,
) -> None:
    marker = 24
    marker_gap = 11

    cell_width = width / len(ALGORITHM_ORDER)
    for idx, alg in enumerate(ALGORITHM_ORDER):
        color = COLORS[alg]
        label = ALGORITHM_SHORT[alg]
        label_width = draw.textlength(label, font=font(LEGEND_SIZE))
        item_width = marker + marker_gap + label_width
        x = left + idx * cell_width + (cell_width - item_width) / 2
        draw.rounded_rectangle((x, y - 12, x + marker, y + 12), radius=3, fill=color)
        draw_png_text(draw, x + marker + marker_gap, y, label, LEGEND_SIZE, fill="#273444", anchor="lm")


def draw_png_attack_legend(draw: ImageDraw.ImageDraw, left: int, y: int, width: int) -> None:
    label = "Blocked request rate"
    marker = 24
    marker_gap = 11
    label_width = draw.textlength(label, font=font(LEGEND_SIZE))
    total_width = marker + marker_gap + label_width
    x = left + (width - total_width) / 2

    draw.rounded_rectangle((x, y - 12, x + marker, y + 12), radius=3, fill=ATTACK_COLOR)
    draw_png_text(draw, x + marker + marker_gap, y, label, LEGEND_SIZE, fill="#273444", anchor="lm")


def draw_png_axes(
    img: Image.Image,
    draw: ImageDraw.ImageDraw,
    y_label: str,
    ticks: list[float],
    y_map,
) -> None:
    left, top, right, bottom = plot_area()
    for tick in ticks:
        y = y_map(tick)
        draw.line((left, y, right, y), fill=GRID, width=2)
        draw_png_text(draw, left - 18, y + 8, fmt(tick), TICK_SIZE, fill="#425466", anchor="ra")
    draw.line((left, bottom, right, bottom), fill=AXIS, width=3)
    draw.line((left, top, left, bottom), fill=AXIS, width=3)
    draw_rotated_png_text(img, 60, (top + bottom) / 2, y_label, AXIS_SIZE, fill=AXIS)


def save_png(img: Image.Image, name: str) -> Path:
    path = OUT_DIR / f"{name}.png"
    img.save(path, dpi=(300, 300))
    return path


def plot_area() -> tuple[int, int, int, int]:
    left = MARGIN["left"]
    top = MARGIN["top"]
    right = W - MARGIN["right"]
    bottom = H - MARGIN["bottom"]
    return left, top, right, bottom


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def png_text_dims(draw: ImageDraw.ImageDraw, text: str, size: int, bold: bool = True) -> tuple[float, float]:
    bbox = draw.textbbox((0, 0), text, font=font(size, bold))
    return (bbox[2] - bbox[0]) + 14, (bbox[3] - bbox[1]) + 10


def overlap_area(a: tuple[float, float, float, float], b: tuple[float, float, float, float]) -> float:
    width = max(0, min(a[2], b[2]) - max(a[0], b[0]))
    height = max(0, min(a[3], b[3]) - max(a[1], b[1]))
    return width * height


def expand_box(box: tuple[float, float, float, float], padding: float) -> tuple[float, float, float, float]:
    return (box[0] - padding, box[1] - padding, box[2] + padding, box[3] + padding)


def value_label_box(
    draw: ImageDraw.ImageDraw,
    x: float,
    y: float,
    text: str,
    bounds: tuple[float, float, float, float],
    size: int = VALUE_SIZE,
) -> tuple[float, float, tuple[float, float, float, float]]:
    left, top, right, bottom = bounds
    tw, th = png_text_dims(draw, text, size, True)
    cx = clamp(x, left + tw / 2 + 4, right - tw / 2 - 4)
    cy = clamp(y, top + th / 2 + 4, bottom - th / 2 - 4)
    return cx, cy, (cx - tw / 2, cy - th / 2, cx + tw / 2, cy + th / 2)


def png_value_label(
    draw: ImageDraw.ImageDraw,
    x: float,
    y: float,
    text: str,
    bounds: tuple[float, float, float, float],
    size: int = VALUE_SIZE,
) -> tuple[float, float, float, float]:
    cx, cy, box = value_label_box(draw, x, y, text, bounds, size)
    draw.rounded_rectangle(box, radius=5, fill=LABEL_BG, outline=LABEL_BORDER, width=1)
    draw_png_text(draw, cx, cy, text, size, fill=TEXT, bold=True, anchor="mm")
    return box


def point_label_offsets() -> list[tuple[int, int]]:
    base = [
        (0, -34),
        (0, 34),
        (52, -16),
        (-52, -16),
        (52, 24),
        (-52, 24),
        (0, -62),
        (0, 62),
        (82, 0),
        (-82, 0),
    ]
    offsets: list[tuple[int, int]] = []
    seen: set[tuple[int, int]] = set()
    for offset in base:
        seen.add(offset)
        offsets.append(offset)
    for radius in (44, 68, 94, 124, 158, 196, 238):
        for deg in (-90, 90, -45, 45, -135, 135, 0, 180, -70, 70, -110, 110):
            offset = (
                round(math.cos(math.radians(deg)) * radius),
                round(math.sin(math.radians(deg)) * radius),
            )
            if offset not in seen:
                seen.add(offset)
                offsets.append(offset)
    return offsets


def placed_point_labels(
    draw: ImageDraw.ImageDraw,
    raw_labels: list[tuple[float, float, str]],
    bounds: tuple[float, float, float, float],
    size: int = STRESS_VALUE_SIZE,
) -> list[tuple[float, float, str, tuple[float, float, float, float]]]:
    offsets = point_label_offsets()
    used: list[tuple[float, float, float, float]] = []
    placed: list[tuple[float, float, str, tuple[float, float, float, float]]] = []

    ranked_labels: list[tuple[int, float, float, str]] = []
    for idx, (x, y, text) in enumerate(raw_labels):
        crowding = sum(
            1
            for other_idx, (other_x, other_y, _) in enumerate(raw_labels)
            if other_idx != idx and abs(x - other_x) < 160 and abs(y - other_y) < 95
        )
        ranked_labels.append((-crowding, x, y, text))

    for _, x, y, text in sorted(ranked_labels):
        candidates: list[tuple[float, float, tuple[float, float, float, float], float]] = []
        for dx, dy in offsets:
            cx, cy, box = value_label_box(draw, x + dx, y + dy, text, bounds, size)
            padded_box = expand_box(box, 4)
            overlap = sum(overlap_area(padded_box, existing) for existing in used)
            edge_penalty = (abs((x + dx) - cx) + abs((y + dy) - cy)) * 4
            distance = math.hypot(dx, dy)
            candidates.append((cx, cy, box, overlap * 10000 + edge_penalty + distance))
        cx, cy, box, _ = min(candidates, key=lambda item: item[3])
        used.append(expand_box(box, 4))
        placed.append((cx, cy, text, box))
    return placed


def nice_step(raw_step: float) -> float:
    if raw_step <= 0:
        return 1
    exp = math.floor(math.log10(raw_step))
    frac = raw_step / (10**exp)
    if frac <= 1:
        nice_frac = 1
    elif frac <= 2:
        nice_frac = 2
    elif frac <= 5:
        nice_frac = 5
    else:
        nice_frac = 10
    return nice_frac * (10**exp)


def linear_ticks(values: list[float], count: int = 5) -> tuple[list[float], float, float]:
    max_value = max(values) if values else 1
    if max_value <= 0:
        return [0, 1], 0, 1
    step = nice_step(max_value / count)
    y_max = math.ceil(max_value / step) * step
    ticks = [i * step for i in range(int(round(y_max / step)) + 1)]
    return ticks, 0, y_max


def log_ticks(values: list[float]) -> tuple[list[float], float, float]:
    positives = [v for v in values if v and v > 0]
    if not positives:
        return [0.1, 1, 10], 0.1, 10
    min_value = min(positives)
    max_value = max(positives)
    y_min = 10 ** math.floor(math.log10(min_value))
    y_max = 10 ** math.ceil(math.log10(max_value))
    ticks: list[float] = []
    exp_min = math.floor(math.log10(y_min))
    exp_max = math.ceil(math.log10(y_max))
    for exp in range(exp_min, exp_max + 1):
        for mult in (1, 2, 5):
            tick = mult * (10**exp)
            if y_min <= tick <= y_max:
                ticks.append(tick)
    if y_min not in ticks:
        ticks.insert(0, y_min)
    if y_max not in ticks:
        ticks.append(y_max)
    return ticks, y_min, y_max


def make_y_map(values: list[float], log_scale: bool):
    left, top, right, bottom = plot_area()
    if log_scale:
        ticks, y_min, y_max = log_ticks(values)

        def mapper(v: float) -> float:
            safe = max(v, y_min)
            frac = (math.log10(safe) - math.log10(y_min)) / (math.log10(y_max) - math.log10(y_min))
            return bottom - frac * (bottom - top)

    else:
        ticks, y_min, y_max = linear_ticks(values)

        def mapper(v: float) -> float:
            frac = (v - y_min) / (y_max - y_min)
            return bottom - frac * (bottom - top)

    return mapper, ticks, y_min, y_max


def isolated_values(benchmark: dict, accessor) -> list[tuple[str, float]]:
    by_alg = {item["algorithm"]: item for item in benchmark["algorithms"]}
    return [(alg, float(accessor(by_alg[alg]))) for alg in ALGORITHM_ORDER]


def render_isolated_metric_png(
    name: str,
    y_label: str,
    values: list[tuple[str, float]],
    log_scale: bool,
) -> Path:
    img, draw = new_png_canvas()
    left, top, right, bottom = plot_area()
    raw_values = [v for _, v in values]
    y_map, ticks, _, _ = make_y_map(raw_values, log_scale)
    draw_png_axes(img, draw, y_label, ticks, y_map)

    width = right - left
    gap = 54
    slot = (width - gap * (len(values) - 1)) / len(values)
    bar_w = min(112, slot * 0.62)
    baseline = bottom
    marker_r = 13
    label_bounds = (left, top, right, bottom)

    for idx, (alg, value) in enumerate(values):
        cx = left + slot / 2 + idx * (slot + gap)
        color = COLORS[alg]
        y = y_map(value)
        if log_scale:
            draw.line((cx, baseline, cx, y), fill=color, width=8)
            draw.ellipse(
                (cx - marker_r - 4, y - marker_r - 4, cx + marker_r + 4, y + marker_r + 4),
                fill=WHITE,
            )
            draw.ellipse((cx - marker_r, y - marker_r, cx + marker_r, y + marker_r), fill=color)
        else:
            x = cx - bar_w / 2
            draw.rounded_rectangle((x, y, x + bar_w, baseline), radius=5, fill=color)
        png_value_label(draw, cx, y - 30, fmt(value), label_bounds, VALUE_SIZE)
        draw_png_multiline(draw, cx, bottom + 42, ALGORITHM_WRAP[alg])

    draw_png_algorithm_legend(draw, left, H - 64, right - left)
    return save_png(img, name)


def stress_series(benchmark: dict, accessor) -> dict[str, list[tuple[int, float]]]:
    result: dict[str, list[tuple[int, float]]] = {}
    by_alg = {item["algorithm"]: item for item in benchmark["algorithms"]}
    for alg in ALGORITHM_ORDER:
        result[alg] = [(int(row["vus"]), float(accessor(row))) for row in by_alg[alg]["stress"]]
    return result


def render_stress_metric_png(
    name: str,
    y_label: str,
    series: dict[str, list[tuple[int, float]]],
    log_scale: bool,
) -> Path:
    img, draw = new_png_canvas()
    left, top, right, bottom = plot_area()
    all_values = [value for rows in series.values() for _, value in rows]
    y_map, ticks, _, _ = make_y_map(all_values, log_scale)
    draw_png_axes(img, draw, y_label, ticks, y_map)

    x_values = sorted({x for rows in series.values() for x, _ in rows})
    x_min, x_max = min(x_values), max(x_values)

    def x_map(v: int) -> float:
        if x_max == x_min:
            return (left + right) / 2
        return left + (v - x_min) / (x_max - x_min) * (right - left)

    for vu in x_values:
        x = x_map(vu)
        draw.line((x, top, x, bottom), fill=GRID, width=2)
        draw_png_text(draw, x, bottom + 48, str(vu), TICK_SIZE, fill="#425466", anchor="ma")

    draw_png_text(
        draw,
        (left + right) / 2,
        bottom + 108,
        "Concurrent virtual users (VUs)",
        AXIS_SIZE,
        fill=AXIS,
        anchor="ma",
    )

    raw_labels: list[tuple[float, float, str]] = []
    label_bounds = (left, top, right, bottom)
    for alg in ALGORITHM_ORDER:
        color = COLORS[alg]
        points = [(x_map(vu), y_map(value), value) for vu, value in series[alg]]
        draw.line([(x, y) for x, y, _ in points], fill=color, width=6, joint="curve")
        for x, y, value in points:
            draw.ellipse((x - 14, y - 14, x + 14, y + 14), fill=WHITE)
            draw.ellipse((x - 10, y - 10, x + 10, y + 10), fill=color)
            raw_labels.append((x, y, fmt(value)))

    for x, y, text, _ in placed_point_labels(draw, raw_labels, label_bounds, STRESS_VALUE_SIZE):
        png_value_label(draw, x, y, text, label_bounds, STRESS_VALUE_SIZE)

    draw_png_algorithm_legend(draw, left, H - 64, right - left)
    return save_png(img, name)


def render_attack_metric_png(adversarial: dict) -> Path:
    name = "fig_13_security_attack_block_rate_pct"
    img, draw = new_png_canvas()
    left = 430
    top = 115
    right = W - 120
    bottom = H - 245
    width = right - left
    attacks = adversarial["attacks"]
    row_h = (bottom - top) / len(attacks)
    label_bounds = (left, top, right, bottom)

    for tick in [0, 25, 50, 75, 100]:
        x = left + tick / 100 * width
        draw.line((x, top, x, bottom), fill=GRID, width=2)
        draw_png_text(draw, x, bottom + 48, str(tick), TICK_SIZE, fill="#425466", anchor="ma")
    draw.line((left, bottom, right, bottom), fill=AXIS, width=3)
    draw.line((left, top, left, bottom), fill=AXIS, width=3)
    draw_png_text(draw, (left + right) / 2, bottom + 108, "Block rate (%)", AXIS_SIZE, fill=AXIS, anchor="ma")

    for idx, attack in enumerate(attacks):
        y = top + idx * row_h + row_h * 0.58
        bar_h = min(46, row_h * 0.52)
        rate = float(attack["block_rate_pct"])
        draw_png_text(draw, left - 26, y + 8, f"#{attack['id']} {attack['name']}", TICK_SIZE, fill="#425466", anchor="ra")
        draw.rounded_rectangle(
            (left, y - bar_h / 2, left + rate / 100 * width, y + bar_h / 2),
            radius=5,
            fill=ATTACK_COLOR,
        )
        png_value_label(draw, left + rate / 100 * width - 34, y, f"{fmt(rate)}%", label_bounds, VALUE_SIZE)

    draw_png_attack_legend(draw, left, H - 64, right - left)
    return save_png(img, name)


def write_palette() -> None:
    with (OUT_DIR / "article_graphics_palette.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["algorithm", "label", "hex_color"])
        for alg in ALGORITHM_ORDER:
            writer.writerow([alg, ALGORITHM_SHORT[alg], COLORS[alg]])


def write_data_csv(benchmark: dict, adversarial: dict) -> None:
    with (OUT_DIR / "article_graphics_data.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["scope", "algorithm", "vus", "metric", "value", "unit"])
        for item in benchmark["algorithms"]:
            alg = item["algorithm"]
            if alg not in ALGORITHM_SET:
                continue
            iso = item["isolated"]
            rows = [
                ("isolated", alg, "", "access_token_generation_avg", iso["token_generation_ms"]["avg"], "ms"),
                ("isolated", alg, "", "access_token_generation_p95", iso["token_generation_ms"]["p95"], "ms"),
                ("isolated", alg, "", "refresh_token_generation_avg", iso["refresh_token_generation_ms"]["avg"], "ms"),
                ("isolated", alg, "", "refresh_token_generation_p95", iso["refresh_token_generation_ms"]["p95"], "ms"),
                ("isolated", alg, "", "total_generation_avg", iso["total_ms"]["avg"], "ms"),
                ("isolated", alg, "", "cpu_utilization_avg", iso["cpu_pct"]["avg"], "%"),
                ("isolated", alg, "", "memory_alloc_avg", iso["memory_alloc_kb"]["avg"] / 1024, "MB"),
            ]
            for row in rows:
                writer.writerow(row)
            for stress in item["stress"]:
                vus = stress["vus"]
                stress_rows = [
                    ("stress", alg, vus, "access_token_generation_avg", stress["token_generation_ms"]["avg"], "ms"),
                    ("stress", alg, vus, "access_token_generation_p95", stress["token_generation_ms"]["p95"], "ms"),
                    ("stress", alg, vus, "end_to_end_response_avg", stress["e2e_ms"]["avg"], "ms"),
                    ("stress", alg, vus, "login_avg", stress["login_ms"]["avg"], "ms"),
                    ("stress", alg, vus, "refresh_avg", stress["refresh_ms"]["avg"], "ms"),
                    ("stress", alg, vus, "throughput_ok", stress["throughput_ok_per_s"], "requests/s"),
                ]
                for row in stress_rows:
                    writer.writerow(row)
        for attack in adversarial["attacks"]:
            writer.writerow(
                [
                    "security",
                    adversarial["meta"]["algorithm"],
                    "",
                    f"attack_{attack['id']}_block_rate",
                    attack["block_rate_pct"],
                    "%",
                ]
            )


def write_captions(figures: list[dict]) -> None:
    lines = [
        "# Article Graphics Captions",
        "",
        "Legend:",
    ]
    for alg in ALGORITHM_ORDER:
        lines.append(f"- `{ALGORITHM_SHORT[alg]}`: `{COLORS[alg]}`")
    lines.extend(["", "Captions:"])
    for fig in figures:
        lines.append(f"- {fig['figure_id']}: {fig['title']}. Metric: {fig['metric']}.")
    lines.append("")
    (OUT_DIR / "article_graphics_captions.md").write_text("\n".join(lines), encoding="utf-8")


def write_manifest(figures: list[dict]) -> None:
    with (OUT_DIR / "article_graphics_manifest.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["figure_id", "name", "metric", "png"])
        for fig in figures:
            writer.writerow(
                [
                    fig["figure_id"],
                    fig["name"],
                    fig["metric"],
                    f"{fig['name']}.png" if fig.get("png") else "",
                ]
            )


def write_contact_sheet(figures: list[dict]) -> Path:
    cols = 2
    tile_w = 760
    tile_h = 448
    pad = 24
    rows = math.ceil(len(figures) / cols)
    sheet = Image.new("RGB", (cols * tile_w + (cols + 1) * pad, rows * tile_h + (rows + 1) * pad), WHITE)
    for idx, fig in enumerate(figures):
        png_path = OUT_DIR / f"{fig['name']}.png"
        with Image.open(png_path) as img:
            thumb = img.resize((tile_w, tile_h), Image.Resampling.LANCZOS)
        x = pad + (idx % cols) * (tile_w + pad)
        y = pad + (idx // cols) * (tile_h + pad)
        sheet.paste(thumb, (x, y))
    path = OUT_DIR / "article_graphics_contact_sheet.png"
    sheet.save(path, dpi=(300, 300))
    return path


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    benchmark = read_json_file("benchmark_sign_result.json", BENCHMARK_FILES)
    adversarial = read_json_file("adversarial_result.json", ADVERSARIAL_FILES)

    isolated_specs = [
        (
            "fig_01_isolated_access_token_generation_avg_ms",
            "Fig. 1",
            "Isolated access-token generation latency",
            "Average latency (ms, log10)",
            lambda item: item["isolated"]["token_generation_ms"]["avg"],
            True,
            "access_token_generation_avg_ms",
        ),
        (
            "fig_02_isolated_access_token_generation_p95_ms",
            "Fig. 2",
            "Isolated access-token generation p95 latency",
            "P95 latency (ms, log10)",
            lambda item: item["isolated"]["token_generation_ms"]["p95"],
            True,
            "access_token_generation_p95_ms",
        ),
        (
            "fig_03_isolated_refresh_token_generation_avg_ms",
            "Fig. 3",
            "Isolated refresh-token generation latency",
            "Average latency (ms, log10)",
            lambda item: item["isolated"]["refresh_token_generation_ms"]["avg"],
            True,
            "refresh_token_generation_avg_ms",
        ),
        (
            "fig_04_isolated_total_generation_avg_ms",
            "Fig. 4",
            "Isolated total token generation latency",
            "Average latency (ms, log10)",
            lambda item: item["isolated"]["total_ms"]["avg"],
            True,
            "total_generation_avg_ms",
        ),
        (
            "fig_05_isolated_cpu_utilization_avg_pct",
            "Fig. 5",
            "Isolated CPU utilization",
            "Average CPU utilization (%)",
            lambda item: item["isolated"]["cpu_pct"]["avg"],
            False,
            "cpu_utilization_avg_pct",
        ),
        (
            "fig_06_isolated_memory_alloc_avg_mb",
            "Fig. 6",
            "Isolated memory allocation",
            "Average allocation (MB)",
            lambda item: item["isolated"]["memory_alloc_kb"]["avg"] / 1024,
            False,
            "memory_alloc_avg_mb",
        ),
    ]

    stress_specs = [
        (
            "fig_07_stress_access_token_generation_avg_ms",
            "Fig. 7",
            "Stress access-token generation latency",
            "Average latency (ms, log10)",
            lambda row: row["token_generation_ms"]["avg"],
            True,
            "stress_access_token_generation_avg_ms",
        ),
        (
            "fig_08_stress_access_token_generation_p95_ms",
            "Fig. 8",
            "Stress access-token generation p95 latency",
            "P95 latency (ms, log10)",
            lambda row: row["token_generation_ms"]["p95"],
            True,
            "stress_access_token_generation_p95_ms",
        ),
        (
            "fig_09_stress_end_to_end_response_avg_ms",
            "Fig. 9",
            "Stress end-to-end response latency",
            "Average latency (ms, log10)",
            lambda row: row["e2e_ms"]["avg"],
            True,
            "stress_end_to_end_response_avg_ms",
        ),
        (
            "fig_10_stress_login_avg_ms",
            "Fig. 10",
            "Stress login latency",
            "Average latency (ms, log10)",
            lambda row: row["login_ms"]["avg"],
            True,
            "stress_login_avg_ms",
        ),
        (
            "fig_11_stress_refresh_avg_ms",
            "Fig. 11",
            "Stress refresh latency",
            "Average latency (ms, log10)",
            lambda row: row["refresh_ms"]["avg"],
            True,
            "stress_refresh_avg_ms",
        ),
        (
            "fig_12_stress_throughput_ok_per_s",
            "Fig. 12",
            "Stress successful throughput",
            "Successful requests/s",
            lambda row: row["throughput_ok_per_s"],
            False,
            "stress_throughput_ok_per_s",
        ),
    ]

    figures: list[dict] = []
    for name, fig_id, title, y_label, accessor, log_scale, metric in isolated_specs:
        values = isolated_values(benchmark, accessor)
        render_isolated_metric_png(name, y_label, values, log_scale)
        figures.append(
            {
                "figure_id": fig_id,
                "name": name,
                "title": title,
                "metric": metric,
                "png": True,
            }
        )

    for name, fig_id, title, y_label, accessor, log_scale, metric in stress_specs:
        series = stress_series(benchmark, accessor)
        render_stress_metric_png(name, y_label, series, log_scale)
        figures.append(
            {
                "figure_id": fig_id,
                "name": name,
                "title": title,
                "metric": metric,
                "png": True,
            }
        )

    render_attack_metric_png(adversarial)
    figures.append(
        {
            "figure_id": "Fig. 13",
            "name": "fig_13_security_attack_block_rate_pct",
            "title": "JWT adversarial block rate by attack vector",
            "metric": "security_attack_block_rate_pct",
            "png": True,
        }
    )

    write_palette()
    write_data_csv(benchmark, adversarial)
    write_manifest(figures)
    write_captions(figures)
    write_contact_sheet(figures)
    print(f"Generated {len(figures)} figures in {OUT_DIR}")


if __name__ == "__main__":
    main()

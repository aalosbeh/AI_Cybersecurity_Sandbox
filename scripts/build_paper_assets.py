#!/usr/bin/env python3
"""Generate paper figures and LaTeX tables from the KEV/EPSS analysis."""

from __future__ import annotations

import csv
import json
import math
import textwrap
from pathlib import Path

import pandas as pd
from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
REPORT_TABLES = ROOT / "reports" / "tables"
PAPER = ROOT / "paper"
FIGURES = PAPER / "figures"
TABLES = PAPER / "tables"
SUMMARY_PATH = ROOT / "reports" / "analysis_summary.json"

INK = "#18202f"
MUTED = "#5b6475"
GRID = "#dce1ea"
PANEL = "#ffffff"
SURFACE = "#f7f8fb"
BLUE = "#5477c4"
BLUE_DARK = "#2e4780"
GOLD = "#b8a037"
ORANGE = "#cc6f47"
OLIVE = "#71b436"
PINK = "#bd569b"
LIGHT_BLUE = "#cedffe"
LIGHT_ORANGE = "#ffbda1"
LIGHT_OLIVE = "#beeb96"


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = [
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf" if bold else "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/Library/Fonts/Arial Bold.ttf" if bold else "/Library/Fonts/Arial.ttf",
        "/System/Library/Fonts/Supplemental/Helvetica Bold.ttf" if bold else "/System/Library/Fonts/Supplemental/Helvetica.ttf",
    ]
    for path in candidates:
        try:
            return ImageFont.truetype(path, size=size)
        except OSError:
            continue
    return ImageFont.load_default()


FONT_TITLE = font(36, True)
FONT_SUBTITLE = font(22)
FONT_BODY = font(22)
FONT_BODY_BOLD = font(22, True)
FONT_SMALL = font(18)
FONT_SMALL_BOLD = font(18, True)
FONT_MONO = font(18)


def read_table(name: str) -> pd.DataFrame:
    return pd.read_csv(REPORT_TABLES / name)


def pct_to_float(value: str) -> float:
    return float(str(value).replace("%", "")) / 100.0


def int_from_cell(value: object) -> int:
    return int(str(value).replace(",", ""))


def text_size(draw: ImageDraw.ImageDraw, text: str, fnt: ImageFont.ImageFont) -> tuple[int, int]:
    box = draw.textbbox((0, 0), text, font=fnt)
    return box[2] - box[0], box[3] - box[1]


def wrap_lines(text: str, width: int) -> list[str]:
    return textwrap.wrap(str(text), width=width, break_long_words=False)


def save_canvas(img: Image.Image, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    img.save(path, "PNG", optimize=True)


def draw_header(draw: ImageDraw.ImageDraw, title: str, subtitle: str, width: int) -> int:
    y = 42
    for line in wrap_lines(title, 54):
        draw.text((56, y), line, fill=INK, font=FONT_TITLE)
        y += 42
    y += 8
    for line in wrap_lines(subtitle, 88):
        draw.text((56, y), line, fill=MUTED, font=FONT_SUBTITLE)
        y += 30
    draw.line((56, y + 10, width - 56, y + 10), fill=GRID, width=2)
    return y + 42


def draw_horizontal_bar_chart(
    path: Path,
    title: str,
    subtitle: str,
    labels: list[str],
    values: list[float],
    value_labels: list[str],
    color: str = BLUE,
    width: int = 1600,
    height: int = 1000,
) -> None:
    img = Image.new("RGB", (width, height), SURFACE)
    draw = ImageDraw.Draw(img)
    y0 = draw_header(draw, title, subtitle, width)
    chart_left = 440
    chart_right = width - 130
    max_value = max(values) if values else 1
    row_h = min(72, max(44, int((height - y0 - 80) / max(1, len(labels)))))
    y = y0 + 20
    for label, value, value_label in zip(labels, values, value_labels):
        bar_w = int((chart_right - chart_left) * (value / max_value))
        label_lines = wrap_lines(label, 32)
        label_y = y + max(0, (row_h - 24 * len(label_lines)) // 2)
        for line in label_lines[:2]:
            draw.text((56, label_y), line, fill=INK, font=FONT_SMALL)
            label_y += 23
        draw.rounded_rectangle((chart_left, y + 12, chart_right, y + row_h - 12), radius=8, fill="#eef3fa", outline=GRID)
        draw.rounded_rectangle((chart_left, y + 12, chart_left + bar_w, y + row_h - 12), radius=8, fill=color)
        draw.text((chart_left + bar_w + 12, y + row_h / 2 - 11), value_label, fill=INK, font=FONT_SMALL_BOLD)
        y += row_h
    save_canvas(img, path)


def draw_threshold_chart(path: Path) -> None:
    df = read_table("epss_thresholds.csv")
    thresholds = [row.replace(">= ", "") for row in df["EPSS threshold"]]
    captured = [pct_to_float(x) for x in df["Captured share"]]
    missed = [pct_to_float(x) for x in df["Missed share"]]
    width, height = 1600, 1000
    img = Image.new("RGB", (width, height), SURFACE)
    draw = ImageDraw.Draw(img)
    y0 = draw_header(
        draw,
        "EPSS-only thresholds miss confirmed exploited vulnerabilities",
        "Share of CISA KEV entries captured or missed by current EPSS probability cutoffs.",
        width,
    )
    left, right = 150, width - 90
    top, bottom = y0 + 40, height - 150
    for i in range(6):
        y = bottom - i * (bottom - top) / 5
        draw.line((left, y, right, y), fill=GRID, width=1)
        draw.text((60, y - 12), f"{i*20}%", fill=MUTED, font=FONT_SMALL)
    n = len(thresholds)
    group_w = (right - left) / n
    bar_w = group_w * 0.30
    for i, label in enumerate(thresholds):
        cx = left + group_w * (i + 0.5)
        cap_h = captured[i] * (bottom - top)
        miss_h = missed[i] * (bottom - top)
        draw.rectangle((cx - bar_w - 6, bottom - cap_h, cx - 6, bottom), fill=BLUE, outline=BLUE_DARK)
        draw.rectangle((cx + 6, bottom - miss_h, cx + bar_w + 6, bottom), fill=ORANGE, outline="#804126")
        draw.text((cx - 42, bottom + 18), f">= {label}", fill=INK, font=FONT_SMALL)
        draw.text((cx - bar_w - 16, bottom - cap_h - 28), f"{captured[i]*100:.1f}%", fill=BLUE_DARK, font=FONT_SMALL_BOLD)
        draw.text((cx + 2, bottom - miss_h - 28), f"{missed[i]*100:.1f}%", fill="#804126", font=FONT_SMALL_BOLD)
    draw.text((left, height - 72), "Blue: captured KEV", fill=BLUE_DARK, font=FONT_BODY_BOLD)
    draw.text((left + 320, height - 72), "Orange: missed exploited KEV", fill="#804126", font=FONT_BODY_BOLD)
    draw.line((left, bottom, right, bottom), fill=INK, width=2)
    save_canvas(img, path)


def draw_due_window_chart(path: Path) -> None:
    df = read_table("due_windows.csv")
    labels = list(df["Cohort"])
    median = [float(str(x).replace(" days", "")) for x in df["Median due window"]]
    le3 = [pct_to_float(x) for x in df["Due in <= 3 days"]]
    width, height = 1600, 1000
    img = Image.new("RGB", (width, height), SURFACE)
    draw = ImageDraw.Draw(img)
    y0 = draw_header(
        draw,
        "Recent KEV entries create compressed remediation windows",
        "Median due windows and the share due within three days by catalog cohort.",
        width,
    )
    left, right = 160, width - 100
    top, bottom = y0 + 50, height - 165
    max_days = 24
    for i in range(5):
        x = left + i * (right - left) / 4
        draw.line((x, top, x, bottom), fill=GRID, width=1)
        draw.text((x - 16, bottom + 16), f"{i*6}", fill=MUTED, font=FONT_SMALL)
    row_h = (bottom - top) / len(labels)
    for i, label in enumerate(labels):
        cy = top + row_h * (i + 0.5)
        bar_w = (right - left) * min(median[i], max_days) / max_days
        draw.text((left, cy - 48), label, fill=INK, font=FONT_SMALL_BOLD)
        draw.rounded_rectangle((left, cy - 12, right, cy + 18), radius=8, fill="#eef3fa", outline=GRID)
        draw.rounded_rectangle((left, cy - 12, left + bar_w, cy + 18), radius=8, fill=OLIVE)
        draw.text((left + bar_w + 14, cy - 15), f"{median[i]:.0f} days median", fill=INK, font=FONT_SMALL_BOLD)
        dot_x = left + (right - left) * le3[i]
        draw.ellipse((dot_x - 9, cy + 34, dot_x + 9, cy + 52), fill=ORANGE, outline="#804126")
        draw.text((dot_x + 14, cy + 28), f"{le3[i]*100:.1f}% due <= 3 days", fill="#804126", font=FONT_SMALL)
    draw.text((left, height - 80), "Olive bar: median due window in days. Orange dot: share due within three days.", fill=MUTED, font=FONT_BODY)
    save_canvas(img, path)


def draw_year_chart(path: Path) -> None:
    df = read_table("kev_year_counts.csv")
    labels = [str(x) for x in df["Year added to KEV"]]
    values = [int(x) for x in df["Count"]]
    draw_horizontal_bar_chart(
        path,
        "CISA KEV catalog additions by year",
        "Counts reflect dateAdded in the analyzed catalog snapshot.",
        labels,
        values,
        [str(v) for v in values],
        color=PINK,
    )


def draw_architecture(path: Path) -> None:
    width, height = 1800, 1100
    img = Image.new("RGB", (width, height), SURFACE)
    draw = ImageDraw.Draw(img)
    draw_header(
        draw,
        "Privacy-Preserving Exposure Reasoning Sandbox architecture",
        "Real public threat intelligence is combined with synthetic institutional context and evidence-grounded AI explanations.",
        width,
    )
    boxes = [
        ("Public evidence feeds", "CISA KEV\nEPSS\nCWE/CVE references", (70, 250, 410, 430), BLUE),
        ("Synthetic lab context", "Assets\nUsers\nBusiness criticality\nControl gaps", (70, 560, 410, 780), OLIVE),
        ("Scanner simulation", "OpenVAS exports\nWireshark traces\nDemo Defender alerts", (520, 400, 860, 610), GOLD),
        ("Evidence graph", "CVE -> product -> asset\nCVE -> CWE -> control\nFinding -> action", (970, 400, 1310, 610), PINK),
        ("AI reasoning layer", "Grounded explanation\nPriority score\nFramework mapping", (1420, 250, 1760, 470), ORANGE),
        ("Instructor dashboard", "Rubric scoring\nStudent submissions\nPrivacy checks", (1420, 600, 1760, 820), BLUE_DARK),
    ]
    for title, body, (x1, y1, x2, y2), color in boxes:
        draw.rounded_rectangle((x1, y1, x2, y2), radius=18, fill=PANEL, outline=color, width=4)
        draw.rectangle((x1, y1, x2, y1 + 54), fill=color)
        draw.text((x1 + 18, y1 + 13), title, fill="#ffffff", font=FONT_BODY_BOLD)
        by = y1 + 78
        for line in body.split("\n"):
            draw.text((x1 + 22, by), line, fill=INK, font=FONT_BODY)
            by += 34
    arrows = [
        ((410, 340), (520, 470)),
        ((410, 670), (520, 540)),
        ((860, 505), (970, 505)),
        ((1310, 505), (1420, 360)),
        ((1310, 505), (1420, 710)),
        ((1590, 470), (1590, 600)),
    ]
    for start, end in arrows:
        draw.line((*start, *end), fill=INK, width=4)
        ex, ey = end
        draw.polygon([(ex, ey), (ex - 18, ey - 10), (ex - 18, ey + 10)], fill=INK)
    draw.text((70, 940), "Rule: no student or production telemetry enters the lab. All institutional context is synthetic unless approved and aggregated.", fill="#804126", font=FONT_BODY_BOLD)
    save_canvas(img, path)


def draw_synthetic_screenshot(path: Path) -> None:
    width, height = 1800, 1120
    img = Image.new("RGB", (width, height), "#e9edf5")
    draw = ImageDraw.Draw(img)
    draw.rounded_rectangle((70, 70, width - 70, height - 70), radius=24, fill="#ffffff", outline=GRID, width=3)
    draw.rectangle((70, 70, width - 70, 155), fill=BLUE_DARK)
    draw.text((105, 96), "PERS Instructor Cockpit - synthetic screenshot", fill="#ffffff", font=FONT_TITLE)
    draw.text((105, 170), "No UVU production data. All assets and users below are synthetic.", fill="#804126", font=FONT_BODY_BOLD)
    cards = [
        ("Critical findings", "18", ORANGE),
        ("Known exploited", "11", BLUE),
        ("Ransomware-linked", "4", PINK),
        ("Due <= 3 days", "7", OLIVE),
    ]
    x = 105
    for title, value, color in cards:
        draw.rounded_rectangle((x, 220, x + 360, 350), radius=14, fill="#f7faff", outline=GRID)
        draw.text((x + 24, 244), value, fill=color, font=font(48, True))
        draw.text((x + 24, 306), title, fill=INK, font=FONT_BODY_BOLD)
        x += 405
    headers = ["Priority", "Synthetic asset", "Finding", "Evidence", "Student action"]
    col_x = [105, 250, 555, 980, 1335]
    y = 430
    draw.rounded_rectangle((95, y - 18, width - 95, y + 48), radius=10, fill="#f1f5fb", outline=GRID)
    for hx, header in zip(col_x, headers):
        draw.text((hx, y), header, fill=BLUE_DARK, font=FONT_SMALL_BOLD)
    rows = [
        ("1", "web-lab-03", "Log4j2 RCE", "KEV + EPSS 1.000", "Patch, isolate, verify"),
        ("2", "vpn-lab-01", "Pulse path traversal", "KEV + ransomware", "Mitigate, inspect logs"),
        ("3", "mail-lab-02", "Exchange exploit chain", "KEV + internet exposed", "Patch and hunt IOCs"),
        ("4", "db-lab-01", "Excess write access", "Control gap", "Read-only role"),
        ("5", "client-lab-07", "Browser memory safety", "KEV + low EPSS", "Explain exception"),
    ]
    y += 70
    for i, row in enumerate(rows):
        fill = "#ffffff" if i % 2 == 0 else "#fbfcfe"
        draw.rounded_rectangle((95, y - 20, width - 95, y + 68), radius=8, fill=fill, outline=GRID)
        for hx, cell in zip(col_x, row):
            draw.text((hx, y), cell, fill=INK, font=FONT_SMALL)
        y += 96
    draw.rounded_rectangle((105, 965, width - 105, 1035), radius=12, fill="#fff8f4", outline=LIGHT_ORANGE)
    draw.text((135, 984), "AI explanation guardrail: each recommendation must cite public CVE evidence, synthetic asset facts, and lab scanner output.", fill="#804126", font=FONT_BODY_BOLD)
    save_canvas(img, path)


def latex_escape(value: object) -> str:
    text = str(value)
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    return "".join(replacements.get(ch, ch) for ch in text)


def write_tabular(path: Path, df: pd.DataFrame, align: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if align is None:
        align = "l" + "r" * (len(df.columns) - 1)
    lines = [rf"\begin{{tabular}}{{{align}}}", r"\toprule"]
    lines.append(" & ".join(latex_escape(c) for c in df.columns) + r" \\")
    lines.append(r"\midrule")
    for _, row in df.iterrows():
        lines.append(" & ".join(latex_escape(v) for v in row.tolist()) + r" \\")
    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def truncate(df: pd.DataFrame, column: str, length: int) -> pd.DataFrame:
    out = df.copy()
    out[column] = out[column].fillna("").map(
        lambda x: textwrap.shorten(str(x), width=length, placeholder="...")
    )
    return out


def write_tables() -> None:
    threshold = read_table("epss_thresholds.csv")
    ransomware = read_table("ransomware_epss_thresholds.csv")
    vendors = read_table("top_vendors.csv").head(8)
    cwes = read_table("top_cwes.csv").head(10)
    due = read_table("due_windows.csv")
    high = read_table("high_epss_examples.csv").head(6)
    low = read_table("low_epss_examples.csv").head(6)
    high = truncate(high, "Product", 34)
    high = truncate(high, "CWE(s)", 28)
    low = truncate(low, "Product", 34)
    low = truncate(low, "CWE(s)", 28)
    write_tabular(TABLES / "epss_thresholds.tex", threshold, "lrrrr")
    write_tabular(TABLES / "ransomware_thresholds.tex", ransomware, "lrrrr")
    write_tabular(TABLES / "top_vendors.tex", vendors, "lrr")
    write_tabular(TABLES / "top_cwes.tex", cwes, "lrr")
    write_tabular(TABLES / "due_windows.tex", due, "lrrrrr")
    write_tabular(TABLES / "high_epss_examples.tex", high, "llllrrrr")
    write_tabular(TABLES / "low_epss_examples.tex", low, "llllrrrr")


def write_summary_macros() -> None:
    summary = json.loads(SUMMARY_PATH.read_text(encoding="utf-8"))
    h = summary["headline_metrics"]
    c = summary["cisa_kev"]
    e = summary["epss"]
    macros = {
        "KevCount": f"{c['observed_rows']:,}",
        "KevCatalogVersion": c["catalog_version"],
        "KevDateReleased": c["date_released"],
        "EpssModelVersion": e["model_version"],
        "EpssScoreDate": e["score_date"],
        "EpssRows": f"{e['rows']:,}",
        "EpssCoverage": f"{h['epss_coverage'] * 100:.1f}\\%",
        "RansomwareKnown": f"{h['ransomware_known']:,}",
        "RansomwareKnownShare": f"{h['ransomware_known_share'] * 100:.1f}\\%",
        "EpssMedian": f"{h['epss_median']:.3f}",
        "DueMedian": f"{h['due_days_median']:.0f}",
        "NoCweCount": f"{h['no_cwe']:,}",
        "NoCweShare": f"{h['no_cwe_share'] * 100:.1f}\\%",
    }
    lines = [f"\\newcommand{{\\{name}}}{{{value}}}" for name, value in macros.items()]
    (PAPER / "summary_macros.tex").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    FIGURES.mkdir(parents=True, exist_ok=True)
    TABLES.mkdir(parents=True, exist_ok=True)
    draw_threshold_chart(FIGURES / "fig_epss_thresholds.png")
    ransomware = read_table("ransomware_epss_thresholds.csv")
    labels = list(ransomware["EPSS threshold"])
    values = [pct_to_float(x) for x in ransomware["Missed share"]]
    draw_horizontal_bar_chart(
        FIGURES / "fig_ransomware_missed.png",
        "High EPSS thresholds still miss ransomware-linked KEV entries",
        "Missed share among CISA KEV entries flagged as known ransomware campaign use.",
        labels,
        values,
        list(ransomware["Missed share"]),
        color=ORANGE,
    )
    vendors = read_table("top_vendors.csv").head(10)
    draw_horizontal_bar_chart(
        FIGURES / "fig_top_vendors.png",
        "Top vendor/project concentration in KEV",
        "Top ten vendor/project values in the analyzed catalog snapshot.",
        list(vendors["Vendor/project"]),
        [int_from_cell(v) for v in vendors["Count"]],
        [str(v) for v in vendors["Count"]],
        color=BLUE,
    )
    cwes = read_table("top_cwes.csv").head(12)
    draw_horizontal_bar_chart(
        FIGURES / "fig_top_cwes.png",
        "Most frequent CWE patterns in KEV",
        "Top CWE labels after exploding the KEV cwes array; entries without CWE values are excluded from this ranking.",
        list(cwes["CWE"]),
        [int_from_cell(v) for v in cwes["Count"]],
        [str(v) for v in cwes["Count"]],
        color=OLIVE,
    )
    draw_due_window_chart(FIGURES / "fig_due_windows.png")
    draw_year_chart(FIGURES / "fig_year_counts.png")
    draw_architecture(FIGURES / "fig_pers_architecture.png")
    draw_synthetic_screenshot(FIGURES / "fig_synthetic_screenshot.png")
    write_tables()
    write_summary_macros()
    print(f"Wrote figures to {FIGURES}")
    print(f"Wrote tables to {TABLES}")


if __name__ == "__main__":
    main()

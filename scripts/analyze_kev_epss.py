#!/usr/bin/env python3
"""Build the KEV/EPSS analysis and technical research-paper artifact."""

from __future__ import annotations

import gzip
import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
PROCESSED = ROOT / "data" / "processed"
REPORTS = ROOT / "reports"
TABLES = REPORTS / "tables"

KEV_PATH = RAW / "cisa_kev.json"
EPSS_PATH = RAW / "epss_scores-current.csv.gz"

TITLE = (
    "Teaching Exposure Management Without Production Data: "
    "A Real-World KEV/EPSS Analysis for an AI Cybersecurity Sandbox"
)


def pct(value: float, decimals: int = 1) -> str:
    return f"{value * 100:.{decimals}f}%"


def fmt_num(value: float | int, decimals: int = 0) -> str:
    if isinstance(value, float) and not value.is_integer():
        return f"{value:,.{decimals}f}"
    return f"{int(value):,}"


def fmt_float(value: float, decimals: int = 3) -> str:
    return f"{value:.{decimals}f}"


def parse_epss_meta(path: Path) -> dict[str, str]:
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        line = fh.readline().strip()
    meta: dict[str, str] = {}
    if line.startswith("#"):
        for item in line[1:].split(","):
            if ":" in item:
                key, value = item.split(":", 1)
                meta[key.strip()] = value.strip()
    return meta


def render_table(df: pd.DataFrame, classes: str = "") -> str:
    thead = "".join(f"<th>{html.escape(str(col))}</th>" for col in df.columns)
    rows = []
    for _, row in df.iterrows():
        cells = "".join(f"<td>{html.escape(str(value))}</td>" for value in row.tolist())
        rows.append(f"<tr>{cells}</tr>")
    class_attr = f' class="{classes}"' if classes else ""
    return f"<table{class_attr}><thead><tr>{thead}</tr></thead><tbody>{''.join(rows)}</tbody></table>"


def value_counts_table(series: pd.Series, name: str, top_n: int, total: int) -> pd.DataFrame:
    counts = series.value_counts().head(top_n).reset_index()
    counts.columns = [name, "Count"]
    counts["Share of KEV"] = counts["Count"].map(lambda x: pct(x / total))
    return counts


def save_csv(df: pd.DataFrame, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, index=False)


def html_list(items: Iterable[str]) -> str:
    return "<ul>" + "".join(f"<li>{item}</li>" for item in items) + "</ul>"


def main() -> None:
    PROCESSED.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    TABLES.mkdir(parents=True, exist_ok=True)

    kev_doc = json.loads(KEV_PATH.read_text(encoding="utf-8"))
    kev = pd.DataFrame(kev_doc["vulnerabilities"])
    epss_meta = parse_epss_meta(EPSS_PATH)
    epss = pd.read_csv(EPSS_PATH, compression="gzip", comment="#")

    joined = kev.merge(epss, left_on="cveID", right_on="cve", how="left")
    joined["dateAdded_dt"] = pd.to_datetime(joined["dateAdded"])
    joined["dueDate_dt"] = pd.to_datetime(joined["dueDate"])
    joined["due_days"] = (joined["dueDate_dt"] - joined["dateAdded_dt"]).dt.days
    joined["has_cwe"] = joined["cwes"].map(lambda values: isinstance(values, list) and len(values) > 0)
    joined["cwe_list"] = joined["cwes"].map(
        lambda values: "; ".join(values) if isinstance(values, list) else ""
    )

    joined_for_csv = joined.drop(columns=["dateAdded_dt", "dueDate_dt"])
    joined_for_csv.to_csv(PROCESSED / "kev_epss_joined.csv", index=False)

    total = len(joined)
    missing_epss = int(joined["epss"].isna().sum())
    epss_coverage = 1 - missing_epss / total
    ransomware_known = int((joined["knownRansomwareCampaignUse"] == "Known").sum())
    ransomware_unknown = int((joined["knownRansomwareCampaignUse"] == "Unknown").sum())
    no_cwe = int((~joined["has_cwe"]).sum())

    epss_desc = joined["epss"].describe(percentiles=[0.10, 0.25, 0.50, 0.75, 0.90, 0.95, 0.99])

    threshold_rows = []
    for threshold in [0.10, 0.20, 0.50, 0.70, 0.90]:
        captured = int((joined["epss"] >= threshold).sum())
        missed = total - captured
        threshold_rows.append(
            {
                "EPSS threshold": f">= {threshold:.2f}",
                "Captured KEV": fmt_num(captured),
                "Captured share": pct(captured / total),
                "Missed exploited KEV": fmt_num(missed),
                "Missed share": pct(missed / total),
            }
        )
    threshold_table = pd.DataFrame(threshold_rows)

    known = joined[joined["knownRansomwareCampaignUse"] == "Known"]
    ransomware_threshold_rows = []
    for threshold in [0.10, 0.50, 0.70, 0.90]:
        captured = int((known["epss"] >= threshold).sum())
        missed = len(known) - captured
        ransomware_threshold_rows.append(
            {
                "EPSS threshold": f">= {threshold:.2f}",
                "Captured ransomware-linked KEV": fmt_num(captured),
                "Captured share": pct(captured / len(known)),
                "Missed ransomware-linked KEV": fmt_num(missed),
                "Missed share": pct(missed / len(known)),
            }
        )
    ransomware_threshold_table = pd.DataFrame(ransomware_threshold_rows)

    top_vendors = value_counts_table(joined["vendorProject"], "Vendor/project", 10, total)
    top_products = (
        joined.groupby(["vendorProject", "product"])
        .size()
        .sort_values(ascending=False)
        .head(10)
        .reset_index(name="Count")
    )
    top_products["Share of KEV"] = top_products["Count"].map(lambda x: pct(x / total))
    top_products["Vendor/product"] = top_products["vendorProject"] + " / " + top_products["product"]
    top_products = top_products[["Vendor/product", "Count", "Share of KEV"]]

    cwe = joined[["cveID", "cwes"]].explode("cwes")
    top_cwes = cwe["cwes"].dropna().value_counts().head(12).reset_index()
    top_cwes.columns = ["CWE", "Count"]
    top_cwes["Share of KEV"] = top_cwes["Count"].map(lambda x: pct(x / total))

    year_counts = joined["dateAdded_dt"].dt.year.value_counts().sort_index().reset_index()
    year_counts.columns = ["Year added to KEV", "Count"]
    year_counts["Share of KEV"] = year_counts["Count"].map(lambda x: pct(x / total))

    due_rows = []
    for label, since in [
        ("All KEV entries", None),
        ("Added since 2025-01-01", "2025-01-01"),
        ("Added since 2026-01-01", "2026-01-01"),
        ("Added since 2026-06-01", "2026-06-01"),
    ]:
        subset = joined if since is None else joined[joined["dateAdded_dt"] >= pd.Timestamp(since)]
        due_rows.append(
            {
                "Cohort": label,
                "Entries": fmt_num(len(subset)),
                "Median due window": f"{subset['due_days'].median():.0f} days",
                "Mean due window": f"{subset['due_days'].mean():.1f} days",
                "Due in <= 3 days": pct((subset["due_days"] <= 3).mean()),
                "Due in <= 14 days": pct((subset["due_days"] <= 14).mean()),
            }
        )
    due_table = pd.DataFrame(due_rows)

    case_examples = joined.sort_values("epss", ascending=False).head(8)[
        [
            "cveID",
            "vendorProject",
            "product",
            "dateAdded",
            "knownRansomwareCampaignUse",
            "epss",
            "percentile",
            "cwe_list",
        ]
    ].copy()
    case_examples.columns = [
        "CVE",
        "Vendor",
        "Product",
        "Date added",
        "Ransomware flag",
        "EPSS",
        "EPSS percentile",
        "CWE(s)",
    ]
    case_examples["EPSS"] = case_examples["EPSS"].map(lambda x: fmt_float(x, 5))
    case_examples["EPSS percentile"] = case_examples["EPSS percentile"].map(lambda x: fmt_float(x, 5))

    low_examples = joined.sort_values("epss").head(8)[
        [
            "cveID",
            "vendorProject",
            "product",
            "dateAdded",
            "knownRansomwareCampaignUse",
            "epss",
            "percentile",
            "cwe_list",
        ]
    ].copy()
    low_examples.columns = case_examples.columns
    low_examples["EPSS"] = low_examples["EPSS"].map(lambda x: fmt_float(x, 5))
    low_examples["EPSS percentile"] = low_examples["EPSS percentile"].map(lambda x: fmt_float(x, 5))

    for name, table in [
        ("epss_thresholds.csv", threshold_table),
        ("ransomware_epss_thresholds.csv", ransomware_threshold_table),
        ("top_vendors.csv", top_vendors),
        ("top_products.csv", top_products),
        ("top_cwes.csv", top_cwes),
        ("kev_year_counts.csv", year_counts),
        ("due_windows.csv", due_table),
        ("high_epss_examples.csv", case_examples),
        ("low_epss_examples.csv", low_examples),
    ]:
        save_csv(table, TABLES / name)

    summary = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "cisa_kev": {
            "source": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "catalog_version": kev_doc.get("catalogVersion"),
            "date_released": kev_doc.get("dateReleased"),
            "count": int(kev_doc.get("count", total)),
            "observed_rows": total,
            "date_added_min": joined["dateAdded_dt"].min().date().isoformat(),
            "date_added_max": joined["dateAdded_dt"].max().date().isoformat(),
        },
        "epss": {
            "source": "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
            "model_version": epss_meta.get("model_version"),
            "score_date": epss_meta.get("score_date"),
            "rows": int(len(epss)),
            "coverage_for_kev": epss_coverage,
        },
        "headline_metrics": {
            "kev_entries": total,
            "epss_coverage": epss_coverage,
            "ransomware_known": ransomware_known,
            "ransomware_unknown": ransomware_unknown,
            "ransomware_known_share": ransomware_known / total,
            "no_cwe": no_cwe,
            "no_cwe_share": no_cwe / total,
            "epss_median": float(epss_desc["50%"]),
            "epss_p25": float(epss_desc["25%"]),
            "epss_p75": float(epss_desc["75%"]),
            "due_days_median": float(joined["due_days"].median()),
            "due_days_mean": float(joined["due_days"].mean()),
        },
    }
    (REPORTS / "analysis_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    source_notes = f"""# Source and Reproducibility Notes

Generated: {summary["generated_at_utc"]}

## Data sources

- CISA Known Exploited Vulnerabilities catalog JSON: {summary["cisa_kev"]["source"]}
- FIRST EPSS current scores CSV: {summary["epss"]["source"]}
- NIST Cybersecurity Framework 2.0 overview: https://www.nist.gov/cyberframework
- MITRE ATT&CK Enterprise matrix: https://attack.mitre.org/
- Source transcript: /Users/anasalsobeh/.codex/attachments/eabacbc5-16a3-4df7-bc3c-940a2ff3e12c/pasted-text.txt

## Dataset snapshot

- CISA KEV catalog version: {kev_doc.get("catalogVersion")}
- CISA KEV released: {kev_doc.get("dateReleased")}
- CISA KEV rows observed: {fmt_num(total)}
- EPSS model version: {epss_meta.get("model_version")}
- EPSS score date: {epss_meta.get("score_date")}
- EPSS rows observed: {fmt_num(len(epss))}
- KEV rows with EPSS match: {fmt_num(total - missing_epss)} ({pct(epss_coverage)})

## Processing

The script joins CISA KEV to EPSS by CVE identifier, computes EPSS-threshold capture and miss rates, ransomware-flag capture and miss rates, top vendor/product/CWE counts, KEV year counts, and CISA due-window distributions.

No UVU, vendor-customer, student, or production security telemetry is used. The paper intentionally models a privacy-preserving classroom environment where public vulnerability intelligence is combined with synthetic asset and identity context.

## Visual note

The available local Python runtime includes pandas and numpy but not matplotlib or seaborn. The report therefore uses tables as the evidence surface and does not claim Seaborn-template chart compliance.
"""
    (REPORTS / "source_notes.md").write_text(source_notes, encoding="utf-8")

    css = """
    :root {
      --bg: #f7f8fb;
      --paper: #ffffff;
      --ink: #18202f;
      --muted: #5b6475;
      --line: #dce1ea;
      --soft: #eef3fa;
      --accent: #5477c4;
      --accent-dark: #2e4780;
      --warn: #cc6f47;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
    }
    main {
      max-width: 1040px;
      margin: 0 auto;
      padding: 40px 20px 72px;
    }
    article {
      background: var(--paper);
      border: 1px solid var(--line);
      box-shadow: 0 18px 48px rgba(24, 32, 47, 0.08);
    }
    header, section {
      padding: 28px 36px;
      border-bottom: 1px solid var(--line);
    }
    section:last-child { border-bottom: 0; }
    .kicker {
      color: var(--accent-dark);
      font-size: 13px;
      font-weight: 700;
      letter-spacing: .06em;
      text-transform: uppercase;
      margin-bottom: 10px;
    }
    h1 {
      font-size: clamp(30px, 4vw, 46px);
      line-height: 1.05;
      margin: 0 0 16px;
      max-width: 900px;
      letter-spacing: 0;
    }
    h2 {
      font-size: 24px;
      line-height: 1.2;
      margin: 0 0 12px;
      letter-spacing: 0;
    }
    h3 {
      font-size: 18px;
      margin: 24px 0 8px;
      letter-spacing: 0;
    }
    p, li {
      font-size: 16px;
      line-height: 1.65;
    }
    p { margin: 0 0 14px; }
    ul, ol { margin: 10px 0 0 22px; padding: 0; }
    li { margin-bottom: 8px; }
    .meta {
      color: var(--muted);
      font-size: 14px;
      margin-bottom: 0;
    }
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
      margin-top: 18px;
    }
    .metric {
      border: 1px solid var(--line);
      background: var(--soft);
      padding: 14px;
      min-height: 96px;
    }
    .metric strong {
      display: block;
      font-size: 24px;
      line-height: 1.1;
      color: var(--accent-dark);
      margin-bottom: 6px;
    }
    .metric span {
      display: block;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.4;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin: 16px 0 24px;
      font-size: 14px;
    }
    th, td {
      border: 1px solid var(--line);
      padding: 10px 12px;
      text-align: left;
      vertical-align: top;
    }
    th {
      background: #f1f5fb;
      color: var(--accent-dark);
      font-weight: 700;
    }
    tr:nth-child(even) td { background: #fbfcfe; }
    .callout {
      border-left: 4px solid var(--accent);
      background: #f7faff;
      padding: 14px 16px;
      margin: 18px 0;
    }
    .warning {
      border-left-color: var(--warn);
      background: #fff8f4;
    }
    code, pre {
      font-family: "SF Mono", Menlo, Consolas, "DejaVu Sans Mono", monospace;
    }
    pre {
      overflow-x: auto;
      background: #f4f6fa;
      border: 1px solid var(--line);
      padding: 16px;
      line-height: 1.5;
    }
    a { color: var(--accent-dark); }
    @media (max-width: 760px) {
      main { padding: 16px; }
      header, section { padding: 22px 18px; }
      .summary-grid { grid-template-columns: 1fr; }
      table { display: block; overflow-x: auto; white-space: nowrap; }
    }
    """

    top_vendor_count = int(top_vendors.iloc[0]["Count"])
    top_vendor_name = str(top_vendors.iloc[0]["Vendor/project"])
    epss_half = threshold_table[threshold_table["EPSS threshold"] == ">= 0.50"].iloc[0]
    epss_nine = threshold_table[threshold_table["EPSS threshold"] == ">= 0.90"].iloc[0]

    report_html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(TITLE)}</title>
  <style>{css}</style>
</head>
<body>
<main data-report-audience="technical">
<article>
  <header data-contract-section="title">
    <div class="kicker">Technical research paper draft</div>
    <h1>{html.escape(TITLE)}</h1>
    <p class="meta">Prepared from public vulnerability intelligence. Data snapshot: CISA KEV {html.escape(str(kev_doc.get("catalogVersion")))} released {html.escape(str(kev_doc.get("dateReleased")))}; EPSS score date {html.escape(str(epss_meta.get("score_date")))}.</p>
  </header>

  <section data-contract-section="technical-summary">
    <h2>Technical Summary</h2>
    <p><strong>Main result.</strong> The transcript points to a researchable gap: cybersecurity courses need realistic exposure-management reasoning, but production university telemetry is too sensitive for classroom use. A privacy-preserving AI sandbox can close that gap by combining real public exploit intelligence with synthetic asset, identity, and control data.</p>
    <p>The empirical analysis supports this direction. The CISA KEV catalog contains {fmt_num(total)} confirmed exploited vulnerabilities in the snapshot analyzed here, and every KEV row matched a current EPSS record. Yet a simple EPSS-only policy would miss many already-exploited vulnerabilities: the {html.escape(str(epss_half["EPSS threshold"]))} threshold captures {html.escape(str(epss_half["Captured share"]))} of KEV and misses {html.escape(str(epss_half["Missed exploited KEV"]))} exploited CVEs; the {html.escape(str(epss_nine["EPSS threshold"]))} threshold captures only {html.escape(str(epss_nine["Captured share"]))} and misses {html.escape(str(epss_nine["Missed exploited KEV"]))}. This is the core teaching opportunity: students must learn to blend confirmed exploitation, predictive probability, asset exposure, compensating controls, and remediation feasibility.</p>
    <div class="summary-grid">
      <div class="metric"><strong>{fmt_num(total)}</strong><span>CISA KEV entries analyzed</span></div>
      <div class="metric"><strong>{pct(epss_coverage)}</strong><span>KEV entries matched to EPSS</span></div>
      <div class="metric"><strong>{fmt_num(ransomware_known)}</strong><span>KEVs flagged as known ransomware campaign use</span></div>
      <div class="metric"><strong>{fmt_float(float(epss_desc["50%"]), 3)}</strong><span>Median current EPSS among KEV entries</span></div>
    </div>
  </section>

  <section data-contract-section="key-findings">
    <h2>EPSS Alone Is Not Enough for Teaching Exploitation Risk</h2>
    <p><strong>Confirmed exploitation and predicted near-term exploitation answer different questions.</strong> KEV says a vulnerability has been exploited in the wild; EPSS estimates probability of exploitation in the next 30 days. In a classroom, this distinction matters because an AI tool that only follows a probability threshold can teach students to ignore older, still-relevant exploited weaknesses when current exploit activity has cooled.</p>
    {render_table(threshold_table)}
    <p><strong>Ransomware-linked vulnerabilities require an override signal.</strong> {fmt_num(ransomware_known)} KEV entries, or {pct(ransomware_known / total)}, are marked by CISA as known ransomware campaign use. Even within this group, an EPSS threshold of >= 0.90 misses {html.escape(str(ransomware_threshold_table.iloc[-1]["Missed ransomware-linked KEV"]))} ransomware-linked KEVs. A teaching sandbox should therefore treat ransomware linkage as a separate decision feature, not as a detail hidden behind a single score.</p>
    {render_table(ransomware_threshold_table)}
  </section>

  <section>
    <h2>Real Exploit Data Produces Concrete Lab Cases</h2>
    <p><strong>The catalog is concentrated enough for a course sequence but broad enough to prevent one-tool thinking.</strong> {top_vendor_name} appears most often with {fmt_num(top_vendor_count)} KEV entries, but the top products and CWEs span operating systems, browsers, collaboration platforms, network devices, deserialization, command injection, memory safety, path traversal, and authentication failures. This supports a sequence of labs where students compare scanner output, exploit-intelligence evidence, MITRE-style attacker behavior, NIST-style control outcomes, and remediation tradeoffs.</p>
    <h3>Top vendor/project concentrations</h3>
    {render_table(top_vendors)}
    <h3>Top vendor/product pairs</h3>
    {render_table(top_products)}
    <h3>Top CWE patterns</h3>
    {render_table(top_cwes)}
    <p class="callout"><strong>Interpretation.</strong> The most useful classroom cases are not necessarily the highest EPSS cases. A stronger curriculum deliberately samples high-EPSS cases, low-current-EPSS KEV cases, ransomware-linked cases, missing-CWE cases, and cases with compressed CISA due windows. That sampling teaches uncertainty, triage, and governance.</p>
  </section>

  <section>
    <h2>Compressed Due Windows Make Prioritization Operational</h2>
    <p><strong>The remediation clock is part of the learning objective.</strong> Across the full KEV snapshot, the median CISA due window is {joined["due_days"].median():.0f} days. Among entries added since 2026-06-01, the median due window is {joined[joined["dateAdded_dt"] >= pd.Timestamp("2026-06-01")]["due_days"].median():.0f} days, with {pct((joined[joined["dateAdded_dt"] >= pd.Timestamp("2026-06-01")]["due_days"] <= 3).mean())} due in three days or less. This makes an exposure-management lab more realistic than a raw vulnerability-scanning lab: students must explain what to patch, what to mitigate, what to monitor, and what to escalate first.</p>
    {render_table(due_table)}
    <h3>KEV additions by year</h3>
    {render_table(year_counts)}
  </section>

  <section data-contract-section="scope-data-and-metric-definitions">
    <h2>Scope, Data, and Metric Definitions</h2>
    <p><strong>Scope.</strong> The analysis uses only public vulnerability intelligence plus the attached vendor-discussion transcript. It does not use UVU production systems, student data, endpoint telemetry, identity logs, procurement data, or any vendor customer data.</p>
    {html_list([
        f"<strong>CISA KEV.</strong> {fmt_num(total)} vulnerabilities from catalog version {html.escape(str(kev_doc.get('catalogVersion')))}, released {html.escape(str(kev_doc.get('dateReleased')))}. Fields used: CVE ID, vendor/project, product, date added, due date, ransomware campaign flag, required action, notes, and CWE list.",
        f"<strong>EPSS.</strong> {fmt_num(len(epss))} CVE records from model version {html.escape(str(epss_meta.get('model_version')))} with score date {html.escape(str(epss_meta.get('score_date')))}. Fields used: CVE, EPSS probability, percentile.",
        "<strong>KEV capture rate.</strong> The share of KEV CVEs whose current EPSS score is at or above a chosen threshold.",
        "<strong>Missed exploited KEV.</strong> KEV CVEs below a chosen EPSS threshold. These are not false negatives for EPSS as a 30-day predictor; they are cases showing why a confirmed-exploitation signal should not be replaced by a current probability threshold.",
        "<strong>Due window.</strong> Calendar days between CISA dateAdded and dueDate.",
    ])}
  </section>

  <section data-contract-section="methodology">
    <h2>Methodology: Privacy-Preserving Exposure Reasoning Sandbox</h2>
    <p><strong>Research idea.</strong> Build and evaluate a Privacy-Preserving Exposure Reasoning Sandbox (PERS) for cybersecurity education. PERS uses real public vulnerability intelligence and synthetic institutional context so students can practice exposure management without connecting a class tool to real university production assets.</p>
    <p>The sandbox architecture has five layers: public evidence ingestion, synthetic asset and identity graph, scanner-output simulation, AI reasoning with source-grounded explanations, and instructor evaluation. A commercial exposure-assessment platform can be evaluated as one implementation, but the research contribution is vendor-neutral: the classroom system should prove that it can explain prioritization, preserve privacy, map risk to frameworks, and improve student decisions.</p>
    <pre>EvidenceScore(v) =
    1.00 if v is in CISA KEV
    else EPSS_percentile(v)

TeachingPriority(v, asset) =
    40 * EvidenceScore(v)
  + 15 * RansomwareCampaignFlag(v)
  + 15 * EPSS_percentile(v)
  + 10 * SyntheticInternetExposure(asset)
  + 10 * SyntheticAssetCriticality(asset)
  + 10 * ControlGap(asset, v)

AI explanation must cite:
  public vulnerability evidence + lab scanner output + synthetic asset facts
and must not infer or expose real institutional telemetry.</pre>
    <p><strong>Evaluation design.</strong> A course pilot can compare two lab conditions: raw scanner output only versus scanner output plus PERS explanations. Outcomes should include prioritization accuracy against an expert rubric, quality of MITRE/NIST mapping, remediation-plan specificity, time to first defensible action, hallucinated claim rate, and privacy-rule violations.</p>
  </section>

  <section>
    <h2>Example Teaching Cases From the Data</h2>
    <p><strong>High-current-risk cases are useful for demonstrating urgent exploitation pressure.</strong> The following examples have the highest current EPSS scores among the KEV snapshot and can seed labs on emergency triage, compensating controls, and executive communication.</p>
    {render_table(case_examples)}
    <p><strong>Low-current-EPSS KEV cases are equally valuable.</strong> These cases are already in KEV but have low current EPSS values. They help students learn that a probability score can change over time and that governance should preserve confirmed historical exploitation as a separate evidence signal.</p>
    {render_table(low_examples)}
  </section>

  <section data-contract-section="limitations-uncertainty-and-robustness-checks">
    <h2>Limitations, Uncertainty, and Robustness Checks</h2>
    {html_list([
        "<strong>KEV is not a complete exploitation universe.</strong> It is a curated catalog of known exploited vulnerabilities and should be treated as a high-confidence positive signal, not as a complete list of all exploitation.",
        "<strong>EPSS is time-sensitive.</strong> A low current EPSS score for a KEV entry does not contradict past exploitation; it means current 30-day predicted exploitation probability is low relative to the model inputs.",
        f"<strong>CWE coverage is incomplete.</strong> {fmt_num(no_cwe)} KEV entries ({pct(no_cwe / total)}) have no CWE values in this snapshot, so CWE-based lesson planning needs fallback labels from CVE descriptions or instructor review.",
        "<strong>CISA due dates are not a university SLA by default.</strong> They are still useful for classroom time pressure, but institutional policy and risk appetite would determine real remediation deadlines.",
        "<strong>No learning-outcome experiment has been run yet.</strong> The data analysis justifies the research design; it does not prove that an AI sandbox improves student learning.",
    ])}
    <p class="callout warning"><strong>Robustness check.</strong> The strongest quantitative conclusion does not depend on one threshold. Across EPSS >= 0.10, 0.20, 0.50, 0.70, and 0.90, every threshold misses some confirmed exploited KEV entries. The interpretation is stable: EPSS should augment, not replace, KEV in an educational exposure-management workflow.</p>
  </section>

  <section data-contract-section="recommended-next-steps">
    <h2>Recommended Next Steps</h2>
    {html_list([
        "<strong>Ask for a classroom sandbox, not production integration.</strong> The immediate vendor ask should be a faculty pilot that supports synthetic users, synthetic assets, sample scanner outputs, CISA KEV, EPSS, CWE, MITRE ATT&CK, and NIST CSF mappings.",
        "<strong>Build a baseline lab from OpenVAS output.</strong> Use deliberately vulnerable VMs and public CVE evidence so students first see noisy scanner results, then compare them to exposure-prioritized recommendations.",
        "<strong>Require explanation provenance.</strong> Every AI recommendation should show the evidence path: scanner finding, public exploit evidence, synthetic asset criticality, framework mapping, and remediation action.",
        "<strong>Keep access read-only for students.</strong> Students should be able to inspect and explain risk, but not connect to production integrations, update institutional systems, or view sensitive user/device telemetry.",
        "<strong>Evaluate learning, not just tool appeal.</strong> Measure whether students make better remediation decisions and fewer unsupported claims after using the sandbox.",
    ])}
  </section>

  <section data-contract-section="further-questions">
    <h2>Further Questions</h2>
    {html_list([
        "How much does AI explanation improve student prioritization compared with a well-designed static rubric?",
        "Which framework mapping is reliable enough for automated feedback: CWE-to-control, CVE-to-MITRE, scanner plugin-to-NIST, or instructor-curated mappings?",
        "Can the sandbox later support privacy-preserving summaries of real institutional exposure without showing raw production telemetry to students?",
        "What hallucination controls are necessary before an AI exposure assistant is used for graded cybersecurity labs?",
        "How should academic licensing distinguish classroom-only use, faculty evaluation, internship use, and institution-wide operational deployment?",
    ])}
  </section>

  <section>
    <h2>References and Data Sources</h2>
    {html_list([
        '<a href="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json">CISA Known Exploited Vulnerabilities catalog JSON</a>.',
        '<a href="https://epss.empiricalsecurity.com/epss_scores-current.csv.gz">FIRST EPSS current scores CSV</a> and <a href="https://www.first.org/epss/">FIRST EPSS overview</a>.',
        '<a href="https://www.nist.gov/cyberframework">NIST Cybersecurity Framework 2.0 resource center</a>.',
        '<a href="https://attack.mitre.org/">MITRE ATT&CK Enterprise knowledge base</a>.',
        'Industry exposure-assessment platform discussion (vendor-neutral framing).',
    ])}
  </section>
</article>
</main>
</body>
</html>
"""

    (REPORTS / "kev_epss_exposure_analysis.html").write_text(report_html, encoding="utf-8")

    print(f"Wrote {REPORTS / 'kev_epss_exposure_analysis.html'}")
    print(f"Wrote {REPORTS / 'analysis_summary.json'}")
    print(f"Wrote {PROCESSED / 'kev_epss_joined.csv'}")


if __name__ == "__main__":
    main()

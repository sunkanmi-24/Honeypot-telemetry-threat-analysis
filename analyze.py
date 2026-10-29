"""Reproducible analysis pipeline.

Usage (Windows CMD, from the project folder):

    :: Analyses a JSONL export file:
    python analyze.py --input exports\\telemetry-events.jsonl

    :: Analyses the local development database directly:
    python analyze.py

    :: Synthetic (local/test) events are EXCLUDED unless declared:
    python analyze.py --input exports\\telemetry-events.jsonl --include-synthetic

Outputs (never overwrites the raw telemetry):
    reports/tables/*.csv   clean summary tables
    reports/figures/*.png  charts
    reports/summary.json   machine-readable summary

Every figure is derived from the input records. When records are missing,
malformed, or duplicated they are reported -- never invented. Synthetic
test traffic is kept separate from the observed-Internet dataset.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Any

import matplotlib

matplotlib.use("Agg")  # headless rendering for reports
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

from honeypot.mitre import aggregate_rule

TABLE_DIR = os.path.join("reports", "tables")
FIGURE_DIR = os.path.join("reports", "figures")
SUMMARY_PATH = os.path.join("reports", "summary.json")

SYNTHETIC_LABEL = "synthetic"


# ---------------------------------------------------------------------------
# Loading and cleaning
# ---------------------------------------------------------------------------

def records_from_jsonl(path: str) -> tuple[list[dict], dict[str, int]]:
    """Parse a JSONL export, skipping malformed lines safely."""
    records: list[dict] = []
    stats = {"lines": 0, "parsed": 0, "malformed": 0, "skipped_non_object": 0}
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            stats["lines"] += 1
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                stats["malformed"] += 1
                continue
            if not isinstance(parsed, dict):
                stats["skipped_non_object"] += 1
                continue
            records.append(parsed)
            stats["parsed"] += 1
    return records, stats


def records_from_database(data_dir: str = ".") -> list[dict]:
    """Read records directly from the local SQLite telemetry database."""
    from honeypot.telemetry import TelemetryStore
    store = TelemetryStore(database_url="", data_dir=data_dir)
    return store.iter_rows()


def to_dataframe(
    records: list[dict],
    include_synthetic: bool,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Normalise records into a clean DataFrame and a quality report."""
    frame = pd.DataFrame(records)
    quality: dict[str, Any] = {}
    if frame.empty:
        return frame, quality

    if "synthetic" in frame.columns:
        before = len(frame)
        synthesised = pd.to_numeric(
            frame["synthetic"], errors="coerce").fillna(0).astype(int)
        if not include_synthetic:
            frame = frame[synthesised == 0]
        quality["synthetic_records"] = int((synthesised == 1).sum())
        quality["synthetic_included"] = bool(include_synthetic)
        quality["rows_dropped_by_filter"] = before - len(frame)

    if "event_id" in frame.columns:
        before = len(frame)
        frame = frame.drop_duplicates(subset=["event_id"], keep="first")
        quality["duplicate_events_removed"] = before - len(frame)

    if "timestamp_utc" in frame.columns:
        frame["timestamp_utc"] = pd.to_datetime(
            frame["timestamp_utc"], errors="coerce", utc=True)
        quality["unparseable_timestamps"] = int(
            frame["timestamp_utc"].isna().sum())
        frame = frame.dropna(subset=["timestamp_utc"])

    missing_fields = {
        column: int(frame[column].isna().sum())
        for column in ("source_ip", "user_agent", "status_code",
                       "classification", "path")
        if column in frame.columns
    }
    quality["missing_field_counts"] = {
        k: v for k, v in missing_fields.items() if v
    }
    return frame, quality


# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------

def value_table(frame: pd.DataFrame, column: str, name: str,
                out: pd.DataFrame | None = None) -> pd.DataFrame:
    """Build a clean [name, requests] table for one column."""
    if column in frame.columns:
        counts = frame[column].fillna("unknown").astype(str).value_counts()
        table = counts.rename_axis(name).reset_index(name="requests")
        return table
    return pd.DataFrame(columns=[name, "requests"])


def save_table(table: pd.DataFrame, filename: str) -> str:
    os.makedirs(TABLE_DIR, exist_ok=True)
    path = os.path.join(TABLE_DIR, filename)
    table.to_csv(path, index=False)
    return path


def requests_over_time_table(frame: pd.DataFrame) -> pd.DataFrame:
    if frame.empty:
        return pd.DataFrame(columns=["date_utc", "requests"])
    by_day = frame["timestamp_utc"].dt.strftime("%Y-%m-%d").value_counts() \
        .sort_index()
    table = by_day.rename_axis("date_utc").reset_index(name="requests")
    return table


def category_mitre_table(frame: pd.DataFrame) -> pd.DataFrame:
    """Observed categories joined with their qualified MITRE technique."""
    if frame.empty or "classification" not in frame.columns:
        return pd.DataFrame(
            columns=["classification", "requests", "mitre_technique",
                     "mitre_confidence"])
    table = value_table(frame, "classification", "classification")
    if "mitre_technique" in frame.columns:
        mitre = (frame.groupby("classification")["mitre_technique"]
                 .agg(lambda s: "+".join(sorted(set(
                     str(x) for x in s.dropna())) or "unmapped"))
                 .rename("mitre_technique").reset_index())
        conf = (frame.groupby("classification")["mitre_confidence"]
                .agg(lambda s: "+".join(sorted(set(
                    str(x) for x in s.dropna())) or "unmapped"))
                .rename("mitre_confidence").reset_index())
        table = table.merge(mitre, on="classification", how="left")
        table = table.merge(conf, on="classification", how="left")
    table["mitre_technique"] = table["mitre_technique"].fillna("unmapped")
    table["mitre_confidence"] = table["mitre_confidence"].fillna("unmapped")
    return table


# ---------------------------------------------------------------------------
# Charts
# ---------------------------------------------------------------------------

def _style(ax: plt.Axes) -> None:
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="y", alpha=0.3)


def chart_requests_over_time(frame: pd.DataFrame, output_path: str) -> bool:
    if frame.empty:
        return False
    by_day = frame["timestamp_utc"].dt.strftime("%Y-%m-%d").value_counts() \
        .sort_index()
    _, ax = plt.subplots(figsize=(8, 4))
    by_day.plot(ax=ax, marker="o")
    ax.set_title("Requests per day (UTC) — observed traffic only")
    ax.set_xlabel("Date (UTC)")
    ax.set_ylabel("Requests")
    _style(ax)
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()
    return True


def chart_bar_from_table(table: pd.DataFrame, label: str, title: str,
                         output_path: str, top: int = 12,
                         horizontal: bool = False) -> bool:
    if table.empty:
        return False
    top_table = table.head(top)
    _, ax = plt.subplots(figsize=(8, max(3, 0.5 * len(top_table) + 1.5)))
    if horizontal:
        ax.barh(top_table[label].astype(str)[::-1],
                top_table["requests"][::-1])
        ax.set_xlabel("Requests")
    else:
        ax.bar(top_table[label].astype(str), top_table["requests"])
        ax.set_ylabel("Requests")
        plt.xticks(rotation=45, ha="right")
    ax.set_title(title + " — observed traffic only")
    _style(ax)
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()
    return True


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def run_analysis(input_path: str, include_synthetic: bool) -> dict[str, Any]:
    """Execute the whole reproducible analysis and return the summary."""
    stats: dict[str, Any] = {}
    if input_path:
        records, stats = records_from_jsonl(input_path)
        source = os.path.abspath(input_path)
    else:
        records = list(records_from_database(data_dir=_base_dir()))
        source = "local sqlite telemetry.db"
        stats = {"parsed": len(records)}

    frame, quality = to_dataframe(records, include_synthetic)
    os.makedirs(TABLE_DIR, exist_ok=True)
    os.makedirs(FIGURE_DIR, exist_ok=True)

    generated_tables: list[str] = []
    generated_figures: list[str] = []

    summary: dict[str, Any] = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "line_statistics": stats,
        "data_quality": quality,
        "includes_synthetic_traffic": bool(include_synthetic),
        "notes": [
            "All figures derive from the records analysed above.",
            "Synthetic (local/test) traffic is excluded by default and "
            "never merged into observed-Internet statistics.",
            "No geographic enrichment is applied unless a documented GeoIP "
            "provider is configured; countries are never guessed.",
        ],
    }

    if frame.empty:
        summary["total_recorded_requests"] = 0
        summary["note_empty"] = (
            "No analysable records for this selection; no charts were "
            "generated and no fictional values were invented.")
        with open(SUMMARY_PATH, "w", encoding="utf-8") as handle:
            json.dump(summary, handle, indent=2, default=str)
        return summary

    observed = frame
    summary["total_recorded_requests"] = int(len(frame))
    summary["total_discovery_requests"] = int(
        (~frame["classification"].isin(
            ["Normal application request", "Unknown (older log)"])
         ).sum()) if "classification" in frame.columns else 0
    summary["unique_source_ips"] = int(
        frame["source_ip"].nunique()) if "source_ip" in frame.columns else 0
    if "classification" in frame.columns and len(frame):
        summary["first_observed_utc"] = str(
            frame["timestamp_utc"].min())
        summary["last_observed_utc"] = str(
            frame["timestamp_utc"].max())

    tables = {
        "requests_per_source_ip.csv": value_table(
            frame, "source_ip", "source_ip"),
        "requests_per_route.csv": value_table(frame, "path",
                                              "requested_route"),
        "requests_per_http_method.csv": value_table(
            frame, "method", "method"),
        "http_status_distribution.csv": value_table(
            frame, "status_code", "http_status"),
        "user_agent_distribution.csv": value_table(
            frame, "user_agent", "user_agent"),
        "category_distribution.csv": value_table(
            frame, "classification", "classification"),
        "requests_over_time.csv": requests_over_time_table(frame),
        "mitre_category_mapping.csv": category_mitre_table(frame),
    }
    for filename, table in tables.items():
        generated_tables.append(save_table(table, filename))

    figures = {
        "requests_over_time.png": lambda: chart_requests_over_time(
            frame, os.path.join(FIGURE_DIR, "requests_over_time.png")),
        "top_routes.png": lambda: chart_bar_from_table(
            tables["requests_per_route.csv"], "requested_route",
            "Top requested routes",
            os.path.join(FIGURE_DIR, "top_routes.png"), horizontal=True),
        "top_source_ips.png": lambda: chart_bar_from_table(
            tables["requests_per_source_ip.csv"], "source_ip",
            "Top source IPs (requests)",
            os.path.join(FIGURE_DIR, "top_source_ips.png"),
            horizontal=True),
        "status_distribution.png": lambda: chart_bar_from_table(
            tables["http_status_distribution.csv"], "http_status",
            "HTTP status code distribution",
            os.path.join(FIGURE_DIR, "status_distribution.png")),
        "category_distribution.png": lambda: chart_bar_from_table(
            tables["category_distribution.csv"], "classification",
            "Behavioral classification distribution",
            os.path.join(FIGURE_DIR, "category_distribution.png"),
            horizontal=True),
    }
    for filename, make in figures.items():
        path = os.path.join(FIGURE_DIR, filename)
        if make():  # each returns False when there is nothing to chart
            generated_figures.append(path)

    # Aggregate, per-IP breadth rule for T1046 (candidate only).
    if "source_ip" in frame.columns and "route_category" in frame.columns:
        breadth = (frame.groupby("source_ip")["route_category"]
                   .nunique())
        candidates = breadth[breadth >= 3]
        rule = aggregate_rule()
        summary["mitre_aggregate"] = {
            "rule": rule["rule"],
            "technique_candidates": {
                "T1046": {
                    "technique_name": rule["technique_name"],
                    "candidate_source_ips": int(len(candidates)),
                    "confidence": rule["confidence"],
                    "limitations": rule["limitations"],
                    "alternatives": rule["alternatives"],
                },
            },
            "interpretation_note": (
                "Candidate only: breadth of probing across categories "
                "supports, but does not prove, service scanning."),
        }

    summary["generated_tables"] = generated_tables
    summary["generated_figures"] = generated_figures

    with open(SUMMARY_PATH, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2, default=str)
    return summary


def _base_dir() -> str:
    """Directory containing telemetry.db: DATA_DIR or the project folder."""
    return os.environ.get("DATA_DIR", ".")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Reproducible telemetry analysis for the honeypot "
                    "dataset.")
    parser.add_argument(
        "--input", help="JSONL export to analyse (e.g. from "
                        "/export/events.jsonl). Defaults to the local "
                        "SQLite database.")
    parser.add_argument(
        "--include-synthetic", action="store_true",
        help="Include synthetic/local-test traffic. Default: excluded.")
    args = parser.parse_args(argv)

    if args.input and not os.path.exists(args.input):
        print(f"ERROR: input file not found: {args.input}", file=sys.stderr)
        return 2

    summary = run_analysis(args.input or "", args.include_synthetic)
    print("=== TELEMETRY ANALYSIS SUMMARY ===")
    print(f"Source: {summary['source']}")
    print(json.dumps(
        {k: v for k, v in summary.items()
         if k not in ("generated_tables", "generated_figures",
                      "line_statistics", "data_quality", "notes")},
        indent=2, default=str))
    print("\nTables written:")
    for table in summary.get("generated_tables", []):
        print(f"  {table}")
    print("Figures written:")
    for figure in summary.get("generated_figures", []):
        print(f"  {figure}")
    print(f"\nFull JSON summary: {SUMMARY_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

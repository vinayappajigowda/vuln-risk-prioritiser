"""Prioritise vulnerability scan findings by real-world risk.

Usage:
    python prioritise.py                       # scans in data/scans/, assets in data/assets.csv if present
    python prioritise.py --scans path/to/csvs --assets data/assets.csv
    python prioritise.py --offline             # use cached EPSS/KEV data only
"""
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from src.enrich import load_epss, load_kev
from src.history import add_sla, build_history, trend
from src.parsers import load_scans
from src.report import cvss_vs_tier, export, sort_fix_first
from src.scoring import score_findings


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scans", default="data/scans")
    ap.add_argument("--assets", default="data/assets.csv")
    ap.add_argument("--out", default="outputs")
    ap.add_argument("--offline", action="store_true")
    args = ap.parse_args()

    scans = load_scans(args.scans)
    dates = sorted(scans["scan_date"].unique())
    print(f"Loaded {len(scans):,} findings from {len(dates)} scan(s): {', '.join(map(str, dates))}")

    history = build_history(scans)
    cves = sorted({c for lst in history["cves"] for c in lst})
    print(f"{len(history):,} unique findings, {len(cves):,} unique CVEs")

    print("Fetching CISA KEV and EPSS data...")
    kev = load_kev(offline=args.offline)
    epss = load_epss(cves, offline=args.offline)
    print(f"  KEV catalogue: {len(kev):,} CVEs | EPSS scores found: {sum(v is not None for v in epss.values()):,}/{len(cves):,}")

    live_epss = sum(v is not None for v in epss.values())
    scanner_epss = int(pd.to_numeric(history.get("scanner_epss"), errors="coerce").notna().sum()) \
        if "scanner_epss" in history else 0
    if cves and not live_epss:
        if scanner_epss:
            print(f"  Live EPSS lookup unavailable; using the EPSS scores from the Nessus report "
                  f"({scanner_epss} findings).")
        else:
            print("  WARNING: no EPSS scores available. Priorities use CVSS and KEV only. "
                  "Check your internet connection.")

    assets = pd.read_csv(args.assets) if Path(args.assets).exists() else None
    scored = add_sla(score_findings(history, epss, kev, assets))
    summary = export(scored, trend(scans, scored), args.out)

    open_ = scored[scored["status"] == "Open"]
    print("\n=== Open findings by priority ===")
    for t, n in summary["open_by_tier"].items():
        print(f"  {t}: {n}")
    print(f"  In CISA KEV: {summary['open_in_kev']}  |  Overdue: {summary['overdue']}  |  Fixed: {summary['fixed_findings']}")
    print("\n=== CVSS band vs risk tier (open findings) ===")
    print(cvss_vs_tier(open_).to_string())
    print(f"\n{summary['high_cvss_but_low_priority']} of {summary['high_cvss_open']} High/Critical CVSS findings "
          f"have low real-world exploit likelihood (P3/P4).")
    print(f"{summary['below_high_cvss_but_urgent']} findings below High CVSS are urgent (P1/P2) because of exploit evidence.")
    if summary["top10_overlap"]:
        o = summary["top10_overlap"]
        print(f"Fixing the top {o['n']} by CVSS would miss {o['missed_by_cvss']} of the top {o['n']} by real risk.")
    print("\n=== Fix first ===")
    cols = ["tier", "host", "port", "title", "cvss", "epss", "in_kev"]
    print(sort_fix_first(open_)[cols].head(10).to_string(index=False, max_colwidth=45))
    print(f"\nSaved {args.out}/findings.csv, trend.csv, summary.json and vulnerability_report.xlsx")


if __name__ == "__main__":
    main()

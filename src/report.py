"""Summaries and exports: the CVSS-vs-risk comparison, KPIs, CSV and Excel files."""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

BAND_ORDER = ["Critical", "High", "Medium", "Low", "None", "Unknown"]
TIER_ORDER = ["P1", "P2", "P3", "P4"]
EXPORT_COLS = [
    "tier", "tier_label", "risk_score", "reason", "host", "port", "protocol", "title", "cves", "cvss", "cvss_band",
    "epss", "in_kev", "kev_recent", "ransomware", "kev_date_added", "asset_critical", "status", "first_seen",
    "last_seen", "fixed_date", "due_date", "age_days", "days_to_fix", "overdue", "fixed_late", "solution",
    "scanner", "finding_id",
]


def sort_fix_first(df: pd.DataFrame) -> pd.DataFrame:
    return df.sort_values(["tier", "risk_score", "cvss"], ascending=[True, False, False])


def cvss_vs_tier(df: pd.DataFrame) -> pd.DataFrame:
    """Rows = CVSS band, columns = risk tier. Shows where CVSS and real-world risk disagree."""
    t = pd.crosstab(df["cvss_band"], df["tier"])
    return t.reindex(index=[b for b in BAND_ORDER if b in t.index],
                     columns=[c for c in TIER_ORDER if c in t.columns], fill_value=0)


def top_n_overlap(df: pd.DataFrame, n: int = 10) -> dict:
    """If you fixed the top N by CVSS, how many of the top N by real risk would you have fixed?"""
    n = min(n, len(df))
    by_cvss = set(df.sort_values(["cvss", "risk_score"], ascending=False).head(n).index)
    by_risk = set(sort_fix_first(df).head(n).index)
    return {"n": n, "overlap": len(by_cvss & by_risk), "missed_by_cvss": len(by_risk - by_cvss)}


def summarise(scored: pd.DataFrame) -> dict:
    open_ = scored[scored["status"] == "Open"]
    fixed = scored[scored["status"] == "Fixed"]
    high_cvss = open_[open_["cvss"] >= 7.0]
    low_cvss = open_[open_["cvss"] < 7.0]
    return {
        "latest_scan": str(scored["host_latest_scan"].max().date()) if len(scored) else None,
        "hosts": int(scored["host"].nunique()),
        "open_findings": int(len(open_)),
        "fixed_findings": int(len(fixed)),
        "open_by_tier": {t: int((open_["tier"] == t).sum()) for t in TIER_ORDER},
        "open_in_kev": int(open_["in_kev"].sum()),
        "open_ransomware": int(open_["ransomware"].sum()),
        "open_kev_recent": int(open_["kev_recent"].sum()),
        "overdue": int(open_["overdue"].sum()),
        "mean_days_to_fix": round(float(fixed["days_to_fix"].mean()), 1) if len(fixed) else None,
        "fixed_within_sla_pct": round(float((~fixed["fixed_late"]).mean() * 100), 1) if len(fixed) else None,
        "high_cvss_open": int(len(high_cvss)),
        "high_cvss_but_low_priority": int(high_cvss["tier"].isin(["P3", "P4"]).sum()),
        "below_high_cvss_but_urgent": int(low_cvss["tier"].isin(["P1", "P2"]).sum()),
        "top10_overlap": top_n_overlap(open_, 10) if len(open_) else None,
        "cves_without_epss": int(open_["cves"].map(len).gt(0).sum() - open_["epss"].notna().sum()),
        "findings_without_cve": int(open_["cves"].map(len).eq(0).sum()),
    }


def export(scored: pd.DataFrame, trend_df: pd.DataFrame, out_dir: str | Path = "outputs") -> dict:
    """Write findings.csv, trend.csv, summary.json and an Excel workbook. Returns the summary."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    df = sort_fix_first(scored)[EXPORT_COLS].copy()
    df["cves"] = df["cves"].map(", ".join)
    for c in ["first_seen", "last_seen", "fixed_date", "due_date"]:
        df[c] = pd.to_datetime(df[c]).dt.date
    summary = {"scans": int(pd.Series(trend_df["scan_date"]).nunique()), **summarise(scored)}

    df.to_csv(out / "findings.csv", index=False)
    trend_df.assign(scan_date=pd.to_datetime(trend_df["scan_date"]).dt.date).to_csv(out / "trend.csv", index=False)
    (out / "summary.json").write_text(json.dumps(summary, indent=2))

    # Excel workbook: easy to open, share, or load into Power BI.
    with pd.ExcelWriter(out / "vulnerability_report.xlsx", engine="openpyxl") as xl:
        df[df["status"] == "Open"].to_excel(xl, sheet_name="Open - fix first", index=False)
        df.to_excel(xl, sheet_name="All findings", index=False)
        cvss_vs_tier(scored[scored["status"] == "Open"]).to_excel(xl, sheet_name="CVSS vs risk tier")
        trend_df.to_excel(xl, sheet_name="Trend", index=False)
        pd.DataFrame(list(summary.items()), columns=["metric", "value"]).astype(str).to_excel(
            xl, sheet_name="Summary", index=False)
        for ws in xl.book.worksheets:
            ws.freeze_panes = "A2"
            for col in ws.columns:
                width = min(max(len(str(c.value or "")) for c in col[:200]) + 2, 60)
                ws.column_dimensions[col[0].column_letter].width = width
    return summary

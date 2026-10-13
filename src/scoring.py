"""Turn CVSS + EPSS + CISA KEV + asset context into a fix-first priority.

Why not CVSS alone? CVSS measures how bad a vulnerability *could* be. It says nothing
about whether anyone is actually exploiting it. Most high-CVSS vulnerabilities are never
exploited, while some medium ones are used by ransomware gangs. EPSS and KEV add that
real-world evidence.
"""
from __future__ import annotations

from datetime import date

import pandas as pd

# ---- Rules (kept in one place so they're easy to explain and change) ----
EPSS_HIGH = 0.10        # 10%+ chance of exploitation in the next 30 days
EPSS_SOME = 0.01        # 1%+  chance
KEV_RECENT_DAYS = 30    # KEV entries added in the last 30 days = "new and actively exploited"
SLA_DAYS = {"P1": 7, "P2": 30, "P3": 90, "P4": 180}
TIER_LABEL = {"P1": "P1 Fix now", "P2": "P2 High", "P3": "P3 Medium", "P4": "P4 Low"}


def cvss_band(score) -> str:
    """Standard CVSS v3 qualitative bands."""
    if pd.isna(score):
        return "Unknown"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"


def base_tier(in_kev: bool, epss, cvss, has_cve: bool = True) -> tuple[str, str]:
    """Priority from the vulnerability alone. Returns (tier, reason)."""
    has_epss = not pd.isna(epss)
    e = float(epss) if has_epss else 0.0
    c = 0.0 if pd.isna(cvss) else float(cvss)
    e_txt = f"EPSS {e:.1%}" if has_epss else "no EPSS data"
    if in_kev:
        return "P1", "Known exploited in the wild (CISA KEV)"
    if e >= 0.5:
        return "P1", f"Very likely to be exploited ({e_txt})"
    if e >= EPSS_HIGH:
        return "P2", f"Likely to be exploited ({e_txt})"
    if c >= 9.0 and e >= EPSS_SOME:
        return "P2", f"Critical severity with some exploit activity (CVSS {c:.1f}, {e_txt})"
    if c >= 9.0 and not has_cve:
        # Backdoors, default passwords and end-of-life software often have no CVE, so EPSS/KEV
        # can't speak for them. Don't let "no data" push a critical finding down the list.
        return "P2", f"Critical severity with no CVE, so no exploit data exists: review manually (CVSS {c:.1f})"
    if c >= 7.0:
        label = "low exploit likelihood" if has_epss else "exploit likelihood unknown"
        return "P3", f"High severity, {label} (CVSS {c:.1f}, {e_txt})"
    if e >= EPSS_SOME:
        return "P3", f"Some exploit activity ({e_txt})"
    return "P4", f"Low severity, no sign of exploitation (CVSS {c:.1f}, {e_txt})"


def bump(tier: str) -> str:
    return {"P2": "P1", "P3": "P2"}.get(tier, tier)


def score_findings(findings: pd.DataFrame, epss: dict, kev: dict, assets: pd.DataFrame | None = None,
                   today: date | None = None) -> pd.DataFrame:
    """Add exploit data, tier, reason and a 0-100 risk score to each finding."""
    today = today or date.today()
    df = findings.copy()

    def best_epss(cves):
        vals = [epss[c]["epss"] for c in cves if epss.get(c)]
        return max(vals) if vals else float("nan")

    def kev_hits(cves):
        return [c for c in cves if c in kev]

    for col, default in {"scanner_epss": float("nan"), "scanner_kev": ""}.items():
        if col not in df.columns:
            df[col] = default
    df["scanner_kev"] = df["scanner_kev"].fillna("").astype(str)

    df["epss"] = df["cves"].map(best_epss)
    # Fall back to the scanner's own EPSS value if the live lookup had nothing.
    df["epss"] = df["epss"].fillna(pd.to_numeric(df["scanner_epss"], errors="coerce"))
    df["kev_cves"] = df["cves"].map(kev_hits)
    # Known exploited if CISA's catalogue lists one of its CVEs, or the scanner flags it as CISA KEV.
    df["in_kev"] = df["kev_cves"].map(bool) | df["scanner_kev"].ne("")
    df["ransomware"] = df["kev_cves"].map(lambda hits: any(kev[c]["ransomware"] for c in hits))
    df["kev_date_added"] = df["kev_cves"].map(
        lambda hits: min((kev[c]["date_added"] for c in hits if kev[c]["date_added"]), default=None))
    df["kev_date_added"] = df["kev_date_added"].where(
        df["kev_date_added"].notna(), df["scanner_kev"].where(df["scanner_kev"].ne(""), None))
    df["kev_recent"] = df["kev_date_added"].map(
        lambda d: isinstance(d, str) and (today - date.fromisoformat(d)).days <= KEV_RECENT_DAYS)
    df["cvss_band"] = df["cvss"].map(cvss_band)

    tiers = [base_tier(k, e, c, bool(cv)) for k, e, c, cv in zip(df["in_kev"], df["epss"], df["cvss"], df["cves"])]
    df["tier"] = [t for t, _ in tiers]
    df["reason"] = [r for _, r in tiers]

    # Asset context: an exposed or business-critical host moves P2/P3 up one level.
    df["asset_critical"] = False
    if assets is not None and not assets.empty:
        a = assets.copy()
        a.columns = [c.strip().lower() for c in a.columns]
        col = lambda name: a[name].astype(str).str.strip().str.lower() if name in a.columns \
            else pd.Series("", index=a.index)
        is_crit = col("criticality").eq("high") | col("internet_facing").isin(["yes", "true", "1"])
        crit = set(a.loc[is_crit, "host"].astype(str).str.strip())
        df["asset_critical"] = df["host"].isin(crit)
        bumped = df["asset_critical"] & df["tier"].isin(["P2", "P3"])
        df.loc[bumped, "reason"] = df.loc[bumped, "reason"] + "; raised one level: critical or internet-facing host"
        df.loc[bumped, "tier"] = df.loc[bumped, "tier"].map(bump)
    if df["ransomware"].any():
        df.loc[df["ransomware"], "reason"] = df.loc[df["ransomware"], "reason"] + "; used in ransomware campaigns"

    # 0-100 score for sorting inside a tier. Exploit evidence weighs more than raw severity.
    epss_part = df["epss"].fillna(0) * 40
    cvss_part = df["cvss"].fillna(0) / 10 * 30
    kev_part = df["in_kev"] * 25 + df["ransomware"] * 5
    df["risk_score"] = (epss_part + cvss_part + kev_part).clip(upper=100).round(1)
    df["tier_label"] = df["tier"].map(TIER_LABEL)
    return df

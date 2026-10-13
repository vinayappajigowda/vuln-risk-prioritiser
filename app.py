"""Vulnerability risk dashboard. Reads the files written by prioritise.py.

Run:  streamlit run app.py
"""
from __future__ import annotations

import json
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

OUT = Path("outputs")
TIERS = ["P1", "P2", "P3", "P4"]
TIER_NAMES = {"P1": "P1 Fix now", "P2": "P2 High", "P3": "P3 Medium", "P4": "P4 Low"}
# Status-style colours: each tier is always shown with its text label too, never colour alone.
TIER_COLORS = ["#d03b3b", "#ec835a", "#fab219", "#8a8984"]
BANDS = ["Critical", "High", "Medium", "Low", "None", "Unknown"]

st.set_page_config(page_title="Vulnerability Risk Dashboard", page_icon="🛡️", layout="wide")


@st.cache_data
def load():
    f = pd.read_csv(OUT / "findings.csv", parse_dates=["first_seen", "last_seen", "fixed_date", "due_date"])
    f["cves"] = f["cves"].fillna("")
    t = pd.read_csv(OUT / "trend.csv", parse_dates=["scan_date"]) if (OUT / "trend.csv").exists() else None
    s = json.loads((OUT / "summary.json").read_text()) if (OUT / "summary.json").exists() else {}
    return f, t, s


if not (OUT / "findings.csv").exists():
    st.title("Vulnerability Risk Dashboard")
    st.error("No results yet. Put scan exports in data/scans/ and run `python prioritise.py`.")
    st.stop()

findings, trend_df, summary = load()

st.title("Vulnerability Risk Dashboard")
st.caption(f"Scan findings ranked by real-world risk (CVSS + EPSS + CISA KEV). "
           f"Latest scan: {summary.get('latest_scan', '-')} · {summary.get('scans', '-')} scan(s) · "
           f"{findings['host'].nunique()} host(s)")

# ---- Filters, in one row above the charts ----
c1, c2, c3 = st.columns([2, 2, 1])
hosts = c1.multiselect("Hosts", sorted(findings["host"].unique()), placeholder="All hosts")
tiers = c2.multiselect("Priority", TIERS, format_func=TIER_NAMES.get, placeholder="All priorities")
status = c3.selectbox("Status", ["Open", "Fixed", "All"])

f = findings.copy()
if hosts:
    f = f[f["host"].isin(hosts)]
if tiers:
    f = f[f["tier"].isin(tiers)]
view = f if status == "All" else f[f["status"] == status]
open_ = f[f["status"] == "Open"]
fixed = f[f["status"] == "Fixed"]

# ---- Headline numbers ----
k = st.columns(5)
k[0].metric("Open findings", len(open_))
k[1].metric("P1 · fix now", int((open_["tier"] == "P1").sum()))
k[2].metric("In CISA KEV", int(open_["in_kev"].sum()), help="Confirmed exploited in the wild")
k[3].metric("Overdue", int(open_["overdue"].sum()), help="Open past the SLA for its priority (P1 7d, P2 30d, P3 90d, P4 180d)")
k[4].metric("Mean days to fix", f"{fixed['days_to_fix'].mean():.0f}" if len(fixed) else "-")

# ---- The key insight: CVSS vs real-world risk ----
high = open_[open_["cvss"] >= 7]
low = open_[open_["cvss"] < 7]
n_high_low = int(high["tier"].isin(["P3", "P4"]).sum())
n_low_urgent = int(low["tier"].isin(["P1", "P2"]).sum())
st.info(f"**{n_high_low} of {len(high)}** open High/Critical CVSS findings show little sign of real-world "
        f"exploitation, while **{n_low_urgent}** findings rated below High by CVSS are urgent because of "
        f"exploit evidence. Patching by CVSS alone would put effort in the wrong place.")

left, right = st.columns(2)

with left:
    st.subheader("Open findings by priority")
    counts = (open_["tier"].value_counts().reindex(TIERS, fill_value=0).rename_axis("tier")
              .reset_index(name="findings"))
    counts["label"] = counts["tier"].map(TIER_NAMES)
    bars = alt.Chart(counts).mark_bar(cornerRadiusEnd=4, height=22).encode(
        x=alt.X("findings:Q", title=None, axis=alt.Axis(grid=True, tickMinStep=1)),
        y=alt.Y("label:N", sort=[TIER_NAMES[t] for t in TIERS], title=None),
        color=alt.Color("tier:N", scale=alt.Scale(domain=TIERS, range=TIER_COLORS), legend=None),
        tooltip=[alt.Tooltip("label:N", title="Priority"), alt.Tooltip("findings:Q", title="Open findings")],
    )
    text = bars.mark_text(align="left", dx=4).encode(text="findings:Q", color=alt.value("#888"))
    st.altair_chart((bars + text).properties(height=170), width="stretch")

with right:
    st.subheader("CVSS severity vs real-world priority")
    grid = pd.crosstab(open_["cvss_band"], open_["tier"]).reindex(
        index=[b for b in BANDS if b in set(open_["cvss_band"])], columns=TIERS, fill_value=0)
    long = grid.stack().rename("findings").reset_index()
    long.columns = ["cvss_band", "tier", "findings"]
    long["tier_label"] = long["tier"].map(TIER_NAMES)
    base = alt.Chart(long).encode(
        x=alt.X("tier_label:N", sort=[TIER_NAMES[t] for t in TIERS], title="Priority (CVSS + EPSS + KEV)",
                axis=alt.Axis(labelAngle=0)),
        y=alt.Y("cvss_band:N", sort=BANDS, title="CVSS band"),
        tooltip=[alt.Tooltip("cvss_band:N", title="CVSS band"), alt.Tooltip("tier_label:N", title="Priority"),
                 alt.Tooltip("findings:Q", title="Findings")],
    )
    heat = base.mark_rect(stroke="white", strokeWidth=2).encode(
        color=alt.Color("findings:Q", scale=alt.Scale(range=["#f0efec", "#2a78d6"]), legend=None))
    labels = base.mark_text(fontSize=13).encode(
        text="findings:Q",
        color=alt.condition(alt.datum.findings > long["findings"].max() * 0.55, alt.value("white"), alt.value("#333")))
    st.altair_chart((heat + labels).properties(height=170), width="stretch")

if trend_df is not None and trend_df["scan_date"].nunique() > 1:
    st.subheader("Findings present in each scan")
    t = trend_df.copy()
    t["tier_label"] = t["tier"].map(TIER_NAMES)
    t["order"] = t["tier"].map({k: i for i, k in enumerate(TIERS)})
    chart = alt.Chart(t).mark_bar(width={"band": 0.6}, stroke="white", strokeWidth=2).encode(
        x=alt.X("yearmonthdate(scan_date):O", title="Scan date", axis=alt.Axis(labelAngle=0)),
        y=alt.Y("findings:Q", title="Findings", stack=True),
        color=alt.Color("tier_label:N", title="Priority",
                        scale=alt.Scale(domain=[TIER_NAMES[x] for x in TIERS], range=TIER_COLORS)),
        order=alt.Order("order:Q"),
        tooltip=[alt.Tooltip("yearmonthdate(scan_date):T", title="Scan"),
                 alt.Tooltip("tier_label:N", title="Priority"), alt.Tooltip("findings:Q", title="Findings")],
    )
    st.altair_chart(chart.properties(height=260), width="stretch")

st.subheader("Fix first" if status != "Fixed" else "Fixed findings")
cols = ["tier_label", "host", "port", "title", "cves", "cvss", "epss", "in_kev", "ransomware", "reason",
        "status", "first_seen", "due_date", "overdue", "days_to_fix", "solution"]
st.dataframe(
    view[cols], hide_index=True, width="stretch",
    column_config={
        "tier_label": st.column_config.TextColumn("Priority"),
        "cvss": st.column_config.NumberColumn("CVSS", format="%.1f"),
        "epss": st.column_config.ProgressColumn("EPSS", help="Chance of exploitation in the next 30 days",
                                                format="percent", min_value=0, max_value=1),
        "in_kev": st.column_config.CheckboxColumn("KEV"),
        "ransomware": st.column_config.CheckboxColumn("Ransomware"),
        "first_seen": st.column_config.DateColumn("First seen"),
        "due_date": st.column_config.DateColumn("Due"),
        "overdue": st.column_config.CheckboxColumn("Overdue"),
        "days_to_fix": st.column_config.NumberColumn("Days to fix"),
        "host": "Host", "port": st.column_config.NumberColumn("Port", format="%d"),
        "cves": "CVEs", "title": "Finding", "reason": "Why this priority", "solution": "Fix",
    },
)
st.download_button("Download findings (CSV)", view.to_csv(index=False), "findings.csv", "text/csv")

with st.expander("How priorities are decided"):
    st.markdown("""
| Priority | Rule | Fix within |
|---|---|---|
| **P1 Fix now** | Listed in CISA KEV (exploited in the wild), or EPSS ≥ 50% | 7 days |
| **P2 High** | EPSS ≥ 10%, or CVSS ≥ 9.0 with EPSS ≥ 1% | 30 days |
| **P3 Medium** | CVSS ≥ 7.0, or EPSS ≥ 1% | 90 days |
| **P4 Low** | Everything else | 180 days |

Findings on hosts marked internet-facing or high-criticality in `data/assets.csv` move up one level (P3→P2, P2→P1).
**EPSS** (FIRST.org) estimates the probability a CVE is exploited in the next 30 days.
**CISA KEV** lists CVEs confirmed as exploited in real attacks.
""")

"""Track findings across repeated scans: first seen, fixed, age, SLA and time to fix."""
from __future__ import annotations

import pandas as pd

from .scoring import SLA_DAYS

KEY = ["host", "port", "protocol", "finding_id"]


def build_history(all_scans: pd.DataFrame) -> pd.DataFrame:
    """One row per unique finding, with its lifecycle across scans.

    A finding is 'fixed' if it was seen before but is missing from the latest scan of that host.
    """
    scans = all_scans.copy()
    scans["scan_date"] = pd.to_datetime(scans["scan_date"])
    latest_per_host = scans.groupby("host")["scan_date"].max().rename("host_latest_scan")
    host_dates = scans.groupby("host")["scan_date"].apply(lambda s: sorted(s.unique()))

    life = scans.groupby(KEY).agg(first_seen=("scan_date", "min"), last_seen=("scan_date", "max"),
                                  times_seen=("scan_date", "nunique")).reset_index()
    # Keep the details from the most recent sighting of each finding.
    latest_rows = scans.sort_values("scan_date").drop_duplicates(KEY, keep="last")
    life = life.merge(latest_rows.drop(columns=["scan_date"]), on=KEY).merge(latest_per_host, on="host")

    life["status"] = (life["last_seen"] == life["host_latest_scan"]).map({True: "Open", False: "Fixed"})

    def fixed_on(row):
        if row["status"] == "Open":
            return pd.NaT
        later = [d for d in host_dates[row["host"]] if d > row["last_seen"]]
        return later[0] if later else pd.NaT

    life["fixed_date"] = life.apply(fixed_on, axis=1)
    return life


def add_sla(history: pd.DataFrame, as_of=None) -> pd.DataFrame:
    """Add due date, overdue flag, age and days to fix. Needs a 'tier' column (run scoring first)."""
    df = history.copy()
    as_of = pd.Timestamp(as_of) if as_of is not None else df["host_latest_scan"].max()
    df["sla_days"] = df["tier"].map(SLA_DAYS)
    df["due_date"] = df["first_seen"] + pd.to_timedelta(df["sla_days"], unit="D")
    end = df["fixed_date"].where(df["status"] == "Fixed", as_of)
    df["age_days"] = (end - df["first_seen"]).dt.days
    df["days_to_fix"] = (df["fixed_date"] - df["first_seen"]).dt.days
    df["overdue"] = (df["status"] == "Open") & (as_of > df["due_date"])
    df["fixed_late"] = (df["status"] == "Fixed") & (df["fixed_date"] > df["due_date"])
    return df


def trend(all_scans: pd.DataFrame, scored: pd.DataFrame) -> pd.DataFrame:
    """How many findings of each tier were present in each scan (for the trend chart)."""
    tiers = scored.set_index(KEY)["tier"]
    s = all_scans.copy()
    s["tier"] = s.set_index(KEY).index.map(tiers)
    return (s.groupby(["scan_date", "tier"]).size().rename("findings").reset_index()
            .sort_values(["scan_date", "tier"]))

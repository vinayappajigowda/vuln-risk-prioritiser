"""Tests on small made-up scan exports. EPSS and KEV are mocked so tests run offline."""
from datetime import date
from pathlib import Path

import pandas as pd
import pytest

from src.history import add_sla, build_history, trend
from src.parsers import load_scan, load_scans
from src.report import export, summarise, top_n_overlap
from src.scoring import base_tier, cvss_band, score_findings

FIX = Path(__file__).parent / "fixtures"
EPSS = {
    "CVE-2021-44228": {"epss": 0.94, "percentile": 0.99},
    "CVE-2099-0001": {"epss": 0.002, "percentile": 0.5},
    "CVE-2099-0002": {"epss": 0.02, "percentile": 0.8},
    "CVE-2099-0003": {"epss": 0.0, "percentile": 0.1},
    "CVE-2099-0004": {"epss": 0.6, "percentile": 0.99},
}
KEV = {"CVE-2021-44228": {"date_added": "2021-12-10", "ransomware": True, "name": "Log4Shell", "required_action": ""}}


def _scored(assets=None):
    scans = load_scans(FIX / "scans")
    return scans, add_sla(score_findings(build_history(scans), EPSS, KEV, assets, today=date(2026, 9, 15)))


def _row(df, port):
    return df[df["port"] == port].iloc[0]


def test_nessus_parsing_merges_cves_and_drops_info():
    df = load_scan(FIX / "scans" / "nessus_2026-09-01.csv")
    assert len(df) == 4                                     # info plugin dropped, 2 SMB rows merged
    smb = _row(df, 445)
    assert smb["cves"] == ["CVE-2099-0002", "CVE-2099-0003"]
    assert smb["cvss"] == 9.8                               # prefers CVSS v3
    assert str(df["scan_date"].iloc[0]) == "2026-09-01"     # date taken from the file name


def test_openvas_parsing():
    df = load_scan(FIX / "openvas" / "openvas_results.csv")
    assert set(df["scanner"]) == {"openvas"}
    assert len(df) == 2                                     # 'Log' result dropped
    assert _row(df, 21)["cves"] == ["CVE-2099-0005", "CVE-2099-0006"]
    assert str(df["scan_date"].iloc[0]) == "2026-09-20"     # date taken from the Timestamp column


def test_tiers_and_reasons():
    _, df = _scored()
    assert _row(df, 8080)["tier"] == "P1" and "KEV" in _row(df, 8080)["reason"]
    assert "ransomware" in _row(df, 8080)["reason"]
    assert _row(df, 80)["tier"] == "P1"     # medium CVSS (6.1) but EPSS 60%
    assert _row(df, 445)["tier"] == "P2"    # critical CVSS with some exploit activity
    assert _row(df, 22)["tier"] == "P3"     # high CVSS, very low EPSS
    assert _row(df, 443)["tier"] == "P4"    # no CVE, medium CVSS


def test_asset_context_raises_priority():
    assets = pd.DataFrame({"host": ["10.0.0.6"], "criticality": ["medium"], "internet_facing": ["yes"]})
    _, df = _scored(assets)
    smb = _row(df, 445)
    assert smb["tier"] == "P1" and smb["asset_critical"] and "raised one level" in smb["reason"]
    assert _row(df, 22)["tier"] == "P3"     # other host unaffected


def test_history_fixed_and_sla():
    _, df = _scored()
    log4j = _row(df, 8080)
    assert log4j["status"] == "Fixed"
    assert log4j["days_to_fix"] == 14
    assert bool(log4j["fixed_late"])        # P1 SLA is 7 days
    new = _row(df, 80)
    assert new["status"] == "Open" and new["age_days"] == 0
    ssh = _row(df, 22)
    assert ssh["status"] == "Open" and ssh["age_days"] == 14 and not ssh["overdue"]


def test_trend_counts_per_scan():
    scans, df = _scored()
    t = trend(scans, df)
    first = t[t["scan_date"] == pd.Timestamp("2026-09-01").date()]
    assert first["findings"].sum() == 4


def test_summary_and_export(tmp_path):
    scans, df = _scored()
    s = export(df, trend(scans, df), tmp_path)
    assert s["open_findings"] == 4 and s["fixed_findings"] == 1 and s["scans"] == 2
    assert s["high_cvss_but_low_priority"] == 1     # SSH: CVSS 7.5 but P3
    assert s["below_high_cvss_but_urgent"] == 1     # web app: CVSS 6.1 but P1
    for f in ["findings.csv", "trend.csv", "summary.json", "vulnerability_report.xlsx"]:
        assert (tmp_path / f).exists()
    assert pd.read_csv(tmp_path / "findings.csv")["tier"].iloc[0] == "P1"   # fix-first order


@pytest.mark.parametrize("score,band", [(9.8, "Critical"), (7.0, "High"), (6.9, "Medium"), (0.1, "Low")])
def test_cvss_band(score, band):
    assert cvss_band(score) == band


def test_base_tier_without_data():
    assert base_tier(False, float("nan"), float("nan"))[0] == "P4"


def test_nessus_xml_parsing():
    df = load_scan(FIX / "xml" / "lab_2026-10-01.nessus")
    assert len(df) == 2                                     # informational item dropped
    ftp = _row(df, 21)
    assert ftp["cves"] == ["CVE-2011-2523"] and ftp["cvss"] == 9.8
    assert _row(df, 445)["cves"] == []
    assert str(df["scan_date"].iloc[0]) == "2026-10-01"     # date from the file name


def test_nessus_html_report_parsing_and_scoring():
    df = load_scan(FIX / "xml" / "lab_report.html")
    assert len(df) == 4                          # info item dropped; RC4 finding split across 2 ports
    assert str(df["scan_date"].iloc[0]) == "2026-10-01"   # from the report's start time
    ajp = _row(df, 8009)
    assert ajp["cves"] == ["CVE-2020-1938"] and ajp["scanner_kev"] == "2022-03-17"
    assert ajp["scanner_epss"] == 0.9927 and ajp["solution"] == "Upgrade Tomcat."
    scored = score_findings(build_history(df), {}, {}, today=date(2026, 10, 1))   # no live EPSS/KEV data
    assert _row(scored, 8009)["tier"] == "P1" and _row(scored, 8009)["in_kev"]     # scanner's KEV flag used
    assert _row(scored, 25)["tier"] == "P1"                                        # scanner's EPSS 84% used
    backdoor = _row(scored, 1524)
    assert backdoor["tier"] == "P2" and "no CVE" in backdoor["reason"]

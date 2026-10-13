"""Read Nessus (.nessus, CSV or HTML report) and OpenVAS (Greenbone) CSV exports into one common table.

Output columns (one row per finding per host/port):
    scan_date, scanner, host, port, protocol, finding_id, title, cvss, cves, solution
`cves` is a sorted, de-duplicated list of CVE IDs (may be empty).
"""
from __future__ import annotations

import re
from html import unescape
import xml.etree.ElementTree as ET
from datetime import date, datetime
from pathlib import Path

import pandas as pd

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
DATE_IN_NAME = re.compile(r"(\d{4}-\d{2}-\d{2})")
COLUMNS = ["scan_date", "scanner", "host", "port", "protocol", "finding_id", "title", "cvss", "cves", "solution",
           "severity", "scanner_epss", "scanner_kev"]
# Optional columns: only some formats provide them (the Nessus HTML report includes Tenable's own
# EPSS score and CISA KEV cross-reference). Used as a fallback when live lookups have no data.
OPTIONAL_DEFAULTS = {"severity": "", "scanner_epss": float("nan"), "scanner_kev": ""}


def _norm(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = [str(c).strip().lower() for c in df.columns]
    return df


def _cves(value) -> list[str]:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return []
    return sorted({c.upper() for c in CVE_RE.findall(str(value))})


def _num(series: pd.Series) -> pd.Series:
    return pd.to_numeric(series, errors="coerce")


def detect_scanner(df: pd.DataFrame) -> str:
    cols = set(df.columns)
    if {"plugin id", "host"} <= cols:
        return "nessus"
    if {"nvt oid", "ip"} <= cols or {"nvt name", "ip"} <= cols:
        return "openvas"
    raise ValueError(f"Unrecognised scan export. Columns found: {sorted(cols)[:12]}...")


def scan_date_for(path: Path, df: pd.DataFrame | None = None) -> date:
    """Date from the file name (e.g. nessus_2026-10-01.csv), else the export's timestamp, else file time."""
    m = DATE_IN_NAME.search(path.name)
    if m:
        return datetime.strptime(m.group(1), "%Y-%m-%d").date()
    if df is not None and "timestamp" in df.columns:
        ts = pd.to_datetime(df["timestamp"], errors="coerce", utc=True).dropna()
        if not ts.empty:
            return ts.min().date()
    return datetime.fromtimestamp(path.stat().st_mtime).date()


def parse_nessus(df: pd.DataFrame) -> pd.DataFrame:
    # Nessus writes one row per CVE, so several rows can describe the same plugin on the same port.
    cvss = None
    for col in ("cvss v3.0 base score", "cvss v3 base score", "cvss v2.0 base score", "cvss"):
        if col in df.columns:
            cvss = _num(df[col]) if cvss is None else cvss.fillna(_num(df[col]))
    out = pd.DataFrame({
        "host": df["host"].astype(str).str.strip(),
        "port": _num(df.get("port", pd.Series(0, index=df.index))).fillna(0).astype(int),
        "protocol": df.get("protocol", pd.Series("", index=df.index)).fillna("").astype(str).str.lower(),
        "finding_id": "nessus:" + df["plugin id"].astype(str).str.strip(),
        "title": df.get("name", pd.Series("", index=df.index)).fillna("").astype(str),
        "cvss": cvss if cvss is not None else pd.Series(float("nan"), index=df.index),
        "risk": df.get("risk", pd.Series("", index=df.index)).fillna("").astype(str).str.lower(),
        "cve_raw": df.get("cve", pd.Series("", index=df.index)),
        "solution": df.get("solution", pd.Series("", index=df.index)).fillna("").astype(str),
    })
    out = out[out["risk"] != "none"]   # informational plugins
    return out


def parse_openvas(df: pd.DataFrame) -> pd.DataFrame:
    fid = df["nvt oid"] if "nvt oid" in df.columns else df["nvt name"]
    out = pd.DataFrame({
        "host": df["ip"].astype(str).str.strip(),
        "port": _num(df.get("port", pd.Series(0, index=df.index))).fillna(0).astype(int),
        "protocol": df.get("port protocol", pd.Series("", index=df.index)).fillna("").astype(str).str.lower(),
        "finding_id": "openvas:" + fid.astype(str).str.strip(),
        "title": df.get("nvt name", pd.Series("", index=df.index)).fillna("").astype(str),
        "cvss": _num(df.get("cvss", pd.Series(float("nan"), index=df.index))),
        "risk": df.get("severity", pd.Series("", index=df.index)).fillna("").astype(str).str.lower(),
        "cve_raw": df.get("cves", pd.Series("", index=df.index)),
        "solution": df.get("solution", pd.Series("", index=df.index)).fillna("").astype(str),
    })
    out = out[~out["risk"].isin(["log", "none"])]
    return out


def parse_nessus_xml(path: Path) -> tuple[pd.DataFrame, date | None]:
    """Read a .nessus file (Nessus's own XML export, available in the free Essentials edition)."""
    rows, starts = [], []
    root = ET.parse(path).getroot()
    for host in root.iter("ReportHost"):
        props = {t.get("name"): (t.text or "") for t in host.iter("tag")}
        ip = props.get("host-ip") or host.get("name", "")
        if props.get("HOST_START_TIMESTAMP", "").isdigit():
            starts.append(datetime.fromtimestamp(int(props["HOST_START_TIMESTAMP"])).date())
        for item in host.iter("ReportItem"):
            if item.get("severity", "0") == "0":      # informational
                continue
            text = lambda tag: (item.findtext(tag) or "").strip()
            cvss = text("cvss3_base_score") or text("cvss_base_score")
            rows.append({
                "host": ip.strip(),
                "port": int(item.get("port", "0") or 0),
                "protocol": item.get("protocol", "").lower(),
                "finding_id": "nessus:" + item.get("pluginID", ""),
                "title": item.get("pluginName", ""),
                "cvss": float(cvss) if cvss else float("nan"),
                "risk": text("risk_factor").lower(),
                "cve_raw": " ".join(c.text or "" for c in item.findall("cve")),
                "solution": text("solution"),
            })
    cols = ["host", "port", "protocol", "finding_id", "title", "cvss", "risk", "cve_raw", "solution"]
    return pd.DataFrame(rows, columns=cols), (min(starts) if starts else None)


SEVERITY_COLOURS = {"#91243e": "critical", "#dd4b50": "high", "#f18c43": "medium", "#f8c851": "low", "#67ace1": "info"}
_PLUGIN_HDR = re.compile(r"background:\s*(#[0-9a-fA-F]{6});[^>]*onclick=\"toggleSection\('(id\d+)-container'\);\"[^>]*>"
                         r"\s*(\d+) - (.*?)<div", re.S)
_IP_ROW = re.compile(r">IP:</td>\s*<td[^>]*>([^<]+)</td>")
_START = re.compile(r">Start time:</td>\s*<td[^>]*>([^<]+)</td>")


def _section(block: str, name: str) -> str:
    """Text of one 'details-header' section (e.g. Solution) inside a plugin block."""
    m = re.search(rf'details-header">{re.escape(name)}<div class="clear"></div>\s*</div>\s*(.*?)'
                  rf'(?=<div class="details-header">|$)', block, re.S)
    if not m:
        return ""
    text = re.sub(r"<br\s*/?>", "\n", m.group(1))
    return unescape(re.sub(r"<[^>]+>", " ", text)).strip()


def _first_float(text: str) -> float:
    m = re.search(r"\d+(?:\.\d+)?", text or "")
    return float(m.group(0)) if m else float("nan")


def parse_nessus_html(path: Path) -> tuple[pd.DataFrame, date | None]:
    """Read a Nessus HTML report using the 'Detailed Vulnerabilities By Host' template.

    Exports (CSV/.nessus) aren't available in Nessus Essentials, but this report is, and it
    contains everything needed: CVEs, CVSS, ports, solution, plus Tenable's EPSS and KEV notes.
    """
    html = path.read_text(encoding="utf-8", errors="replace")
    hosts = [(m.start(), m.group(1).strip()) for m in _IP_ROW.finditer(html)]
    headers = list(_PLUGIN_HDR.finditer(html))
    if not headers:
        raise ValueError(f"{path.name}: no vulnerability details found. Use the 'Detailed Vulnerabilities "
                         f"By Host' HTML template, not the summary one.")
    rows = []
    for i, h in enumerate(headers):
        severity = SEVERITY_COLOURS.get(h.group(1).lower(), "")
        if severity == "info":
            continue
        end = headers[i + 1].start() if i + 1 < len(headers) else len(html)
        block = html[h.end():end]
        host = next((ip for pos, ip in reversed(hosts) if pos < h.start()), "")
        cvss = _first_float(_section(block, "CVSS v3.0 Base Score"))
        if pd.isna(cvss):
            cvss = _first_float(_section(block, "CVSS v2.0 Base Score"))
        refs = _section(block, "References")
        kev = re.search(r"CISA-KNOWN-EXPLOITED:(\d{4})/(\d{2})/(\d{2})", refs)
        ports = re.findall(r"<h2>\s*((?:tcp|udp|icmp)/[^<]*)</h2>", block) or ["tcp/0"]
        for p in dict.fromkeys(ports):
            proto, port = (p.split("/") + ["0"])[:2]
            rows.append({
                "host": host, "port": int(port) if port.isdigit() else 0, "protocol": proto.lower(),
                "finding_id": "nessus:" + h.group(3), "title": unescape(h.group(4)).strip(), "cvss": cvss,
                "risk": severity, "cve_raw": refs, "solution": _section(block, "Solution"),
                "severity": severity, "scanner_epss": _first_float(_section(block, "EPSS Score")),
                "scanner_kev": "-".join(kev.groups()) if kev else "",
            })
    start = _START.search(html)
    scan_dt = None
    if start:
        try:
            scan_dt = datetime.strptime(start.group(1).strip(), "%a %b %d %H:%M:%S %Y").date()
        except ValueError:
            pass
    return pd.DataFrame(rows), scan_dt


def load_scan(path: str | Path) -> pd.DataFrame:
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix in (".nessus", ".html", ".htm"):
        scanner = "nessus"
        rows, file_date = parse_nessus_xml(path) if suffix == ".nessus" else parse_nessus_html(path)
        m = DATE_IN_NAME.search(path.name)
        scan_date = datetime.strptime(m.group(1), "%Y-%m-%d").date() if m else (file_date or scan_date_for(path))
    else:
        # keep_default_na=False: otherwise pandas turns Nessus's risk value "None" into a blank.
        raw = _norm(pd.read_csv(path, dtype=str, keep_default_na=False, encoding_errors="replace",
                                on_bad_lines="skip"))
        scanner = detect_scanner(raw)
        rows = parse_nessus(raw) if scanner == "nessus" else parse_openvas(raw)
        scan_date = scan_date_for(path, raw)

    # Merge rows that describe the same finding, collecting all of its CVEs.
    key = ["host", "port", "protocol", "finding_id"]
    for col, default in OPTIONAL_DEFAULTS.items():
        if col not in rows.columns:
            rows[col] = default
    rows["cves"] = rows["cve_raw"].map(_cves)
    merged = rows.groupby(key, as_index=False).agg(
        title=("title", "first"),
        cvss=("cvss", "max"),
        cves=("cves", lambda s: sorted({c for lst in s for c in lst})),
        solution=("solution", "first"),
        severity=("severity", "first"),
        scanner_epss=("scanner_epss", "max"),
        scanner_kev=("scanner_kev", "first"),
    )
    merged.insert(0, "scanner", scanner)
    merged.insert(0, "scan_date", scan_date)
    return merged[COLUMNS]


def load_scans(folder: str | Path) -> pd.DataFrame:
    files = sorted(p for p in Path(folder).iterdir() if p.suffix.lower() in (".csv", ".nessus", ".html", ".htm"))
    if not files:
        raise FileNotFoundError(f"No scan files (.nessus, .csv or .html) in {folder}. Export a scan first.")
    return pd.concat([load_scan(f) for f in files], ignore_index=True)

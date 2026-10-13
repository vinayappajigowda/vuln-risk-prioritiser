"""Add real-world exploit data to CVEs.

- EPSS (FIRST.org): probability a CVE will be exploited in the next 30 days.
- CISA KEV: CVEs confirmed to be exploited in the wild.

Results are cached in data/cache/ so repeat runs are fast and work offline.
"""
from __future__ import annotations

import json
import time
from datetime import date, datetime, timedelta
from pathlib import Path

import requests

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    # Official CISA mirror on GitHub, used if the main site is unreachable.
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
]
CACHE_DIR = Path("data/cache")
EPSS_BATCH = 50          # CVEs per API request
MAX_AGE = timedelta(days=1)


def _read_json(path: Path):
    return json.loads(path.read_text()) if path.exists() else None


def _fresh(path: Path) -> bool:
    return path.exists() and datetime.now() - datetime.fromtimestamp(path.stat().st_mtime) < MAX_AGE


def load_kev(offline: bool = False, cache_dir: Path = CACHE_DIR) -> dict[str, dict]:
    """Return {CVE: {date_added, ransomware, name, required_action}} from the CISA KEV catalogue."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_dir / "kev.json"
    if not offline and not _fresh(path):
        for url in KEV_URLS:
            try:
                r = requests.get(url, timeout=30)
                r.raise_for_status()
                path.write_text(r.text)
                break
            except requests.RequestException as e:
                print(f"  KEV download failed from {url}: {e}")
    data = _read_json(path)
    if data is None:
        raise RuntimeError("No CISA KEV data available. Run once with internet access.")
    return {
        v["cveID"].upper(): {
            "date_added": v.get("dateAdded"),
            "ransomware": str(v.get("knownRansomwareCampaignUse", "")).lower() == "known",
            "name": v.get("vulnerabilityName", ""),
            "required_action": v.get("requiredAction", ""),
        }
        for v in data.get("vulnerabilities", [])
    }


def load_epss(cves: list[str], offline: bool = False, cache_dir: Path = CACHE_DIR) -> dict[str, dict]:
    """Return {CVE: {epss, percentile}} for the given CVEs, using and updating a local cache."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_dir / "epss.json"
    cache = _read_json(path) or {"date": None, "scores": {}}
    today = date.today().isoformat()
    stale = {}
    if cache.get("date") != today and not offline:
        # EPSS updates daily, so re-fetch once a day. Keep yesterday's scores as a fallback.
        stale, cache = cache["scores"], {"date": today, "scores": {}}

    missing = sorted({c.upper() for c in cves} - set(cache["scores"]))
    if missing and not offline:
        for i in range(0, len(missing), EPSS_BATCH):
            batch = missing[i:i + EPSS_BATCH]
            try:
                r = requests.get(EPSS_URL, params={"cve": ",".join(batch)}, timeout=30)
                r.raise_for_status()
                for row in r.json().get("data", []):
                    cache["scores"][row["cve"].upper()] = {
                        "epss": float(row["epss"]), "percentile": float(row["percentile"])}
                # CVEs with no EPSS entry (e.g. reserved/rejected) are stored as None so we don't re-ask.
                for c in batch:
                    cache["scores"].setdefault(c, None)
            except requests.RequestException as e:
                print(f"  EPSS request failed: {e}")
                for c in batch:
                    if stale.get(c) is not None:
                        cache["scores"][c] = stale[c]
            time.sleep(0.2)   # be polite to the free API
        path.write_text(json.dumps(cache))
    return {c: cache["scores"].get(c.upper()) for c in cves}

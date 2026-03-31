# FINAL CLEAN VERSION — SecureWatch CVE Sync
# Fixes:
# - Removed duplicate KEV functions
# - Single JSON save at end
# - Stable CISA KEV integration
# - Advisories temporarily disabled safely

import json
import os
import time
import urllib.request
from datetime import datetime, timedelta

OUT_FILE = 'cve-data.json'

CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def http_get(url, timeout=20):
    req = urllib.request.Request(url, headers={'User-Agent': 'SecureWatch/Final'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


# ✅ ONLY ONE KEV FUNCTION (FIXED)
def fetch_cisa_kev():
    log("Fetching CISA KEV...")
    try:
        raw = http_get(CISA_KEV_URL)
        data = json.loads(raw)
        kev = {}

        for v in data.get('vulnerabilities', []):
            cid = v.get('cveID', '').upper()
            if not cid:
                continue

            kev[cid] = {
                'kev': True,
                'name': v.get('vulnerabilityName', ''),
                'dateAdded': v.get('dateAdded', ''),
                'dueDate': v.get('dueDate', ''),
                'action': v.get('requiredAction', ''),
                'product': f"{v.get('vendorProject','')} {v.get('product','')}".strip()
            }

        log(f"KEV loaded: {len(kev)}")
        return kev

    except Exception as e:
        log(f"KEV ERROR: {e}")
        return {}


# Advisories disabled safely
def fetch_cisa_advisories():
    return []


def fetch_cisa_data():
    kev = fetch_cisa_kev()
    advisories = fetch_cisa_advisories()

    return {
        'lastFetch': datetime.utcnow().isoformat() + 'Z',
        'kevCount': len(kev),
        'advisoryCount': len(advisories),
        'kev': kev,
        'advisories': advisories
    }


def main():
    db = {}

    log("Starting sync...")

    # Only CISA for now (simplified clean version)
    cisa_data = fetch_cisa_data()
    db['cisa'] = cisa_data

    # ✅ SINGLE FINAL SAVE
    db['lastSync'] = datetime.utcnow().isoformat() + 'Z'

    with open(OUT_FILE, 'w') as f:
        json.dump(db, f, separators=(',', ':'))

    log("DONE — JSON saved")


if __name__ == "__main__":
    main()

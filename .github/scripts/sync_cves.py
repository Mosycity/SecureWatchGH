"""
SecureWatch CVE Sync — GitHub Actions version
Fetches CVEs from NVD and saves cve-data.json to the repo
Runs every 6 hours via GitHub Actions (free, no server needed)
"""

import json
import os
import time
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timedelta

OUT_FILE  = 'cve-data.json'                     # saved to repo root
NVD_KEY   = os.environ.get('NVD_API_KEY', '')   # from GitHub secret
DAYS_BACK = int(os.environ.get('DAYS_BACK', 90))
THROTTLE  = 0.3 if NVD_KEY else 1.5             # seconds between requests

# ── All 30 vendors ────────────────────────────────────────────
VENDORS = [
    {'id': 'cisco',        'keyword': 'cisco'},
    {'id': 'juniper',      'keyword': 'juniper'},
    {'id': 'paloalto',     'keyword': 'palo alto'},
    {'id': 'fortinet',     'keyword': 'fortinet'},
    {'id': 'checkpoint',   'keyword': 'checkpoint'},
    {'id': 'sonicwall',    'keyword': 'sonicwall'},
    {'id': 'aruba',        'keyword': 'aruba'},
    {'id': 'f5',           'keyword': 'f5'},
    {'id': 'dell',         'keyword': 'dell'},
    {'id': 'hp',           'keyword': 'hewlett'},
    {'id': 'lenovo',       'keyword': 'lenovo'},
    {'id': 'intel_hw',     'keyword': 'intel'},
    {'id': 'microsoft',    'keyword': 'microsoft'},
    {'id': 'adobe',        'keyword': 'adobe'},
    {'id': 'oracle',       'keyword': 'oracle'},
    {'id': 'sap',          'keyword': 'sap'},
    {'id': 'atlassian',    'keyword': 'atlassian'},
    {'id': 'apache',       'keyword': 'apache'},
    {'id': 'citrix',       'keyword': 'citrix'},
    {'id': 'ivanti',       'keyword': 'ivanti'},
    {'id': 'ericsson',     'keyword': 'ericsson'},
    {'id': 'nokia',        'keyword': 'nokia'},
    {'id': 'huawei',       'keyword': 'huawei'},
    {'id': 'vmware',       'keyword': 'vmware'},
    {'id': 'xen',          'keyword': 'xen'},
    {'id': 'redhat',       'keyword': 'redhat'},
    {'id': 'ubuntu',       'keyword': 'ubuntu'},
    {'id': 'debian',       'keyword': 'debian'},
    {'id': 'amazon',       'keyword': 'amazon'},
    {'id': 'google_cloud', 'keyword': 'google'},
]

# ── Logging ───────────────────────────────────────────────────
def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)

# ── NVD fetch ─────────────────────────────────────────────────
def nvd_fetch(params, attempt=0):
    base = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    qs   = urllib.parse.urlencode({'resultsPerPage': 2000, 'startIndex': 0, **params})
    req  = urllib.request.Request(f"{base}?{qs}", headers={
        'User-Agent': 'SecureWatch/3.0',
        **(({'apiKey': NVD_KEY}) if NVD_KEY else {})
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        if e.code == 429:
            raise Exception('RATE_LIMITED')
        raise Exception(f'HTTP {e.code}')
    except urllib.error.URLError as e:
        raise Exception(f'Network: {e.reason}')

# ── Fetch one vendor with retry ───────────────────────────────
def fetch_vendor(vendor, attempt=0):
    now   = datetime.utcnow()
    start = (now - timedelta(days=DAYS_BACK)).strftime('%Y-%m-%dT00:00:00.000')
    end   = now.strftime('%Y-%m-%dT%H:%M:%S.000')
    try:
        data = nvd_fetch({'keywordSearch': vendor['keyword'],
                          'pubStartDate': start, 'pubEndDate': end})
        cves = [parse_cve(v) for v in data.get('vulnerabilities', [])]
        log(f"  ✅ {vendor['id']:15} {len(cves):4} CVEs")
        return cves
    except Exception as e:
        if str(e) == 'RATE_LIMITED' and attempt < 3:
            wait = (attempt + 1) * 35
            log(f"  ⏳ {vendor['id']}: rate limited — waiting {wait}s…")
            time.sleep(wait)
            return fetch_vendor(vendor, attempt + 1)
        log(f"  ❌ {vendor['id']}: {e}")
        return []

# ── Parse CVE ─────────────────────────────────────────────────
def sf_score(s):
    if s is None: return 'NONE'
    return 'CRITICAL' if s>=9 else 'HIGH' if s>=7 else 'MEDIUM' if s>=4 else 'LOW' if s>0 else 'NONE'

def find_scores(arr):
    if not arr: return None, None
    primary   = next((m for m in arr if m.get('type')=='Primary'), arr[0])
    secondary = next((m for m in arr if m.get('type')=='Secondary'), None)
    return primary, secondary

def parse_cve(v):
    cve     = v.get('cve', {})
    metrics = cve.get('metrics', {})
    score   = severity = vector = cvss_ver = None
    vs_score = vs_sev = vs_src = None

    p31, s31 = find_scores(metrics.get('cvssMetricV31'))
    p30, s30 = find_scores(metrics.get('cvssMetricV30'))
    p2,  s2  = find_scores(metrics.get('cvssMetricV2'))

    if p31:
        d = p31.get('cvssData', {})
        score, severity, vector, cvss_ver = d.get('baseScore'), d.get('baseSeverity',''), d.get('vectorString',''), '3.1'
    elif p30:
        d = p30.get('cvssData', {})
        score, severity, vector, cvss_ver = d.get('baseScore'), d.get('baseSeverity',''), d.get('vectorString',''), '3.0'
    elif p2:
        d = p2.get('cvssData', {})
        score, severity, vector, cvss_ver = d.get('baseScore'), p2.get('baseSeverity') or sf_score(d.get('baseScore')), d.get('vectorString',''), '2.0'

    # Vendor score if different
    vs = s31 or s30 or s2
    if vs:
        vd = vs.get('cvssData', {})
        vsc = vd.get('baseScore')
        if vsc is not None and vsc != score:
            vs_score = vsc
            vs_sev   = (vd.get('baseSeverity') or sf_score(vsc)).upper()
            vs_src   = vs.get('source', 'Vendor')

    av = ('NETWORK'  if vector and 'AV:N' in vector else
          'ADJACENT' if vector and 'AV:A' in vector else
          'LOCAL'    if vector and 'AV:L' in vector else
          'PHYSICAL' if vector and 'AV:P' in vector else None)

    products = set()
    for cfg in cve.get('configurations', []):
        for node in cfg.get('nodes', []):
            for m in node.get('cpeMatch', []):
                if m.get('vulnerable') and m.get('criteria'):
                    pts = m['criteria'].split(':')
                    if len(pts) > 4:
                        products.add(pts[3] + (' ' + pts[4] if pts[4] != '*' else ''))

    return {
        'id':             cve.get('id',''),
        'desc':           next((d['value'] for d in cve.get('descriptions',[]) if d.get('lang')=='en'), ''),
        'score':          score,
        'severity':       (severity or 'NONE').upper(),
        'vector':         vector,
        'cvssVersion':    cvss_ver,
        'av':             av,
        'vendorScore':    vs_score,
        'vendorSeverity': vs_sev,
        'vendorSource':   vs_src,
        'refs':           [r['url'] for r in cve.get('references',[])[:8]],
        'published':      (cve.get('published') or '')[:10],
        'modified':       (cve.get('lastModified') or '')[:10],
        'products':       list(products)[:6],
        'epss':           None,
    }

# ── Main ──────────────────────────────────────────────────────
def main():
    log('=' * 50)
    log('SecureWatch CVE Sync — GitHub Actions')
    log(f'Days: {DAYS_BACK}  |  API key: {"YES" if NVD_KEY else "NO (slower)"}  |  Vendors: {len(VENDORS)}')
    log('=' * 50)

    # Load existing file to preserve data on partial failure
    db = {'lastSync': None, 'vendors': {}}
    if os.path.exists(OUT_FILE):
        try:
            with open(OUT_FILE) as f:
                db = json.load(f)
            log(f'Loaded existing data: {sum(len(v.get("cves",[])) for v in db["vendors"].values()):,} CVEs')
        except Exception:
            pass

    success = failed = 0

    for i, vendor in enumerate(VENDORS):
        log(f"[{i+1:2}/{len(VENDORS)}] {vendor['id']}…")
        cves = fetch_vendor(vendor)

        db['vendors'][vendor['id']] = {
            'lastFetch': datetime.utcnow().isoformat() + 'Z',
            'count':     len(cves),
            'cves':      cves,
        }
        if cves: success += 1
        else:    failed  += 1

        # Save after every vendor — progress not lost on timeout
        db['lastSync'] = datetime.utcnow().isoformat() + 'Z'
        with open(OUT_FILE, 'w') as f:
            json.dump(db, f, separators=(',', ':'))  # compact — smaller file

        if i < len(VENDORS) - 1:
            time.sleep(THROTTLE)

    total = sum(len(v.get('cves',[])) for v in db['vendors'].values())
    size  = os.path.getsize(OUT_FILE) / 1024 / 1024

    log('=' * 50)
    log(f'Done: {success} vendors OK · {failed} skipped')
    log(f'Total CVEs: {total:,}  |  File size: {size:.1f} MB')
    log(f'Saved to: {OUT_FILE}')
    log('=' * 50)

if __name__ == '__main__':
    main()

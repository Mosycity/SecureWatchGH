"""
SecureWatch CVE Sync — GitHub Actions version
Fetches CVEs from NVD + direct vendor advisories (Cisco, Microsoft, Fortinet, Palo Alto, Juniper)
Runs every 6 hours via GitHub Actions (free, no server needed)

Data sources:
  - NVD API      : all 30 vendors (up to 7 days behind vendor advisories)
  - Cisco RSS    : same-day advisories from sec.cloudapps.cisco.com
  - Microsoft    : same-day advisories from msrc.microsoft.com
  - Fortinet RSS : same-day advisories from fortiguard.com
  - Palo Alto    : same-day advisories from security.paloaltonetworks.com
  - Juniper RSS  : same-day advisories from supportportal.juniper.net
"""

import json
import os
import time
import xml.etree.ElementTree as ET
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timedelta

OUT_FILE  = 'cve-data.json'
NVD_KEY   = os.environ.get('NVD_API_KEY', '')
DAYS_BACK = int(os.environ.get('DAYS_BACK', 90))
THROTTLE  = 0.3 if NVD_KEY else 1.5

# ── All 30 vendors (NVD) ──────────────────────────────────────
VENDORS = [
    # ── Network / Security ──────────────────────────────────
    {'id': 'cisco',        'keyword': 'cisco'},           # ✅ correct
    {'id': 'juniper',      'keyword': 'juniper'},          # ✅ correct
    {'id': 'paloalto',     'keyword': 'paloaltonetworks'}, # FIX: NVD CPE vendor is paloaltonetworks
    {'id': 'fortinet',     'keyword': 'fortinet'},         # ✅ correct
    {'id': 'checkpoint',   'keyword': 'checkpoint'},       # FIX: use "check point" for keyword search
    {'id': 'sonicwall',    'keyword': 'sonicwall'},        # ✅ correct
    {'id': 'aruba',        'keyword': 'aruba'},            # ✅ correct
    {'id': 'f5',           'keyword': 'f5'},               # ✅ correct (BIG-IP/TMOS)
    {'id': 'nginx',        'keyword': 'nginx'},            # NEW: nginx is separate NVD vendor (F5-owned)
    # ── Hardware / Endpoints ─────────────────────────────────
    {'id': 'dell',         'keyword': 'dell'},             # ✅ correct
    {'id': 'hp',           'keyword': 'hewlett packard'},  # FIX: catches both HP + HPE
    {'id': 'lenovo',       'keyword': 'lenovo'},           # ✅ correct
    {'id': 'intel_hw',     'keyword': 'intel'},            # ✅ correct
    # ── Software / Cloud ─────────────────────────────────────
    {'id': 'microsoft',    'keyword': 'microsoft'},        # ✅ correct
    {'id': 'adobe',        'keyword': 'adobe'},            # ✅ correct
    {'id': 'oracle',       'keyword': 'oracle'},           # ✅ correct
    {'id': 'sap',          'keyword': 'sap'},              # ✅ correct
    {'id': 'atlassian',    'keyword': 'atlassian'},        # ✅ correct
    {'id': 'apache',       'keyword': 'apache'},           # ✅ correct
    {'id': 'citrix',       'keyword': 'citrix'},           # ✅ correct
    {'id': 'ivanti',       'keyword': 'ivanti'},           # ✅ correct
    {'id': 'vmware',       'keyword': 'vmware'},           # ✅ correct (pre-2024 products)
    {'id': 'broadcom',     'keyword': 'broadcom'},         # NEW: post-2024 VMware products now under broadcom
    # ── Telco ────────────────────────────────────────────────
    {'id': 'ericsson',     'keyword': 'ericsson'},         # ✅ correct
    {'id': 'nokia',        'keyword': 'nokia'},            # ✅ correct
    {'id': 'huawei',       'keyword': 'huawei'},           # ✅ correct
    # ── OS / Infra ───────────────────────────────────────────
    {'id': 'xen',          'keyword': 'xen'},              # ✅ correct
    {'id': 'redhat',       'keyword': 'red hat'},          # FIX: "red hat" (with space) matches more NVD entries
    {'id': 'ubuntu',       'keyword': 'ubuntu'},           # ✅ correct
    {'id': 'canonical',    'keyword': 'canonical'},        # NEW: some Ubuntu CVEs filed under canonical
    {'id': 'debian',       'keyword': 'debian'},           # ✅ correct
    {'id': 'amazon',       'keyword': 'amazon'},           # ✅ correct (AWS + Amazon products)
    {'id': 'google_cloud', 'keyword': 'google'},           # ✅ correct (broad but intentional)
]

# ── Vendor RSS / API feeds ────────────────────────────────────
# Each entry: vendor_id, url, format, severity_map
VENDOR_FEEDS = [
    {
        'id':     'cisco',
        'name':   'Cisco PSIRT',
        'urls':   [
            'https://sec.cloudapps.cisco.com/security/center/json/getProductAdvisories.x?advisoryType=Security%20Advisory&sortBy=firstPublished&output=json',
        ],
        'format': 'cisco_json',
    },
    {
        'id':     'microsoft',
        'name':   'Microsoft MSRC',
        'urls':   [
            'https://api.msrc.microsoft.com/cvrf/v3.0/updates',
        ],
        'format': 'msrc',
    },
    {
        'id':     'fortinet',
        'name':   'Fortinet PSIRT',
        'urls':   [
            'https://www.fortiguard.com/rss/ir.xml',
            'https://filestore.fortinet.com/fortiguard/rss/ir.xml',
            'https://www.fortiguard.com/rss/psirt.xml',
        ],
        'format': 'rss',
    },
    {
        'id':     'paloalto',
        'name':   'Palo Alto Security',
        'urls':   [
            'https://security.paloaltonetworks.com/rss.xml',
        ],
        'format': 'rss',
    },
    {
        'id':     'juniper',
        'name':   'Juniper SIRT',
        'urls':   [
            'https://www.juniper.net/us/en/local/xml/rss/juniper-security-advisories.xml',
            'https://kb.juniper.net/InfoCenter/index?page=rss&channel=PSIRT',
            'https://kb.juniper.net/InfoCenter/index?page=rss&channel=SIRT',
        ],
        'format': 'rss_lenient'
    },
]

# ── Logging ───────────────────────────────────────────────────
def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)

# ── Generic HTTP fetch ────────────────────────────────────────
def http_get(url, headers=None, timeout=20):
    req = urllib.request.Request(url, headers={
        'User-Agent': 'SecureWatch/3.0',
        **(headers or {})
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()

def http_get_with_fallback(urls, headers=None, timeout=15):
    """Try each URL in list, return first success."""
    last_err = None
    for url in urls:
        try:
            return http_get(url, headers=headers, timeout=timeout)
        except Exception as e:
            last_err = e
            continue
    raise last_err

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

# ── Parse NVD CVE ─────────────────────────────────────────────
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
        '_src':           'NVD',
    }

# ── Fetch one vendor from NVD with retry ─────────────────────
def fetch_vendor_nvd(vendor, attempt=0):
    now   = datetime.utcnow()
    start = (now - timedelta(days=DAYS_BACK)).strftime('%Y-%m-%dT00:00:00.000')
    end   = now.strftime('%Y-%m-%dT%H:%M:%S.000')
    try:
        data = nvd_fetch({'keywordSearch': vendor['keyword'],
                          'pubStartDate': start, 'pubEndDate': end})
        cves = [parse_cve(v) for v in data.get('vulnerabilities', [])]
        log(f"  ✅ NVD  {vendor['id']:15} {len(cves):4} CVEs")
        return cves
    except Exception as e:
        if str(e) == 'RATE_LIMITED' and attempt < 3:
            wait = (attempt + 1) * 35
            log(f"  ⏳ {vendor['id']}: rate limited — waiting {wait}s…")
            time.sleep(wait)
            return fetch_vendor_nvd(vendor, attempt + 1)
        log(f"  ❌ NVD  {vendor['id']}: {e}")
        return []

# ── RSS feed parser ───────────────────────────────────────────
import re as _re

def extract_cves_from_text(text):
    """Extract all CVE IDs mentioned in a string."""
    return list(set(_re.findall(r'CVE-\d{4}-\d{4,7}', text, _re.IGNORECASE)))

def parse_rss_date(date_str):
    """Parse RSS pubDate to YYYY-MM-DD. Returns '' on failure."""
    if not date_str:
        return ''
    # Try common RSS date formats
    for fmt in ['%a, %d %b %Y %H:%M:%S %z', '%a, %d %b %Y %H:%M:%S %Z',
                '%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%dT%H:%M:%S%z']:
        try:
            return datetime.strptime(date_str.strip(), fmt).strftime('%Y-%m-%d')
        except Exception:
            pass
    # Fallback: grab first 10 chars if looks like ISO
    if date_str[:4].isdigit():
        return date_str[:10]
    return datetime.utcnow().strftime('%Y-%m-%d')

def severity_from_title(title):
    """Guess severity from advisory title keywords."""
    t = title.lower()
    if any(w in t for w in ['critical', 'remote code execution', 'rce', 'unauthenticated']):
        return 'CRITICAL'
    if any(w in t for w in ['high', 'privilege escalation', 'authentication bypass']):
        return 'HIGH'
    if any(w in t for w in ['medium', 'moderate', 'xss', 'csrf']):
        return 'MEDIUM'
    if any(w in t for w in ['low', 'minor', 'informational']):
        return 'LOW'
    return 'HIGH'  # default assumption for vendor advisories

def parse_xml_lenient(raw):
    """Try strict XML first, fall back to cleaning malformed XML."""
    import re as _rexml
    # Detect HTML login redirect — not a real XML feed
    preview = raw[:300].lower()
    if b'<html' in preview or b'<!doctype' in preview:
        raise ValueError("Got HTML instead of XML — feed requires login")
    try:
        return ET.fromstring(raw)
    except ET.ParseError:
        # Decode and strip control chars that break XML parsing
        clean = raw.decode('utf-8', errors='replace')
        clean = ''.join(c for c in clean if ord(c) >= 32 or c in '\t\n\r')
        # Fix bare & not part of a proper XML entity
        clean = _rexml.sub(r'&(?![a-zA-Z#][a-zA-Z0-9#]*;)', '&amp;', clean)
        return ET.fromstring(clean.encode('utf-8'))


def fetch_rss_feed(feed):
    """Parse an RSS/Atom feed and return list of advisory dicts."""
    vendor_id = feed['id']
    cutoff    = (datetime.utcnow() - timedelta(days=DAYS_BACK)).strftime('%Y-%m-%d')
    advisories = []
    lenient   = feed.get('format') == 'rss_lenient'

    try:
        urls = feed.get('urls', [feed.get('url','')])
        raw = http_get_with_fallback(urls, timeout=15)
        root = parse_xml_lenient(raw) if lenient else ET.fromstring(raw)

        # Handle both RSS and Atom namespaces
        ns = {'atom': 'http://www.w3.org/2005/Atom'}

        # Try RSS items first, then Atom entries
        items = root.findall('.//item') or root.findall('.//atom:entry', ns)

        for item in items:
            # Get text content helper
            def txt(tag, ns_prefix=None):
                el = item.find(tag) if not ns_prefix else item.find(f'{ns_prefix}:{tag}', ns)
                return (el.text or '').strip() if el is not None else ''

            title   = txt('title') or txt('title', 'atom')
            link    = txt('link')  or txt('link', 'atom')
            desc    = txt('description') or txt('summary', 'atom') or txt('content', 'atom')
            pub_raw = txt('pubDate') or txt('published', 'atom') or txt('updated', 'atom')
            pub     = parse_rss_date(pub_raw)

            # Skip if older than DAYS_BACK
            if pub and pub < cutoff:
                continue

            # Extract CVE IDs from title + description
            all_text = f"{title} {desc}"
            cve_ids  = extract_cves_from_text(all_text)

            # Build an advisory entry for each CVE found
            # If no CVE ID in text, still include as advisory-only entry
            if cve_ids:
                for cve_id in cve_ids:
                    advisories.append({
                        'cve_id':    cve_id.upper(),
                        'title':     title,
                        'desc':      _re.sub('<[^>]+>', '', desc)[:500].strip(),  # strip HTML
                        'url':       link,
                        'published': pub,
                        'severity':  severity_from_title(title),
                        'vendor_id': vendor_id,
                    })
            else:
                # Advisory without CVE ID — include with generated ref
                advisories.append({
                    'cve_id':    None,
                    'title':     title,
                    'desc':      _re.sub('<[^>]+>', '', desc)[:500].strip(),
                    'url':       link,
                    'published': pub,
                    'severity':  severity_from_title(title),
                    'vendor_id': vendor_id,
                })

        log(f"  ✅ RSS  {vendor_id:15} {len(advisories):4} advisories ({len([a for a in advisories if a['cve_id']])} with CVE IDs)")
        return advisories

    except Exception as e:
        log(f"  ⚠️  RSS  {vendor_id}: {e} — skipping vendor feed")
        return []

def fetch_cisco_feed(feed):
    """Fetch Cisco PSIRT advisories via their public JSON API."""
    import re as _recisco
    vendor_id = feed['id']
    cutoff    = (datetime.utcnow() - timedelta(days=DAYS_BACK)).strftime('%Y-%m-%d')
    advisories = []
    try:
        urls = feed.get('urls', [])
        raw  = http_get_with_fallback(urls, timeout=20)
        data = json.loads(raw)
        items = data if isinstance(data, list) else data.get('advisories', data.get('data', []))
        for item in items:
            pub = (item.get('firstPublished') or item.get('publicationUrl',''))[:10]
            if pub and pub < cutoff:
                continue
            title   = item.get('advisoryTitle','') or item.get('title','')
            url     = item.get('publicationUrl','') or item.get('url','')
            desc    = item.get('summary','') or item.get('description','')
            cve_ids = item.get('cves', item.get('cveIds', []))
            # Also extract from text
            if not cve_ids:
                cve_ids = _recisco.findall(r'CVE-\d{4}-\d{4,7}', f"{title} {desc}")
            sev = (item.get('sir','') or item.get('severity','')).upper()
            if sev not in ('CRITICAL','HIGH','MEDIUM','LOW'):
                sev = severity_from_title(title)
            if cve_ids:
                for cid in (cve_ids if isinstance(cve_ids, list) else [cve_ids]):
                    advisories.append({
                        'cve_id': str(cid).upper(), 'title': title,
                        'desc': desc[:500], 'url': url,
                        'published': pub, 'severity': sev, 'vendor_id': vendor_id,
                    })
            else:
                advisories.append({
                    'cve_id': None, 'title': title, 'desc': desc[:500],
                    'url': url, 'published': pub, 'severity': sev, 'vendor_id': vendor_id,
                })
        log(f"  ✅ JSON {vendor_id:15} {len(advisories):4} advisories ({len([a for a in advisories if a['cve_id']])} with CVE IDs)")
        return advisories
    except Exception as e:
        log(f"  ⚠️  JSON {vendor_id}: {e} — skipping vendor feed")
        return []

def fetch_msrc_feed(feed):
    """Fetch Microsoft MSRC updates JSON API."""
    vendor_id = feed['id']
    cutoff    = (datetime.utcnow() - timedelta(days=DAYS_BACK)).strftime('%Y-%m-%d')
    advisories = []

    try:
        urls = feed.get('urls', [feed.get('url','')])
        raw  = http_get_with_fallback(urls, headers={'Accept': 'application/json'}, timeout=20)
        data = json.loads(raw)
        updates = data.get('value', [])

        for upd in updates:
            pub = (upd.get('InitialReleaseDate') or upd.get('CurrentReleaseDate') or '')[:10]
            if pub and pub < cutoff:
                continue

            title = upd.get('DocumentTitle', {})
            if isinstance(title, dict):
                title = title.get('Value', '')
            cve_id = upd.get('ID', '')  # MSRC uses CVE ID as document ID

            advisories.append({
                'cve_id':    cve_id if cve_id.startswith('CVE-') else None,
                'title':     title,
                'desc':      f"Microsoft Security Update: {title}",
                'url':       f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}",
                'published': pub,
                'severity':  severity_from_title(title),
                'vendor_id': vendor_id,
            })

        log(f"  ✅ MSRC {vendor_id:15} {len(advisories):4} advisories")
        return advisories

    except Exception as e:
        log(f"  ⚠️  MSRC {vendor_id}: {e} — skipping vendor feed")
        return []

# ── Merge vendor advisories into NVD CVE list ─────────────────

# ─────────────────────────────────────────────────────────────
# CISA KEV + Advisories
# ─────────────────────────────────────────────────────────────
CISA_KEV_URL       = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
CISA_ADVISORY_URL  = 'https://www.cisa.gov/cybersecurity-advisories/all.xml'

def fetch_cisa_kev():
    """Fetch CISA Known Exploited Vulnerabilities catalog.
    Returns dict: { 'CVE-XXXX-YYYY': { kev fields } }
    """
    log("  Fetching CISA KEV catalog...")
    try:
        raw  = http_get(CISA_KEV_URL, timeout=30)
        data = json.loads(raw)
        vulns = data.get('vulnerabilities', [])
        kev = {}
        for v in vulns:
            cid = v.get('cveID','').upper()
            if not cid:
                continue
            kev[cid] = {
                'kev':           True,
                'kevDueDate':    v.get('dueDate',''),
                'kevDateAdded':  v.get('dateAdded',''),
                'kevRansomware': v.get('knownRansomwareCampaignUse','Unknown') == 'Known',
                'kevProduct':    (v.get('vendorProject','') + ' ' + v.get('product','')).strip(),
                'kevAction':     v.get('requiredAction',''),
                'kevName':       v.get('vulnerabilityName',''),
            }
        log(f"  KEV {len(kev):5} entries loaded")
        return kev
    except Exception as e:
        log(f"  WARNING CISA KEV: {e} -- skipping")
        return {}

def fetch_cisa_advisories():
    """Fetch CISA advisories via cisagov/CSAF GitHub repo (IT=AA, OT=ICS)."""
    import re as _re
    YEAR      = str(datetime.utcnow().year)
    PREV_YEAR = str(datetime.utcnow().year - 1)
    cutoff    = (datetime.utcnow() - timedelta(days=30)).strftime('%Y-%m-%d')
    advisories = []
    seen_ids   = set()

    def parse_csaf(raw_bytes, adv_type):
        try:
            d     = json.loads(raw_bytes)
            doc   = d.get('document', {})
            track = doc.get('tracking', {})
            adv_id   = track.get('id', '')
            title    = doc.get('title', '')
            pub_date = (track.get('current_release_date') or
                        track.get('initial_release_date', ''))[:10]
            if pub_date and pub_date < cutoff:
                return None
            cves_out = []
            for vuln in d.get('vulnerabilities', []):
                cve_id = vuln.get('cve', '').upper()
                if not cve_id:
                    ids = vuln.get('ids', [])
                    cve_id = ids[0].get('text','').upper() if ids else ''
                score, vector, severity = None, '', 'UNKNOWN'
                for sc in vuln.get('scores', []):
                    cv = sc.get('cvss_v3') or sc.get('cvss_v4') or {}
                    if cv.get('base_score'):
                        score    = float(cv['base_score'])
                        vector   = cv.get('vector_string','')
                        severity = ('CRITICAL' if score>=9 else 'HIGH' if score>=7
                                    else 'MEDIUM' if score>=4 else 'LOW')
                        break
                action = ''
                for rem in vuln.get('remediations', []):
                    if rem.get('category') in ('vendor_fix','mitigation','workaround'):
                        action = rem.get('details','')[:300]; break
                if cve_id:
                    cves_out.append({'cveID': cve_id, 'score': score,
                                     'vector': vector, 'severity': severity,
                                     'action': action})
            products = []
            for br in d.get('product_tree',{}).get('branches',[]):
                vendor = br.get('name','')
                for sub in br.get('branches',[]):
                    p = sub.get('name','')
                    if p: products.append((vendor + ' ' + p).strip())
            link = ('https://www.cisa.gov/news-events/' +
                    ('ics-advisories' if adv_type=='ics' else 'cybersecurity-advisories') +
                    '/' + adv_id.lower())
            for ref in doc.get('references',[]):
                if ref.get('category')=='self' and 'cisa.gov' in ref.get('url',''):
                    link = ref['url']; break
            return {'id': adv_id, 'title': title, 'date': pub_date,
                    'type': adv_type, 'link': link,
                    'cves': cves_out,
                    'products': list(set(products))[:8]}
        except Exception:
            return None

    def fetch_dir(path, adv_type, label):
        count = 0
        for year in [YEAR, PREV_YEAR]:
            try:
                api_url = (CSAF_API_BASE + '/' + path + '/' + year)
                raw     = http_get(api_url,
                    headers={'Accept': 'application/vnd.github.v3+json',
                             'User-Agent': 'SecureWatch/3.0'}, timeout=20)
                files = sorted(json.loads(raw),
                               key=lambda f: f.get('name',''), reverse=True)
                batch = 0
                for f in files:
                    if not f.get('name','').endswith('.json'): continue
                    try:
                        raw_json = http_get(
                            CSAF_RAW_BASE + '/' + path + '/' + year + '/' + f['name'],
                            timeout=15)
                        adv = parse_csaf(raw_json, adv_type)
                        if adv and adv['id'] not in seen_ids:
                            seen_ids.add(adv['id'])
                            advisories.append(adv)
                            count += 1
                            batch += 1
                    except Exception:
                        pass
                    if batch >= 40: break
            except Exception as e:
                log('  WARNING CSAF ' + label + ' ' + year + ': ' + str(e))
        return count

    log('')
    log('── CISA CSAF Advisories ────────────────────────────────')
    it_count  = fetch_dir('IT/white', 'aa',  'IT/AA')
    ics_count = fetch_dir('OT/white', 'ics', 'OT/ICS')
    advisories.sort(key=lambda a: a['date'], reverse=True)
    total_cves = sum(len(a['cves']) for a in advisories)
    crit_count = sum(1 for a in advisories
                     if any(c['score'] and c['score'] >= 9.0 for c in a['cves']))
    log('  ✅ AA advisories : ' + str(it_count))
    log('  ✅ ICS advisories: ' + str(ics_count))
    log('  Total CVE refs  : ' + str(total_cves))
    log('  Critical 9.0+   : ' + str(crit_count))
    return advisories


def merge_advisories(nvd_cves, advisories, vendor_id):
    """
    - For CVEs already in NVD list: enrich with vendor advisory URL + title
    - For CVEs NOT in NVD yet: add as new entry with vendor data
    - Advisory-only entries (no CVE ID): add as vendor-advisory type
    Returns merged list, counts of enriched + new entries.
    """
    nvd_map   = {c['id']: c for c in nvd_cves}
    enriched  = 0
    added_new = 0

    for adv in advisories:
        cve_id = adv.get('cve_id')

        if cve_id and cve_id in nvd_map:
            # Enrich existing NVD entry with vendor advisory link
            existing = nvd_map[cve_id]
            if adv['url'] and adv['url'] not in existing.get('refs', []):
                existing.setdefault('refs', []).insert(0, adv['url'])  # vendor URL first
            existing['_vendorTitle']  = adv['title']
            existing['_vendorSource'] = adv['vendor_id'].title()
            existing['_src']          = 'NVD+Vendor'
            enriched += 1

        elif cve_id and cve_id not in nvd_map:
            # New CVE not yet in NVD — add from vendor advisory
            nvd_map[cve_id] = {
                'id':             cve_id,
                'desc':           adv['desc'] or adv['title'],
                'score':          None,   # NVD hasn't scored it yet
                'severity':       adv['severity'],
                'vector':         None,
                'cvssVersion':    None,
                'av':             'NETWORK',  # safe default for vendor advisories
                'vendorScore':    None,
                'vendorSeverity': adv['severity'],
                'vendorSource':   adv['vendor_id'].title(),
                'refs':           [adv['url']] if adv['url'] else [],
                'published':      adv['published'],
                'modified':       adv['published'],
                'products':       [],
                'epss':           None,
                '_src':           'Vendor',
                '_vendorTitle':   adv['title'],
                '_vendorSource':  adv['vendor_id'].title(),
            }
            added_new += 1

        # Advisory-only (no CVE ID) — skip for now, NVD is source of truth for IDs

    return list(nvd_map.values()), enriched, added_new

# ── Main ──────────────────────────────────────────────────────

def fetch_cisa_data(existing_cve_map):
    """Fetch all CISA data: KEV catalog + CSAF advisories. Enrich with NVD data."""
    kev_map    = fetch_cisa_kev()
    advisories = fetch_cisa_advisories()

    # Build flat CVE lookup from all advisories
    cisa_cve_map = {}
    for adv in advisories:
        # Handle both old format (cveRefs: list of str) and new (cves: list of dicts)
        raw_cves = adv.get('cves') or adv.get('cveRefs') or []
        for c in raw_cves:
            # Normalise: old format is plain string, new is dict
            if isinstance(c, str):
                cid = c.upper()
                cscore, cvector, csev, caction = None, '', '', ''
            else:
                cid     = c.get('cveID', '').upper()
                cscore  = c.get('score')
                cvector = c.get('vector', '')
                csev    = c.get('severity', '')
                caction = c.get('action', '')
            if not cid:
                continue
            if cid not in cisa_cve_map or (cscore or 0) > (cisa_cve_map[cid].get('score') or 0):
                cisa_cve_map[cid] = {
                    'score':    cscore,
                    'severity': csev,
                    'vector':   cvector,
                    'action':   caction,
                    'advID':    adv.get('id', ''),
                    'advTitle': adv.get('title', ''),
                    'advLink':  adv.get('link') or adv.get('url', ''),
                    'advType':  adv.get('type', 'advisory'),
                    'advDate':  adv.get('date') or adv.get('pubDate', ''),
                }

    # Enrich KEV entries with NVD CVSS scores (KEV JSON has no scores)
    kev_enriched = 0
    for cve_id, kev in kev_map.items():
        nvd = existing_cve_map.get(cve_id, {})
        kev['cvss']     = nvd.get('score')
        kev['severity'] = nvd.get('severity', '')
        kev['vector']   = nvd.get('vector', '')
        kev['epss']     = nvd.get('epss')
        if cve_id in cisa_cve_map:
            kev['cisaAdv'] = cisa_cve_map[cve_id]
        if nvd:
            kev_enriched += 1

    cisa_in_env = sum(1 for c in cisa_cve_map if c in existing_cve_map)
    log(f"  🔗 KEV enriched with NVD: {kev_enriched}/{len(kev_map)}")
    log(f"  🏢 CISA advisory CVEs in your vendors: {cisa_in_env}")

    cutoff30   = (datetime.utcnow() - timedelta(days=30)).strftime('%Y-%m-%d')
    recent_kev = [v for v in kev_map.values() if v.get('kevDateAdded','') >= cutoff30]

    return {
        'lastFetch':      datetime.utcnow().isoformat() + 'Z',
        'kevCount':       len(kev_map),
        'recentKevCount': len(recent_kev),
        'advisoryCount':  len(advisories),
        'cisaCveCount':   len(cisa_cve_map),
        'kev':            kev_map,
        'advisories':     advisories,
        'cisaCveMap':     cisa_cve_map,
    }


# ── News Sources ──────────────────────────────────────────────
NEWS_SOURCES = [
    {'id': 'bc',   'label': 'BleepingComputer', 'url': 'https://www.bleepingcomputer.com/feed/'},
    {'id': 'thn',  'label': 'The Hacker News',  'url': 'https://feeds.feedburner.com/TheHackersNews'},
    {'id': 'sw',   'label': 'SecurityWeek',     'url': 'https://feeds.feedburner.com/securityweek'},
    {'id': 'cisa', 'label': 'CISA',             'url': 'https://www.cisa.gov/cybersecurity-advisories/all.xml'},
    {'id': 'kos',  'label': 'Krebs on Security','url': 'https://krebsonsecurity.com/feed/'},
]

NEWS_KEYWORDS = {
    'zero-day':   ['zero-day','zero day','0-day','zeroday'],
    'ransomware': ['ransomware','ransom','lockbit','blackcat','clop','akira'],
    'exploit':    ['exploit','proof-of-concept','remote code','rce'],
    'breach':     ['breach','data leak','exposed','stolen','compromised'],
    'critical':   ['critical','emergency','urgent','patch now','actively exploited'],
}

def parse_news_date(date_str):
    if not date_str:
        return datetime.utcnow().isoformat() + 'Z'
    for fmt in ['%a, %d %b %Y %H:%M:%S %z','%a, %d %b %Y %H:%M:%S %Z',
                '%Y-%m-%dT%H:%M:%SZ','%Y-%m-%dT%H:%M:%S%z']:
        try:
            return datetime.strptime(date_str.strip(), fmt).strftime('%Y-%m-%dT%H:%M:%SZ')
        except Exception:
            pass
    return datetime.utcnow().isoformat() + 'Z'

def strip_html(text):
    import re as _re
    return _re.sub(r'<[^>]+>', '', text or '').strip()

def get_news_tags(text):
    t = text.lower()
    return [tag for tag, kws in NEWS_KEYWORDS.items() if any(k in t for k in kws)]

def fetch_news_feed(source):
    cutoff = (datetime.utcnow() - timedelta(days=7)).isoformat()
    items  = []
    try:
        raw  = http_get(source['url'], timeout=15)
        root = ET.fromstring(raw)
        nodes = root.findall('.//item') or root.findall('.//{http://www.w3.org/2005/Atom}entry')
        for node in nodes[:20]:
            def txt(tag, n=node):
                el = n.find(tag)
                return (el.text or '').strip() if el is not None else ''
            title   = txt('title')
            link    = txt('link') or txt('guid')
            desc    = strip_html(txt('description') or txt('summary') or '')[:300]
            pub     = parse_news_date(txt('pubDate') or txt('published') or txt('updated'))
            if pub[:10] < cutoff[:10]:
                continue
            items.append({'id':source['id'],'src':source['label'],'title':title,
                          'url':link,'desc':desc,'pub':pub,'tags':get_news_tags(f"{title} {desc}")})
        log(f"  ✅ News  {source['id']:8} {len(items):3} articles")
    except Exception as e:
        log(f"  ⚠️  News  {source['id']}: {e}")
    return items

def fetch_all_news():
    log('')
    log('── Step 3: Security News ───────────────────────────────')
    all_items, seen = [], set()
    for source in NEWS_SOURCES:
        for item in fetch_news_feed(source):
            key = item['title'].lower()[:60]
            if key not in seen:
                seen.add(key)
                all_items.append(item)
        time.sleep(0.5)
    all_items.sort(key=lambda x: x['pub'], reverse=True)
    log(f"  📰 Total: {len(all_items)} articles from {len(NEWS_SOURCES)} sources")
    return all_items


# ── CISA KEV + Advisories ────────────────────────────────────
CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

def fetch_cisa_kev():
    """Fetch CISA Known Exploited Vulnerabilities catalog."""
    log('')
    log('── Step 4: CISA KEV Catalog ────────────────────────────')
    try:
        raw  = http_get(CISA_KEV_URL, timeout=30)
        data = json.loads(raw)
        vulns = data.get('vulnerabilities', [])

        # Build lookup dict: cveID -> enriched KEV data
        kev = {}
        ransomware_count = 0
        for v in vulns:
            cve_id = v.get('cveID','').upper()
            if not cve_id:
                continue
            is_ransomware = str(v.get('knownRansomwareCampaignUse','')).lower() == 'known'
            if is_ransomware:
                ransomware_count += 1
            kev[cve_id] = {
                'vendor':     v.get('vendorProject',''),
                'product':    v.get('product',''),
                'name':       v.get('vulnerabilityName',''),
                'dateAdded':  v.get('dateAdded',''),
                'dueDate':    v.get('dueDate',''),
                'action':     v.get('requiredAction',''),
                'desc':       v.get('shortDescription',''),
                'ransomware': is_ransomware,
                'notes':      v.get('notes',''),
                'cwes':       v.get('cwes',''),
            }

        log(f"  ✅ KEV catalog: {len(kev)} entries ({ransomware_count} ransomware-linked)")
        return kev

    except Exception as e:
        log(f"  ⚠️  KEV fetch failed: {e}")
        return {}

def enrich_cves_with_kev(db, kev):
    """Stamp _kev data onto any matching CVE in all vendor lists."""
    enriched = 0
    for vendor_id, vendor_data in db.get('vendors', {}).items():
        for cve in vendor_data.get('cves', []):
            cid = cve.get('id','').upper()
            if cid in kev:
                cve['_kev'] = kev[cid]
                enriched += 1
    log(f"  ✅ KEV enrichment: {enriched} CVEs enriched across all vendors")
    return enriched

def main():
    log('=' * 60)
    log('SecureWatch CVE Sync — NVD + Vendor Feeds')
    log(f'Days: {DAYS_BACK}  |  API key: {"YES" if NVD_KEY else "NO (slower)"}  |  Vendors: {len(VENDORS)}')
    log(f'Vendor feeds: {", ".join(f["id"] for f in VENDOR_FEEDS)}')
    log('=' * 60)

    # Load existing file to preserve data on partial failure
    db = {'lastSync': None, 'vendors': {}}
    if os.path.exists(OUT_FILE):
        try:
            with open(OUT_FILE) as f:
                db = json.load(f)
            log(f'Loaded existing: {sum(len(v.get("cves",[])) for v in db["vendors"].values()):,} CVEs')
        except Exception:
            pass

    # CISA runs in Step 3 below
    # ── Step 1: Fetch all vendor RSS/API feeds first (fast, no rate limits) ──
    log('')
    log('── Step 1: Vendor advisory feeds ──────────────────────')
    vendor_advisories = {}  # vendor_id → list of advisories

    for feed in VENDOR_FEEDS:
        log(f"  Fetching {feed['name']}…")
        if feed['format'] == 'msrc':
            advisories = fetch_msrc_feed(feed)
        elif feed['format'] == 'cisco_json':
            advisories = fetch_cisco_feed(feed)
        else:
            advisories = fetch_rss_feed(feed)
        vendor_advisories[feed['id']] = advisories
        time.sleep(0.5)  # small delay between feed fetches

    # ── Step 2: Fetch all vendors from NVD ────────────────────
    log('')
    log('── Step 2: NVD API ─────────────────────────────────────')

    success = failed = total_enriched = total_new = 0

    for i, vendor in enumerate(VENDORS):
        log(f"[{i+1:2}/{len(VENDORS)}] {vendor['id']}…")
        nvd_cves = fetch_vendor_nvd(vendor)

        # ── Step 3: Merge vendor advisories if available ──────
        adv_list = vendor_advisories.get(vendor['id'], [])
        if adv_list:
            nvd_cves, enriched, added_new = merge_advisories(nvd_cves, adv_list, vendor['id'])
            total_enriched += enriched
            total_new      += added_new
            if enriched or added_new:
                log(f"  🔗 Merged: {enriched} enriched · {added_new} new from vendor feed")

        # Sort by published date descending
        nvd_cves.sort(key=lambda c: c.get('published',''), reverse=True)

        db['vendors'][vendor['id']] = {
            'lastFetch':    datetime.utcnow().isoformat() + 'Z',
            'count':        len(nvd_cves),
            'hasVendorFeed': vendor['id'] in vendor_advisories,
            'cves':         nvd_cves,
        }
        if nvd_cves: success += 1
        else:        failed  += 1

        # Save after every vendor — progress not lost on timeout
        db['lastSync'] = datetime.utcnow().isoformat() + 'Z'
        with open(OUT_FILE, 'w') as f:
            json.dump(db, f, separators=(',', ':'))

        if i < len(VENDORS) - 1:
            time.sleep(THROTTLE)

    # ── Step 3: CISA KEV + Advisories ────────────────────────
    cve_map = {}
    for vid, vdata in db.get('vendors', {}).items():
        for cve in vdata.get('cves', []):
            cid = cve.get('id','').upper()
            if cid:
                cve_map[cid] = cve
    log(f"  CVE lookup map: {len(cve_map):,} entries")
    cisa_data = fetch_cisa_data(cve_map)
    db['cisa'] = cisa_data
    if db['cisa'].get('kev'):
        enrich_cves_with_kev(db, db['cisa']['kev'])
    with open(OUT_FILE, 'w') as f:
        json.dump(db, f, separators=(',', ':'))

    # ── Step 4: Security news ─────────────────────────────────
    news_items = fetch_all_news()
    db['news'] = {'lastFetch': datetime.utcnow().isoformat()+'Z', 'items': news_items}
    with open(OUT_FILE, 'w') as f:
        json.dump(db, f, separators=(',', ':'))

    total = sum(len(v.get('cves',[])) for v in db['vendors'].values())
    size  = os.path.getsize(OUT_FILE) / 1024 / 1024

    log('')
    log('=' * 60)
    log(f'Done: {success} vendors OK · {failed} skipped')
    log(f'Total CVEs: {total:,}  |  File: {size:.1f} MB')
    log(f'News articles: {len(news_items)} from {len(NEWS_SOURCES)} sources')
    kev_count = len(db.get('cisa', {}).get('kev', {}))
    adv_count = len(db.get('cisa', {}).get('advisories', []))
    log(f'CISA KEV: {kev_count:,} entries | Advisories: {adv_count}')
    log(f'Vendor enrichments: {total_enriched} enriched · {total_new} new CVEs from vendor feeds')
    log('=' * 60)

if __name__ == '__main__':
    main()

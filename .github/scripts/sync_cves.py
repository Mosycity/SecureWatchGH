python

"""
SecureWatch CVE Sync — GitHub Actions version
Fetches CVEs from NVD + vendor feeds + CISA KEV + CISA advisories + security news
Runs every 6 hours via GitHub Actions
"""

import json, os, time, re, xml.etree.ElementTree as ET
import urllib.request, urllib.parse, urllib.error
from datetime import datetime, timedelta

OUT_FILE  = 'cve-data.json'
NVD_KEY   = os.environ.get('NVD_API_KEY', '')
DAYS_BACK = int(os.environ.get('DAYS_BACK', 90))
THROTTLE  = 0.3 if NVD_KEY else 1.5

# ── Vendors (NVD) ─────────────────────────────────────────────
VENDORS = [
    # Network / Security
    {'id': 'cisco',       'keyword': 'cisco'},
    {'id': 'juniper',     'keyword': 'juniper'},
    {'id': 'paloalto',    'keyword': 'paloaltonetworks'},
    {'id': 'fortinet',    'keyword': 'fortinet'},
    {'id': 'checkpoint',  'keyword': 'checkpoint'},
    {'id': 'sonicwall',   'keyword': 'sonicwall'},
    {'id': 'aruba',       'keyword': 'aruba'},
    {'id': 'f5',          'keyword': 'f5'},
    {'id': 'nginx',       'keyword': 'nginx'},
    # Hardware
    {'id': 'dell',        'keyword': 'dell'},
    {'id': 'hp',          'keyword': 'hewlett packard'},
    {'id': 'lenovo',      'keyword': 'lenovo'},
    {'id': 'intel_hw',    'keyword': 'intel'},
    # Software / Application
    {'id': 'microsoft',   'keyword': 'microsoft'},
    {'id': 'adobe',       'keyword': 'adobe'},
    {'id': 'oracle',      'keyword': 'oracle'},
    {'id': 'sap',         'keyword': 'sap'},
    {'id': 'atlassian',   'keyword': 'atlassian'},
    {'id': 'apache',      'keyword': 'apache'},
    {'id': 'citrix',      'keyword': 'citrix'},
    {'id': 'ivanti',      'keyword': 'ivanti'},
    # Telecom
    {'id': 'ericsson',    'keyword': 'ericsson'},
    {'id': 'nokia',       'keyword': 'nokia'},
    {'id': 'huawei',      'keyword': 'huawei'},
    # Hypervisor / Virtualisation
    {'id': 'vmware',      'keyword': 'vmware'},
    {'id': 'broadcom',    'keyword': 'broadcom'},
    {'id': 'xen',         'keyword': 'xen'},
    # OS / Infrastructure
    {'id': 'redhat',      'keyword': 'red hat'},
    {'id': 'ubuntu',      'keyword': 'ubuntu'},
    {'id': 'canonical',   'keyword': 'canonical'},
    {'id': 'debian',      'keyword': 'debian'},
    # Cloud
    {'id': 'amazon',      'keyword': 'amazon'},
    {'id': 'google_cloud','keyword': 'google'},
]

# ── Vendor RSS / API feeds ────────────────────────────────────
VENDOR_FEEDS = [
    {
        'id': 'cisco', 'name': 'Cisco PSIRT',
        'urls': ['https://sec.cloudapps.cisco.com/security/center/json/getProductAdvisories.x?advisoryType=Security%20Advisory&sortBy=firstPublished&output=json'],
        'format': 'cisco_json',
    },
    {
        'id': 'microsoft', 'name': 'Microsoft MSRC',
        'urls': ['https://api.msrc.microsoft.com/cvrf/v3.0/updates'],
        'format': 'msrc',
    },
    {
        'id': 'fortinet', 'name': 'Fortinet PSIRT',
        'urls': ['https://www.fortiguard.com/rss/ir.xml', 'https://filestore.fortinet.com/fortiguard/rss/ir.xml'],
        'format': 'rss',
    },
    {
        'id': 'paloalto', 'name': 'Palo Alto Security',
        'urls': ['https://security.paloaltonetworks.com/rss.xml'],
        'format': 'rss',
    },
    {
        'id': 'juniper', 'name': 'Juniper SIRT',
        'urls': ['https://kb.juniper.net/InfoCenter/index?page=rss&channel=SIRT', 'https://www.juniper.net/us/en/rss/security-advisories.xml'],
        'format': 'rss_lenient',
    },
]

# ── CISA ──────────────────────────────────────────────────────
CISA_KEV_URL   = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
CSAF_API_BASE  = 'https://api.github.com/repos/cisagov/CSAF/contents/csaf_files'
CSAF_RAW_BASE  = 'https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files'

# ── News ──────────────────────────────────────────────────────
NEWS_SOURCES = [
    {'id': 'bc',   'label': 'BleepingComputer', 'url': 'https://www.bleepingcomputer.com/feed/'},
    {'id': 'thn',  'label': 'The Hacker News',  'url': 'https://feeds.feedburner.com/TheHackersNews'},
    {'id': 'sw',   'label': 'SecurityWeek',     'url': 'https://feeds.feedburner.com/securityweek'},
    {'id': 'cisa', 'label': 'CISA',             'url': 'https://www.cisa.gov/cybersecurity-advisories/all.xml'},
    {'id': 'kos',  'label': 'Krebs on Security','url': 'https://krebsonsecurity.com/feed/'},
]

# ─────────────────────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────────────────────
def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)

def http_get(url, headers=None, timeout=20):
    req = urllib.request.Request(url, headers={'User-Agent': 'SecureWatch/3.0', **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()

def http_get_with_fallback(urls, headers=None, timeout=15):
    last_err = None
    for url in urls:
        try:
            return http_get(url, headers=headers, timeout=timeout)
        except Exception as e:
            last_err = e
    raise last_err

def parse_xml_lenient(raw):
    try:
        return ET.fromstring(raw)
    except ET.ParseError:
        clean = raw.decode('utf-8', errors='replace')
        clean = ''.join(c for c in clean if ord(c) >= 32 or c in '\t\n\r')
        clean = re.sub(r'&(?![a-zA-Z#][a-zA-Z0-9#]*;)', '&amp;', clean)
        return ET.fromstring(clean.encode('utf-8'))

def sf_score(s):
    if s is None: return 'NONE'
    return 'CRITICAL' if s>=9 else 'HIGH' if s>=7 else 'MEDIUM' if s>=4 else 'LOW' if s>0 else 'NONE'

def severity_from_title(title):
    t = title.lower()
    if any(w in t for w in ['critical','remote code execution','rce','unauthenticated']): return 'CRITICAL'
    if any(w in t for w in ['high','privilege escalation','authentication bypass']): return 'HIGH'
    if any(w in t for w in ['medium','moderate','xss','csrf']): return 'MEDIUM'
    return 'HIGH'

# ─────────────────────────────────────────────────────────────
# NVD
# ─────────────────────────────────────────────────────────────
def nvd_fetch(params):
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
        if e.code == 429: raise Exception('RATE_LIMITED')
        raise Exception(f'HTTP {e.code}')
    except urllib.error.URLError as e:
        raise Exception(f'Network: {e.reason}')

def find_scores(arr):
    if not arr: return None, None
    primary   = next((m for m in arr if m.get('type')=='Primary'), arr[0])
    secondary = next((m for m in arr if m.get('type')=='Secondary'), None)
    return primary, secondary

def parse_cve(v):
    cve     = v.get('cve', {})
    metrics = cve.get('metrics', {})
    score = severity = vector = cvss_ver = None
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
        'id':            cve.get('id',''),
        'desc':          next((d['value'] for d in cve.get('descriptions',[]) if d.get('lang')=='en'), ''),
        'score':         score,
        'severity':      (severity or 'NONE').upper(),
        'vector':        vector,
        'cvssVersion':   cvss_ver,
        'av':            av,
        'vendorScore':   vs_score,
        'vendorSeverity':vs_sev,
        'vendorSource':  vs_src,
        'refs':          [r['url'] for r in cve.get('references',[])[:8]],
        'published':     (cve.get('published') or '')[:10],
        'modified':      (cve.get('lastModified') or '')[:10],
        'products':      list(products)[:6],
        'epss':          None,
        '_src':          'NVD',
    }

def fetch_vendor_nvd(vendor, attempt=0):
    now   = datetime.utcnow()
    start = (now - timedelta(days=DAYS_BACK)).strftime('%Y-%m-%dT00:00:00.000')
    end   = now.strftime('%Y-%m-%dT%H:%M:%S.000')
    try:
        data = nvd_fetch({'keywordSearch': vendor['keyword'], 'pubStartDate': start, 'pubEndDate': end})
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

# ─────────────────────────────────────────────────────────────
# VENDOR FEEDS
# ─────────────────────────────────────────────────────────────
def parse_rss_date(date_str):
    if not date_str: return ''
    for fmt in ['%a, %d %b %Y %H:%M:%S %z','%a, %d %b %Y %H:%M:%S %Z','%Y-%m-%dT%H:%M:%SZ','%Y-%m-%dT%H:%M:%S%z']:
        try:
            return datetime.strptime(date_str.strip(), fmt).strftime('%Y-%m-%d')
        except Exception:
            pass
    if date_str[:4].isdigit(): return date_str[:10]
    return datetime.utcnow().strftime('%Y-%m-%d')

def fetch_rss_feed(feed):
    vendor_id = feed['id']
    cutoff    = (datetime.utcnow() - timedelta(days=DAYS_BACK)).strftime('%Y-%m-%d')
    advisories= []
    lenient   = feed.get('format') == 'rss_lenient'
    try:
        urls = feed.get('urls', [feed.get('url','')])
        raw  = http_get_with_fallback(urls, timeout=15)
        if b'<html' in raw[:200].lower() or b'<!doctype' in raw[:200].lower():
            raise ValueError("Got HTML instead of XML — feed requires login")
        root = parse_xml_lenient(raw) if lenient else ET.fromstring(raw)
        for item in root.findall('.//item') or root.findall('.//{http://www.w3.org/2005/Atom}entry'):
            def txt(tag): el = item.find(tag); return (el.text or '').strip() if el is not None else ''
            title = txt('title')
            link  = txt('link') or txt('guid')
            desc  = txt('description') or txt('summary') or ''
            pub   = parse_rss_date(txt('pubDate') or txt('published') or txt('updated'))
            if pub and pub < cutoff: continue
            cve_ids = list(set(re.findall(r'CVE-\d{4}-\d{4,7}', f"{title} {desc}", re.IGNORECASE)))
            sev = severity_from_title(title)
            if cve_ids:
                for cid in cve_ids:
                    advisories.append({'cve_id':cid.upper(),'title':title,'desc':desc[:400],'url':link,'published':pub,'severity':sev,'vendor_id':vendor_id})
            else:
                advisories.append({'cve_id':None,'title':title,'desc':desc[:400],'url':link,'published':pub,'severity':sev,'vendor_id':vendor_id})
        cve_count = len([a for a in advisories if a['cve_id']])
        log(f"  ✅ RSS  {vendor_id:15} {len(advisories):4} advisories ({cve_count} with CVE IDs)")
    except Exception as e:
        log(f"  ⚠️  RSS  {vendor_id}: {e} — skipping vendor feed")
    return advisories

def fetch_cisco_feed(feed):
    vendor_id = feed['id']
    cutoff    = (datetime.utcnow() - timedelta(days=DAYS_BACK)).strftime('%Y-%m-%d')
    advisories= []
    try:
        urls = feed.get('urls', [])
        raw  = http_get_with_fallback(urls, timeout=20)
        data = json.loads(raw)
        items = data if isinstance(data, list) else data.get('advisories', data.get('data', []))
        for item in items:
            pub = (item.get('firstPublished') or item.get('publicationUrl',''))[:10]
            if pub and pub < cutoff: continue
            title = item.get('advisoryTitle','') or item.get('title','')
            url   = item.get('publicationUrl','') or item.get('url','')
            desc  = item.get('summary','') or item.get('description','')
            cve_ids = item.get('cves', item.get('cveIds', []))
            if not cve_ids:
                cve_ids = re.findall(r'CVE-\d{4}-\d{4,7}', f"{title} {desc}")
            sev = (item.get('sir','') or item.get('severity','')).upper()
            if sev not in ('CRITICAL','HIGH','MEDIUM','LOW'): sev = severity_from_title(title)
            if cve_ids:
                for cid in (cve_ids if isinstance(cve_ids, list) else [cve_ids]):
                    advisories.append({'cve_id':str(cid).upper(),'title':title,'desc':desc[:400],'url':url,'published':pub,'severity':sev,'vendor_id':vendor_id})
            else:
                advisories.append({'cve_id':None,'title':title,'desc':desc[:400],'url':url,'published':pub,'severity':sev,'vendor_id':vendor_id})
        cve_count = len([a for a in advisories if a['cve_id']])
        log(f"  ✅ JSON {vendor_id:15} {len(advisories):4} advisories ({cve_count} with CVE IDs)")
    except Exception as e:
        log(f"  ⚠️  JSON {vendor_id}: {e} — skipping vendor feed")
    return advisories

def fetch_msrc_feed(feed):
    vendor_id = feed['id']
    cutoff    = (datetime.utcnow() - timedelta(days=DAYS_BACK)).strftime('%Y-%m-%d')
    advisories= []
    try:
        urls = feed.get('urls', [feed.get('url','')])
        raw  = http_get_with_fallback(urls, headers={'Accept': 'application/json'}, timeout=20)
        data = json.loads(raw)
        for upd in data.get('value', []):
            pub = (upd.get('InitialReleaseDate') or upd.get('CurrentReleaseDate') or '')[:10]
            if pub and pub < cutoff: continue
            title  = upd.get('DocumentTitle', {})
            if isinstance(title, dict): title = title.get('Value', '')
            cve_id = upd.get('ID', '')
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
    except Exception as e:
        log(f"  ⚠️  MSRC {vendor_id}: {e} — skipping vendor feed")
    return advisories

def merge_advisories(nvd_cves, advisories, vendor_id):
    nvd_map  = {c['id']: c for c in nvd_cves}
    enriched = 0
    added    = 0
    for adv in advisories:
        cid = adv.get('cve_id')
        if cid and cid in nvd_map:
            ex = nvd_map[cid]
            if adv['url'] and adv['url'] not in ex.get('refs', []):
                ex.setdefault('refs', []).insert(0, adv['url'])
            ex['_vendorTitle']  = adv['title']
            ex['_vendorSource'] = adv['vendor_id'].title()
            ex['_src']          = 'NVD+Vendor'
            enriched += 1
        elif cid and cid not in nvd_map:
            nvd_map[cid] = {
                'id':cid,'desc':adv['desc'] or adv['title'],
                'score':None,'severity':adv['severity'],'vector':None,
                'cvssVersion':None,'av':'NETWORK','vendorScore':None,
                'vendorSeverity':adv['severity'],'vendorSource':adv['vendor_id'].title(),
                'refs':[adv['url']] if adv['url'] else [],
                'published':adv['published'],'modified':adv['published'],
                'products':[],'epss':None,'_src':'Vendor',
                '_vendorTitle':adv['title'],'_vendorSource':adv['vendor_id'].title(),
            }
            added += 1
    return list(nvd_map.values()), enriched, added

# ─────────────────────────────────────────────────────────────
# CISA KEV + ADVISORIES
# ─────────────────────────────────────────────────────────────
def fetch_cisa_kev():
    log('')
    log('── CISA KEV Catalog ────────────────────────────────────')
    try:
        raw  = http_get(CISA_KEV_URL, timeout=20)
        data = json.loads(raw)
        vulns= data.get('vulnerabilities', [])
        kev  = {}
        for v in vulns:
            cid = v.get('cveID','').upper()
            if cid:
                kev[cid] = {
                    'cveID':       cid,
                    'kevProduct':  (v.get('vendorProject','') + ' ' + v.get('product','')).strip(),
                    'kevName':     v.get('vulnerabilityName',''),
                    'kevDateAdded':v.get('dateAdded',''),
                    'kevDueDate':  v.get('dueDate',''),
                    'kevAction':   v.get('requiredAction',''),
                    'kevRansomware': v.get('knownRansomwareCampaignUse','Unknown') == 'Known',
                    'cvss': None, 'severity': '', 'vector': '', 'epss': None,
                }
        cutoff30 = (datetime.utcnow() - timedelta(days=30)).strftime('%Y-%m-%d')
        recent   = [v for v in kev.values() if v['kevDateAdded'] >= cutoff30]
        log(f"  ✅ KEV catalog: {len(kev):,} entries ({len(recent)} added last 30d)")
        return kev
    except Exception as e:
        log(f"  ⚠️  KEV fetch failed: {e}")
        return {}

def fetch_cisa_advisories():
    log('')
    log('── CISA CSAF Advisories ─────────────────────────────────')
    advisories = []
    seen       = set()
    YEAR       = str(datetime.utcnow().year)
    PREV_YEAR  = str(datetime.utcnow().year - 1)
    cutoff     = (datetime.utcnow() - timedelta(days=30)).strftime('%Y-%m-%d')

    def parse_csaf(raw_json, adv_type):
        try:
            d     = json.loads(raw_json)
            doc   = d.get('document', {})
            track = doc.get('tracking', {})
            adv_id   = track.get('id','')
            title    = doc.get('title','')
            pub_date = (track.get('current_release_date') or track.get('initial_release_date',''))[:10]
            if pub_date and pub_date < cutoff:
                return None
            cves_out = []
            for vuln in d.get('vulnerabilities', []):
                cve_id = vuln.get('cve','').upper()
                score = vector = severity = None
                for sc in vuln.get('scores', []):
                    cv3 = sc.get('cvss_v3') or sc.get('cvss_v4') or {}
                    if cv3.get('base_score'):
                        score  = float(cv3['base_score'])
                        vector = cv3.get('vector_string','')
                        bs     = score
                        severity = 'CRITICAL' if bs>=9 else 'HIGH' if bs>=7 else 'MEDIUM' if bs>=4 else 'LOW'
                        break
                products = []
                for br in d.get('product_tree',{}).get('branches',[]):
                    vendor = br.get('name','')
                    for sub in br.get('branches',[]):
                        prod = sub.get('name','')
                        if prod: products.append(f"{vendor} {prod}".strip())
                action = ''
                for rem in vuln.get('remediations',[]):
                    if rem.get('category') in ('vendor_fix','mitigation','workaround'):
                        action = rem.get('details','')[:300]; break
                if cve_id:
                    cves_out.append({'cveID':cve_id,'score':score,'vector':vector,'severity':severity,'action':action})
            link = f"https://www.cisa.gov/news-events/{'ics-advisories' if adv_type=='ics' else 'cybersecurity-advisories'}/{adv_id.lower()}"
            for ref in doc.get('references',[]):
                if ref.get('category')=='self' and 'cisa.gov' in ref.get('url',''):
                    link = ref['url']; break
            return {'id':adv_id,'title':title,'date':pub_date,'type':adv_type,'link':link,'cves':cves_out,'products':list(set(products))[:6]}
        except Exception:
            return None

    def fetch_dir(path, adv_type, label):
        count = 0
        for year in [YEAR, PREV_YEAR]:
            try:
                raw   = http_get(f"{CSAF_API_BASE}/{path}/{year}", headers={'Accept':'application/vnd.github.v3+json'}, timeout=20)
                files = sorted(json.loads(raw), key=lambda f: f.get('name',''), reverse=True)
                fetched = 0
                for f in files:
                    if not f.get('name','').endswith('.json'): continue
                    try:
                        raw_json = http_get(f"{CSAF_RAW_BASE}/{path}/{year}/{f['name']}", timeout=15)
                        adv = parse_csaf(raw_json, adv_type)
                        if adv and adv['id'] not in seen:
                            seen.add(adv['id'])
                            advisories.append(adv)
                            count += 1; fetched += 1
                    except Exception:
                        pass
                    if fetched >= 40: break
            except Exception as e:
                log(f"  ⚠️  CSAF {label} {year}: {e}")
        return count

    aa_count  = fetch_dir('IT/white', 'aa',  'IT/AA')
    ics_count = fetch_dir('OT/white', 'ics', 'OT/ICS')
    advisories.sort(key=lambda a: a['date'], reverse=True)
    total_cves = sum(len(a['cves']) for a in advisories)
    log(f"  ✅ AA advisories:  {aa_count}")
    log(f"  ✅ ICS advisories: {ics_count}")
    log(f"  📋 Total CVE refs: {total_cves}")
    return advisories

def fetch_cisa_data(cve_map):
    kev_map    = fetch_cisa_kev()
    advisories = fetch_cisa_advisories()

    # Build flat CVE→advisory map
    cisa_cve_map = {}
    for adv in advisories:
        for c in adv['cves']:
            cid = c['cveID']
            if cid not in cisa_cve_map or (c['score'] or 0) > (cisa_cve_map[cid].get('score') or 0):
                cisa_cve_map[cid] = {'score':c['score'],'severity':c['severity'],'vector':c['vector'],'action':c['action'],'advID':adv['id'],'advTitle':adv['title'],'advLink':adv['link'],'advType':adv['type'],'advDate':adv['date']}

    # Enrich KEV with NVD CVSS scores
    enriched = 0
    for cid, kev in kev_map.items():
        nvd = cve_map.get(cid, {})
        kev['cvss']     = nvd.get('score')
        kev['severity'] = nvd.get('severity','')
        kev['vector']   = nvd.get('vector','')
        kev['epss']     = nvd.get('epss')
        if cid in cisa_cve_map: kev['cisaAdv'] = cisa_cve_map[cid]
        if nvd: enriched += 1

    cutoff30 = (datetime.utcnow() - timedelta(days=30)).strftime('%Y-%m-%d')
    recent   = len([v for v in kev_map.values() if v.get('kevDateAdded','') >= cutoff30])
    in_env   = sum(1 for c in cisa_cve_map if c in cve_map)
    log(f"  🔗 KEV enriched with NVD: {enriched}/{len(kev_map)}")
    log(f"  🏢 CISA advisory CVEs in your vendors: {in_env}")

    return {
        'lastFetch':      datetime.utcnow().isoformat()+'Z',
        'kevCount':       len(kev_map),
        'recentKevCount': recent,
        'advisoryCount':  len(advisories),
        'cisaCveCount':   len(cisa_cve_map),
        'kev':            kev_map,
        'advisories':     advisories,
        'cisaCveMap':     cisa_cve_map,
    }

# ─────────────────────────────────────────────────────────────
# SECURITY NEWS
# ─────────────────────────────────────────────────────────────
def fetch_news_feed(source):
    cutoff = (datetime.utcnow() - timedelta(days=7)).isoformat()
    items  = []
    try:
        raw  = http_get(source['url'], timeout=15)
        root = ET.fromstring(raw)
        nodes = root.findall('.//item') or root.findall('.//{http://www.w3.org/2005/Atom}entry')
        for node in nodes[:20]:
            def txt(tag): el = node.find(tag); return (el.text or '').strip() if el is not None else ''
            title   = txt('title')
            link    = txt('link') or txt('guid')
            desc    = re.sub(r'<[^>]+>','',txt('description') or txt('summary') or '')[:300].strip()
            pub_raw = txt('pubDate') or txt('published') or txt('updated')
            pub     = ''
            for fmt in ['%a, %d %b %Y %H:%M:%S %z','%a, %d %b %Y %H:%M:%S %Z','%Y-%m-%dT%H:%M:%SZ','%Y-%m-%dT%H:%M:%S%z']:
                try: pub = datetime.strptime(pub_raw.strip(), fmt).isoformat()+'Z'; break
                except Exception: pass
            if not pub: pub = datetime.utcnow().isoformat()+'Z'
            if pub[:19] < cutoff[:19]: continue
            tags = [t for t, kws in {
                'zero-day':['zero-day','0-day','zeroday'],
                'ransomware':['ransomware','ransom','lockbit'],
                'exploit':['exploit','poc','rce','injection'],
                'breach':['breach','data leak','exposed','stolen'],
                'critical':['critical','emergency','patch now','actively exploited'],
            }.items() if any(k in f"{title} {desc}".lower() for k in kws)]
            items.append({'id':source['id'],'src':source['label'],'title':title,'url':link,'desc':desc,'pub':pub,'tags':tags})
        log(f"  ✅ News  {source['id']:8} {len(items):3} articles")
    except Exception as e:
        log(f"  ⚠️  News  {source['id']}: {e}")
    return items

def fetch_all_news():
    log('')
    log('── Security News ────────────────────────────────────────')
    all_items, seen = [], set()
    for source in NEWS_SOURCES:
        for item in fetch_news_feed(source):
            key = item['title'].lower()[:60]
            if key not in seen:
                seen.add(key); all_items.append(item)
        time.sleep(0.5)
    all_items.sort(key=lambda x: x['pub'], reverse=True)
    log(f"  📰 Total: {len(all_items)} articles from {len(NEWS_SOURCES)} sources")
    return all_items

# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────
def main():
    log('=' * 60)
    log('SecureWatch CVE Sync — NVD + Vendor Feeds + CISA + News')
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

    # ── Step 1: Vendor RSS/API feeds ─────────────────────────
    log('')
    log('── Step 1: Vendor advisory feeds ──────────────────────')
    vendor_advisories = {}
    for feed in VENDOR_FEEDS:
        log(f"  Fetching {feed['name']}…")
        if feed['format'] == 'msrc':
            advisories = fetch_msrc_feed(feed)
        elif feed['format'] == 'cisco_json':
            advisories = fetch_cisco_feed(feed)
        else:
            advisories = fetch_rss_feed(feed)
        vendor_advisories[feed['id']] = advisories
        time.sleep(0.5)

    # ── Step 2: NVD API ───────────────────────────────────────
    log('')
    log('── Step 2: NVD API ─────────────────────────────────────')
    success = failed = total_enriched = total_new = 0

    for i, vendor in enumerate(VENDORS):
        log(f"[{i+1:2}/{len(VENDORS)}] {vendor['id']}…")
        nvd_cves = fetch_vendor_nvd(vendor)

        adv_list = vendor_advisories.get(vendor['id'], [])
        if adv_list:
            nvd_cves, enriched, added = merge_advisories(nvd_cves, adv_list, vendor['id'])
            total_enriched += enriched; total_new += added
            if enriched or added:
                log(f"  🔗 Merged: {enriched} enriched · {added} new from vendor feed")

        nvd_cves.sort(key=lambda c: c.get('published',''), reverse=True)
        db['vendors'][vendor['id']] = {
            'lastFetch':    datetime.utcnow().isoformat()+'Z',
            'count':        len(nvd_cves),
            'hasVendorFeed':vendor['id'] in vendor_advisories,
            'cves':         nvd_cves,
        }
        if nvd_cves: success += 1
        else: failed += 1

        db['lastSync'] = datetime.utcnow().isoformat()+'Z'
        with open(OUT_FILE,'w') as f:
            json.dump(db, f, separators=(',',':'))

        if i < len(VENDORS) - 1:
            time.sleep(THROTTLE)

    # ── Step 3: CISA ──────────────────────────────────────────
    cve_map = {}
    for vid, vdata in db.get('vendors',{}).items():
        for cve in vdata.get('cves',[]):
            cid = cve.get('id','').upper()
            if cid: cve_map[cid] = cve
    log(f"  CVE lookup map: {len(cve_map):,} entries")

    cisa_data = fetch_cisa_data(cve_map)
    db['cisa'] = cisa_data
    # Enrich vendor CVEs with KEV flag
    kev = cisa_data.get('kev', {})
    for vid, vdata in db.get('vendors',{}).items():
        for cve in vdata.get('cves',[]):
            if cve.get('id','').upper() in kev:
                cve['kev'] = True

    with open(OUT_FILE,'w') as f:
        json.dump(db, f, separators=(',',':'))

    # ── Step 4: Security news ─────────────────────────────────
    news_items = fetch_all_news()
    db['news'] = {'lastFetch':datetime.utcnow().isoformat()+'Z','items':news_items}
    with open(OUT_FILE,'w') as f:
        json.dump(db, f, separators=(',',':'))

    total = sum(len(v.get('cves',[])) for v in db['vendors'].values())
    size  = os.path.getsize(OUT_FILE) / 1024 / 1024

    log('')
    log('=' * 60)
    log(f'Done: {success} vendors OK · {failed} skipped')
    log(f'Total CVEs: {total:,}  |  File: {size:.1f} MB')
    log(f'CISA KEV: {cisa_data["kevCount"]:,} | Advisories: {cisa_data["advisoryCount"]}')
    log(f'News: {len(news_items)} articles')
    log(f'Vendor enrichments: {total_enriched} enriched · {total_new} new CVEs from vendor feeds')
    log('=' * 60)

if __name__ == '__main__':
    main()

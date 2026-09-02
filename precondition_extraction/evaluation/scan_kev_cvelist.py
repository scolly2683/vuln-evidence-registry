"""Scan every CISA KEV CVE's CVE 5.x record (cvelistV5) and record which containers the
CNA and the CISA ADP actually populated. Produced data/kev_cvelist_scan_2026-09-02.json;
findings in STANDARDS.md. Re-run: download the KEV JSON to data/ first.
"""
import json, urllib.request, concurrent.futures as cf, time, sys
kev = json.load(open('data/known_exploited_vulnerabilities.json'))['vulnerabilities']  # CISA KEV feed JSON
ids = [v['cveID'] for v in kev]
def url(c):
    y, n = c.split('-')[1], c.split('-')[2]
    return f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{y}/{n[:-3]}xxx/{c}.json"
def fetch(c):
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url(c), timeout=40) as r: return c, json.load(r)
        except Exception as e:
            err = str(e); time.sleep(2*(attempt+1))
    return c, {'_error': err}
def summarise(c, d):
    if '_error' in d: return {'cve': c, 'error': d['_error'][:60]}
    cna = d.get('containers', {}).get('cna', {}); adps = d.get('containers', {}).get('adp', []) or []
    def tlen(container, key):
        items = container.get(key) or []
        return sum(len(x.get('value', '')) for x in items if isinstance(x, dict))
    out = {'cve': c, 'cna': d.get('cveMetadata', {}).get('assignerShortName'),
           'desc_len': tlen(cna, 'descriptions'),
           'configurations_len': tlen(cna, 'configurations'), 'workarounds_len': tlen(cna, 'workarounds'),
           'solutions_len': tlen(cna, 'solutions'), 'exploits_len': tlen(cna, 'exploits'),
           'cna_cpe': any(a.get('cpes') for a in (cna.get('affected') or [])),
           'cna_cvss': any(k.startswith('cvss') for m in (cna.get('metrics') or []) for k in m),
           'adp_names': [a.get('providerMetadata', {}).get('shortName') for a in adps],
           'adp_ssvc': any('ssvc' in json.dumps(m).lower() for a in adps for m in (a.get('metrics') or [])),
           'adp_cvss': any(k.startswith('cvss') for a in adps for m in (a.get('metrics') or []) for k in m),
           'adp_cpe': any(x.get('cpes') for a in adps for x in (a.get('affected') or [])),
           'adp_cwe': any(a.get('problemTypes') for a in adps),
           'adp_kev_tag': any('kev' in json.dumps(a.get('timeline') or a.get('tags') or '').lower() for a in adps),
           'adp_conf_len': sum(tlen(a, 'configurations') + tlen(a, 'workarounds') for a in adps)}
    return out
rows = []
with cf.ThreadPoolExecutor(6) as ex:
    for i, (c, d) in enumerate(ex.map(fetch, ids), 1):
        rows.append(summarise(c, d))
        if i % 200 == 0: print(i, flush=True); json.dump(rows, open('data/kev_cvelist_scan.json', 'w'))
json.dump(rows, open('data/kev_cvelist_scan.json', 'w'))
print('DONE', len(rows))

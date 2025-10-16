import requests

NVD_RECENT_FEED = 'https://services.nvd.nist.gov/rest/json/cves/1.0'

def fetch_recent_cves(params=None):
    r = requests.get(NVD_RECENT_FEED, params=params or {})
    r.raise_for_status()
    data = r.json()
    return data.get('result', {}).get('CVE_Items', [])

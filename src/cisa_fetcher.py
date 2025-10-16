import requests

CISA_KEV_JSON = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

def fetch_cisa_kevs():
    r = requests.get(CISA_KEV_JSON)
    r.raise_for_status()
    data = r.json()
    return data.get('vulnerabilities', [])

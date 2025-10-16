import requests

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known-exploited-vulnerabilities.json"

def fetch_recent_kevs():
    """
    Fetch KEVs from CISA catalog.
    Returns a list of CVE dicts with keys: cve_id, vendor, product, description, cvss
    """
    try:
        response = requests.get(KEV_FEED_URL)
        response.raise_for_status()
        data = response.json()
        cves = []

        for item in data.get("vulnerabilities", []):
            cves.append({
                "cve_id": item.get("cveID", "N/A"),
                "vendor": item.get("vendorProject", "N/A"),
                "product": item.get("product", "N/A"),
                "description": item.get("vulnerabilityName", "N/A"),
                "cvss": item.get("cvssScore", "N/A")
            })

        print(f"[+] Fetched {len(cves)} KEVs")
        return cves

    except Exception as e:
        print(f"Error fetching KEVs: {e}")
        return []

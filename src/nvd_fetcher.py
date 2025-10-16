import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_recent_cves(keyword, results_per_page=50):
    """
    Fetch CVEs from NVD API for a given keyword.
    For testing, ignores publish date to ensure results.
    """
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": results_per_page,
        "startIndex": 0
    }

    try:
        response = requests.get(NVD_API_URL, params=params)
        response.raise_for_status()
        data = response.json()
        cves = []

        for item in data.get("vulnerabilities", []):
            cve_item = item.get("cve", {})
            cves.append({
                "cve_id": cve_item.get("id", "N/A"),
                "vendor": cve_item.get("vendor", "N/A"),
                "product": cve_item.get("product", "N/A"),
                "description": cve_item.get("descriptions", [{}])[0].get("value", "N/A"),
                "cvss": cve_item.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A")
            })
        print(f"[+] Fetched {len(cves)} CVEs for {keyword}")
        return cves

    except requests.exceptions.HTTPError as e:
        print(f"Error fetching CVEs for {keyword}: {e}")
        return []
    except Exception as e:
        print(f"Unexpected error for {keyword}: {e}")
        return []

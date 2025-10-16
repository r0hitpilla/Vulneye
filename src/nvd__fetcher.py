# Example template for NVD CVE fetcher
# You can replace this with your existing logic

def fetch_cves(asset):
    """
    Returns a list of CVE dictionaries:
    [
        {
            "cve_id": "CVE-xxxx-xxxx",
            "vendor": "Vendor",
            "product": "Product",
            "vuln_name": "Vulnerability Name",
            "date_added": "YYYY-MM-DD",
            "description": "Description text",
            "cvss": 7.5
        },
        ...
    ]
    """
    # TODO: Replace with actual NVD fetching logic
    return []
import requests
from datetime import datetime, timedelta

NVD_API_KEY = "https://services.nvd.nist.gov/rest/json/cves/2.0" 

def fetch_cves(asset):
    """
    Fetch CVEs from NVD API for the given asset in the last 15 days.
    Handles pagination and returns a list of dictionaries:
    cve_id, vendor, product, vuln_name, date_added, description, cvss
    """
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": NVD_API_KEY}

    # Date range: last 15 days
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=15)
    start_date_str = start_date.strftime("%Y-%m-%dT%H:%M:%S:000 UTC+00:00")
    end_date_str = end_date.strftime("%Y-%m-%dT%H:%M:%S:000 UTC+00:00")

    params = {
        "keywordSearch": asset,
        "pubStartDate": start_date_str,
        "pubEndDate": end_date_str,
        "resultsPerPage": 200,  # Max per page
        "startIndex": 0
    }

    all_results = []

    try:
        while True:
            response = requests.get(base_url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()
            cve_items = data.get("vulnerabilities", [])
            if not cve_items:
                break

            for item in cve_items:
                cve_info = item.get("cve", {})
                cve_id = cve_info.get("id", "N/A")
                descriptions = cve_info.get("descriptions", [])
                description = descriptions[0]["value"] if descriptions else "N/A"

                metrics = cve_info.get("metrics", {})
                cvss = "N/A"
                if "cvssMetricV31" in metrics:
                    cvss = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore", "N/A")
                elif "cvssMetricV30" in metrics:
                    cvss = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore", "N/A")

                vendor, product = "N/A", "N/A"
                configs = cve_info.get("configurations", [])
                if configs:
                    nodes = configs[0].get("nodes", [])
                    if nodes:
                        cpe_matches = nodes[0].get("cpeMatches", [])
                        if cpe_matches:
                            cpe = cpe_matches[0].get("criteria", "")
                            parts = cpe.split(":")
                            if len(parts) >= 4:
                                vendor = parts[2]
                                product = parts[3]

                all_results.append({
                    "cve_id": cve_id,
                    "vendor": vendor,
                    "product": product,
                    "vuln_name": "N/A",
                    "date_added": cve_info.get("published", "N/A"),
                    "description": description,
                    "cvss": cvss
                })

            # Pagination: check if more results exist
            total_results = data.get("totalResults", 0)
            params["startIndex"] += params["resultsPerPage"]
            if params["startIndex"] >= total_results:
                break

        return all_results

    except Exception as e:
        print(f"Error fetching CVEs for {asset}: {e}")
        return []
